"""Suite 1 — EventBus unit tests (T1).

Section 18.1: test_event_bus.py.
"""

from __future__ import annotations

import pytest

from backend.core.event_bus import DurableEventLog, EventBus


@pytest.fixture
async def event_log(tmp_path):
    log = DurableEventLog(db_path=tmp_path / "test_events.db")
    await log.initialize()
    yield log
    await log.close()


@pytest.fixture
async def event_bus(tmp_path):
    log = DurableEventLog(db_path=tmp_path / "test_bus.db")
    bus = EventBus(durable_log=log)
    await bus.initialize()
    yield bus
    await bus.close()


class TestDurableEventLog:
    """SQLite write confirmed before delivery."""

    @pytest.mark.asyncio
    async def test_append_returns_sequence_number(self, event_log):
        seq = await event_log.append("findings", "FINDING_CREATED", {"test": True})
        assert seq >= 1

    @pytest.mark.asyncio
    async def test_sequence_is_monotonic(self, event_log):
        seq1 = await event_log.append("findings", "FINDING_CREATED", {"n": 1})
        seq2 = await event_log.append("findings", "FINDING_CREATED", {"n": 2})
        seq3 = await event_log.append("lifecycle", "AGENT_SPAWNED", {"n": 3})
        assert seq1 < seq2 < seq3

    @pytest.mark.asyncio
    async def test_replay_returns_events_after_seq(self, event_log):
        """Replay delivers all events with seq > last_seq."""
        seqs = []
        for i in range(5):
            seq = await event_log.append("findings", "FINDING_CREATED", {"n": i})
            seqs.append(seq)

        # Replay from after 2nd event
        events = await event_log.replay(seqs[1])
        assert len(events) == 3
        assert events[0]["seq"] == seqs[2]
        assert events[-1]["seq"] == seqs[4]

    @pytest.mark.asyncio
    async def test_replay_from_zero_returns_all(self, event_log):
        for i in range(3):
            await event_log.append("findings", "FINDING_CREATED", {"n": i})

        events = await event_log.replay(0)
        assert len(events) == 3

    @pytest.mark.asyncio
    async def test_prune_removes_old_events(self, event_log):
        await event_log.append("findings", "FINDING_CREATED", {"old": True})
        # Prune with 0 hours removes everything
        removed = await event_log.prune(max_age_hours=0)
        assert removed >= 1
        events = await event_log.replay(0)
        assert len(events) == 0

    @pytest.mark.asyncio
    async def test_acknowledge_event(self, event_log):
        seq = await event_log.append("findings", "FINDING_CREATED", {"ack_test": True})
        await event_log.acknowledge(seq, "frontend-1")


class TestEventBus:
    """EventBus writes to SQLite before delivery."""

    @pytest.mark.asyncio
    async def test_publish_persists_before_delivery(self, event_bus):
        received = []

        async def subscriber(event):
            received.append(event)

        event_bus.subscribe("findings", subscriber)
        seq = await event_bus.publish("findings", "FINDING_CREATED", {"test": True})

        # Verify persisted
        events = await event_bus.replay(0)
        assert len(events) >= 1
        assert events[-1]["event_type"] == "FINDING_CREATED"

        # Verify delivered
        assert len(received) == 1
        assert received[0]["seq"] == seq

    @pytest.mark.asyncio
    async def test_replay_after_publish(self, event_bus):
        seq1 = await event_bus.publish("lifecycle", "AGENT_SPAWNED", {"agent": "recon"})
        seq2 = await event_bus.publish("findings", "FINDING_CREATED", {"vuln": "xss"})

        events = await event_bus.replay(seq1)
        assert len(events) == 1
        assert events[0]["event_type"] == "FINDING_CREATED"

    @pytest.mark.asyncio
    async def test_subscriber_error_does_not_block(self, event_bus):
        """Subscriber failure does not prevent event persistence."""
        async def failing_subscriber(event):
            raise RuntimeError("Subscriber crashed")

        event_bus.subscribe("findings", failing_subscriber)
        seq = await event_bus.publish("findings", "FINDING_CREATED", {"test": True})

        # Event still persisted despite subscriber failure
        events = await event_bus.replay(0)
        assert len(events) >= 1


# ---------------------------------------------------------------------------
# M1 additional tests (T3)
# ---------------------------------------------------------------------------

class TestEventBusChannelFiltering:
    """Channel filtering works correctly."""

    @pytest.mark.asyncio
    async def test_subscriber_only_receives_own_channel(self, event_bus):
        """Subscriber on 'findings' should not receive 'lifecycle' events."""
        findings_events = []
        lifecycle_events = []

        async def findings_sub(event):
            findings_events.append(event)

        async def lifecycle_sub(event):
            lifecycle_events.append(event)

        event_bus.subscribe("findings", findings_sub)
        event_bus.subscribe("lifecycle", lifecycle_sub)

        await event_bus.publish("findings", "FINDING_CREATED", {"f": 1})
        await event_bus.publish("lifecycle", "AGENT_SPAWNED", {"a": 1})
        await event_bus.publish("findings", "FINDING_VERIFIED", {"f": 2})

        assert len(findings_events) == 2
        assert len(lifecycle_events) == 1

    @pytest.mark.asyncio
    async def test_multiple_subscribers_on_same_channel(self, event_bus):
        """Multiple subscribers on the same channel all receive events."""
        received_a = []
        received_b = []

        async def sub_a(event):
            received_a.append(event)

        async def sub_b(event):
            received_b.append(event)

        event_bus.subscribe("system", sub_a)
        event_bus.subscribe("system", sub_b)

        await event_bus.publish("system", "KALI_UNREACHABLE", {"test": True})

        assert len(received_a) == 1
        assert len(received_b) == 1


class TestEventBusConcurrency:
    """Multiple concurrent publishers don't lose events."""

    @pytest.mark.asyncio
    async def test_concurrent_publishers(self, event_bus):
        """10 concurrent publishes all persist."""
        import asyncio

        async def publish_one(i: int):
            return await event_bus.publish("findings", "FINDING_CREATED", {"n": i})

        seqs = await asyncio.gather(*[publish_one(i) for i in range(10)])

        # All should have unique sequence numbers
        assert len(set(seqs)) == 10

        # All should be replayable
        events = await event_bus.replay(0)
        assert len(events) == 10

    @pytest.mark.asyncio
    async def test_concurrent_publish_and_replay(self, event_bus):
        """Publishing and replaying concurrently doesn't crash."""
        import asyncio

        # Publish some initial events
        for i in range(5):
            await event_bus.publish("lifecycle", "AGENT_RUNNING", {"n": i})

        # Concurrently publish more and replay
        async def publish_more():
            for i in range(5):
                await event_bus.publish("lifecycle", "AGENT_RUNNING", {"n": i + 5})

        async def replay_events():
            return await event_bus.replay(0)

        _, events = await asyncio.gather(publish_more(), replay_events())
        # Events should be at least 5 (initial), possibly more
        assert len(events) >= 5


class TestKaliUnreachableEvent:
    """KALI_UNREACHABLE event flows through EventBus correctly."""

    @pytest.mark.asyncio
    async def test_kali_unreachable_event_persisted(self, event_bus):
        """KALI_UNREACHABLE event is persisted to DurableEventLog."""
        seq = await event_bus.publish(
            "system",
            "KALI_UNREACHABLE",
            {"message": "All connections failed", "pool_size": 3},
        )

        events = await event_bus.replay(0)
        assert any(e["event_type"] == "KALI_UNREACHABLE" for e in events)

    @pytest.mark.asyncio
    async def test_kali_unreachable_delivered_to_subscribers(self, event_bus):
        """System subscribers receive KALI_UNREACHABLE."""
        received = []

        async def system_sub(event):
            received.append(event)

        event_bus.subscribe("system", system_sub)
        await event_bus.publish(
            "system",
            "KALI_UNREACHABLE",
            {"message": "All connections failed"},
        )

        assert len(received) == 1
        assert received[0]["event_type"] == "KALI_UNREACHABLE"
