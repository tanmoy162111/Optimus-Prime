"""SEC-01 integration tests — Docker-isolated SandboxOnDemandBackend (Section 6.2).

Verifies `SandboxOnDemandBackend.run_tool_code()` executes generated tool code
inside an isolated Docker container (`--network=none --memory=256m --rm`)
rather than as a host `python3` subprocess.

All tests are skipped when no Docker daemon is reachable — this backend has
zero live callers today (D-02), so these tests validate it via direct
instantiation, not through the chat UI.
"""

from __future__ import annotations

import os
import tempfile
import textwrap

import pytest

from backend.tools.backends.sandbox import SandboxOnDemandBackend


def docker_available() -> bool:
    """Return True only if the `docker` package is importable and a daemon answers ping()."""
    try:
        import docker
    except ImportError:
        return False

    try:
        docker.from_env().ping()
    except Exception:
        return False

    return True


def _container_count() -> int:
    import docker

    client = docker.from_env()
    return len(client.containers.list(all=True))


@pytest.mark.skipif(not docker_available(), reason="Docker daemon required")
class TestSandboxDockerIsolation:
    """SEC-01: run_tool_code() must execute inside an isolated container."""

    @pytest.mark.asyncio
    async def test_run_tool_code_returns_success_shape(self):
        """A trivial stdout script returns the expected dict shape with exit_code 0."""
        backend = SandboxOnDemandBackend()
        code = textwrap.dedent(
            """
            import sys
            print("hello from sandbox")
            """
        )

        result = await backend.run_tool_code(code, "trivial_stdout_tool", target="http://sandbox:80")

        assert result["status"] == "success"
        assert result["exit_code"] == 0
        assert isinstance(result["stdout"], str)
        assert isinstance(result["stderr"], str)
        assert "hello from sandbox" in result["stdout"]
        assert result["passed"] is True
        assert "effectiveness_score" in result

    @pytest.mark.asyncio
    async def test_no_leaked_container_after_success(self):
        """Container count does not grow after a successful run (no leak)."""
        backend = SandboxOnDemandBackend()
        code = "print('no leak check')"

        before = _container_count()
        await backend.run_tool_code(code, "no_leak_tool", target="http://sandbox:80")
        after = _container_count()

        assert after <= before

    @pytest.mark.asyncio
    async def test_container_filesystem_is_isolated_from_host(self):
        """Sandboxed code must NOT see host files outside the mounted script dir.

        This is the real isolation discriminator (SEC-01's containment
        boundary): a host `python3` subprocess would see this marker file
        (full host filesystem access); a `--network=none` container with
        only the script's own directory mounted read-only at /work must not.
        """
        marker_dir = tempfile.mkdtemp(prefix="optimus_host_marker_")
        marker_path = os.path.join(marker_dir, "host_only_marker.txt")
        with open(marker_path, "w") as fh:
            fh.write("host-only-content")

        try:
            backend = SandboxOnDemandBackend()
            code = textwrap.dedent(
                f"""
                import os
                print("VISIBLE" if os.path.exists({marker_path!r}) else "NOT_VISIBLE")
                """
            )

            result = await backend.run_tool_code(code, "fs_isolation_tool", target="http://sandbox:80")

            assert "NOT_VISIBLE" in result["stdout"]
        finally:
            os.remove(marker_path)
            os.rmdir(marker_dir)

    @pytest.mark.asyncio
    async def test_timeout_returns_timeout_status_and_no_leak(self):
        """A script that sleeps past `timeout` returns status='timeout' and leaves no container."""
        backend = SandboxOnDemandBackend()
        code = textwrap.dedent(
            """
            import time
            time.sleep(30)
            """
        )

        before = _container_count()
        result = await backend.run_tool_code(
            code, "sleepy_tool", target="http://sandbox:80", timeout=2,
        )
        after = _container_count()

        assert result["status"] == "timeout"
        assert after <= before


class TestSandboxToolNameValidation:
    """CR-02: tool_name must be rejected before it reaches any filesystem/tar path.

    No Docker daemon required — validation happens before any container work.
    """

    @pytest.mark.asyncio
    async def test_path_traversal_tool_name_rejected(self):
        backend = SandboxOnDemandBackend()

        result = await backend.run_tool_code(
            "print('x')", "../../../../tmp/evil", target="http://sandbox:80",
        )

        assert result["status"] == "error"
        assert "Invalid tool_name" in result["error"]

    @pytest.mark.asyncio
    async def test_safe_tool_name_passes_validation(self):
        """A conforming tool_name is not rejected by the validator (may still
        error later if no Docker daemon is reachable in this environment)."""
        backend = SandboxOnDemandBackend()

        result = await backend.run_tool_code(
            "print('x')", "safe_tool-123", target="http://sandbox:80",
        )

        assert result.get("error", "").startswith("Invalid tool_name") is False
