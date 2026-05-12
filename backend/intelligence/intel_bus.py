import asyncio
import logging
from typing import Dict, Any, Callable, List
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import hashlib

logger = logging.getLogger(__name__)


@dataclass
class IntelEvent:
    event_type: str
    source: str
    data: Any
    timestamp: datetime = field(default_factory=datetime.now)
    ttl: int = 3600


class IntelBus:
    def __init__(self, ttl_seconds: int = 3600):
        self.ttl_seconds = ttl_seconds
        self.publishers: Dict[str, asyncio.Queue] = {}
        self.subscribers: Dict[str, List[asyncio.Queue]] = {}
        self.cache: Dict[str, IntelEvent] = {}
        self._running = False

    async def start(self):
        self._running = True
        asyncio.create_task(self._cache_cleanup())
        logger.info("IntelBus started")

    async def stop(self):
        self._running = False

    def subscribe(self, topic: str) -> asyncio.Queue:
        queue = asyncio.Queue()
        if topic not in self.subscribers:
            self.subscribers[topic] = []
        self.subscribers[topic].append(queue)
        return queue

    def publish(self, topic: str, event: IntelEvent):
        if topic not in self.publishers:
            self.publishers[topic] = asyncio.Queue()
        
        cache_key = self._make_cache_key(topic, event.data)
        self.cache[cache_key] = event
        
        if topic in self.subscribers:
            for queue in self.subscribers[topic]:
                asyncio.create_task(queue.put(event))

    async def get_cached(self, topic: str, key: str) -> Optional[IntelEvent]:
        cache_key = f"{topic}:{key}"
        event = self.cache.get(cache_key)
        
        if event:
            age = (datetime.now() - event.timestamp).total_seconds()
            if age < self.ttl_seconds:
                return event
        
        return None

    def _make_cache_key(self, topic: str, data: Any) -> str:
        data_str = str(data)
        return f"{topic}:{hashlib.md5(data_str.encode()).hexdigest()}"

    async def _cache_cleanup(self):
        while self._running:
            await asyncio.sleep(60)
            
            now = datetime.now()
            expired = []
            
            for key, event in self.cache.items():
                age = (now - event.timestamp).total_seconds()
                if age > event.ttl:
                    expired.append(key)
            
            for key in expired:
                self.cache.pop(key, None)
            
            if expired:
                logger.debug(f"IntelBus cache cleanup: {len(expired)} entries")


class IntelBusPublisher:
    def __init__(self, bus: IntelBus, source: str):
        self.bus = bus
        self.source = source

    async def publish(self, event_type: str, data: Any):
        event = IntelEvent(
            event_type=event_type,
            source=self.source,
            data=data,
            ttl=self.bus.ttl_seconds,
        )
        self.bus.publish(event_type, event)


class IntelBusSubscriber:
    def __init__(self, bus: IntelBus, topic: str):
        self.bus = bus
        self.topic = topic
        self.queue = bus.subscribe(topic)

    async def listen(self) -> IntelEvent:
        return await self.queue.get()