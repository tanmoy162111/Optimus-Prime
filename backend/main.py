"""Optimus Prime backend — FastAPI entrypoint.

Wires together all M0–M3 components:
  - EventBus (DurableEventLog) with 24h prune
  - KaliConnectionManager connection pool
  - LLMRouter with Claude/Ollama(Gemma4) providers
  - ToolRegistry, ToolExecutor, PermissionPipeline
  - EngineRouter with Engine 1
  - OmX -> OmO -> ChatHandler
  - SmartMemory (Tier 2 semantic memory)
  - ClientProfileDB (Tier 3 client profiles)
  - IntelligentReporter + ComplianceMappingDB
  - ResearchKB + ResearchDaemon + StrategyEvolutionEngine
  - CustomToolGenerator (three-gate pipeline)
  - WebSocket endpoints for events and chat
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
load_dotenv()  # Load .env before any os.environ.get calls

from fastapi import Body, FastAPI, HTTPException, Response, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from backend.core.chat_handler import ChatHandler
from backend.core.credential_vault import CredentialVault
from backend.core.event_bus import DurableEventLog, EventBus
from backend.core.hook_runner import HookRunner
from backend.core.llm_router import (
    ClaudeProvider,
    LLMRouter,
    OllamaProvider,
    TokenBudgetManager,
)
from backend.core.models import ScopeConfig
from backend.core.omo import OmO
from backend.core.omx import OmX
from backend.core.permission import PermissionEnforcer, PermissionPipeline
from backend.core.task_registry import TaskRegistry
from backend.core.tool_executor import ToolExecutor
from backend.core.xai_logger import XAILogger
from backend.engines.engine_infra import EngineInfra
from backend.engines.engine_interface import EngineRouter
from backend.tools.backends.kali_ssh import KaliConnectionManager

# M3 imports
from backend.memory.smart_memory import SmartMemory
from backend.memory.client_profile import ClientProfileDB
from backend.intelligence.intelligent_reporter import IntelligentReporter, REPORT_FORMATS
from backend.intelligence.compliance_mapping import ComplianceMappingDB
from backend.intelligence.research_kb import ResearchKB
from backend.intelligence.research_daemon import ResearchDaemon
from backend.intelligence.strategy_evolution import StrategyEvolutionEngine
from backend.intelligence.custom_tool_generator import CustomToolGenerator

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Logging configuration (#16)
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(name)-30s | %(levelname)-8s | %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)

# Reduce noise from third-party libraries
logging.getLogger("paramiko").setLevel(logging.WARNING)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("uvicorn.access").setLevel(logging.WARNING)

# ---------------------------------------------------------------------------
# Global state (initialized in lifespan)
# ---------------------------------------------------------------------------
_state: dict[str, Any] = {}


def _get(key: str) -> Any:
    return _state.get(key)


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan — initialize and teardown all services."""
    logger.info("Optimus Prime v2.0 — starting up")

    # EventBus
    data_dir = Path(os.environ.get("DATA_DIR", "data"))
    log_path = data_dir / "events" / "event_log.db"
    durable_log = DurableEventLog(db_path=log_path)
    event_bus = EventBus(durable_log=durable_log)
    await event_bus.initialize()
    _state["event_bus"] = event_bus

    # XAI Logger
    xai_dir = data_dir / "xai"
    xai_logger = XAILogger(log_dir=xai_dir)
    _state["xai_logger"] = xai_logger

    # CredentialVault
    vault = CredentialVault()
    _state["vault"] = vault

    # Permission Pipeline
    pipeline = PermissionPipeline(
        permission_enforcer=PermissionEnforcer(),
        credential_vault=vault,
        hook_runner=HookRunner(),
    )
    _state["pipeline"] = pipeline

    # Tool Registry (built-in tools from M0)
    from backend.tools.tool_registry import BUILTIN_TOOLS
    tool_registry = dict(BUILTIN_TOOLS)
    _state["tool_registry"] = tool_registry

    # Tool Executor
    tool_executor = ToolExecutor(
        tool_registry=tool_registry,
        permission_pipeline=pipeline,
        xai_logger=xai_logger,
        event_bus=event_bus,
    )
    _state["tool_executor"] = tool_executor

    # KaliConnectionManager
    kali_mgr = KaliConnectionManager(
        host=os.environ.get("KALI_HOST", "kali"),
        port=int(os.environ.get("KALI_PORT", "22")),
        username=os.environ.get("KALI_USER", "root"),
        password=os.environ.get("KALI_PASSWORD", "optimus"),
        event_bus=event_bus,
    )
    _state["kali_mgr"] = kali_mgr
    # Eagerly initialize Kali connection pool at startup
    try:
        await kali_mgr.connect()
    except Exception as exc:
        logger.warning("Kali SSH pool init deferred — %s", exc)

    # Register Kali backend in ToolExecutor
    tool_executor.register_backend("kali_ssh", kali_mgr)

    # Register all additional backends (#5) — prevent silent failures
    from backend.tools.backends.local_subprocess import LocalSubprocessBackend
    from backend.tools.backends.tor_socks5 import TorSOCKS5Backend
    from backend.tools.backends.sandbox import SandboxOnDemandBackend
    from backend.tools.backends.ml_runtime_ipc import MLRuntimeIPC
    from backend.tools.backends.ics_runtime_ipc import ICSRuntimeIPC

    tool_executor.register_backend("local", LocalSubprocessBackend())
    tool_executor.register_backend("tor_socks5", TorSOCKS5Backend())
    tool_executor.register_backend("sandbox", SandboxOnDemandBackend(
        dvwa_url=f"http://{os.environ.get('DVWA_HOST', 'sandbox')}:{os.environ.get('DVWA_PORT', '80')}",
    ))
    ml_ipc_path = Path(os.environ.get("DATA_DIR", "data")) / "ml-runtime-ipc"
    tool_executor.register_backend("ml_runtime_ipc", MLRuntimeIPC(
        ipc_dir=ml_ipc_path,
    ))
    ics_ipc_path = Path(os.environ.get("DATA_DIR", "data")) / "ics-runtime-ipc"
    tool_executor.register_backend("ics_runtime_ipc", ICSRuntimeIPC(
        ipc_dir=ics_ipc_path,
    ))

    # Engine Router — EngineInfra gets full dependency injection
    engine_infra = EngineInfra(
        tool_executor=tool_executor,
        event_bus=event_bus,
        xai_logger=xai_logger,
        kali_mgr=kali_mgr,
    )
    engine_router = EngineRouter()
    engine_router.register_engine(engine_infra)
    _state["engine_router"] = engine_router
    _state["engine_infra"] = engine_infra

    # Task Registry
    task_registry = TaskRegistry()
    _state["task_registry"] = task_registry

    # LLM Router
    claude = ClaudeProvider(
        api_key=os.environ.get("CLAUDE_API_KEY", ""),
        model=os.environ.get("CLAUDE_MODEL", "claude-sonnet-4-6"),
    )
    ollama_fallback = OllamaProvider(
        base_url=os.environ.get("OLLAMA_HOST", "http://ollama:11434"),
        model=os.environ.get("OLLAMA_MODEL", "qwen2.5:3b"),
        thinking_enabled=False,
    )
    budget_mgr = TokenBudgetManager(
        budget=int(os.environ.get("TOKEN_BUDGET", "200000")),
        event_bus=event_bus,
    )
    llm_router = LLMRouter(
        claude=claude,
        fallback=ollama_fallback,
        budget_manager=budget_mgr,
        event_bus=event_bus,
    )
    _state["llm_router"] = llm_router

    # Now inject llm_router into EngineInfra (created before LLMRouter was ready)
    engine_infra._llm_router = llm_router

    # -----------------------------------------------------------------------
    # M3 Components
    # -----------------------------------------------------------------------

    # SmartMemory (Tier 2)
    smart_memory_db = data_dir / "memory" / "smart_memory.db"
    ollama_url = os.environ.get("OLLAMA_HOST", "http://ollama:11434")
    smart_memory = SmartMemory(db_path=smart_memory_db, ollama_url=ollama_url)
    _state["smart_memory"] = smart_memory

    # ClientProfileDB (Tier 3)
    client_db_path = data_dir / "memory" / "client_profiles.db"
    client_profile_db = ClientProfileDB(db_path=client_db_path)
    _state["client_profile_db"] = client_profile_db

    # ComplianceMappingDB
    compliance_db = ComplianceMappingDB()
    _state["compliance_db"] = compliance_db

    # IntelligentReporter
    reporter = IntelligentReporter(
        event_bus=event_bus,
        compliance_db=compliance_db,
    )
    await reporter.subscribe_to_findings()
    _state["reporter"] = reporter

    # ResearchKB
    research_db_path = data_dir / "intelligence" / "research_kb.db"
    research_kb = ResearchKB(db_path=research_db_path)
    _state["research_kb"] = research_kb

    # ResearchDaemon (scheduled but not auto-started in dev)
    research_daemon = ResearchDaemon(
        research_kb=research_kb,
        event_bus=event_bus,
    )
    _state["research_daemon"] = research_daemon

    # StrategyEvolutionEngine
    strategy_engine = StrategyEvolutionEngine(
        research_kb=research_kb,
        smart_memory=smart_memory,
    )
    _state["strategy_engine"] = strategy_engine

    # CustomToolGenerator
    custom_tool_gen = CustomToolGenerator(
        llm_router=llm_router,
        event_bus=event_bus,
        tool_registry=tool_registry,
    )
    _state["custom_tool_generator"] = custom_tool_gen

    # OmX Workflow Planner
    omx = OmX(llm_router=llm_router)
    _state["omx"] = omx

    # OmO Coordinator
    omo = OmO(
        engine_router=engine_router,
        task_registry=task_registry,
        event_bus=event_bus,
    )
    _state["omo"] = omo

    # Chat Handler
    chat_handler = ChatHandler(
        omx=omx,
        llm_router=llm_router,
        event_bus=event_bus,
    )
    _state["chat_handler"] = chat_handler

    # Background task: 24h EventBus prune
    prune_task = asyncio.create_task(_prune_loop(event_bus))
    _state["prune_task"] = prune_task

    await event_bus.publish(
        channel="system",
        event_type="SYSTEM_STARTED",
        payload={"version": "2.0.0", "milestone": "M3"},
    )

    logger.info("Optimus Prime v2.0 — startup complete")
    yield

    # Teardown
    logger.info("Optimus Prime v2.0 — shutting down")
    prune_task.cancel()
    try:
        await prune_task
    except asyncio.CancelledError:
        pass

    await kali_mgr.close()
    await event_bus.close()
    logger.info("Optimus Prime v2.0 — shutdown complete")


def _resolve_findings(
    body_findings: list[dict[str, Any]] | None,
    reporter: IntelligentReporter,
) -> list[dict[str, Any]]:
    """Return body_findings if non-empty; fall back to reporter accumulated findings."""
    if body_findings:
        return body_findings
    return reporter.confirmed_findings


def _get_validated_reporter(fmt: str) -> IntelligentReporter:
    """Return the reporter from state, raising HTTPException if unavailable or format invalid."""
    reporter: IntelligentReporter | None = _get("reporter")
    if reporter is None:
        raise HTTPException(status_code=503, detail="Reporter not initialized")
    if fmt not in REPORT_FORMATS:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown format. Valid: {', '.join(REPORT_FORMATS)}",
        )
    return reporter


async def _prune_loop(event_bus: EventBus) -> None:
    """Prune old events every hour."""
    while True:
        try:
            await asyncio.sleep(3600)
            removed = await event_bus.prune()
            if removed:
                logger.info("Pruned %d old events", removed)
        except asyncio.CancelledError:
            break
        except Exception as exc:
            logger.error("Prune loop error: %s", exc)


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Optimus Prime",
    description="Universal AI Security Platform — v2.0",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# REST endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    kali_healthy = False
    kali_mgr = _get("kali_mgr")
    if kali_mgr and kali_mgr._pool:
        try:
            kali_healthy = await kali_mgr.health_check()
        except Exception:
            pass

    return {
        "status": "ok",
        "version": "2.0.0",
        "milestone": "M3",
        "kali_connected": kali_healthy,
        "budget_remaining": (
            _get("llm_router").budget_manager.remaining
            if _get("llm_router") else None
        ),
    }


@app.get("/directives")
async def list_directives():
    """List available OmX directives."""
    omx: OmX | None = _get("omx")
    if omx:
        return {"directives": omx.get_available_directives()}
    return {"directives": {}}


@app.post("/scope")
async def set_scope(scope_data: dict[str, Any]):
    """Set the active engagement scope."""
    scope = ScopeConfig(
        targets=scope_data.get("targets", []),
        excluded_targets=scope_data.get("excluded_targets", []),
        ports=scope_data.get("ports", "all"),
        protocols=scope_data.get("protocols", ["tcp", "udp"]),
    )
    chat_handler: ChatHandler | None = _get("chat_handler")
    if chat_handler:
        chat_handler.set_scope(scope)
    # Also propagate scope to OmO so dispatched agents inherit it
    omo: OmO | None = _get("omo")
    if omo:
        omo._scope = scope
    return {"status": "ok", "targets": scope.targets}


@app.post("/gate/{action}/{gate_event_id}")
async def resolve_gate(action: str, gate_event_id: str):
    """Resolve a human gate — confirm or skip a phase.

    POST /gate/confirm/<gate_event_id>  -> approve the gate
    POST /gate/skip/<gate_event_id>     -> reject/skip the gate
    """
    omo: OmO | None = _get("omo")
    if not omo:
        return {"status": "error", "message": "OmO not initialized"}

    approved = action.lower() == "confirm"
    omo.resolve_gate(gate_event_id, approved)
    return {"status": "ok", "gate_event_id": gate_event_id, "approved": approved}


# ---------------------------------------------------------------------------
# Report endpoints (Section 16)
# ---------------------------------------------------------------------------

@app.post("/report/{fmt}")
async def generate_report_json(
    fmt: str,
    body: dict[str, Any] | None = Body(default=None),
) -> dict[str, Any]:
    """Generate a report in JSON format.

    Body: { findings?: list[dict], framework?: str }
    Uses body findings if non-empty; falls back to reporter accumulated findings.
    """
    reporter = _get_validated_reporter(fmt)
    body = body or {}
    findings = _resolve_findings(body.get("findings") or [], reporter)
    return reporter.generate_report(
        report_format=fmt,
        framework=body.get("framework"),
        findings=findings,
    )


@app.post("/report/{fmt}/html")
async def generate_report_html(
    fmt: str,
    body: dict[str, Any] | None = Body(default=None),
) -> Response:
    """Generate a report and return it as a downloadable HTML file."""
    reporter = _get_validated_reporter(fmt)
    body = body or {}
    findings = _resolve_findings(body.get("findings") or [], reporter)
    report = reporter.generate_report(
        report_format=fmt,
        framework=body.get("framework"),
        findings=findings,
    )
    html = reporter.render_html(report)
    return Response(
        content=html.encode("utf-8"),
        media_type="text/html",
        headers={"Content-Disposition": f'attachment; filename="report-{fmt}.html"'},
    )


@app.post("/report/{fmt}/pdf")
async def generate_report_pdf(
    fmt: str,
    body: dict[str, Any] | None = Body(default=None),
) -> Response:
    """Generate a report and return it as a downloadable PDF file.

    Falls back to HTML bytes if WeasyPrint is not installed.
    """
    reporter = _get_validated_reporter(fmt)
    body = body or {}
    findings = _resolve_findings(body.get("findings") or [], reporter)
    report = reporter.generate_report(
        report_format=fmt,
        framework=body.get("framework"),
        findings=findings,
    )
    pdf_bytes = await reporter.export_pdf(report)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="report-{fmt}.pdf"'},
    )


# ---------------------------------------------------------------------------
# WebSocket: Event stream with replay-on-reconnect (N7)
# ---------------------------------------------------------------------------

class ConnectionManager:
    """Manages active WebSocket connections for event streaming."""

    def __init__(self) -> None:
        self._connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self._connections.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self._connections:
            self._connections.remove(websocket)

    async def broadcast(self, message: dict[str, Any]) -> None:
        """Broadcast a message to all connected clients."""
        disconnected = []
        for conn in self._connections:
            try:
                await conn.send_json(message)
            except Exception:
                disconnected.append(conn)
        for conn in disconnected:
            self.disconnect(conn)


ws_manager = ConnectionManager()


@app.websocket("/ws")
async def websocket_events(websocket: WebSocket):
    """WebSocket endpoint for real-time event streaming.

    Protocol:
      - On connect: client optionally sends {"type": "reconnect", "last_seq": N}
      - Server replays all events with seq > N from DurableEventLog
      - Then streams new events in real time via EventBus subscription
    """
    await ws_manager.connect(websocket)
    event_bus: EventBus | None = _get("event_bus")

    try:
        # Wait for optional reconnect message
        try:
            raw = await asyncio.wait_for(websocket.receive_text(), timeout=2.0)
            msg = json.loads(raw)
            if msg.get("type") == "reconnect" and event_bus:
                last_seq = msg.get("last_seq", 0)
                events = await event_bus.replay(last_seq)
                for event in events:
                    await websocket.send_json(event)
                logger.info("WS: replayed %d events from seq %d", len(events), last_seq)
        except (asyncio.TimeoutError, json.JSONDecodeError):
            pass  # No reconnect message — fresh connection

        # Subscribe to EventBus for real-time events
        async def _forward_event(event: dict[str, Any]) -> None:
            try:
                await websocket.send_json(event)
            except Exception:
                pass  # Connection may have closed

        if event_bus:
            for channel in ("findings", "lifecycle", "intel", "system"):
                event_bus.subscribe(channel, _forward_event)

        # Keep connection alive — listen for client messages
        while True:
            data = await websocket.receive_text()
            msg = json.loads(data)

            if msg.get("type") == "ack" and event_bus:
                # Acknowledge event
                seq = msg.get("seq")
                subscriber_id = msg.get("subscriber_id", "frontend")
                if seq:
                    await event_bus._log.acknowledge(seq, subscriber_id)

    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception as exc:
        logger.error("WS error: %s", exc)
        ws_manager.disconnect(websocket)


# ---------------------------------------------------------------------------
# WebSocket: Chat (operator commands)
# ---------------------------------------------------------------------------

@app.websocket("/chat")
async def websocket_chat(websocket: WebSocket):
    """WebSocket endpoint for operator chat commands.

    Receives operator messages, routes through ChatHandler -> OmX -> OmO.
    Responses are sent back on the same connection.
    Agent events are streamed via /ws (clawhip pattern).
    """
    await websocket.accept()
    chat_handler: ChatHandler | None = _get("chat_handler")
    omo: OmO | None = _get("omo")

    try:
        while True:
            data = await websocket.receive_text()
            msg = json.loads(data)
            content = msg.get("content", msg.get("message", ""))

            # Ignore handshake/control messages (e.g. reconnect sent by the
            # useWebSocket hook on every connect).
            if msg.get("type") in ("reconnect", "ack") or not content:
                continue

            # Handle gate confirmation commands via chat text
            if omo and content.startswith(("confirm-", "skip-")):
                parts = content.split("-", 1)
                action = parts[0]
                gate_id = parts[1] if len(parts) > 1 else ""
                approved = action == "confirm"
                omo.resolve_gate(gate_id, approved)
                await websocket.send_json({
                    "type": "chat",
                    "content": f"Gate {'approved' if approved else 'skipped'}: {gate_id}",
                })
                continue

            if chat_handler:
                response = await chat_handler.handle_message(content)
                await websocket.send_json(response.to_dict())

                # Auto-execute directive plans immediately
                if response.plan and omo:
                    logger.info(
                        "Auto-executing plan %s (directive=%s)",
                        response.plan.plan_id, response.plan.directive,
                    )
                    asyncio.create_task(
                        _execute_plan_background(omo, response.plan, websocket)
                    )
            else:
                await websocket.send_json({
                    "type": "error",
                    "content": "Chat handler not initialized",
                })

    except WebSocketDisconnect:
        pass
    except Exception as exc:
        logger.error("Chat WS error: %s", exc)


async def _execute_plan_background(
    omo: OmO,
    plan: Any,
    websocket: WebSocket,
) -> None:
    """Execute an engagement plan in the background."""
    try:
        result = await omo.execute_plan(plan)

        # Collect per-phase errors for operator visibility
        phase_errors = [
            {"phase": pr.phase_name, "error": pr.error}
            for pr in result.phase_results
            if pr.error
        ]
        # Surface agent-level errors when phase errors are empty
        if not phase_errors:
            for pr in result.phase_results:
                for ar in pr.agent_results:
                    if ar.error:
                        phase_errors.append({"phase": pr.phase_name, "error": ar.error})

        payload: dict[str, Any] = {
            "type": "engagement_complete",
            "plan_id": result.plan_id,
            "status": result.status,
            "total_findings": result.total_findings,
        }
        if phase_errors:
            payload["errors"] = phase_errors

        await websocket.send_json(payload)
    except Exception as exc:
        logger.error("Background plan execution failed: %s", exc)
        try:
            await websocket.send_json({
                "type": "error",
                "content": f"Plan execution failed: {exc}",
            })
        except Exception:
            pass
