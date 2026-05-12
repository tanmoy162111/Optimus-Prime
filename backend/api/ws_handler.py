import logging
from typing import Dict

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from backend.auth import verify_ws_token
from backend.session.session_store import session_store

logger = logging.getLogger(__name__)
router = APIRouter()


class ConnectionManager:
    def __init__(self) -> None:
        self.active: Dict[str, WebSocket] = {}

    async def connect(self, session_id: str, websocket: WebSocket) -> None:
        self.active[session_id] = websocket

    def disconnect(self, session_id: str) -> None:
        self.active.pop(session_id, None)

    async def send(self, session_id: str, payload: dict) -> None:
        ws = self.active.get(session_id)
        if ws:
            await ws.send_json(payload)


manager = ConnectionManager()


@router.websocket("/chat")
async def websocket_chat(websocket: WebSocket):
    await websocket.accept()
    session_id = None
    try:
        await verify_ws_token(websocket)
    except Exception:
        return

    try:
        await websocket.send_json({"type": "welcome", "message": "Connected to Optimus"})

        async for message in websocket.iter_json():
            msg_type = message.get("type")

            if msg_type == "init":
                raw_id = message.get("session_id")
                session = (
                    session_store.resolve(raw_id) if raw_id else None
                ) or session_store.create()
                session_id = session.session_id
                await manager.connect(session_id, websocket)
                await websocket.send_json({"type": "session", "session_id": session_id})

            elif msg_type == "chat":
                if not session_id:
                    await websocket.send_json({"type": "error", "message": "Send 'init' first"})
                    continue

                session = session_store.resolve(session_id)
                if not session:
                    await websocket.send_json({"type": "error", "message": "Session expired"})
                    continue

                session_store.touch(session_id)
                text = message.get("message", "")
                mode = message.get("mode")

                from backend.agent.orchestrator import Orchestrator
                orchestrator = Orchestrator()

                async for chunk in orchestrator.process_stream(
                    message=text,
                    session=session,
                    mode=mode,
                ):
                    await manager.send(session_id, {"chunk": chunk, "done": False})

                await manager.send(session_id, {"chunk": "", "done": True})

            elif msg_type == "ping":
                await websocket.send_json({"type": "pong"})

    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        if session_id:
            await manager.send(session_id, {"type": "error", "message": str(e)})
    finally:
        if session_id:
            manager.disconnect(session_id)
