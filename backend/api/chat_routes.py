import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from backend.auth import verify_token
from backend.session.session_store import session_store

logger = logging.getLogger(__name__)
router = APIRouter(tags=["chat"])


class ChatRequest(BaseModel):
    message: str
    session_id: Optional[str] = None
    mode: Optional[str] = None


class ChatResponse(BaseModel):
    session_id: str
    reply: str
    tokens_used: int


@router.post("/chat", response_model=ChatResponse)
async def chat(
    request: ChatRequest,
    _: str = Depends(verify_token),
):
    from backend.agent.orchestrator import Orchestrator

    session = (
        session_store.resolve(request.session_id)
        if request.session_id
        else None
    ) or session_store.create()

    session_store.touch(session.session_id)

    try:
        orchestrator = Orchestrator()
        result = await orchestrator.process(
            message=request.message,
            session=session,
            mode=request.mode,
        )
        return ChatResponse(
            session_id=session.session_id,
            reply=result["reply"],
            tokens_used=result["tokens_used"],
        )
    except Exception as e:
        logger.error(f"Chat error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/session/{session_id}")
async def get_session(
    session_id: str,
    _: str = Depends(verify_token),
):
    session = session_store.resolve(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return {
        "session_id": session.session_id,
        "engagement_id": session.engagement_id,
        "created_at": session.created_at.isoformat(),
        "last_active": session.last_active.isoformat(),
        "message_count": len(session.conv_history.messages),
    }


@router.get("/health")
async def health():
    return {"status": "healthy", "version": "1.0.0"}
