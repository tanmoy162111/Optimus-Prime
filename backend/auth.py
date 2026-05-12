from fastapi import HTTPException, Security, WebSocket, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from backend.config import settings

_bearer = HTTPBearer()


async def verify_token(
    credentials: HTTPAuthorizationCredentials = Security(_bearer),
) -> str:
    if credentials.credentials != settings.bearer_token:
        raise HTTPException(status_code=401, detail="Invalid token")
    return credentials.credentials


async def verify_ws_token(websocket: WebSocket) -> str:
    token = websocket.query_params.get("token", "")
    if token != settings.bearer_token:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        raise HTTPException(status_code=403, detail="Invalid token")
    return token
