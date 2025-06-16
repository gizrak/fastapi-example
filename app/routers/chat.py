from fastapi import APIRouter, WebSocket, Depends, WebSocketDisconnect, HTTPException, status
from typing import List, Dict # List is not used directly, but Dict is.
from app.auth import get_current_user
from app.models import User

router = APIRouter()

class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[User, WebSocket] = {}

    async def connect(self, websocket: WebSocket, user: User):
        await websocket.accept()
        self.active_connections[user] = websocket

    def disconnect(self, websocket: WebSocket, user: User):
        if user in self.active_connections and self.active_connections[user] == websocket:
            del self.active_connections[user]

    async def broadcast(self, message: str, user: User):
        for connection_user, connection_ws in self.active_connections.items():
            if connection_user != user:
                await connection_ws.send_text(message)

manager = ConnectionManager()

@router.websocket("/ws/{token}")
async def websocket_endpoint(websocket: WebSocket, token: str):
    try:
        # Pass the websocket object as the 'request' argument,
        # and the token from the path as the 'token_from_header' argument.
        # This makes get_current_user use our path token if no cookie token is found.
        user: User = await get_current_user(request=websocket, token_from_header=token)
    except HTTPException as e:
        # If authentication fails (e.g., token invalid), get_current_user raises HTTPException.
        # We should close the WebSocket connection.
        # Use a custom code or a standard one like 1008 (Policy Violation)
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    if not user: # Should be caught by HTTPException, but as a safeguard.
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await manager.connect(websocket, user)
    try:
        while True:
            data = await websocket.receive_text()
            await manager.broadcast(f"{user.username}: {data}", user)
    except WebSocketDisconnect:
        manager.disconnect(websocket, user)
        await manager.broadcast(f"{user.username} left the chat", user) # Notify others
    except Exception as e:
        # Log exception e here if a logger is available
        # print(f"Error for user {user.username}: {e}")
        manager.disconnect(websocket, user)
        # Notify others about the disconnection due to an error
        await manager.broadcast(f"User {user.username} disconnected due to an error.", user)
        # Ensure websocket is closed. It might already be closed by WebSocketDisconnect.
        # Closing again if not already closed is generally safe.
        await websocket.close(code=status.WS_1011_INTERNAL_ERROR)
