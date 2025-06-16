from typing import Dict  # List is not used directly, but Dict is.

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status

from app.models import User

router = APIRouter()


class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[int, WebSocket] = {}
        self.user_mapping: Dict[int, User] = {}

    async def connect(self, websocket: WebSocket, user: User):
        await websocket.accept()
        self.active_connections[user.id] = websocket
        self.user_mapping[user.id] = user

    def disconnect(self, websocket: WebSocket, user: User):
        if (
            user.id in self.active_connections
            and self.active_connections[user.id] == websocket
        ):
            del self.active_connections[user.id]
            del self.user_mapping[user.id]

    async def broadcast(self, message: str, user: User):
        for user_id, connection_ws in self.active_connections.items():
            if user_id != user.id:
                await connection_ws.send_text(message)


manager = ConnectionManager()


@router.websocket("/ws/{token}")
async def websocket_endpoint(websocket: WebSocket, token: str):
    print(
        f"WebSocket connection attempt with token: {token[:20]}..."
        if token
        else "No token"
    )

    try:
        # For WebSocket connections, we'll directly validate the token
        from jose import JWTError, jwt

        from app.auth import ALGORITHM, AUTH_ENABLED, SECRET_KEY, users_db

        if not AUTH_ENABLED:
            print("Auth disabled, using mock user")
            # If auth is disabled, use a mock user
            if users_db:
                user = users_db[0]
                print(f"Using existing user: {user.username}")
            else:
                from app.models import User

                user = User(
                    id=0,
                    username="mockuser",
                    email="mock@example.com",
                    hashed_password=None,
                )
                print("Created mock user")
        else:
            print("Auth enabled, validating token")
            # Validate the JWT token
            try:
                payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
                email: str = payload.get("sub")
                if email is None:
                    raise JWTError("Invalid token")

                # Find user by email
                user = None
                for u in users_db:
                    if u.email == email:
                        user = u
                        break

                if user is None:
                    raise JWTError("User not found")

                print(f"Token validated for user: {user.username}")
            except JWTError as e:
                print(f"Token validation failed: {e}")
                await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
                return
    except Exception as e:
        # If any other error occurs, close the connection
        print(f"WebSocket error: {e}")
        await websocket.close(code=status.WS_1011_INTERNAL_ERROR)
        return

    await manager.connect(websocket, user)
    try:
        while True:
            data = await websocket.receive_text()
            await manager.broadcast(f"{user.username}: {data}", user)
    except WebSocketDisconnect:
        manager.disconnect(websocket, user)
        await manager.broadcast(f"{user.username} left the chat", user)  # Notify others
    except Exception as e:
        # Log exception e here if a logger is available
        # print(f"Error for user {user.username}: {e}")
        manager.disconnect(websocket, user)
        # Notify others about the disconnection due to an error
        await manager.broadcast(
            f"User {user.username} disconnected due to an error.", user
        )
        # Ensure websocket is closed. It might already be closed by WebSocketDisconnect.
        # Closing again if not already closed is generally safe.
        await websocket.close(code=status.WS_1011_INTERNAL_ERROR)
