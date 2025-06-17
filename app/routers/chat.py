from typing import Dict, List
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status, Request

from app.auth import (
    is_auth_enabled,
    get_secret_key,
    get_algorithm,
    # users_db is no longer imported globally
    # SECRET_KEY, ALGORITHM, AUTH_ENABLED are also no longer imported globally
)
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
        # Optional: Send chat history to the newly connected user
        # chat_history = websocket.app.state.chat_history
        # for msg in chat_history:
        #     await websocket.send_text(msg)


    def disconnect(self, websocket: WebSocket, user: User):
        if user.id in self.active_connections and self.active_connections[user.id] == websocket:
            del self.active_connections[user.id]
            del self.user_mapping[user.id]

    async def broadcast(self, message: str, broadcasting_user: User):
        for user_id, connection_ws in self.active_connections.items():
            # Standard broadcast: send to all *other* connections
            # If sender self-echo is desired, client can handle it or this logic can change.
            if user_id != broadcasting_user.id:
                await connection_ws.send_text(message)

manager = ConnectionManager()

@router.websocket("/ws/{token}")
async def websocket_endpoint(websocket: WebSocket, token: str):
    current_app_state = websocket.app.state
    users_db_on_state = current_app_state.users_db
    chat_history_on_state: List[str] = current_app_state.chat_history

    user: User # Define user for this scope

    try:
        if not is_auth_enabled(): # Dynamic check
            print("Auth disabled, using mock user for WebSocket")
            if users_db_on_state: # Check app.state's db
                user = users_db_on_state[0]
                print(f"Using existing user from app.state: {user.username}")
            else:
                user = User(id=0, username="mockuser_ws", email="mock_ws@example.com", hashed_password=None)
                print("Created mock user for WebSocket")
        else:
            print("Auth enabled, validating token for WebSocket")
            from jose import JWTError, jwt # Keep imports local if only used here
            try:
                payload = jwt.decode(token, get_secret_key(), algorithms=[get_algorithm()])
                email: str = payload.get("sub")
                if email is None:
                    raise JWTError("Invalid token: email missing")

                temp_user = None
                for u_obj in users_db_on_state: # Check app.state's db
                    if u_obj.email == email:
                        temp_user = u_obj
                        break

                if temp_user is None:
                    # Optionally, if user is not in app.state.users_db but token is valid,
                    # one might load user from a persistent DB here.
                    # For this example, if not in users_db_on_state, it's an error.
                    raise JWTError("User not found in current app state")
                user = temp_user
                print(f"Token validated for user: {user.username}")
            except JWTError as e:
                print(f"Token validation failed for WebSocket: {e}")
                await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
                return
    except Exception as e:
        print(f"WebSocket connection setup error: {e}")
        await websocket.close(code=status.WS_1011_INTERNAL_ERROR)
        return

    await manager.connect(websocket, user)

    # Send chat history to the newly connected user (optional)
    # for msg_history_item in chat_history_on_state:
    #    await websocket.send_text(msg_history_item)

    try:
        while True:
            data = await websocket.receive_text()
            formatted_message = f"{user.username}: {data}"
            chat_history_on_state.append(formatted_message) # Store in app.state
            await manager.broadcast(formatted_message, user)
    except WebSocketDisconnect:
        manager.disconnect(websocket, user)
        disconnect_message = f"{user.username} left the chat"
        chat_history_on_state.append(disconnect_message) # Store in app.state
        await manager.broadcast(disconnect_message, user)
    except Exception as e:
        manager.disconnect(websocket, user)
        error_message = f"User {user.username} disconnected due to an error: {str(e)}"
        chat_history_on_state.append(error_message) # Store in app.state
        # Log actual exception e with a logger if available
        await manager.broadcast(error_message, user)
        try:
            await websocket.close(code=status.WS_1011_INTERNAL_ERROR)
        except RuntimeError: # Handle cases where websocket might already be closed
            pass
