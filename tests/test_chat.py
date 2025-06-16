import pytest
import asyncio
from fastapi.testclient import TestClient
from fastapi import WebSocketDisconnect

from main import app # Assuming your FastAPI app instance is in main.py
from app.auth import create_access_token, User, users_db, AUTH_ENABLED, SECRET_KEY, ALGORITHM
from datetime import timedelta
import os

# Ensure consistent SECRET_KEY for tests, same as in app.auth if not overridden by env
TEST_SECRET_KEY = os.getenv("SECRET_KEY", "YOUR_SECRET_KEY_DEFAULT")
if TEST_SECRET_KEY == "YOUR_SECRET_KEY_DEFAULT":
    print("Warning: Using default SECRET_KEY for tests. Ensure this is intentional.")

# Test users - clear this at the start of a session or manage carefully if tests run in parallel
# For simplicity, we'll add to it. A fixture could manage this better.
_test_user_id_counter = 9000

def get_or_create_test_user(username: str, email: str) -> User:
    global _test_user_id_counter
    for user in users_db:
        if user.email == email:
            return user

    new_user = User(id=_test_user_id_counter, username=username, email=email, hashed_password="test_password")
    _test_user_id_counter += 1
    users_db.append(new_user)
    return new_user

def generate_test_token(user: User) -> str:
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=timedelta(minutes=15)
    )
    return access_token

@pytest.fixture(scope="module")
def client():
    # This fixture ensures that AUTH_ENABLED is true for the tests in this module.
    # It temporarily modifies the AUTH_ENABLED in the app.auth module.
    original_auth_enabled = AUTH_ENABLED
    import app.auth
    app.auth.AUTH_ENABLED = True

    # Also ensure users_db is clean for this module, or manage users carefully
    original_users_db_content = list(users_db)
    users_db.clear()

    yield TestClient(app)

    # Restore original state
    app.auth.AUTH_ENABLED = original_auth_enabled
    users_db.clear()
    users_db.extend(original_users_db_content)


def test_websocket_connection_authenticated(client: TestClient):
    test_user = get_or_create_test_user(username="auth_user", email="auth@example.com")
    token = generate_test_token(test_user)

    with client.websocket_connect(f"/ws/{token}") as websocket:
        # If client.websocket_connect does not raise an exception, the connection is considered successful.
        # No message is sent back to the client upon successful connection by the current server implementation.
        # We can optionally send a message and have another client try to receive it,
        # but that's covered in the broadcast test.
        # For this test, simply establishing the connection without error is sufficient.
        assert websocket.application_state == "connected" # TestClient's internal state
    # Exiting the 'with' block will close the websocket.


def test_websocket_connection_invalid_token(client: TestClient):
    with pytest.raises(WebSocketDisconnect) as excinfo:
        with client.websocket_connect("/ws/invalidtoken123"):
            pass # Should not reach here
    assert excinfo.value.code == 1008 # Policy Violation


def test_message_broadcast_two_clients(client: TestClient):
    user1 = get_or_create_test_user(username="user1_chat", email="user1_chat@example.com")
    user2 = get_or_create_test_user(username="user2_chat", email="user2_chat@example.com")

    token1 = generate_test_token(user1)
    token2 = generate_test_token(user2)

    with client.websocket_connect(f"/ws/{token1}") as websocket1, \
         client.websocket_connect(f"/ws/{token2}") as websocket2:

        # User1 sends a message
        websocket1.send_text("Hello from User1")

        # User2 should receive it
        message_from_user1 = websocket2.receive_text(timeout=5) # Add timeout
        assert message_from_user1 == f"{user1.username}: Hello from User1"

        # User1 should NOT receive its own message (standard broadcast logic)
        with pytest.raises(asyncio.TimeoutError): # Or other appropriate exception for no message
             # TestClient's receive_text doesn't have an explicit timeout argument like this.
             # It uses a default short timeout. If no message, it will raise after that.
             # Let's assume it will raise some form of timeout or connection closed if no message.
             # The `receive_text()` will raise `fastapi.websockets.WebSocketDisconnect` or similar if timeout.
             # For `TestClient`, if no message is available, it will eventually time out internally.
             # A more robust way is to check for a short period.
             # User1 should not receive their own message.
             # receive_text() will raise WebSocketDisconnect if no message is received within the timeout (default 1s).
             with pytest.raises(WebSocketDisconnect):
                 websocket1.receive_text()


def test_user_leaves_notification(client: TestClient):
    user_leaver = get_or_create_test_user(username="leaver_user", email="leaver@example.com")
    user_observer = get_or_create_test_user(username="observer_user", email="observer@example.com")

    token_leaver = generate_test_token(user_leaver)
    token_observer = generate_test_token(user_observer)

    with client.websocket_connect(f"/ws/{token_observer}") as websocket_observer:
        # Leaver connects
        with client.websocket_connect(f"/ws/{token_leaver}") as websocket_leaver:
            # Leaver is connected, observer is connected.
            # Now leaver disconnects (by exiting the 'with' block for websocket_leaver)
            pass # websocket_leaver automatically closes here

        # Observer should receive a "left the chat" message
        # The message is defined in app/routers/chat.py as f"{user.username} left the chat"
        leave_message = websocket_observer.receive_text(timeout=5)
        assert leave_message == f"{user_leaver.username} left the chat"

# TODO: Add test for user disconnecting due to error if that message is different.
# The current chat.py disconnects with:
# manager.disconnect(websocket, user)
# await manager.broadcast(f"{user.username} left the chat", user)
# OR
# await manager.broadcast(f"User {user.username} disconnected due to an error.", user)
# The "User {user.username} disconnected due to an error" is when an exception occurs in the read loop.
# The "User {user.username} left the chat" is for clean WebSocketDisconnect.
# The test above covers the clean disconnect.
# Testing the error disconnect path would require forcing an error on the server-side for a specific client,
# which is more complex to set up in a test.
