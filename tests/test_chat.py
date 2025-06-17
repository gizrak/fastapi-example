import pytest
import asyncio
from fastapi import FastAPI, WebSocketDisconnect
from fastapi.testclient import TestClient
from unittest.mock import patch # For mocking if needed later

# Import from main app factory and models/auth for type hints and direct use in fixtures
from main import create_app
from app.models import User
# Import specific auth functions that fixtures will use from the reloaded app.auth
from app.auth import get_password_hash, create_access_token as app_create_access_token

# --- Core Fixtures ---
@pytest.fixture
def app_settings(request):
    """
    Provides settings for app creation.
    Chat tests generally require AUTH_ENABLED=True.
    Specific tests can override via parametrization if needed.
    """
    default_settings = {
        "AUTH_ENABLED": True,
        "SECRET_KEY": "TEST_CHAT_SECRET_KEY", # Specific key for chat tests if desired
        # Add other necessary env vars for chat app context if any
    }
    if hasattr(request, "param") and isinstance(request.param, dict):
        default_settings.update(request.param)
    return default_settings

@pytest.fixture
def app(app_settings: dict, monkeypatch) -> FastAPI: # Added monkeypatch
    """
    Creates a FastAPI app instance for each test, configured by app_settings,
    using the application factory.
    """
    # Set environment variables based on app_settings before calling create_app
    for key, value in app_settings.items():
        monkeypatch.setenv(key, str(value))

    # Ensure other potentially used env vars are set if not in app_settings
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "TEST_CHAT_GOOGLE_ID") # Placeholder
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "TEST_CHAT_GOOGLE_SECRET") # Placeholder
    monkeypatch.setenv("GOOGLE_REDIRECT_URI", "http://localhost:8000/oauth/callback")


    return create_app(settings_override=app_settings)

@pytest.fixture
def client(app: FastAPI) -> TestClient:
    """Provides a TestClient for the app instance."""
    with TestClient(app) as c:
        yield c

@pytest.fixture
def current_app_auth(app: FastAPI):
    """
    Provides access to the reloaded app.auth module specific to the app instance.
    Relies on create_app having reloaded app.auth and it being in sys.modules.
    """
    import sys
    return sys.modules['app.auth']

# --- User and Token Fixtures ---

@pytest.fixture
def created_chat_user(app: FastAPI, current_app_auth, request) -> User:
    """
    Creates a user in app.state.users_db based on parameters passed via request.param.
    request.param should be a dict like {"username": "user1", "email": "user1@example.com"}
    """
    user_data = request.param
    users_db_on_state = app.state.users_db
    next_user_id_on_state = app.state.next_user_id

    # Check if user already exists by email
    for u in users_db_on_state:
        if u.email == user_data["email"]:
            return u # Return existing user

    # Create new user
    # Chat users might not need passwords if auth is just via token from main login
    hashed_pwd = current_app_auth.get_password_hash("testpassword")
    user = User(
        id=next_user_id_on_state,
        username=user_data["username"],
        email=user_data["email"],
        hashed_password=hashed_pwd
    )
    users_db_on_state.append(user)
    app.state.next_user_id += 1
    return user

@pytest.fixture
def chat_token(current_app_auth, created_chat_user: User) -> str:
    """Generates an auth token for the created_chat_user."""
    return current_app_auth.create_access_token(data={"sub": created_chat_user.email})

# --- Test Functions ---

# This test uses the created_chat_user fixture parametrized.
@pytest.mark.parametrize("created_chat_user", [{"username": "auth_user_ws", "email": "auth_ws@example.com"}], indirect=True)
def test_websocket_connection_authenticated(client: TestClient, chat_token: str):
    with client.websocket_connect(f"/ws/{chat_token}") as websocket:
        assert websocket.application_state == "connected"
    # Connection closes automatically on exit from 'with'

def test_websocket_connection_invalid_token(client: TestClient):
    with pytest.raises(WebSocketDisconnect) as excinfo:
        with client.websocket_connect("/ws/invalidtoken123"):
            pass
    assert excinfo.value.code == 1008 # Policy Violation

# This test does not use created_chat_user fixture parametrization as it sets up two users manually.
def test_message_broadcast_two_clients(client: TestClient, app: FastAPI, current_app_auth):
    # This test will be run twice by pytest due to parametrization of created_chat_user. # This comment is now incorrect.
    # We need two distinct users and tokens.
    # The current fixture setup will create user1 then user2 if we manage it carefully or call fixtures multiple times. # This comment is now incorrect.
    # This is tricky with parametrized created_chat_user.
    # Let's create users manually for this specific test for clarity.

    user1_data = {"username": "user1_broad", "email": "user1_broad@example.com"}
    user2_data = {"username": "user2_broad", "email": "user2_broad@example.com"}

    # Manually create users in the app.state.users_db for this test's app instance
    user1 = User(id=app.state.next_user_id, **user1_data, hashed_password=get_password_hash("pw1"))
    app.state.next_user_id +=1
    app.state.users_db.append(user1)

    user2 = User(id=app.state.next_user_id, **user2_data, hashed_password=get_password_hash("pw2"))
    app.state.next_user_id +=1
    app.state.users_db.append(user2)

    token1 = current_app_auth.create_access_token(data={"sub": user1.email})
    token2 = current_app_auth.create_access_token(data={"sub": user2.email})

    with client.websocket_connect(f"/ws/{token1}") as websocket1, \
         client.websocket_connect(f"/ws/{token2}") as websocket2:

        websocket1.send_text("Hello from User1")
        message_from_user1 = websocket2.receive_text(timeout=1) # Short timeout
        assert message_from_user1 == f"{user1.username}: Hello from User1"

        # User1 should NOT receive its own message if broadcast logic excludes sender
        # The current ConnectionManager.broadcast sends to all *other* connections.
        with pytest.raises(asyncio.TimeoutError):
            websocket1.receive_text(timeout=0.1)

# This test does not use created_chat_user fixture parametrization as it sets up two users manually.
def test_user_leaves_notification(client: TestClient, app: FastAPI, current_app_auth):
    # Similar to above, manual user creation for clarity in this multi-user test
    leaver_data = {"username": "leaver_notify", "email": "leaver_notify@example.com"}
    observer_data = {"username": "observer_notify", "email": "observer_notify@example.com"}

    user_leaver = User(id=app.state.next_user_id, **leaver_data, hashed_password=get_password_hash("pw_l"))
    app.state.next_user_id +=1
    app.state.users_db.append(user_leaver)

    user_observer = User(id=app.state.next_user_id, **observer_data, hashed_password=get_password_hash("pw_o"))
    app.state.next_user_id +=1
    app.state.users_db.append(user_observer)

    token_leaver = current_app_auth.create_access_token(data={"sub": user_leaver.email})
    token_observer = current_app_auth.create_access_token(data={"sub": user_observer.email})

    with client.websocket_connect(f"/ws/{token_observer}") as websocket_observer:
        with client.websocket_connect(f"/ws/{token_leaver}") as websocket_leaver:
            # websocket_leaver is connected
            pass # websocket_leaver automatically closes here, triggering disconnect logic

        leave_message = websocket_observer.receive_text(timeout=1) # Short timeout
        assert leave_message == f"{user_leaver.username} left the chat"
