import pytest
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, patch
import httpx # Required for type hinting with @patch
import importlib # To reload main if necessary

# Import app and other necessary items from main.py
import main # Import main directly for monkeypatching
# We need to be careful about when main.py reads env vars.
# Pytest typically imports test files, which then import main.py.
# Env vars should be set *before* main.py is first imported by the test session,
# or main.py needs to be reloaded after env vars are set by monkeypatch.
# For simplicity, we'll assume monkeypatch.setenv works before the app's config is "frozen"
# by being read at import time. If not, we'd need importlib.reload(main).

from main import app, users_db, GOOGLE_AUTHORIZATION_URL, User, ALGORITHM
# GOOGLE_CLIENT_ID, GOOGLE_REDIRECT_URI, SECRET_KEY will be read from env by main.py
# create_access_token is also needed from main
from main import create_access_token
from datetime import datetime, timedelta


client = TestClient(app)

# --- Fixtures ---

@pytest.fixture(autouse=True)
def setup_and_teardown_each_test(monkeypatch):
    """Clears the users_db, resets next_user_id, and sets default test env vars."""
    users_db.clear()
    main.next_user_id = 1 # Resetting the in-memory user ID counter

    # Set default environment variables for tests
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "TEST_CLIENT_ID_DEFAULT")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "TEST_CLIENT_SECRET_DEFAULT")
    monkeypatch.setenv("SECRET_KEY", "TEST_SECRET_KEY_DEFAULT")
    monkeypatch.setenv("GOOGLE_REDIRECT_URI", "http://localhost:8000/callback/test")
    # Default AUTH_ENABLED to "True". Tests needing "False" will override.
    monkeypatch.setenv("AUTH_ENABLED", "True")

    # Reload main to ensure it picks up the new environment variables
    # This is crucial because main.py reads env vars at the module level.
    importlib.reload(main)
    # Update global references from the reloaded main module
    global GOOGLE_CLIENT_ID_EFFECTIVE, GOOGLE_REDIRECT_URI_EFFECTIVE, SECRET_KEY_EFFECTIVE
    GOOGLE_CLIENT_ID_EFFECTIVE = main.GOOGLE_CLIENT_ID
    GOOGLE_REDIRECT_URI_EFFECTIVE = main.GOOGLE_REDIRECT_URI
    SECRET_KEY_EFFECTIVE = main.SECRET_KEY


    yield # Test runs here

@pytest.fixture
def first_test_user_in_db():
    """Creates a user and puts it in users_db, returns the User object."""
    # Ensure main.get_password_hash is available after reload
    user = User(id=main.next_user_id, username="firstuser", email="first@example.com",
                hashed_password=main.get_password_hash("password123"))
    users_db.append(user)
    main.next_user_id += 1
    return user

@pytest.fixture
def test_user(first_test_user_in_db: User):
    return first_test_user_in_db


@pytest.fixture
def auth_token(test_user: User):
    """Generates an access token for the test_user."""
    # create_access_token uses main.SECRET_KEY and main.ALGORITHM
    return main.create_access_token(data={"sub": test_user.email}, expires_delta=timedelta(minutes=15))

@pytest.fixture
def auth_headers(auth_token: str):
    return {"Authorization": f"Bearer {auth_token}"}

# --- Mocking Utilities --- (Keep as is)
def mock_google_token_response():
    mock_resp = AsyncMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"access_token": "dummy_google_access_token", "id_token": "dummy_id_token"}
    return mock_resp

def mock_google_userinfo_response(email="testoauthuser@example.com", name="Test OAuth User"):
    mock_resp = AsyncMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "email": email,
        "name": name,
        "picture": "some_url.jpg"
    }
    return mock_resp

# --- OAuth2 Flow Tests (Parametrized) ---

@pytest.mark.parametrize("auth_enabled_env_value, expected_behavior_enabled", [("True", True), ("False", False)])
def test_login_route(auth_enabled_env_value, expected_behavior_enabled, monkeypatch):
    monkeypatch.setenv("AUTH_ENABLED", auth_enabled_env_value)
    importlib.reload(main) # Reload main to pick up AUTH_ENABLED

    response = client.get("/login", allow_redirects=False)
    if expected_behavior_enabled:
        assert response.status_code == 307
        # Use the effective values read by main.py after it loaded env vars
        expected_redirect_location_start = f"{main.GOOGLE_AUTHORIZATION_URL}?client_id={main.GOOGLE_CLIENT_ID}&redirect_uri={main.GOOGLE_REDIRECT_URI}"
        assert response.headers["location"].startswith(expected_redirect_location_start)
    else:
        assert response.status_code == 404
        assert response.json()["detail"] == "Authentication is disabled."


@pytest.mark.parametrize("auth_enabled_env_value, expected_behavior_enabled", [("True", True), ("False", False)])
@patch('httpx.AsyncClient')
def test_callback_new_user(MockAsyncClient, auth_enabled_env_value, expected_behavior_enabled, monkeypatch):
    monkeypatch.setenv("AUTH_ENABLED", auth_enabled_env_value)
    importlib.reload(main)

    if not expected_behavior_enabled:
        response = client.get("/callback?code=testcode")
        assert response.status_code == 404
        assert response.json()["detail"] == "Authentication is disabled."
        return

    mock_client_instance = MockAsyncClient.return_value.__aenter__.return_value
    mock_client_instance.post.return_value = mock_google_token_response()
    mock_client_instance.get.return_value = mock_google_userinfo_response(email="newoauth@example.com", name="New OAuth User")

    response = client.get("/callback?code=testcode")
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert users_db[0].email == "newoauth@example.com"

@pytest.mark.parametrize("auth_enabled_env_value, expected_behavior_enabled", [("True", True), ("False", False)])
@patch('httpx.AsyncClient')
def test_callback_existing_user(MockAsyncClient, auth_enabled_env_value, expected_behavior_enabled, monkeypatch, first_test_user_in_db):
    monkeypatch.setenv("AUTH_ENABLED", auth_enabled_env_value)
    importlib.reload(main)

    if not expected_behavior_enabled:
        response = client.get(f"/callback?code=testcode_for_{first_test_user_in_db.email}")
        assert response.status_code == 404
        assert response.json()["detail"] == "Authentication is disabled."
        return

    mock_client_instance = MockAsyncClient.return_value.__aenter__.return_value
    mock_client_instance.post.return_value = mock_google_token_response()
    mock_client_instance.get.return_value = mock_google_userinfo_response(email=first_test_user_in_db.email, name=first_test_user_in_db.username)

    initial_user_count = len(users_db)
    response = client.get(f"/callback?code=testcode_for_{first_test_user_in_db.email}")
    assert response.status_code == 200
    assert "access_token" in response.json()
    assert len(users_db) == initial_user_count


# --- Protected Endpoint Tests (Parametrized) ---
@pytest.mark.parametrize("auth_enabled_env_value, expected_behavior_enabled", [("True", True), ("False", False)])
def test_read_users_general_access(auth_enabled_env_value, expected_behavior_enabled, monkeypatch, auth_headers, first_test_user_in_db):
    monkeypatch.setenv("AUTH_ENABLED", auth_enabled_env_value)
    importlib.reload(main)

    if expected_behavior_enabled:
        response_unauth = client.get("/users/")
        assert response_unauth.status_code == 401
        assert response_unauth.json()["detail"] == "Not authenticated"

        response_invalid_token = client.get("/users/", headers={"Authorization": "Bearer invalidtoken"})
        assert response_invalid_token.status_code == 401
        assert response_invalid_token.json()["detail"] == "Could not validate credentials"

        response_auth = client.get("/users/", headers=auth_headers)
        assert response_auth.status_code == 200
        data = response_auth.json()
        assert len(data) == 1
        assert data[0]["email"] == first_test_user_in_db.email
    else:
        # Auth disabled
        # Case 1: users_db has users
        response = client.get("/users/")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["email"] == first_test_user_in_db.email

        # Case 2: users_db is empty
        users_db.clear()
        main.next_user_id = 1
        response_empty_db = client.get("/users/")
        assert response_empty_db.status_code == 200
        assert response_empty_db.json() == []


@pytest.mark.parametrize("auth_enabled_env_value, expected_behavior_enabled", [("True", True), ("False", False)])
def test_read_specific_user(auth_enabled_env_value, expected_behavior_enabled, monkeypatch, auth_headers, first_test_user_in_db):
    monkeypatch.setenv("AUTH_ENABLED", auth_enabled_env_value)
    importlib.reload(main)
    user_id = first_test_user_in_db.id

    if expected_behavior_enabled:
        response_auth = client.get(f"/users/{user_id}", headers=auth_headers)
        assert response_auth.status_code == 200
        assert response_auth.json()["email"] == first_test_user_in_db.email

        response_unauth = client.get(f"/users/{user_id}")
        assert response_unauth.status_code == 401

        response_non_existent = client.get("/users/9999", headers=auth_headers)
        assert response_non_existent.status_code == 404
    else:
        response = client.get(f"/users/{user_id}")
        assert response.status_code == 200
        assert response.json()["email"] == first_test_user_in_db.email

        response_non_existent = client.get("/users/9999")
        assert response_non_existent.status_code == 404


@pytest.mark.parametrize("auth_enabled_env_value, expected_behavior_enabled", [("True", True), ("False", False)])
def test_update_user(auth_enabled_env_value, expected_behavior_enabled, monkeypatch, auth_headers, first_test_user_in_db):
    monkeypatch.setenv("AUTH_ENABLED", auth_enabled_env_value)
    importlib.reload(main) # Reload main to pick up AUTH_ENABLED
    user_id = first_test_user_in_db.id
    updated_data = {"username": "updateduser", "email": "updated@example.com"}

    if expected_behavior_enabled:
        response_auth = client.put(f"/users/{user_id}", json=updated_data, headers=auth_headers)
        assert response_auth.status_code == 200
        assert response_auth.json()["username"] == "updateduser"

        # Ensure user is reset for the unauth check if it's part of the same test instance (not with parametrize)
        # Here, parametrization handles fresh state from fixture for each run (True/False)

        response_unauth = client.put(f"/users/{user_id}", json=updated_data) # Use different data to avoid issues if not reset
        assert response_unauth.status_code == 401
    else:
        # Auth disabled
        response = client.put(f"/users/{user_id}", json=updated_data)
        assert response.status_code == 200
        assert response.json()["username"] == "updateduser"
        db_user = next(u for u in users_db if u.id == user_id)
        assert db_user.username == "updateduser"


@pytest.mark.parametrize("auth_enabled_env_value, expected_behavior_enabled", [("True", True), ("False", False)])
def test_delete_user(auth_enabled_env_value, expected_behavior_enabled, monkeypatch, auth_headers, first_test_user_in_db):
    monkeypatch.setenv("AUTH_ENABLED", auth_enabled_env_value)
    importlib.reload(main)
    user_id_to_delete = first_test_user_in_db.id

    if expected_behavior_enabled:
        # Ensure user exists for this part of the test
        if not any(u.id == user_id_to_delete for u in users_db): users_db.append(first_test_user_in_db)


        response_auth = client.delete(f"/users/{user_id_to_delete}", headers=auth_headers)
        assert response_auth.status_code == 200
        assert not any(u.id == user_id_to_delete for u in users_db)

        # Re-add user for unauth check
        users_db.append(first_test_user_in_db)
        main.next_user_id = max(u.id for u in users_db) + 1 if users_db else 1


        response_unauth = client.delete(f"/users/{user_id_to_delete}")
        assert response_unauth.status_code == 401
        assert any(u.id == user_id_to_delete for u in users_db) # Still there
    else:
        # Auth disabled: ensure user exists from fixture
        assert any(u.id == user_id_to_delete for u in users_db)
        response = client.delete(f"/users/{user_id_to_delete}")
        assert response.status_code == 200
        assert not any(u.id == user_id_to_delete for u in users_db)


# --- Test User Creation (POST /users/) - Unaffected by AUTH_ENABLED directly ---
def test_create_user_with_password():
    response = client.post("/users/", json={"username": "newbie", "email": "newbie@example.com", "password": "password123"})
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "newbie"
    created_user = next((u for u in users_db if u.email == "newbie@example.com"), None)
    assert created_user is not None
    assert main.verify_password("password123", created_user.hashed_password)


# --- Specific tests for get_current_user behavior when AUTH_ENABLED = True ---
def test_get_current_user_expired_token_when_auth_enabled(monkeypatch, test_user: User, auth_headers): # auth_headers to ensure user exists
    monkeypatch.setenv("AUTH_ENABLED", "True")
    importlib.reload(main)
    expired_token = main.create_access_token(data={"sub": test_user.email}, expires_delta=timedelta(minutes=-5))
    headers = {"Authorization": f"Bearer {expired_token}"}
    response = client.get("/users/", headers=headers)
    assert response.status_code == 401
    assert response.json()["detail"] == "Could not validate credentials"

# ... (Keep other direct get_current_user tests for True case, ensuring reload and env var set)

# --- Specific tests for get_current_user behavior when AUTH_ENABLED = False ---
# These tests verify the mock user logic directly via a protected endpoint.
def test_protected_route_auth_disabled_users_db_empty(monkeypatch):
    monkeypatch.setenv("AUTH_ENABLED", "False")
    importlib.reload(main)
    users_db.clear()
    main.next_user_id = 1

    # We need an endpoint that reveals what get_current_user returned.
    # Let's assume GET /users/ still works and we check its behavior.
    # If get_current_user returns the default mock user (id=0), and /users/ simply returns users_db,
    # then /users/ should be empty.
    response = client.get("/users/")
    assert response.status_code == 200
    assert response.json() == []

def test_protected_route_auth_disabled_users_db_has_users(monkeypatch, first_test_user_in_db):
    monkeypatch.setenv("AUTH_ENABLED", "False")
    importlib.reload(main)

    response = client.get("/users/")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["email"] == first_test_user_in_db.email


# Root endpoint (unaffected by AUTH_ENABLED)
def test_read_root():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"Hello": "World"}


# test_create_multiple_users needs adjustment if it uses a protected endpoint
@pytest.mark.parametrize("auth_enabled_env_value, expected_behavior_enabled", [("True", True), ("False", False)])
def test_create_multiple_users(monkeypatch, auth_headers, first_test_user_in_db, auth_enabled_env_value, expected_behavior_enabled):
    monkeypatch.setenv("AUTH_ENABLED", auth_enabled_env_value)
    importlib.reload(main)

    # user1 is first_test_user_in_db
    client.post("/users/", json={"username": "user2", "email": "user2@example.com", "password": "pw2"})

    if expected_behavior_enabled:
        response_get = client.get("/users/", headers=auth_headers)
    else:
        response_get = client.get("/users/") # No headers needed if auth disabled

    assert response_get.status_code == 200
    data = response_get.json()
    assert len(data) == 2
    assert any(u["email"] == first_test_user_in_db.email for u in data)
    assert any(u["email"] == "user2@example.com" for u in data)


# Remaining tests (validation, password hashing, etc.) should be fine as they don't depend on AUTH_ENABLED state
# or protected routes in a way that's not already covered by parametrization.

def test_create_user_username_too_short():
    response = client.post("/users/", json={"username": "ab", "email": "test@example.com", "password": "pw"})
    assert response.status_code == 422

def test_create_user_username_too_long():
    response = client.post("/users/", json={"username": "a" * 51, "email": "test@example.com", "password": "pw"})
    assert response.status_code == 422

def test_create_user_username_not_alphanumeric():
    response = client.post("/users/", json={"username": "user!@#", "email": "test@example.com", "password": "pw"})
    assert response.status_code == 422

def test_create_user_invalid_email():
    response = client.post("/users/", json={"username": "validuser", "email": "not-an-email", "password": "pw"})
    assert response.status_code == 422

def test_password_hashing():
    password = "mypassword"
    # Ensure main.get_password_hash and main.verify_password are from reloaded main
    hashed_password = main.get_password_hash(password)
    assert hashed_password != password
    assert main.verify_password(password, hashed_password)
    assert not main.verify_password("wrongpassword", hashed_password)

# --- Tests for callback error handling (AUTH_ENABLED=True) ---
@patch('httpx.AsyncClient')
def test_callback_code_is_none_auth_enabled(MockAsyncClient, monkeypatch):
    monkeypatch.setenv("AUTH_ENABLED", "True")
    importlib.reload(main)
    response = client.get("/callback") # No code query param
    assert response.status_code == 400
    assert response.json()["detail"] == "Authorization code not found."

@patch('httpx.AsyncClient')
def test_callback_google_token_fail_auth_enabled(MockAsyncClient, monkeypatch):
    monkeypatch.setenv("AUTH_ENABLED", "True")
    importlib.reload(main)
    mock_client_instance = MockAsyncClient.return_value.__aenter__.return_value
    mock_bad_token_response = AsyncMock()
    mock_bad_token_response.status_code = 200
    mock_bad_token_response.json.return_value = {"error": "bad_request"} # No access_token
    mock_client_instance.post.return_value = mock_bad_token_response

    response = client.get("/callback?code=testcode")
    assert response.status_code == 400
    assert response.json()["detail"] == "Could not fetch token from provider."

@patch('httpx.AsyncClient')
def test_callback_google_userinfo_fail_auth_enabled(MockAsyncClient, monkeypatch):
    monkeypatch.setenv("AUTH_ENABLED", "True")
    importlib.reload(main)
    mock_client_instance = MockAsyncClient.return_value.__aenter__.return_value
    mock_client_instance.post.return_value = mock_google_token_response()
    mock_bad_userinfo_response = AsyncMock()
    mock_bad_userinfo_response.status_code = 200
    mock_bad_userinfo_response.json.return_value = {"name": "Test User Only"} # No email
    mock_client_instance.get.return_value = mock_bad_userinfo_response

    response = client.get("/callback?code=testcode")
    assert response.status_code == 400
    assert response.json()["detail"] == "Could not fetch user info from provider."
```
