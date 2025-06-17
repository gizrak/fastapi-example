import pytest
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, patch
from jose import jwt
from datetime import datetime, timedelta
import sys
import os

# Modules that read environment variables or define global state that needs resetting
MODULES_TO_MANAGE = [
    "app.auth",  # Contains SECRET_KEY, AUTH_ENABLED, users_db, next_user_id etc.
    "app.models", # Contains User model definition (less likely to change with env, but good to be aware)
    "main",       # The main FastAPI app file
    "app.routers.web", # Imports from app.auth
    "app.routers.api.v1.users" # Imports from app.auth
]

@pytest.fixture
def patched_env(monkeypatch, request):
    """
    Fixture to set environment variables based on test parametrization.
    It also handles cleaning up relevant modules from sys.modules to ensure
    they are re-imported, picking up the new environment variables.
    """
    original_modules = {name: sys.modules.get(name) for name in MODULES_TO_MANAGE}

    for module_name in MODULES_TO_MANAGE:
        if module_name in sys.modules:
            del sys.modules[module_name]

    # Set default test environment variables
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "TEST_CLIENT_ID_DEFAULT")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "TEST_CLIENT_SECRET_DEFAULT")
    monkeypatch.setenv("SECRET_KEY", "TEST_SECRET_KEY_DEFAULT_FOR_TESTS")
    monkeypatch.setenv("GOOGLE_REDIRECT_URI", "http://localhost:8000/callback/test")
    monkeypatch.setenv("AUTH_ENABLED", "True") # Default for most tests

    # Override defaults if test is parametrized (request.param should be a dict)
    if hasattr(request, "param") and isinstance(request.param, dict):
        if "auth_enabled" in request.param:
            monkeypatch.setenv("AUTH_ENABLED", str(request.param["auth_enabled"]))
        if "secret_key" in request.param:
            monkeypatch.setenv("SECRET_KEY", request.param["secret_key"])

    yield # Test runs here

    # Teardown: Restore original modules or clear them if they were loaded during the test
    for module_name, module_instance in original_modules.items():
        if module_instance:
            sys.modules[module_name] = module_instance
        elif module_name in sys.modules: # if it was imported during test but not before
            del sys.modules[module_name]

@pytest.fixture
def app_auth_module(patched_env):
    """Imports and returns the app.auth module after patching."""
    import app.auth
    return app.auth

@pytest.fixture
def app_models_module(patched_env):
    """Imports and returns the app.models module."""
    import app.models
    return app.models

@pytest.fixture
def client(patched_env, app_auth_module, app_models_module): # Depends on app_auth_module to ensure it's loaded
    """
    Provides a TestClient instance. Ensures that `main` (the FastAPI app)
    is imported *after* environment variables are set by `patched_env`.
    Also resets the in-memory user database.
    """
    # app.auth is now imported via app_auth_module fixture, which depends on patched_env
    app_auth_module.users_db.clear()
    app_auth_module.next_user_id = 1 # Direct assignment

    # Now import the main application after monkeypatching and db reset
    from main import app as fastapi_app

    with TestClient(fastapi_app) as c:
        yield c

@pytest.fixture
def test_user_in_db(client, app_auth_module, app_models_module):
    """Creates and returns a test user in the database."""
    User = app_models_module.User
    users_db = app_auth_module.users_db

    # Use a direct reference for next_user_id from app_auth_module
    # and increment it there.
    user_id = app_auth_module.next_user_id
    user = User(id=user_id, username="firstuser", email="first@example.com",
                hashed_password=app_auth_module.get_password_hash("password123"))
    users_db.append(user)
    app_auth_module.next_user_id += 1
    return user

@pytest.fixture
def valid_jwt_token(test_user_in_db, app_auth_module):
    """Generates a valid JWT token for the test_user."""
    return app_auth_module.create_access_token(
        data={"sub": test_user_in_db.email},
        # create_access_token in app.auth now uses SECRET_KEY and ALGORITHM from its own module scope
        # which are set based on environment variables due to patched_env and module reloading.
        # No need to pass secret_key or algorithm explicitly if create_access_token uses them globally.
        # expires_delta is also handled by create_access_token default or can be passed if needed.
    )

# --- Mocking Utilities --- (Keep as is)
def mock_google_token_response():
    mock_resp = AsyncMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"access_token": "dummy_google_access_token", "id_token": "dummy_id_token"}
    return mock_resp

def mock_google_userinfo_response(email="testoauthuser@example.com", name="Test OAuth User"):
    mock_resp = AsyncMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"email": email, "name": name, "picture": "some_url.jpg"}
    return mock_resp

# --- Test Cases ---

@pytest.mark.parametrize("patched_env", [{"auth_enabled": True}], indirect=True)
def test_main_page_auth_enabled(client, test_user_in_db, valid_jwt_token):
    response_unauth = client.get("/main")
    assert response_unauth.status_code == 401

    client.cookies.set("access_token", valid_jwt_token)
    response_auth = client.get("/main")
    assert response_auth.status_code == 200
    assert test_user_in_db.username in response_auth.text
    assert test_user_in_db.email in response_auth.text
    client.cookies.clear()

@pytest.mark.parametrize("patched_env", [{"auth_enabled": False}], indirect=True)
def test_main_page_auth_disabled(client, test_user_in_db, app_auth_module):
    response_with_user = client.get("/main")
    assert response_with_user.status_code == 200
    # When auth is disabled, get_current_user returns users_db[0] or mock user
    # test_user_in_db fixture ensures at least one user is in users_db
    # So, it should display that user.
    assert test_user_in_db.username in response_with_user.text

    app_auth_module.users_db.clear()
    app_auth_module.next_user_id = 1
    response_empty_db = client.get("/main")
    assert response_empty_db.status_code == 200
    assert "mockuser" in response_empty_db.text
    assert "mock@example.com" in response_empty_db.text


@pytest.mark.parametrize("patched_env", [{"auth_enabled": True}], indirect=True)
@patch('httpx.AsyncClient')
def test_callback_auth_enabled(MockAsyncClient, client, app_auth_module):
    mock_client_instance = MockAsyncClient.return_value.__aenter__.return_value
    mock_client_instance.post.return_value = mock_google_token_response()
    mock_client_instance.get.return_value = mock_google_userinfo_response(email="callbackuser@example.com", name="Callback User")

    response = client.get("/callback?code=testcode", allow_redirects=False)
    assert response.status_code == 302
    assert response.headers["location"] == "/main"
    assert "access_token" in response.cookies

    token_in_cookie = response.cookies.get("access_token")
    # SECRET_KEY and ALGORITHM are sourced from app_auth_module's global scope
    decoded_token = jwt.decode(token_in_cookie, app_auth_module.SECRET_KEY, algorithms=[app_auth_module.ALGORITHM])
    assert decoded_token["sub"] == "callbackuser@example.com"
    assert "HttpOnly" in response.headers.get("set-cookie")


@pytest.mark.parametrize("patched_env", [{"auth_enabled": False}], indirect=True)
def test_callback_auth_disabled(client):
    response = client.get("/callback?code=testcode")
    assert response.status_code == 404


@pytest.mark.parametrize("patched_env", [{"auth_enabled": True}, {"auth_enabled": False}], indirect=True)
def test_logout(client, valid_jwt_token, test_user_in_db, app_auth_module):
    client.cookies.set("access_token", valid_jwt_token)

    # Check current state based on AUTH_ENABLED from app_auth_module
    if app_auth_module.AUTH_ENABLED:
        resp_main_before = client.get("/main")
        assert resp_main_before.status_code == 200
        assert test_user_in_db.username in resp_main_before.text # Assumes test_user_in_db is the one logged in
    else: # Auth disabled
        resp_main_before = client.get("/main")
        assert resp_main_before.status_code == 200
        # Content depends on get_current_user logic for auth disabled (usually first or mock user)
        # test_user_in_db would be users_db[0] here.
        assert test_user_in_db.username in resp_main_before.text


    response_logout = client.post("/logout", allow_redirects=False)
    assert response_logout.status_code == 302
    assert response_logout.headers["location"] == "/login"
    assert "access_token=;" in response_logout.headers.get("set-cookie") # FastAPI sets value to empty
    assert "Max-Age=0" in response_logout.headers.get("set-cookie")

    # To verify logout, set AUTH_ENABLED to True temporarily for the check if it was False
    # This is a bit of a hack. A better way might be another fixture call.
    original_auth_enabled_value = app_auth_module.AUTH_ENABLED
    app_auth_module.AUTH_ENABLED = True # Force for this check

    response_main_after = client.get("/main")
    assert response_main_after.status_code == 401 # Expect 401 as cookie should be gone/invalid

    app_auth_module.AUTH_ENABLED = original_auth_enabled_value # Restore
    client.cookies.clear()


@pytest.mark.parametrize("patched_env", [{"auth_enabled": True}], indirect=True)
def test_read_users_auth_enabled(client, valid_jwt_token, test_user_in_db):
    response_unauth = client.get("/users/")
    assert response_unauth.status_code == 401

    client.cookies.set("access_token", valid_jwt_token)
    response_auth = client.get("/users/")
    assert response_auth.status_code == 200
    data = response_auth.json()
    assert len(data) == 1
    assert data[0]["email"] == test_user_in_db.email
    client.cookies.clear()

@pytest.mark.parametrize("patched_env", [{"auth_enabled": False}], indirect=True)
def test_read_users_auth_disabled(client, test_user_in_db, app_auth_module):
    response = client.get("/users/")
    assert response.status_code == 200
    data = response.json()
    # When auth is disabled, /users/ route directly returns app_auth_module.users_db
    assert len(data) == len(app_auth_module.users_db)
    assert any(u["email"] == test_user_in_db.email for u in data)


def test_read_root(client):
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"Hello": "World"}


def test_create_user_with_password(client, app_auth_module, app_models_module):
    User = app_models_module.User
    users_db = app_auth_module.users_db
    initial_user_count = len(users_db)

    response = client.post("/users/", json={"username": "newbie", "email": "newbie@example.com", "password": "password123"})
    assert response.status_code == 200
    assert len(users_db) == initial_user_count + 1
    created_user_data = response.json()
    assert created_user_data["email"] == "newbie@example.com"
    # Check if user is actually in db
    assert any(u.email == "newbie@example.com" for u in users_db)


@pytest.mark.parametrize("patched_env", [{"auth_enabled": True}], indirect=True)
def test_get_current_user_expired_token_auth_enabled(client, test_user_in_db, app_auth_module):
    expired_token = app_auth_module.create_access_token(
        data={"sub": test_user_in_db.email},
        expires_delta=timedelta(minutes=-5) # Expired
    )
    client.cookies.set("access_token", expired_token)
    response_cookie = client.get("/main") # /main is protected
    assert response_cookie.status_code == 401
    assert response_cookie.json()["detail"] == "Could not validate credentials"
    client.cookies.clear()


@pytest.mark.parametrize("patched_env", [{"auth_enabled": True}], indirect=True)
def test_read_specific_user_auth_enabled(client, valid_jwt_token, test_user_in_db):
    user_id = test_user_in_db.id

    client.cookies.set("access_token", valid_jwt_token)
    response_auth = client.get(f"/users/{user_id}")
    assert response_auth.status_code == 200
    assert response_auth.json()["email"] == test_user_in_db.email
    client.cookies.clear()

    response_unauth = client.get(f"/users/{user_id}") # No cookie
    assert response_unauth.status_code == 401

    client.cookies.set("access_token", valid_jwt_token)
    response_non_existent = client.get("/users/9999") # Non-existent ID
    assert response_non_existent.status_code == 404 # Assuming users route handles this
    client.cookies.clear()


@pytest.mark.parametrize("patched_env", [{"auth_enabled": False}], indirect=True)
def test_read_specific_user_auth_disabled(client, test_user_in_db, app_models_module):
    user_id = test_user_in_db.id
    response = client.get(f"/users/{user_id}")
    assert response.status_code == 200 # Should find the user
    assert response.json()["email"] == test_user_in_db.email

    response_non_existent = client.get("/users/9999")
    assert response_non_existent.status_code == 404
```
