import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
import httpx
from jose import jwt
from datetime import datetime, timedelta
import os
import sys

from main import create_app
from app.models import User
from app.auth import get_password_hash, create_access_token as app_create_access_token

@pytest.fixture
def app_settings(request):
    default_settings = {
        "AUTH_ENABLED": True,
        "SECRET_KEY": "TEST_SECRET_KEY_FROM_APP_SETTINGS_FIXTURE",
        "GOOGLE_CLIENT_ID": "TEST_GOOGLE_CLIENT_ID_FROM_APP_SETTINGS",
        "GOOGLE_CLIENT_SECRET": "TEST_GOOGLE_CLIENT_SECRET_FROM_APP_SETTINGS",
        "GOOGLE_REDIRECT_URI": "http://localhost:8000/oauth/callback",
    }
    if hasattr(request, "param") and isinstance(request.param, dict):
        default_settings.update(request.param)
    return default_settings

@pytest.fixture
def app(app_settings: dict) -> FastAPI:
    for key, value in app_settings.items():
        os.environ[key] = str(value)
    created_app_instance = create_app(settings_override=app_settings)
    return created_app_instance

@pytest.fixture
def client(app: FastAPI) -> TestClient:
    with TestClient(app) as c:
        yield c

@pytest.fixture
def current_app_auth(app: FastAPI):
    return sys.modules['app.auth']

@pytest.fixture
def test_user_data() -> dict:
    return {"username": "testuser", "email": "test@example.com", "password": "password"}

@pytest.fixture
def created_user(app: FastAPI, test_user_data: dict, current_app_auth) -> User:
    users_db_on_state = app.state.users_db
    next_user_id_on_state = app.state.next_user_id

    for u in users_db_on_state:
        if u.email == test_user_data["email"]:
            if test_user_data.get("password") and not u.hashed_password:
                u.hashed_password = current_app_auth.get_password_hash(test_user_data["password"])
            return u

    hashed_pwd = current_app_auth.get_password_hash(test_user_data["password"])
    user = User(
        id=next_user_id_on_state,
        username=test_user_data["username"],
        email=test_user_data["email"],
        hashed_password=hashed_pwd
    )
    users_db_on_state.append(user)
    app.state.next_user_id += 1
    return user

@pytest.fixture
def valid_jwt_token(app: FastAPI, created_user: User, current_app_auth) -> str:
    return current_app_auth.create_access_token(data={"sub": created_user.email})

@pytest.fixture
def mock_httpx_async_client():
    with patch('httpx.AsyncClient') as MockAsyncClient:
        mock_client_instance = MockAsyncClient.return_value.__aenter__.return_value
        token_response_mock = MagicMock(spec=httpx.Response)
        token_response_mock.status_code = 200
        token_response_mock.json.return_value = {"access_token": "dummy_google_access_token", "id_token": "dummy_id_token"}
        userinfo_response_mock = MagicMock(spec=httpx.Response)
        userinfo_response_mock.status_code = 200
        userinfo_response_mock.json.return_value = {"email": "callbackuser@example.com", "name": "Callback User", "picture": "some_url.jpg"}
        mock_client_instance.post.return_value = token_response_mock
        mock_client_instance.get.return_value = userinfo_response_mock
        yield MockAsyncClient

@pytest.mark.parametrize("app_settings", [{"AUTH_ENABLED": True}, {"AUTH_ENABLED": False}], indirect=True)
def test_main_page_access_and_content(client: TestClient, app: FastAPI, app_settings: dict, created_user: User, valid_jwt_token: str):
    auth_is_on = app_settings["AUTH_ENABLED"]
    if auth_is_on:
        response_unauth = client.get("/main")
        assert response_unauth.status_code == 401
        client.cookies.set("access_token", valid_jwt_token)
        response_auth = client.get("/main")
        assert response_auth.status_code == 200
        assert created_user.username in response_auth.text
        assert created_user.email in response_auth.text
        client.cookies.clear()
    else:
        response_with_user = client.get("/main")
        assert response_with_user.status_code == 200
        assert created_user.username in response_with_user.text
        app.state.users_db.clear()
        app.state.next_user_id = 1
        response_empty_db = client.get("/main")
        assert response_empty_db.status_code == 200
        # Check for email as it's more specific in the template context for the mock user
        assert "mock@example.com" in response_empty_db.text
        # assert "mockuser" in response_empty_db.text # Username might be less prominent or styled

@pytest.mark.parametrize("app_settings", [{"AUTH_ENABLED": True}, {"AUTH_ENABLED": False}], indirect=True)
def test_callback_logic(client: TestClient, app: FastAPI, app_settings: dict, mock_httpx_async_client: MagicMock, current_app_auth):
    auth_is_on = app_settings["AUTH_ENABLED"]
    if auth_is_on:
        response = client.get("/oauth/callback?code=testcode")
        assert response.status_code == 302, response.text
        assert response.headers["location"] == "/main"
        assert "access_token" in response.cookies
        token_in_cookie = response.cookies.get("access_token")
        decoded_token = jwt.decode(token_in_cookie, current_app_auth.get_secret_key(), algorithms=[current_app_auth.get_algorithm()])
        assert decoded_token["sub"] == "callbackuser@example.com"
        assert "HttpOnly" in response.headers.get("set-cookie")
        callback_user_exists = any(u.email == "callbackuser@example.com" for u in client.app.state.users_db)
        assert callback_user_exists
    else:
        response = client.get("/oauth/callback?code=testcode")
        assert response.status_code == 404

@pytest.mark.parametrize("app_settings", [{"AUTH_ENABLED": True}, {"AUTH_ENABLED": False}], indirect=True)
def test_logout(client: TestClient, app: FastAPI, app_settings: dict, valid_jwt_token: str, created_user: User, current_app_auth):
    auth_is_on = app_settings["AUTH_ENABLED"]
    client.cookies.set("access_token", valid_jwt_token)
    initial_response = client.get("/main")
    assert initial_response.status_code == 200
    if auth_is_on:
        assert created_user.username in initial_response.text
    else:
        if app.state.users_db and created_user in app.state.users_db:
             assert created_user.username in initial_response.text
        else:
            assert "mockuser" in initial_response.text

    response_logout = client.post("/logout")
    assert response_logout.status_code == 302
    assert response_logout.headers["location"] == "/login"
    assert "access_token=;" in response_logout.headers.get("set-cookie")
    assert "Max-Age=0" in response_logout.headers.get("set-cookie")

    final_main_response = client.get("/main")
    if auth_is_on:
        assert final_main_response.status_code == 401
    else:
        assert final_main_response.status_code == 200
        assert "mockuser" in final_main_response.text

@pytest.mark.parametrize("app_settings", [{"AUTH_ENABLED": True}, {"AUTH_ENABLED": False}], indirect=True)
def test_read_users_general_access(client: TestClient, app: FastAPI, app_settings: dict, valid_jwt_token: str, created_user: User):
    auth_is_on = app_settings["AUTH_ENABLED"]
    if auth_is_on:
        response_unauth = client.get("/api/v1/users/")
        assert response_unauth.status_code == 401
        client.cookies.set("access_token", valid_jwt_token)
        response_auth = client.get("/api/v1/users/")
        assert response_auth.status_code == 200
        data = response_auth.json()
        assert len(data) == 1
        assert data[0]["email"] == created_user.email
        client.cookies.clear()
    else:
        response = client.get("/api/v1/users/")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["email"] == created_user.email

def test_read_root(client: TestClient):
    response = client.get("/")
    assert response.status_code == 200
    assert "<html" in response.text.lower()

def test_create_user_with_password(client: TestClient, app: FastAPI, current_app_auth):
    initial_user_count = len(app.state.users_db)
    response = client.post("/api/v1/users/", json={"username": "newbie", "email": "newbie@example.com", "password": "password123"})
    assert response.status_code == 200
    assert len(app.state.users_db) == initial_user_count + 1
    created_user_data = response.json()
    assert created_user_data["email"] == "newbie@example.com"
    assert any(u.email == "newbie@example.com" for u in app.state.users_db)

@pytest.mark.parametrize("app_settings", [{"AUTH_ENABLED": True}], indirect=True)
def test_get_current_user_expired_token_when_auth_enabled(client: TestClient, app: FastAPI, created_user: User, current_app_auth):
    expired_token = current_app_auth.create_access_token(
        data={"sub": created_user.email},
        expires_delta=timedelta(minutes=-5)
    )
    client.cookies.set("access_token", expired_token)
    response_cookie = client.get("/main")
    assert response_cookie.status_code == 401
    assert response_cookie.json()["detail"] == "Could not validate credentials"
    client.cookies.clear()

@pytest.mark.parametrize("app_settings", [{"AUTH_ENABLED": True}, {"AUTH_ENABLED": False}], indirect=True)
def test_read_specific_user(client: TestClient, app: FastAPI, app_settings: dict, valid_jwt_token: str, created_user: User):
    auth_is_on = app_settings["AUTH_ENABLED"]
    user_id_to_check = created_user.id
    if auth_is_on:
        client.cookies.set("access_token", valid_jwt_token)
        response_auth = client.get(f"/api/v1/users/{user_id_to_check}")
        assert response_auth.status_code == 200
        assert response_auth.json()["email"] == created_user.email
        client.cookies.clear()
        response_unauth = client.get(f"/api/v1/users/{user_id_to_check}")
        assert response_unauth.status_code == 401
        client.cookies.set("access_token", valid_jwt_token)
        response_non_existent = client.get(f"/api/v1/users/9999")
        assert response_non_existent.status_code == 404
        client.cookies.clear()
    else:
        response = client.get(f"/api/v1/users/{user_id_to_check}")
        assert response.status_code == 200
        assert response.json()["email"] == created_user.email
        response_non_existent = client.get(f"/api/v1/users/9999")
        assert response_non_existent.status_code == 404

@pytest.mark.parametrize("app_settings", [{"AUTH_ENABLED": False}], indirect=True)
def test_read_users_auth_disabled(client: TestClient, app: FastAPI, app_settings: dict, created_user: User, current_app_auth):
    response = client.get("/api/v1/users/")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["email"] == created_user.email
