import asyncio
import os
from datetime import timedelta

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status # Ensure Request is imported
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

# Use getter functions from app.auth
from ..auth import (
    is_auth_enabled,
    get_access_token_expire_minutes,
    create_access_token,
    get_current_user,
    get_or_create_user,
    # users_db, # Removed: No longer importing global users_db
)
from ..models import User

# OAuth2 Configuration Getters
def get_google_client_id():
    return os.getenv("GOOGLE_CLIENT_ID", "YOUR_GOOGLE_CLIENT_ID_DEFAULT_WEB")

def get_google_client_secret():
    return os.getenv("GOOGLE_CLIENT_SECRET", "YOUR_GOOGLE_CLIENT_SECRET_DEFAULT_WEB")

def get_google_redirect_uri():
    return os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:8000/oauth/callback")

# Static Google URLs
GOOGLE_AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v1/userinfo"

router = APIRouter(include_in_schema=False)
templates = Jinja2Templates(directory="templates")

@router.get("/", response_class=HTMLResponse)
async def read_root(request: Request): # Has request
    await asyncio.sleep(0.001)
    current_user = None
    access_token_for_js = None

    if is_auth_enabled():
        try:
            current_user = await get_current_user(request, None)
            if current_user:
                access_token_for_js = request.cookies.get("access_token")
        except HTTPException:
            current_user = None
            access_token_for_js = None
    elif not is_auth_enabled():
        current_user = await get_current_user(request, None)
        if current_user:
            access_token_expires = timedelta(minutes=get_access_token_expire_minutes())
            access_token_for_js = create_access_token(
                data={"sub": current_user.email}, expires_delta=access_token_expires
            )

    user_data = None
    if current_user:
        user_data = {"id": current_user.id, "username": current_user.username, "email": current_user.email}

    return templates.TemplateResponse(
        "index.html.j2",
        {
            "request": request,
            "users": request.app.state.users_db, # Use app.state
            "auth_enabled": is_auth_enabled(),
            "user": current_user,
            "user_data": user_data,
            "access_token_for_js": access_token_for_js,
        },
    )

@router.get("/login")
async def login(request: Request): # Added request for consistency, though not strictly needed here
    if not is_auth_enabled():
        raise HTTPException(status_code=404, detail="Authentication is disabled.")
    return RedirectResponse(
        f"{GOOGLE_AUTHORIZATION_URL}?"
        f"client_id={get_google_client_id()}&"
        f"redirect_uri={get_google_redirect_uri()}&"
        "response_type=code&"
        "scope=openid%20email%20profile"
    )

@router.get("/oauth/callback")
async def callback(request: Request, code: str = None): # Added request
    if not is_auth_enabled():
        raise HTTPException(status_code=404, detail="Authentication is disabled.")
    if code is None:
        raise HTTPException(status_code=400, detail="Authorization code not found.")

    async with httpx.AsyncClient() as client:
        token_response = await client.post(
            GOOGLE_TOKEN_URL,
            data={
                "code": code,
                "client_id": get_google_client_id(),
                "client_secret": get_google_client_secret(),
                "redirect_uri": get_google_redirect_uri(),
                "grant_type": "authorization_code",
            },
        )
    token_json = token_response.json()
    if "access_token" not in token_json:
        raise HTTPException(status_code=400, detail="Could not fetch token from provider.")

    access_token = token_json.get("access_token")
    async with httpx.AsyncClient() as client:
        userinfo_response = await client.get(
            GOOGLE_USERINFO_URL,
            headers={"Authorization": f"Bearer {access_token}"},
        )
    userinfo_json = userinfo_response.json()
    email = userinfo_json.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="Could not fetch user info from provider.")

    username = userinfo_json.get("name", email.split("@")[0])
    # Pass request to get_or_create_user
    user = await get_or_create_user(request, email=email, username=username)

    jwt_token = create_access_token(
        data={"sub": user.email},
        expires_delta=timedelta(minutes=get_access_token_expire_minutes()),
    )
    redirect_response = RedirectResponse(url="/main", status_code=status.HTTP_302_FOUND)
    redirect_response.set_cookie(
        key="access_token", value=jwt_token, httponly=True,
        max_age=get_access_token_expire_minutes() * 60,
        expires=get_access_token_expire_minutes() * 60,
        samesite="Lax", secure=False
    )
    return redirect_response

@router.get("/main", response_class=HTMLResponse)
async def main_page(request: Request, current_user: User = Depends(get_current_user)): # Has request
    access_token_for_js = None
    if current_user:
        access_token_for_js = request.cookies.get("access_token")
    return templates.TemplateResponse(
        "index.html.j2",
        {
            "request": request,
            "user": current_user,
            "users": request.app.state.users_db, # Use app.state
            "auth_enabled": is_auth_enabled(),
            "access_token_for_js": access_token_for_js,
        },
    )

@router.post("/logout")
async def logout_user(request: Request): # Added request for consistency, though not strictly needed
    response = RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    response.delete_cookie(key="access_token", httponly=True, samesite="Lax", secure=False)
    return response
