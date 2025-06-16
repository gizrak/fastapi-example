import asyncio
import os
from datetime import timedelta

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from ..auth import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    AUTH_ENABLED,
    create_access_token,
    get_current_user,
    get_or_create_user,
    users_db,
)
from ..models import User

# OAuth2 Configuration
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "YOUR_GOOGLE_CLIENT_ID_DEFAULT")
GOOGLE_CLIENT_SECRET = os.getenv(
    "GOOGLE_CLIENT_SECRET", "YOUR_GOOGLE_CLIENT_SECRET_DEFAULT"
)
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:8000/callback")
GOOGLE_AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v1/userinfo"

# Create router with include_in_schema=False for all routes
router = APIRouter(include_in_schema=False)

templates = Jinja2Templates(directory="templates")


@router.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    await asyncio.sleep(0.001)

    current_user = None
    access_token_for_js = None
    if AUTH_ENABLED:
        try:
            # Passing request and None for token_from_header, so get_current_user will check cookies.
            current_user = await get_current_user(request, None)
            if current_user:
                access_token_for_js = request.cookies.get("access_token")
        except HTTPException:
            # This will catch errors from get_current_user if token is invalid/expired or user not found
            current_user = None
            access_token_for_js = None  # Ensure it's None if user auth fails
    # If AUTH_ENABLED is false, get_current_user returns a mock user or default.
    # In this case, there might not be a real "access_token" cookie unless previously set.
    # If current_user is None even with AUTH_ENABLED=false (e.g. no mock user setup), token remains None.
    elif not AUTH_ENABLED:  # When auth is disabled
        current_user = await get_current_user(request, None)  # Get mock user if any
        # Create a mock token for WebSocket connection when auth is disabled
        if current_user:
            access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
            access_token_for_js = create_access_token(
                data={"sub": current_user.email}, expires_delta=access_token_expires
            )

    # Convert user object to dict for JSON serialization in template
    user_data = None
    if current_user:
        user_data = {
            "id": current_user.id,
            "username": current_user.username,
            "email": current_user.email,
        }

    return templates.TemplateResponse(
        "index.html.j2",
        {
            "request": request,
            "users": users_db,
            "auth_enabled": AUTH_ENABLED,
            "user": current_user,
            "user_data": user_data,
            "access_token_for_js": access_token_for_js,
        },
    )


@router.get("/login")
async def login():
    if not AUTH_ENABLED:
        raise HTTPException(status_code=404, detail="Authentication is disabled.")
    return RedirectResponse(
        f"{GOOGLE_AUTHORIZATION_URL}?"
        f"client_id={GOOGLE_CLIENT_ID}&"
        f"redirect_uri={GOOGLE_REDIRECT_URI}&"
        "response_type=code&"
        "scope=openid%20email%20profile"
    )


@router.get("/oauth/callback")
async def callback(code: str = None):
    if not AUTH_ENABLED:
        raise HTTPException(status_code=404, detail="Authentication is disabled.")

    if code is None:
        raise HTTPException(status_code=400, detail="Authorization code not found.")

    async with httpx.AsyncClient() as client:
        token_response = await client.post(
            GOOGLE_TOKEN_URL,
            data={
                "code": code,
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "redirect_uri": GOOGLE_REDIRECT_URI,
                "grant_type": "authorization_code",
            },
        )
    token_json = token_response.json()

    if "access_token" not in token_json:
        raise HTTPException(
            status_code=400, detail="Could not fetch token from provider."
        )
    access_token = token_json.get("access_token")

    async with httpx.AsyncClient() as client:
        userinfo_response = await client.get(
            GOOGLE_USERINFO_URL,
            headers={"Authorization": f"Bearer {access_token}"},
        )
    userinfo_json = userinfo_response.json()

    email = userinfo_json.get("email")
    if not email:
        raise HTTPException(
            status_code=400, detail="Could not fetch user info from provider."
        )

    username = userinfo_json.get("name", email.split("@")[0])
    user = await get_or_create_user(email=email, username=username)

    jwt_token = create_access_token(
        data={"sub": user.email},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )

    redirect_response = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    redirect_response.set_cookie(
        key="access_token",
        value=jwt_token,
        httponly=True,
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        expires=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        samesite="Lax",
        secure=False,
    )
    return redirect_response


@router.get("/main", response_class=HTMLResponse)
async def main_page(request: Request, current_user: User = Depends(get_current_user)):
    # current_user is obtained via Depends(get_current_user).
    # If AUTH_ENABLED is true and authentication fails, HTTPException is raised by the dependency.
    # If AUTH_ENABLED is false, get_current_user provides a mock user.

    access_token_for_js = None
    if current_user:  # User is authenticated or it's a mock user
        # We attempt to get the cookie. It might be None if it's a mock user session without a real cookie.
        access_token_for_js = request.cookies.get("access_token")

    # For consistency with read_root, ensure index.html gets all expected context.
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "user": current_user,
            "users": users_db,  # Added for consistency
            "auth_enabled": AUTH_ENABLED,  # Added for consistency
            "access_token_for_js": access_token_for_js,
        },
    )


@router.post("/logout")
async def logout_user():
    response = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    response.delete_cookie(
        key="access_token",
        httponly=True,
        samesite="Lax",
        secure=False,
    )
    return response
