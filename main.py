import asyncio
import os
from datetime import timedelta

import httpx
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.auth import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    AUTH_ENABLED,
    create_access_token,
    get_current_user,
    get_or_create_user,
    users_db,
)
from app.models import User
from app.routers import users

# Load environment variables from .env file
load_dotenv()

# OAuth2 Configuration
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "YOUR_GOOGLE_CLIENT_ID_DEFAULT")
GOOGLE_CLIENT_SECRET = os.getenv(
    "GOOGLE_CLIENT_SECRET", "YOUR_GOOGLE_CLIENT_SECRET_DEFAULT"
)
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:8000/callback")
GOOGLE_AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v1/userinfo"

app = FastAPI(
    title="FastAPI Example",
    description="A FastAPI application with user management and OAuth2 authentication",
    version="1.0.0",
)

templates = Jinja2Templates(directory="templates")

# Include API routers
app.include_router(users.router)


@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    await asyncio.sleep(0.001)

    current_user = None
    if AUTH_ENABLED:
        try:
            current_user = await get_current_user(request, None)
        except HTTPException:
            current_user = None

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "users": users_db,
            "auth_enabled": AUTH_ENABLED,
            "user": current_user,
        },
    )


@app.get("/login")
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


@app.get("/callback")
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


@app.get("/main", response_class=HTMLResponse)
async def main_page(request: Request, current_user: User = Depends(get_current_user)):
    if not AUTH_ENABLED and current_user.username == "mockuser":
        pass

    return templates.TemplateResponse(
        "index.html", {"request": request, "user": current_user}
    )


@app.post("/logout")
async def logout_user():
    response = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    response.delete_cookie(
        key="access_token",
        httponly=True,
        samesite="Lax",
        secure=False,
    )
    return response


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
