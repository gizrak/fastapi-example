import asyncio
import os
from datetime import datetime, timedelta
from typing import List

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import OAuth2PasswordBearer
from fastapi.templating import Jinja2Templates
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, field_validator

# OAuth2 Configuration
# These can be overridden by environment variables:
# GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "YOUR_GOOGLE_CLIENT_ID_DEFAULT")
GOOGLE_CLIENT_SECRET = os.getenv(
    "GOOGLE_CLIENT_SECRET", "YOUR_GOOGLE_CLIENT_SECRET_DEFAULT"
)
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:8000/callback")
GOOGLE_AUTHORIZATION_URL = (
    "https://accounts.google.com/o/oauth2/auth"  # Typically fixed
)
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"  # Typically fixed
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v1/userinfo"  # Typically fixed

# JWT Configuration
# SECRET_KEY can be overridden by environment variable "SECRET_KEY"
SECRET_KEY = os.getenv("SECRET_KEY", "YOUR_SECRET_KEY_DEFAULT")
ALGORITHM = "HS256"  # Typically fixed
ACCESS_TOKEN_EXPIRE_MINUTES = (
    30  # Could be made env configurable if needed, but not requested
)

# Authentication Enabled Flag
# Can be overridden by environment variable "AUTH_ENABLED".
# Set AUTH_ENABLED="False" (case-insensitive) in env to disable authentication. Defaults to True.
AUTH_ENABLED_ENV = os.getenv("AUTH_ENABLED", "True")
AUTH_ENABLED = False if AUTH_ENABLED_ENV.lower() == "false" else True

# Password Hashing Setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)


async def get_current_user(
    request: Request, token_from_header: str = Depends(oauth2_scheme)
):
    if not AUTH_ENABLED:
        if users_db:
            mock_user_data = users_db[0].model_dump()
            return User(**mock_user_data)
        else:
            return User(
                id=0,
                username="mockuser",
                email="mock@example.com",
                hashed_password=None,
            )

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    token_from_cookie = request.cookies.get("access_token")
    final_token = token_from_cookie or token_from_header

    if final_token is None:
        # This will now correctly trigger if neither cookie nor header token is present
        # when auto_error=False for oauth2_scheme.
        raise credentials_exception

    try:
        payload = jwt.decode(final_token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = None
    for u in users_db:
        if u.email == email:
            user = u
            break
    if user is None:
        # This case might happen if a valid token's user was deleted from db
        raise credentials_exception
    return user


def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_or_create_user(email: str, username: str):
    global next_user_id
    for user_in_db in users_db:  # Renamed user to user_in_db to avoid conflict
        if user_in_db.email == email:
            return user_in_db
    # Create new user if not found
    new_user = User(
        id=next_user_id, username=username, email=email, hashed_password=None
    )  # Pass None for hashed_password
    users_db.append(new_user)
    next_user_id += 1
    return new_user


app = FastAPI()
templates = Jinja2Templates(directory="templates")

# In-memory list to store users
users_db: List["User"] = []  # Use forward reference for User
next_user_id = 1


class User(BaseModel):
    id: int
    username: str
    email: str
    hashed_password: str | None = None  # Add this line


class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str | None = None  # Add this line

    @field_validator("username")
    @classmethod
    def validate_username(cls, value):
        if not value.isalnum():
            raise ValueError("Username must be alphanumeric")
        if not (3 <= len(value) <= 50):
            raise ValueError("Username length must be between 3 and 50 characters")
        return value

    @field_validator("username", mode="before")
    @classmethod
    def username_to_lower(cls, value):
        return value.lower()


@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    await asyncio.sleep(0.001)
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "users": users_db, "auth_enabled": AUTH_ENABLED},
    )


@app.post("/users/", response_model=User)
async def create_user(user: UserCreate):  # No protection for now, direct creation
    await asyncio.sleep(0.001)
    global next_user_id

    hashed_password = None
    if user.password:
        hashed_password = get_password_hash(user.password)

    db_user = User(
        id=next_user_id,
        username=user.username,
        email=user.email,
        hashed_password=hashed_password,  # Add this
    )
    users_db.append(db_user)
    next_user_id += 1
    return db_user


@app.get("/users/", response_model=List[User])
async def read_users(current_user: User = Depends(get_current_user)):
    await asyncio.sleep(0.001)
    return users_db


@app.get("/users/{user_id}", response_model=User)
async def read_user(user_id: int, current_user: User = Depends(get_current_user)):
    await asyncio.sleep(0.001)
    for user in users_db:
        if user.id == user_id:
            return user
    raise HTTPException(status_code=404, detail="User not found")


@app.put("/users/{user_id}", response_model=User)
async def update_user(user_id: int, user_update: UserCreate):
    await asyncio.sleep(0.001)
    for db_user in users_db:
        if db_user.id == user_id:
            db_user.username = user_update.username
            db_user.email = user_update.email
            if user_update.password:
                db_user.hashed_password = get_password_hash(user_update.password)
            return db_user
    raise HTTPException(status_code=404, detail="User not found")


@app.delete("/users/{user_id}")
async def delete_user(user_id: int):
    await asyncio.sleep(0.001)
    global users_db
    user_to_delete = None
    for user in users_db:
        if user.id == user_id:
            user_to_delete = user
            break
    if user_to_delete:
        users_db.remove(user_to_delete)
        return {"message": "User deleted successfully"}
    raise HTTPException(status_code=404, detail="User not found")


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
async def callback(code: str = None):  # Made code optional for the disabled case
    if not AUTH_ENABLED:
        raise HTTPException(status_code=404, detail="Authentication is disabled.")

    if (
        code is None
    ):  # Should not happen if AUTH_ENABLED is true and Google redirects correctly
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
    # It's good practice to check if the request was successful
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
    if not email:  # Check if email was retrieved
        raise HTTPException(
            status_code=400, detail="Could not fetch user info from provider."
        )

    username = userinfo_json.get("name", email.split("@")[0])

    user = await get_or_create_user(email=email, username=username)

    jwt_token = create_access_token(
        data={"sub": user.email},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )

    # Set the JWT token in an HttpOnly cookie and redirect to /main
    redirect_response = RedirectResponse(url="/main", status_code=status.HTTP_302_FOUND)
    redirect_response.set_cookie(
        key="access_token",
        value=jwt_token,
        httponly=True,
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,  # max_age is in seconds
        expires=ACCESS_TOKEN_EXPIRE_MINUTES * 60,  # also in seconds from now
        samesite="Lax",  # Or "Strict"
        secure=False,  # Should be True in production (HTTPS)
    )
    return redirect_response


@app.get("/main", response_class=HTMLResponse)  # Specify HTMLResponse
async def main_page(request: Request, current_user: User = Depends(get_current_user)):
    if (
        not AUTH_ENABLED and current_user.username == "mockuser"
    ):  # If auth disabled and it's the generic mock user
        # Potentially provide some indication that this is a mock view
        # For now, just pass it through.
        pass

    return templates.TemplateResponse(
        "index.html", {"request": request, "user": current_user}
    )


@app.post("/logout")  # Changed to POST as it changes server state (session)
async def logout_user():
    # Create a redirect response to the login page
    response = RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    # Clear the access_token cookie by setting it with an expired time and no value
    response.delete_cookie(
        key="access_token",
        httponly=True,  # Match settings used when setting the cookie
        samesite="Lax",  # Match settings
        secure=False,  # Match settings (should be True in prod if original was True)
    )
    return response


@app.get("/api/users", response_model=List[User])
async def get_users_api():
    """API endpoint to get users without authentication for frontend use"""
    await asyncio.sleep(0.001)
    return users_db
