import asyncio
import os # Add os import
from typing import List, Union

from fastapi import Depends, FastAPI, HTTPException, status
from pydantic import BaseModel, EmailStr, field_validator
from fastapi.responses import RedirectResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from datetime import datetime, timedelta
import httpx # Add this import for making HTTP requests
from passlib.context import CryptContext

# OAuth2 Configuration
# These can be overridden by environment variables:
# GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "YOUR_GOOGLE_CLIENT_ID_DEFAULT")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "YOUR_GOOGLE_CLIENT_SECRET_DEFAULT")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:8000/callback")
GOOGLE_AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/auth" # Typically fixed
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token" # Typically fixed
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v1/userinfo" # Typically fixed

# JWT Configuration
# SECRET_KEY can be overridden by environment variable "SECRET_KEY"
SECRET_KEY = os.getenv("SECRET_KEY", "YOUR_SECRET_KEY_DEFAULT")
ALGORITHM = "HS256" # Typically fixed
ACCESS_TOKEN_EXPIRE_MINUTES = 30 # Could be made env configurable if needed, but not requested

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

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token") # tokenUrl can be any placeholder here as we handle token generation separately

async def get_current_user(token: str = Depends(oauth2_scheme)):
    if not AUTH_ENABLED:
        # If auth is disabled, return a mock/first user.
        # This is a simplified approach. In a real app, you might want a more specific mock user
        # or disallow operations that strictly require a real authenticated user.
        if users_db:
            # Returning a copy to prevent accidental modification of the DB user outside of CRUD ops
            mock_user_data = users_db[0].model_dump()
            return User(**mock_user_data)
        else:
            # If no users exist, and auth is disabled, this endpoint probably shouldn't be called
            # or you need a more sophisticated mock user strategy.
            # For now, let's create a very basic mock user on the fly.
            # This part might need adjustment based on how services consuming this expect the user object.
            return User(id=0, username="mockuser", email="mock@example.com", hashed_password=None)

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
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
    for user_in_db in users_db: # Renamed user to user_in_db to avoid conflict
        if user_in_db.email == email:
            return user_in_db
    # Create new user if not found
    new_user = User(id=next_user_id, username=username, email=email, hashed_password=None) # Pass None for hashed_password
    users_db.append(new_user)
    next_user_id += 1
    return new_user

app = FastAPI()

# Mount static files directory
app.mount("/static", StaticFiles(directory="static"), name="static")

# In-memory list to store users
users_db: List["User"] = [] # Use forward reference for User
next_user_id = 1


class User(BaseModel):
    id: int
    username: str
    email: str
    hashed_password: str | None = None # Add this line


class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str | None = None # Add this line

    @field_validator("username")
    @classmethod
    def validate_username(cls, value):
        if not value.isalnum():
            raise ValueError("Username must be alphanumeric")
        if not (3 <= len(value) <= 50):
            raise ValueError("Username length must be between 3 and 50 characters")
        return value

    @field_validator("username", mode='before')
    @classmethod
    def username_to_lower(cls, value):
        return value.lower()


@app.get("/")
async def read_root():
    return FileResponse("static/index.html")


@app.post("/users/", response_model=User)
async def create_user(user: UserCreate): # No protection for now, direct creation
    await asyncio.sleep(0.001)
    global next_user_id

    hashed_password = None
    if user.password:
        hashed_password = get_password_hash(user.password)

    db_user = User(
        id=next_user_id,
        username=user.username,
        email=user.email,
        hashed_password=hashed_password  # Add this
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
async def update_user(user_id: int, user_update: UserCreate, current_user: User = Depends(get_current_user)):
    await asyncio.sleep(0.001)
    for db_user in users_db:
        if db_user.id == user_id:
            # Optionally, you might want to check if current_user.id == user_id or if current_user is an admin
            db_user.username = user_update.username
            db_user.email = user_update.email
            return db_user
    raise HTTPException(status_code=404, detail="User not found")


@app.delete("/users/{user_id}")
async def delete_user(user_id: int, current_user: User = Depends(get_current_user)):
    await asyncio.sleep(0.001)
    global users_db
    # Optionally, you might want to check if current_user.id == user_id or if current_user is an admin
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
async def callback(code: str = None): # Made code optional for the disabled case
    if not AUTH_ENABLED:
        raise HTTPException(status_code=404, detail="Authentication is disabled.")

    if code is None: # Should not happen if AUTH_ENABLED is true and Google redirects correctly
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
        raise HTTPException(status_code=400, detail="Could not fetch token from provider.")
    access_token = token_json.get("access_token")

    async with httpx.AsyncClient() as client:
        userinfo_response = await client.get(
            GOOGLE_USERINFO_URL,
            headers={"Authorization": f"Bearer {access_token}"},
        )
    userinfo_json = userinfo_response.json()

    email = userinfo_json.get("email")
    if not email: # Check if email was retrieved
        raise HTTPException(status_code=400, detail="Could not fetch user info from provider.")

    username = userinfo_json.get("name", email.split("@")[0])

    user = await get_or_create_user(email=email, username=username)

    jwt_token = create_access_token(
        data={"sub": user.email}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return RedirectResponse(
        url=f"/static/handle_auth.html#access_token={jwt_token}&token_type=bearer",
        status_code=status.HTTP_303_SEE_OTHER
    )
