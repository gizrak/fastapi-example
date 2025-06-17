import os
from datetime import datetime, timedelta
from typing import List

from fastapi import Depends, HTTPException, Request, status # Request is needed for app.state
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext

from .models import User # Assuming User model is defined here or imported

# Configuration Getters
def get_secret_key():
    return os.getenv("SECRET_KEY", "YOUR_SECRET_KEY_DEFAULT_FOR_APP_AUTH")

def get_algorithm():
    return "HS256"

def get_access_token_expire_minutes():
    return int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

# Authentication Enabled Flag
def is_auth_enabled():
    auth_enabled_env = os.getenv("AUTH_ENABLED", "True")
    return False if auth_enabled_env.lower() == "false" else True

# Password Hashing Setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)

# users_db and next_user_id are no longer global here.
# They will be initialized in main.create_app and stored on app.state.

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=get_access_token_expire_minutes())
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, get_secret_key(), algorithm=get_algorithm())
    return encoded_jwt

async def get_current_user(
    request: Request, # Now used for request.app.state
    token_from_header: str = Depends(oauth2_scheme),
    direct_token: str = None
):
    users_db_instance = request.app.state.users_db # Get users_db from app.state

    if not is_auth_enabled():
        if users_db_instance: # Check the instance from app.state
            mock_user_data = users_db_instance[0].model_dump()
            return User(**mock_user_data)
        else:
            return User(id=0, username="mockuser", email="mock@example.com", hashed_password=None)

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    final_token = token_from_cookie = request.cookies.get("access_token") or token_from_header
    if direct_token: # WebSocket might pass token directly
        final_token = direct_token

    if final_token is None:
        raise credentials_exception

    try:
        payload = jwt.decode(final_token, get_secret_key(), algorithms=[get_algorithm()])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = None
    for u in users_db_instance: # Iterate over instance from app.state
        if u.email == email:
            user = u
            break
    if user is None:
        raise credentials_exception
    return user

async def get_or_create_user(request: Request, email: str, username: str) -> User:
    users_db_instance = request.app.state.users_db
    next_user_id_val = request.app.state.next_user_id

    for user_in_db in users_db_instance:
        if user_in_db.email == email:
            return user_in_db

    new_user = User(
        id=next_user_id_val, username=username, email=email, hashed_password=None
    )
    users_db_instance.append(new_user)
    request.app.state.next_user_id += 1 # Modify app.state's counter
    return new_user
