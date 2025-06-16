import os
from datetime import datetime, timedelta
from typing import List

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext

from .models import User

# Load from environment variables
SECRET_KEY = os.getenv("SECRET_KEY", "YOUR_SECRET_KEY_DEFAULT")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Authentication Enabled Flag
AUTH_ENABLED_ENV = os.getenv("AUTH_ENABLED", "True")
AUTH_ENABLED = False if AUTH_ENABLED_ENV.lower() == "false" else True

# Password Hashing Setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)

# In-memory database
users_db: List[User] = []
next_user_id = 1


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


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
        raise credentials_exception
    return user


async def get_or_create_user(email: str, username: str):
    global next_user_id
    for user_in_db in users_db:
        if user_in_db.email == email:
            return user_in_db
    # Create new user if not found
    new_user = User(
        id=next_user_id, username=username, email=email, hashed_password=None
    )
    users_db.append(new_user)
    next_user_id += 1
    return new_user
