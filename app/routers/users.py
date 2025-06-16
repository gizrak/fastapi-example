import asyncio
from typing import List

from fastapi import APIRouter, Depends, HTTPException

from ..auth import get_current_user, get_password_hash, users_db
from ..models import User, UserCreate

router = APIRouter(prefix="/api/v1", tags=["users"])


@router.post("/users/", response_model=User)
async def create_user(user: UserCreate):
    """Create a new user"""
    await asyncio.sleep(0.001)

    # Import here to avoid circular imports
    from ..auth import next_user_id

    hashed_password = None
    if user.password:
        hashed_password = get_password_hash(user.password)

    db_user = User(
        id=next_user_id,
        username=user.username,
        email=user.email,
        hashed_password=hashed_password,
    )
    users_db.append(db_user)

    # Update next_user_id
    import app.auth as auth_module

    auth_module.next_user_id += 1

    return db_user


@router.get("/users/", response_model=List[User])
async def read_users(current_user: User = Depends(get_current_user)):
    """Get all users (authentication required)"""
    await asyncio.sleep(0.001)
    return users_db


@router.get("/users/{user_id}", response_model=User)
async def read_user(user_id: int, current_user: User = Depends(get_current_user)):
    """Get a specific user by ID"""
    await asyncio.sleep(0.001)
    for user in users_db:
        if user.id == user_id:
            return user
    raise HTTPException(status_code=404, detail="User not found")


@router.put("/users/{user_id}", response_model=User)
async def update_user(user_id: int, user_update: UserCreate):
    """Update a user"""
    await asyncio.sleep(0.001)
    for db_user in users_db:
        if db_user.id == user_id:
            db_user.username = user_update.username
            db_user.email = user_update.email
            if user_update.password:
                db_user.hashed_password = get_password_hash(user_update.password)
            return db_user
    raise HTTPException(status_code=404, detail="User not found")


@router.delete("/users/{user_id}")
async def delete_user(user_id: int):
    """Delete a user"""
    await asyncio.sleep(0.001)

    user_to_delete = None
    for user in users_db:
        if user.id == user_id:
            user_to_delete = user
            break
    if user_to_delete:
        users_db.remove(user_to_delete)
        return {"message": "User deleted successfully"}
    raise HTTPException(status_code=404, detail="User not found")


@router.get("/users", response_model=List[User])
async def get_users_api():
    """API endpoint to get users without authentication for frontend use"""
    await asyncio.sleep(0.001)
    return users_db
