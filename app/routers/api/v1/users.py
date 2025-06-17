import asyncio
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request # Added Request
from .... import auth as app_auth_module
from ....models import User, UserCreate

router = APIRouter(prefix="/api/v1", tags=["users"])


@router.post("/users/", response_model=User)
async def create_user(user: UserCreate, request: Request): # Added request
    """Create a new user"""
    await asyncio.sleep(0.001) # Simulating I/O

    users_db_instance = request.app.state.users_db
    next_user_id_val = request.app.state.next_user_id

    hashed_password = None
    if user.password:
        hashed_password = app_auth_module.get_password_hash(user.password)

    db_user = User(
        id=next_user_id_val,
        username=user.username,
        email=user.email,
        hashed_password=hashed_password,
    )
    users_db_instance.append(db_user)
    request.app.state.next_user_id += 1

    return db_user


@router.get("/users/", response_model=List[User])
async def read_users(request: Request, current_user: User = Depends(app_auth_module.get_current_user)): # Added request
    """Get all users (authentication required)"""
    await asyncio.sleep(0.001)
    return request.app.state.users_db


@router.get("/users/{user_id}", response_model=User)
async def read_user(user_id: int, request: Request, current_user: User = Depends(app_auth_module.get_current_user)): # Added request
    """Get a specific user by ID"""
    await asyncio.sleep(0.001)
    users_db_instance = request.app.state.users_db
    for user_in_db in users_db_instance:
        if user_in_db.id == user_id:
            return user_in_db
    raise HTTPException(status_code=404, detail="User not found")


@router.put("/users/{user_id}", response_model=User)
async def update_user(user_id: int, user_update: UserCreate, request: Request): # Added request
    """Update a user"""
    await asyncio.sleep(0.001)
    users_db_instance = request.app.state.users_db
    for db_user in users_db_instance:
        if db_user.id == user_id:
            db_user.username = user_update.username
            db_user.email = user_update.email
            if user_update.password:
                db_user.hashed_password = app_auth_module.get_password_hash(user_update.password)
            return db_user
    raise HTTPException(status_code=404, detail="User not found")


@router.delete("/users/{user_id}")
async def delete_user(user_id: int, request: Request): # Added request
    """Delete a user"""
    await asyncio.sleep(0.001)
    users_db_instance = request.app.state.users_db
    user_to_delete = None
    for user_in_db in users_db_instance:
        if user_in_db.id == user_id:
            user_to_delete = user_in_db
            break
    if user_to_delete:
        users_db_instance.remove(user_to_delete)
        return {"message": "User deleted successfully"}
    raise HTTPException(status_code=404, detail="User not found")


@router.get("/users", response_model=List[User])
async def get_users_api(request: Request): # Added request
    """API endpoint to get users without authentication for frontend use"""
    # This endpoint might be intended to be open, or use a different auth.
    # For now, it accesses users_db from app.state.
    # If it needs to be truly unauthenticated and not subject to is_auth_enabled() in get_current_user,
    # it should not have Depends(get_current_user). The current version does not.
    await asyncio.sleep(0.001)
    return request.app.state.users_db
