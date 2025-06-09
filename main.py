from typing import List, Union

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI()

# In-memory list to store users
users_db: List["User"] = [] # Use forward reference for User
next_user_id = 1


class User(BaseModel):
    id: int
    username: str
    email: str


class UserCreate(BaseModel):
    username: str
    email: str


@app.get("/")
def read_root():
    return {"Hello": "World"}


@app.post("/users/", response_model=User)
def create_user(user: UserCreate):
    global next_user_id
    db_user = User(id=next_user_id, username=user.username, email=user.email)
    users_db.append(db_user)
    next_user_id += 1
    return db_user


@app.get("/users/", response_model=List[User])
def read_users():
    return users_db


@app.get("/users/{user_id}", response_model=User)
def read_user(user_id: int):
    for user in users_db:
        if user.id == user_id:
            return user
    raise HTTPException(status_code=404, detail="User not found")


@app.put("/users/{user_id}", response_model=User)
def update_user(user_id: int, user_update: UserCreate):
    for db_user in users_db:
        if db_user.id == user_id:
            db_user.username = user_update.username
            db_user.email = user_update.email
            return db_user
    raise HTTPException(status_code=404, detail="User not found")


@app.delete("/users/{user_id}")
def delete_user(user_id: int):
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
