from pydantic import BaseModel, EmailStr, field_validator


class User(BaseModel):
    id: int
    username: str
    email: str
    hashed_password: str | None = None


class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str | None = None

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
