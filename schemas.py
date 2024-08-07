from datetime import datetime
from pydantic import BaseModel

class UserCreate(BaseModel):
    first_name: str= ...
    last_name: str
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class User(BaseModel):
    id: int
    first_name: str
    last_name: str
    email: str
    created_at: datetime

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    id: str | None = None