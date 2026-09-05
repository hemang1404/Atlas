import uuid
from datetime import datetime
from pydantic import BaseModel

class UserCreate(BaseModel):
    name: str
    username:str
    password:str
    age: int
    email: str

class UserResponse(BaseModel):
    user_id: uuid.UUID
    name: str
    username:str
    age: int
    email: str
    created_at: datetime