# schemas.py
from pydantic import BaseModel, EmailStr

class UserRequest(BaseModel):
    username: str
    email: EmailStr

class UserResponse(BaseModel):
    username: str
    email: EmailStr
    token: str
