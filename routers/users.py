import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException

from schemas.user import UserCreate, UserResponse

router = APIRouter(prefix="/users", tags=["Users"])
users_db ={}

@router.post("/", status_code=201)
def create_user(user: UserCreate) -> UserResponse:
    user_id = uuid.uuid4()
    created_at = datetime.now(timezone.utc)
    new_user = user.model_dump()
    new_user['user_id'] = user_id
    new_user['created_at'] = created_at
    users_db[user_id] = new_user
    return UserResponse(
        user_id=user_id,
        name=user.name,
        username=user.username,
        age=user.age,
        email=user.email,
        created_at=created_at
    )

@router.get("/", response_model=list[UserResponse])
def get_users() -> list[UserResponse]:
    return list(users_db.values())

@router.get("/{user_id}", response_model=UserResponse)
def get_user(user_id: uuid.UUID) -> UserResponse:
    if user_id not in users_db:
        raise HTTPException(status_code=404, detail="User not found")
    return users_db[user_id]

@router.delete("/{user_id}", status_code=204)
def delete_user(user_id: uuid.UUID):
    if user_id not in users_db:
        raise HTTPException(status_code=404, detail="User not found")
    del users_db[user_id]
    return
