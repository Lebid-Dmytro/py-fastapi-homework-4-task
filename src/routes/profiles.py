from datetime import date
from typing import Optional
import os

from fastapi import APIRouter, Depends, status, HTTPException, Form, UploadFile, File, Header
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from config import get_jwt_auth_manager, get_s3_storage_client
from database import (
    get_db,
    UserModel,
    UserProfileModel,
    UserGroupEnum,
)
from database.models.accounts import GenderEnum
from security.interfaces import JWTAuthManagerInterface
from storages import S3StorageInterface
from schemas.profiles import ProfileResponseSchema, ProfileRequestSchema
from exceptions import TokenExpiredError

router = APIRouter()


async def get_current_user(
    authorization: Optional[str] = Header(None),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    db: AsyncSession = Depends(get_db)
):
    if authorization is None:
        raise HTTPException(status_code=401, detail="Authorization header is missing")
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid Authorization header format. Expected 'Bearer <token>'")
    token = authorization.split(" ")[1]
    try:
        payload = jwt_manager.decode_access_token(token)
    except TokenExpiredError:
        raise HTTPException(status_code=401, detail="Token has expired.")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token.")
    user_id = payload.get("user_id")
    result = await db.execute(
        select(UserModel).
        options(
            selectinload(UserModel.group),
            selectinload(UserModel.profile)
        )
        .where(UserModel.id == user_id)
    )
    user = result.scalars().first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or not active.")
    return user


async def get_user_by_id(user_id: int, db: AsyncSession):
    result = await db.execute(
        select(UserModel).
        options(
            selectinload(UserModel.profile)
        )
        .where(UserModel.id == user_id)
    )
    return result.scalars().first()


async def get_current_user_profile(
        first_name: str = Form(...),
        last_name: str = Form(...),
        gender: str = Form(...),
        date_of_birth: date = Form(...),
        info: str = Form(...),
        avatar: UploadFile = File(...),
):
    if not info.strip():
        raise HTTPException(status_code=422, detail="Info field cannot be empty or contain only spaces.")
    try:
        profile_data = ProfileRequestSchema(
            first_name=first_name,
            last_name=last_name,
            gender=gender,
            date_of_birth=date_of_birth,
            info=info,
            avatar=avatar,
        )
    except ValidationError as e:
        custom_errors = [
            {"field": ".".join(str(x) for x in err["loc"]), "message": err["msg"]}
            for err in e.errors()
        ]
        raise HTTPException(status_code=422, detail={"errors": custom_errors})
    return profile_data


@router.post("/users/{user_id}/profile/", response_model=ProfileResponseSchema, status_code=status.HTTP_201_CREATED)
async def create_profile(
        user_id: int,
        profile_data: ProfileRequestSchema = Depends(get_current_user_profile),
        current_user: UserModel = Depends(get_current_user),
        db: AsyncSession = Depends(get_db),
        s3_client: S3StorageInterface = Depends(get_s3_storage_client),
):
    if current_user.id != user_id and not current_user.has_group(UserGroupEnum.ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to edit this profile."
        )
    target_user = await get_user_by_id(user_id, db)
    if not target_user or not target_user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or not active.")
    if target_user.profile is not None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User already has a profile.")
    try:
        file_data = await profile_data.avatar.read()
        _, ext = os.path.splitext(profile_data.avatar.filename)
        ext = ext.lower()
        file_name = f"avatars/{user_id}_avatar{ext}"
        await s3_client.upload_file(file_name, file_data)
        avatar_url = await s3_client.get_file_url(file_name)
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to upload avatar. Please try again later.")
    new_profile = UserProfileModel(
        user_id=user_id,
        first_name=profile_data.first_name.lower(),
        last_name=profile_data.last_name.lower(),
        gender=GenderEnum(profile_data.gender),
        date_of_birth=profile_data.date_of_birth,
        info=profile_data.info.strip(),
        avatar=file_name
    )
    db.add(new_profile)
    await db.commit()
    await db.refresh(new_profile)
    return ProfileResponseSchema(
        id=new_profile.id,
        user_id=user_id,
        first_name=new_profile.first_name,
        last_name=new_profile.last_name,
        gender=new_profile.gender.value if new_profile.gender else None,
        date_of_birth=new_profile.date_of_birth,
        info=new_profile.info,
        avatar=avatar_url
    )
