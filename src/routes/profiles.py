from datetime import date

from fastapi import APIRouter, Depends, status, HTTPException, Request, Form, File, UploadFile
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from config import get_jwt_auth_manager, get_s3_storage_client
from database import get_db, UserModel, UserProfileModel, UserGroupEnum
from database.models.accounts import GenderEnum
from exceptions import S3FileUploadError
from schemas import ProfileResponseSchema
from security.http import get_token
from security.interfaces import JWTAuthManagerInterface
from storages import S3StorageInterface
from validation import validate_name, validate_image, validate_gender, validate_birth_date

router = APIRouter()


def verify_token(request: Request = None) -> str:
    """Dependency to verify token before form validation."""
    return get_token(request)


@router.post(
    "/users/{user_id}/profile/",
    response_model=ProfileResponseSchema,
    summary="Create User Profile",
    description="Create a user profile with avatar upload.",
    status_code=status.HTTP_201_CREATED,
    responses={
        400: {
            "description": "Bad Request - User already has a profile.",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "User already has a profile."
                    }
                }
            },
        },
        401: {
            "description": (
                "Unauthorized - Missing token, invalid token format, "
                "expired token, or user not found/not active."
            ),
            "content": {
                "application/json": {
                    "examples": {
                        "missing_token": {
                            "summary": "Missing Token",
                            "value": {
                                "detail": "Authorization header is missing"
                            }
                        },
                        "invalid_format": {
                            "summary": "Invalid Format",
                            "value": {
                                "detail": "Invalid Authorization header format. Expected 'Bearer <token>'"
                            }
                        },
                        "expired": {
                            "summary": "Expired Token",
                            "value": {
                                "detail": "Token has expired."
                            }
                        },
                        "user_not_found": {
                            "summary": "User Not Found",
                            "value": {
                                "detail": "User not found or not active."
                            }
                        },
                    }
                }
            },
        },
        403: {
            "description": "Forbidden - User doesn't have permission to edit this profile.",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "You don't have permission to edit this profile."
                    }
                }
            },
        },
        500: {
            "description": "Internal Server Error - Failed to upload avatar.",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Failed to upload avatar. Please try again later."
                    }
                }
            },
        },
    },
)
async def create_user_profile(
        user_id: int,
        first_name: str = Form(...),
        last_name: str = Form(...),
        gender: str = Form(...),
        date_of_birth: date = Form(...),
        info: str = Form(...),
        avatar: UploadFile = File(...),
        token: str = Depends(verify_token),
        request: Request = None,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        s3_client: S3StorageInterface = Depends(get_s3_storage_client),
) -> ProfileResponseSchema:
    """
    Create a user profile.

    This endpoint allows authenticated users to create their own profile or allows admins
    to create profiles for other users. The profile includes personal information and
    an avatar image that is uploaded to S3 storage.

    Args:
        user_id: The ID of the user for whom the profile is being created.
        first_name: User's first name.
        last_name: User's last name.
        gender: User's gender.
        date_of_birth: User's date of birth.
        info: Additional information about the user.
        avatar: Avatar image file.
        request: FastAPI Request object for extracting the authorization token.
        db: The database session.
        jwt_manager: JWT authentication manager for token validation.
        s3_client: S3 storage client for avatar upload.

    Returns:
        ProfileResponseSchema: The created profile with avatar URL.

    Raises:
        HTTPException:
            - 401 Unauthorized if token is missing, invalid, expired, or user not found/not active.
            - 403 Forbidden if user doesn't have permission to create this profile.
            - 400 Bad Request if user already has a profile.
            - 500 Internal Server Error if avatar upload fails.
    """
    # Token is already validated via dependency (verify_token)
    # 1. Decode token to get user_id
    try:
        decoded_token = jwt_manager.decode_access_token(token)
        current_user_id = decoded_token.get("user_id")
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired."
        )

    # Validate input fields (after token validation for proper 422 responses)
    try:
        validate_name(first_name)
        validate_name(last_name)
        validate_gender(gender)
        validate_birth_date(date_of_birth)
        if not info or not info.strip():
            raise ValueError("Info field cannot be empty or contain only spaces.")
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )

    # Validate avatar (after token validation for proper 422 responses)
    await avatar.seek(0)
    try:
        validate_image(avatar)
    except ValueError as e:
        await avatar.seek(0)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    await avatar.seek(0)

    try:
        decoded_token = jwt_manager.decode_access_token(token)
        current_user_id = decoded_token.get("user_id")
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired."
        )

    # 2. Authorization rules
    stmt = select(UserModel).options(joinedload(UserModel.group)).where(UserModel.id == current_user_id)
    result = await db.execute(stmt)
    current_user = result.scalars().first()

    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or not active."
        )

    # Check if user can create profile for this user_id
    is_admin = current_user.has_group(UserGroupEnum.ADMIN)
    if current_user_id != user_id and not is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to edit this profile."
        )

    # 3. User existence and status
    stmt = select(UserModel).where(UserModel.id == user_id)
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or not active."
        )

    # 4. Check for existing profile
    stmt = select(UserProfileModel).where(UserProfileModel.user_id == user_id)
    result = await db.execute(stmt)
    existing_profile = result.scalars().first()

    if existing_profile:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User already has a profile."
        )

    # 5. Avatar upload to S3 storage
    avatar_file_name = f"avatars/{user_id}_avatar.jpg"
    try:
        avatar_content = await avatar.read()
        await s3_client.upload_file(avatar_file_name, avatar_content)
    except S3FileUploadError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to upload avatar. Please try again later."
        )

    # 6. Profile creation and storage
    new_profile = UserProfileModel(
        user_id=user_id,
        first_name=first_name.lower(),
        last_name=last_name.lower(),
        gender=GenderEnum(gender),
        date_of_birth=date_of_birth,
        info=info.strip(),
        avatar=avatar_file_name
    )
    db.add(new_profile)
    await db.commit()
    await db.refresh(new_profile)

    # Generate avatar URL
    avatar_url = await s3_client.get_file_url(avatar_file_name)

    # Return response with avatar URL
    # GenderEnum is a string enum, so .value returns the string value
    gender_value = new_profile.gender.value if new_profile.gender else None

    profile_response = ProfileResponseSchema(
        id=new_profile.id,
        user_id=new_profile.user_id,
        first_name=new_profile.first_name,
        last_name=new_profile.last_name,
        gender=gender_value,
        date_of_birth=new_profile.date_of_birth,
        info=new_profile.info,
        avatar=avatar_url
    )

    return profile_response
