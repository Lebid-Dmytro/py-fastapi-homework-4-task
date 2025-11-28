from datetime import date

from fastapi import UploadFile
from pydantic import BaseModel, field_validator

from validation import (
    validate_name,
    validate_image,
    validate_gender,
    validate_birth_date
)


class ProfileRequestSchema(BaseModel):
    first_name: str
    last_name: str
    gender: str
    date_of_birth: date
    info: str
    avatar: UploadFile

    model_config = {
        "from_attributes": True
    }

    @field_validator("first_name")
    @classmethod
    def validate_first_name(cls, v):
        validate_name(v)
        return v

    @field_validator("last_name")
    @classmethod
    def validate_last_name(cls, v):
        validate_name(v)
        return v

    @field_validator("gender")
    @classmethod
    def validate_gender(cls, v):
        validate_gender(v)
        return v

    @field_validator("date_of_birth")
    @classmethod
    def validate_date_of_birth(cls, v):
        validate_birth_date(v)
        return v

    @field_validator("avatar")
    @classmethod
    def validate_avatar(cls, v):
        validate_image(v)
        return v


class ProfileResponseSchema(BaseModel):
    id: int  # noqa: VNE003
    user_id: int
    first_name: str
    last_name: str
    gender: str
    date_of_birth: date
    info: str
    avatar: str

    model_config = {
        "from_attributes": True
    }
