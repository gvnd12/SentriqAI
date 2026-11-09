from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from sentriqai.core.database import get_db
from sentriqai.core.security import create_access_token, hash_password, verify_password
from sentriqai.models import User
from sentriqai.schemas.auth import (
    LoginRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,
)

auth_router = APIRouter()


@auth_router.post(
    "/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED
)
async def register(
    data: RegisterRequest,
    session: Annotated[AsyncSession, Depends(get_db)]
) -> User:
    email = str(data.email).lower()

    result = await session.execute(select(User).where(func.lower(User.email) == email))
    existing_user = result.scalar_one_or_none()

    if existing_user is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists",
        )

    user = User(
        email=email,
        full_name=data.full_name,
        password_hash=hash_password(data.password),
    )
    session.add(user)

    try:
        await session.commit()
        await session.refresh(user)
    except IntegrityError:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists",
        ) from None

    return user


@auth_router.post("/login", response_model=TokenResponse)
async def login(
    data: LoginRequest,
    session: Annotated[AsyncSession, Depends(get_db)]
) -> TokenResponse:
    email = str(data.email).lower()

    result = await session.execute(select(User).where(func.lower(User.email) == email))
    user = result.scalar_one_or_none()

    if user is None or not verify_password(data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="This account is inactive"
        )
    access_token = create_access_token(subject=str(user.id))
    return TokenResponse(access_token=access_token)
