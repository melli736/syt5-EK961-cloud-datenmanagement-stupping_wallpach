from typing import Any, Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

import jwt
from jwt.exceptions import InvalidTokenError
import logging

from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app import schemas, crud, models
from .jwt_helper import verify_password, SECRET_KEY, ALGORITHM


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


class Token(BaseModel):
    access_token: str
    token_type: str


async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    db: Session = Depends(get_db)
) -> schemas.User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: Any = payload.get("sub")
        if user_id == None:
            raise credentials_exception
        user = crud.get_user(db, user_id=int(user_id))
        if user is None:
            raise credentials_exception
        return user
    except jwt.ExpiredSignatureError:
        raise credentials_exception
    except InvalidTokenError:
        raise credentials_exception


async def get_current_active_user(
    current_user: Annotated[models.User, Depends(get_current_user)],
) -> schemas.User:
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


def authenticate_user(
    email: str,
    password: str,
    db: Session
):
    user = crud.get_user_by_email(db, email=email)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user
