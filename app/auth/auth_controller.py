from app.database import get_db
from app import schemas, crud
from .jwt_helper import get_password_hash, create_jwt_token
from .auth_helper import Token, authenticate_user

from typing import Annotated
from fastapi import Depends, HTTPException, APIRouter, status
from fastapi.security import OAuth2PasswordRequestForm

from sqlalchemy.orm import Session


router = APIRouter(tags=["authentication"])


@router.put("/register/", response_model=schemas.User)
async def register_new_user(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Session = Depends(get_db)
) -> schemas.User:
    db_user = crud.get_user_by_email(db, email=form_data.username)
    if db_user:
        raise HTTPException(status_code=400, detail="User already exists")
    # TODO: Check if form_data.username is a valid email address
    # TODO: Check if form_data.password is a valid password
    user: schemas.UserCreate = schemas.UserCreate(email=form_data.username, password=get_password_hash(form_data.password))
    return crud.create_user(db=db, user=user)


@router.post("/login", response_model=Token)
async def login_user(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Session = Depends(get_db)
) -> Token:
    user = authenticate_user(form_data.username, form_data.password, db=db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token: str = create_jwt_token(
        to_encode={"sub": str(user.id)}
    )
    return Token(access_token=access_token, token_type="bearer")
