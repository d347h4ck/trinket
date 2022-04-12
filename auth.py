from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from typing import Optional
from datetime import datetime, timedelta
from hashlib import sha512
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from database import get_db
from schemas import TokenData, User
import crud


SECRET_KEY = "b389de32b42d9cbe6a328bac5a9f18027852bb7a77fda1421da7825a9cbe2be6"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/token")


def authenticate_user(username: str, password: str, db: Session):
    user = crud.get_user_by_login(db, username)
    # print(password, sha512(password.encode('UTF-8')).hexdigest())
    if not user:
        return False
    if not sha512(password.encode('UTF-8')).hexdigest() == user.hashed_password:
        return False
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = crud.get_user_by_login(db, login=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(current_user: User = Depends(get_current_user)):
    return current_user


async def get_current_active_user_dict(current_user: User = Depends(get_current_user)):
    return User.from_orm(current_user).dict()
