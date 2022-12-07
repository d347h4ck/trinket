from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware

from sqlalchemy.orm import Session
import models
import schemas
import crud
from database import engine, get_db
from auth import authenticate_user, create_access_token, ACCESS_TOKEN_EXPIRE_MINUTES
from auth import get_current_active_user
from datetime import timedelta
from typing import List

from utiils import check_group_affiliation
from exceptions import CrudException
from common import access_levels

models.Base.metadata.create_all(bind=engine)

password_manager = FastAPI()

origins = [
    "http://localhost:8080",
    "https://repono.tk"
]

password_manager.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@password_manager.post("/users/", response_model=schemas.User)
async def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = crud.get_user_by_login(db, login=user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Login already registered")

    return crud.create_user(db=db, user=user)


@password_manager.get("/users/{user_id}", response_model=schemas.User)
async def get_user(user_id: int, db: Session = Depends(get_db)):
    db_user = crud.get_user(db, user_id)
    return db_user


@password_manager.post("/token/", response_model=schemas.Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@password_manager.post("/safes/", response_model=schemas.Safe)
async def create_safe(safe: schemas.SafeCreate, current_user: schemas.User = Depends(get_current_active_user),
                      db: Session = Depends(get_db)):
    return crud.create_safe(db, current_user.id, safe)


@password_manager.delete("/safes/{safe_id}")
async def del_safe(safe_id: int,
                   db: Session = Depends(get_db),
                   current_user=Depends(get_current_active_user)):
    access_level = crud.check_safe(db, safe_id, current_user.id)
    if not access_level:
        raise HTTPException(status_code=403, detail="This safe not belong current user")

    if access_level > access_levels['own']:
        return crud.delete_user_safe_association(db, safe_id, current_user.id)
    else:
        return crud.delete_safe(db, safe_id)


@password_manager.get("/users/me/", response_model=schemas.User)
async def read_users_me(current_user: schemas.User = Depends(get_current_active_user)):
    return current_user


@password_manager.post("/safes/{safe_id}/groups/", response_model=schemas.Group)
async def create_group(group: schemas.GroupCreate,
                       safe_id: int,
                       db: Session = Depends(get_db),
                       current_user=Depends(get_current_active_user)):
    access_level = crud.check_safe(db, safe_id, current_user.id)
    if not access_level:
        raise HTTPException(status_code=403, detail="This safe not belong current user")

    if access_level > access_levels['read_write']:
        raise HTTPException(status_code=401, detail="You can not write to this safe")

    db_safe = crud.get_safe(db, safe_id)

    safe_root_group = crud.get_group(db, db_safe.root_group_id)
    if check_group_affiliation(safe_root_group, group.parent_id):
        return crud.create_group(db, group.parent_id, group.title)

    raise HTTPException(status_code=400, detail="Wrong parent group id")


@password_manager.get("/safes/{safe_id}/groups/", response_model=schemas.Group)
async def read_groups_in_safe(safe_id: int,
                              db: Session = Depends(get_db),
                              current_user=Depends(get_current_active_user)):
    access_level = crud.check_safe(db, safe_id, current_user.id)
    if not access_level:
        raise HTTPException(status_code=403, detail="This safe not belong current user")

    db_safe = crud.get_safe(db, safe_id)
    safe_root_group = crud.get_group(db, db_safe.root_group_id)
    return safe_root_group


@password_manager.get("/safes/{safe_id}/", response_model=schemas.Safe)
async def read_safe(safe_id: int,
                    db: Session = Depends(get_db),
                    current_user=Depends(get_current_active_user)):
    access_level = crud.check_safe(db, safe_id, current_user.id)
    if not access_level:
        raise HTTPException(status_code=403, detail="This safe not belong current user")

    # db_safe = crud.get_safe(db, safe_id)
    db_usa = crud.get_user_safe_association(db, safe_id, current_user.id)
    # sym_key = crud.get_symmetric_key(db, current_user.key.id, safe_id)
    s = schemas.Safe(id=db_usa.safe.id,
                     title=db_usa.safe.title,
                     description=db_usa.safe.description,
                     root_group_id=db_usa.safe.root_group_id,
                     access_level=db_usa.access_level,
                     ciphered_key=db_usa.ciphered_key)
    return s


@password_manager.get("/safes/", response_model=List[schemas.SafeMinimal])
async def read_user_safes(db: Session = Depends(get_db),
                          current_user=Depends(get_current_active_user)):
    return crud.get_user_safes(db, current_user.id)


@password_manager.get("/safes/{safe_id}/passwords/", response_model=List[schemas.PasswordEntry])
async def get_user_passwords(safe_id: int, current_user=Depends(get_current_active_user),
                             db: Session = Depends(get_db)):
    access_level = crud.check_safe(db, safe_id, current_user.id)
    if not access_level:
        raise HTTPException(status_code=403, detail="This safe not belong current user")

    db_safe = crud.get_safe(db, safe_id)
    root_safe_group = crud.get_group(db, db_safe.root_group_id)
    return crud.get_user_passwords(db, root_safe_group)


@password_manager.post("/safes/{safe_id}/passwords/", response_model=schemas.PasswordEntry)
async def create_password(pwd: schemas.PasswordEntryCreate,
                          safe_id: int,
                          current_user=Depends(get_current_active_user),
                          db: Session = Depends(get_db)):

    access_level = crud.check_safe(db, safe_id, current_user.id)
    if not access_level:
        raise HTTPException(status_code=403, detail="This safe not belong current user")

    if access_level > access_levels['read_write']:
        raise HTTPException(status_code=401, detail="You can not write to this safe")

    pw_entry = crud.create_password(db, pwd, safe_id)
    if not pw_entry:
        raise HTTPException(status_code=400, detail="Wrong group id")

    return pw_entry


@password_manager.put("/safes/{safe_id}/passwords/{pwd_id}", response_model=schemas.PasswordEntry)
async def update_password(pwd_id: int,
                          pwd: schemas.PasswordEntryUpdate,
                          safe_id: int,
                          current_user=Depends(get_current_active_user),
                          db: Session = Depends(get_db)
                          ):
    access_level = crud.check_safe(db, safe_id, current_user.id)
    if not access_level:
        raise HTTPException(status_code=403, detail="This safe not belong current user")

    if access_level > access_levels['read_write']:
        raise HTTPException(status_code=401, detail="You can not write to this safe")

    try:
        return crud.update_password_by_id(db, pwd, pwd_id, safe_id)
    except CrudException as e:
        raise HTTPException(e.code, e.reason)


@password_manager.put("/safes/{safe_id}/groups/{group_id}", response_model=schemas.Group)
async def update_group(group_id: int,
                       safe_id: int,
                       group: schemas.GroupUpdate,
                       current_user=Depends(get_current_active_user),
                       db: Session = Depends(get_db)):
    access_level = crud.check_safe(db, safe_id, current_user.id)
    if not access_level:
        raise HTTPException(status_code=403, detail="This safe not belong current user")

    if access_level > access_levels['read_write']:
        raise HTTPException(status_code=401, detail="You can not write to this safe")

    db_safe = crud.get_safe(db, safe_id)
    try:
        return crud.update_group_by_id(db, group_id, group, db_safe.root_group_id)
    except CrudException as e:
        raise HTTPException(e.code, e.reason)


@password_manager.delete("/safes/{safe_id}/groups/{group_id}")
async def delete_group(group_id: int,
                       safe_id: int,
                       current_user=Depends(get_current_active_user),
                       db: Session = Depends(get_db)):
    access_level = crud.check_safe(db, safe_id, current_user.id)
    if not access_level:
        raise HTTPException(status_code=403, detail="This safe not belong current user")

    if access_level > access_levels['read_write']:
        raise HTTPException(status_code=401, detail="You can not write to this safe")

    try:
        crud.delete_group(db, group_id)
        return "OK"
    except CrudException as e:
        raise HTTPException(e.code, e.reason)


@password_manager.delete("/safes/{safe_id}/passwords/{pwd_id}")
async def delete_password(pwd_id: int,
                          safe_id: int,
                          current_user=Depends(get_current_active_user),
                          db: Session = Depends(get_db)):
    access_level = crud.check_safe(db, safe_id, current_user.id)
    if not access_level:
        raise HTTPException(status_code=403, detail="This safe not belong current user")

    if access_level > access_levels['read_write']:
        raise HTTPException(status_code=401, detail="You can not write to this safe")

    try:
        crud.delete_password(db, pwd_id)
        return "OK"
    except CrudException as e:
        raise HTTPException(e.code, e.reason)


@password_manager.post("/safes/{safe_id}/share")
async def share_safe(safe: schemas.SafeShare,
                     safe_id: int,
                     current_user=Depends(get_current_active_user),
                     db: Session = Depends(get_db)):
    access_level = crud.check_safe(db, safe_id, current_user.id)
    if not access_level:
        raise HTTPException(status_code=403, detail="This safe not belong current user")

    if safe.access_level < access_level:
        raise HTTPException(status_code=401, detail="You can not share this safe with this rights")

    try:
        crud.share_safe(db, safe_id, safe)
        return "OK"
    except CrudException as e:
        raise HTTPException(e.code, e.reason)


@password_manager.get("/safes/{safe_id}/share", response_model=List[schemas.UserShare])
async def get_users_for_share(safe_id: int,
                              current_user=Depends(get_current_active_user),
                              db: Session = Depends(get_db)):

    access_level = crud.check_safe(db, safe_id, current_user.id)
    if not access_level:
        raise HTTPException(status_code=403, detail="This safe not belong current user")

    return crud.get_share_users(db, safe_id)


@password_manager.get("/passwords/search", response_model=List[schemas.PasswordEntry])
async def get_user_passwords(keyword_raw: str, current_user=Depends(get_current_active_user),
                             db: Session = Depends(get_db)):
    return crud.search_password_entry(db, keyword_raw, current_user.id)
