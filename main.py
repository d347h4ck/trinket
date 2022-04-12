from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware

from sqlalchemy.orm import Session
import models
import schemas
import crud
from database import SessionLocal, engine, get_db
from auth import authenticate_user, create_access_token, ACCESS_TOKEN_EXPIRE_MINUTES
from auth import get_current_active_user, get_current_active_user_dict
from datetime import timedelta
from typing import List

from utiils import check_group_affiliation, get_safe_from_user
from exceptions import CrudException

models.Base.metadata.create_all(bind=engine)

password_manager = FastAPI()

origins = [
    "http://localhost:8080",
]

password_manager.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@password_manager.get("/")
async def root():
    return {"message": "Hello World"}


@password_manager.post("/api/users/", response_model=schemas.User)
async def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = crud.get_user_by_login(db, login=user.login)
    if db_user:
        raise HTTPException(status_code=400, detail="Login already registered")

    return crud.create_user(db=db, user=user)


@password_manager.get("/api/users/{user_id}", response_model=schemas.User)
async def get_user(user_id: int, db: Session = Depends(get_db)):
    db_user = crud.get_user(db, user_id)
    return db_user


@password_manager.post("/api/token/", response_model=schemas.Token)
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
        data={"sub": user.login}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@password_manager.post("/api/safes/", response_model=schemas.Safe)
async def create_safe(safe: schemas.SafeCreate, current_user: schemas.User = Depends(get_current_active_user),
                      db: Session = Depends(get_db)):
    return crud.create_safe(db, current_user.id, safe)


@password_manager.get("/api/users/", response_model=List[schemas.UserIdLogin])
async def get_all_users(db: Session = Depends(get_db)):
    return crud.get_all_users(db)


@password_manager.get("/api/users/me/key/", response_model=schemas.KeyReturn)
async def get_my_key(current_user: schemas.User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    return crud.get_user_key(db, current_user.id)


@password_manager.get("/api/users/{user_id}/key/", response_model=schemas.KeyReturn)
async def get_user_key(user_id: int, db: Session = Depends(get_db)):
    return crud.get_user_key(db, user_id)


@password_manager.get("/api/users/me/", response_model=schemas.User)
async def read_users_me(current_user: schemas.User = Depends(get_current_active_user)):
    # schema_user = schemas.User.from_orm(current_user)
    # print(schema_user.dict())
    return current_user


@password_manager.post("/api/safes/{safe_id}/groups/", response_model=schemas.Group)
async def create_group(group: schemas.GroupCreate,
                       safe_id: int,
                       db: Session = Depends(get_db),
                       current_user: dict = Depends(get_current_active_user_dict)):

    if safe_id not in [a['id'] for a in current_user['safes']]:
        raise HTTPException(status_code=403, detail="This safe not belong current user")

    db_safe = crud.get_safe(db, safe_id)

    if not db_safe:
        raise HTTPException(status_code=404, detail="The safe is not found!")

    safe_root_group = crud.get_group(db, db_safe.root_group_id)
    if check_group_affiliation(safe_root_group, group.parent_id):
        return crud.create_group(db, group.parent_id, group.title)

    raise HTTPException(status_code=400, detail="Wrong parent group id")


@password_manager.get("/api/safes/{safe_id}/groups/", response_model=schemas.Group)
async def read_groups_in_safe(safe_id: int,
                              db: Session = Depends(get_db),
                              current_user: dict = Depends(get_current_active_user_dict)):
    if safe_id not in [a['id'] for a in current_user['safes']]:
        raise HTTPException(status_code=403, detail="This safe not belong current user")

    db_safe = crud.get_safe(db, safe_id)
    safe_root_group = crud.get_group(db, db_safe.root_group_id)
    return safe_root_group


@password_manager.get("/api/safes/{safe_id}/", response_model=schemas.Safe)
async def read_safe(safe_id: int,
                    db: Session = Depends(get_db),
                    current_user: dict = Depends(get_current_active_user_dict)):
    if safe_id not in [a['id'] for a in current_user['safes']]:
        raise HTTPException(status_code=403, detail="This safe not belong current user")

    return crud.get_safe(db, safe_id)


@password_manager.get("/api/safes/{safe_id}/passwords/", response_model=List[schemas.PasswordEntry])
async def get_user_passwords(safe_id: int, current_user: dict = Depends(get_current_active_user_dict),
                             db: Session = Depends(get_db)):

    if safe_id not in [a['id'] for a in current_user['safes']]:
        raise HTTPException(status_code=403, detail="This safe not belong current user")

    db_safe = crud.get_safe(db, safe_id)
    root_safe_group = crud.get_group(db, db_safe.root_group_id)
    return crud.get_user_passwords(db, root_safe_group)


@password_manager.get("/api/safes/{safe_id}/symkey/", response_model=schemas.SymmetricKey)
async def get_safe_symkey(safe_id: int,
                          current_user: dict = Depends(get_current_active_user_dict),
                          db: Session = Depends(get_db)):
    if safe_id not in [a['id'] for a in current_user['safes']]:
        raise HTTPException(status_code=403, detail="This safe not belong current user")

    return crud.get_symmetric_key(db, current_user['key']['id'], safe_id)


@password_manager.post("/api/safes/{safe_id}/passwords/", response_model=schemas.PasswordEntry)
async def create_password(pwd: schemas.PasswordEntryCreate,
                          safe_id: int,
                          current_user: dict = Depends(get_current_active_user_dict),
                          db: Session = Depends(get_db)):

    safe = get_safe_from_user(current_user, safe_id)
    if not safe:
        raise HTTPException(status_code=403, detail="This safe not belong current user")
    if safe['access_level'] != 10:
        raise HTTPException(status_code=401, detail="You can not write to this safe")

    pw_entry = crud.create_password(db, pwd, safe_id)
    if not pw_entry:
        raise HTTPException(status_code=400, detail="Wrong group id")

    return pw_entry


@password_manager.put("/api/safes/{safe_id}/passwords/{pwd_id}", response_model=schemas.PasswordEntry)
async def update_password(pwd_id: int,
                          pwd: schemas.PasswordEntryUpdate,
                          safe_id: int,
                          current_user: dict = Depends(get_current_active_user_dict),
                          db: Session = Depends(get_db)
                          ):
    safe = get_safe_from_user(current_user, safe_id)
    if not safe:
        raise HTTPException(status_code=403, detail="This safe not belong current user")
    if safe['access_level'] != 10:
        raise HTTPException(status_code=401, detail="You can not write to this safe")

    try:
        return crud.update_password_by_id(db, pwd, pwd_id, safe_id)
    except CrudException as e:
        raise HTTPException(e.code, e.reason)


@password_manager.put("/api/safes/{safe_id}/groups/{group_id}", response_model=schemas.Group)
async def update_group(group_id: int,
                       safe_id: int,
                       group: schemas.GroupUpdate,
                       current_user: dict = Depends(get_current_active_user_dict),
                       db: Session = Depends(get_db)):
    safe = get_safe_from_user(current_user, safe_id)
    if not safe:
        raise HTTPException(status_code=403, detail="This safe not belong current user")
    if safe['access_level'] != 10:
        raise HTTPException(status_code=401, detail="You can not write to this safe")

    try:
        return crud.update_group_by_id(db, group_id, group, safe['root_group_id'])
    except CrudException as e:
        raise HTTPException(e.code, e.reason)


@password_manager.delete("/api/safes/{safe_id}/groups/{group_id}")
async def delete_group(group_id: int,
                       safe_id: int,
                       current_user: dict = Depends(get_current_active_user_dict),
                       db: Session = Depends(get_db)):
    safe = get_safe_from_user(current_user, safe_id)
    if not safe:
        raise HTTPException(status_code=403, detail="This safe not belong current user")
    if safe['access_level'] != 10:
        raise HTTPException(status_code=401, detail="You can not write to this safe")
    try:
        crud.delete_group(db, group_id)
        return "OK"
    except CrudException as e:
        raise HTTPException(e.code, e.reason)


@password_manager.delete("/api/safes/{safe_id}/passwords/{pwd_id}")
async def delete_password(pwd_id: int,
                          safe_id: int,
                          current_user: dict = Depends(get_current_active_user_dict),
                          db: Session = Depends(get_db)):
    safe = get_safe_from_user(current_user, safe_id)
    if not safe:
        raise HTTPException(status_code=403, detail="This safe not belong current user")
    if safe['access_level'] != 10:
        raise HTTPException(status_code=401, detail="You can not write to this safe")
    try:
        crud.delete_password(db, pwd_id)
        return "OK"
    except CrudException as e:
        raise HTTPException(e.code, e.reason)
