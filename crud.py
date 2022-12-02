from sqlalchemy.orm import Session
from sqlalchemy import and_, or_
from hashlib import sha512, sha3_512

import models
import schemas

from utiils import get_all_user_groups, check_group_affiliation
from exceptions import CrudException
from fastapi.logger import logger

from common import access_levels
from re import escape

def get_all_users(db: Session):
    return db.query(models.User).all()


def get_share_users(db: Session, safe_id):
    already_shared = db.query(models.UserSafeAssociation)\
        .filter(models.UserSafeAssociation.safe_id == safe_id).all()
    already_shared_ids = [us.user_id for us in already_shared if us.access_level < access_levels['read_only']]
    users = db.query(models.User).filter(models.User.id.not_in(already_shared_ids)).all()
    ret = []
    for user in users:
        u = schemas.UserShare(id=user.id,
                              email=user.email,
                              public_key=user.key.public_key)
        ret.append(u)
    return ret


def get_user(db: Session, user_id: int):
    return db.query(models.User).filter(models.User.id == user_id).first()


def get_user_by_login(db: Session, login: str):
    return db.query(models.User).filter(models.User.email == login).first()


def get_group(db: Session, group_id: int):
    db_group = db.query(models.Group).filter(models.Group.id == group_id).first()
    return db_group


def create_safe(db: Session, user_id: int, safe: schemas.SafeCreate):
    db_user = get_user(db, user_id)

    if not db_user:
        raise CrudException(404, "User not found")

    root_group = create_group(db, title=f"Корень сейфа {safe.title}")
    db_safe = models.Safe(title=safe.title, description=safe.description, root_group_id=root_group.id)
    db.add(db_safe)
    db.commit()

    db.refresh(db_safe)

    # db_sym_key = models.SymmetricKey(safe_id=db_safe.id, key_id=db_user.key.id, ciphered_key=safe.ciphered_key)
    # db.add(db_sym_key)
    # db.commit()

    db_assoc = models.UserSafeAssociation(access_level=10, ciphered_key=safe.ciphered_key)
    db_assoc.user_id = db_user.id
    db_assoc.safe_id = db_safe.id
    db.add(db_assoc)
    db.commit()

    db.refresh(db_assoc)

    s = schemas.Safe(id=db_safe.id,
                     title=db_safe.title,
                     root_group_id=db_safe.root_group_id,
                     ciphered_key=db_assoc.ciphered_key,
                     description=db_safe.description,
                     access_level=db_assoc.access_level)
    return s


def get_user_safes(db: Session, user_id: int):
    safe_users = db.query(models.UserSafeAssociation).filter(models.UserSafeAssociation.user_id == user_id).all()
    ret = []
    for safe_user in safe_users:
        s = schemas.SafeMinimal(id=safe_user.safe.id,
                                title=safe_user.safe.title,
                                description=safe_user.safe.description,
                                access_level=safe_user.access_level)
        ret.append(s)

    return ret


def check_safe(db: Session, safe_id, user_id: int):
    db_usa = get_user_safe_association(db, safe_id, user_id)
    return db_usa.access_level if db_usa else 0


def get_safe(db: Session, safe_id: int):
    return db.query(models.Safe).filter(models.Safe.id == safe_id).first()


def get_user_safe_association(db: Session, safe_id: int, user_id: int):
    return db.query(models.UserSafeAssociation)\
        .filter(models.UserSafeAssociation.safe_id == safe_id)\
        .filter(models.UserSafeAssociation.user_id == user_id).first()


def share_safe(db: Session, safe_id, safe: schemas.SafeShare):
    to_user_db = get_user(db, safe.to_user)
    db_assoc = db.query(models.UserSafeAssociation)\
        .filter(models.UserSafeAssociation.safe_id == safe_id)\
        .filter(models.UserSafeAssociation.user_id == safe.to_user).first()

    if not db_assoc:
        # db_sym_key = models.SymmetricKey(safe_id=safe_id, key_id=to_user_db.key.id, ciphered_key=safe.ciphered_key)
        # db.add(db_sym_key)
        # db.commit()
        db_assoc = models.UserSafeAssociation(access_level=safe.access_level, ciphered_key=safe.ciphered_key)
        db_assoc.user_id = to_user_db.id
        db_assoc.safe_id = safe_id
        db.add(db_assoc)
    else:
        db_assoc.access_level = safe.access_level
    db.commit()

    return True


def delete_safe(db: Session, safe_id: int):
    db_associations = db.query(models.UserSafeAssociation).filter(models.UserSafeAssociation.safe_id == safe_id).all()
    for assoc in db_associations:
        db.delete(assoc)
    db.commit()
    db_safe = db.query(models.Safe).filter(models.Safe.id == safe_id).first()
    db_group = db.query(models.Group).filter(models.Group.id == db_safe.root_group_id).first()
    db.delete(db_group)
    db.delete(db_safe)
    db.commit()
    return 'ОК'


def delete_user_safe_association(db: Session, safe_id: int, user_id: int):
    db_user_safe_assoc = db.query(models.UserSafeAssociation)\
        .filter(models.UserSafeAssociation.user_id == user_id)\
        .filter(models.UserSafeAssociation.safe_id == safe_id).first()

    db.delete(db_user_safe_assoc)
    db.commit()
    return 'ОК'


def create_group(db: Session, parent_id: int = None, title: str = 'Корень'):
    db_group = models.Group(title=title, parent_id=parent_id)
    db.add(db_group)
    db.commit()
    db.refresh(db_group)
    return db_group


def delete_group(db: Session, group_id: int):
    db_group = get_group(db, group_id)
    if not db_group:
        raise CrudException(404, "Group not found")
    db.delete(db_group)
    db.commit()


def update_group_by_id(db: Session, group_id: int, group: schemas.GroupUpdate, root_group_id: int):
    root_group = get_group(db, root_group_id)
    if group.parent_id:
        if not check_group_affiliation(root_group, group.parent_id):
            raise CrudException(400, "Wrong parent group")

    db_group = get_group(db, group_id)
    if not db_group:
        raise CrudException(404, "Group not found")

    db_group.title = group.title
    if group.parent_id:
        if db_group.parent_id:
            db_group.parent_id = group.parent_id

    db.commit()

    return db_group


def create_user(db: Session, user: schemas.UserCreate):
    hashed_password = sha512(user.password.encode('UTF-8')).hexdigest()
    db_user = models.User(email=user.email,
                          hashed_password=hashed_password,
                          hashed_master_password=user.hashed_master_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    db_key = models.AsymmetricKey(public_key=user.public_key,
                                  private_key=user.private_key_enc,
                                  owner_id=db_user.id)
    db.add(db_key)
    db.commit()
    db.refresh(db_user)

    return db_user


def create_password(db: Session, pwd: schemas.PasswordEntryCreate, safe_id: int):
    db_safe = get_safe(db, safe_id)
    root_group = get_group(db, db_safe.root_group_id)
    if not check_group_affiliation(root_group, pwd.group_id):
        return None

    # db_sym_key = db.query(models.SymmetricKey)\
    #     .filter(models.SymmetricKey.safe_id == safe_id)\
    #     .filter(models.SymmetricKey.safe_id == key_id).first()
    # if not db_sym_key:
    #     db_sym_key = models.SymmetricKey(safe_id=safe_id,
    #                                      key_id=key_id)
    #
    #     db.add(db_sym_key)
    #     db.commit()

    db_pwd_entry = models.PasswordEntry(group_id=pwd.group_id,
                                        title=pwd.title,
                                        login=pwd.login,
                                        notes=pwd.notes,
                                        url=pwd.url,
                                        password=pwd.password)
    db.add(db_pwd_entry)
    db.commit()
    db.refresh(db_pwd_entry)
    return db_pwd_entry


def delete_password(db: Session, pwd_id: int):
    db_pwd_entry = get_password_by_id(db, pwd_id)
    if not db_pwd_entry:
        raise CrudException(404, "Password not found")
    db.delete(db_pwd_entry)
    db.commit()


def get_password_by_id(db: Session, pwd_id: int):
    db_pwd_entry = db.query(models.PasswordEntry).filter(models.PasswordEntry.id == pwd_id).first()
    return db_pwd_entry


def update_password_by_id(db: Session, pwd: schemas.PasswordEntryUpdate, pwd_id: int, safe_id):
    db_safe = get_safe(db, safe_id)
    root_group = get_group(db, db_safe.root_group_id)
    if not check_group_affiliation(root_group, pwd.group_id):
        raise CrudException(400, "Wrong group")

    db_pwd = get_password_by_id(db, pwd_id)
    if not db_pwd:
        raise CrudException(404, "Password not found")

    db_pwd.title = pwd.title
    db_pwd.login = pwd.login
    db_pwd.url = pwd.url
    db_pwd.notes = pwd.notes
    db_pwd.password = pwd.password
    db_pwd.group_id = pwd.group_id
    db.commit()
    return db_pwd


def get_user_key(db: Session, user_id: int):
    db_user = db.query(models.User).filter(models.User.id == user_id).first()
    if db_user:
        return db_user.key
    else:
        return None


def get_user_passwords(db: Session, group: schemas.Group):
    user_groups = get_all_user_groups(group)
    passwords = db.query(models.PasswordEntry).filter(models.PasswordEntry.group_id.in_(user_groups)).all()
    return passwords


def get_symmetric_key(db: Session, key_id: int, safe_id: int):
    return db.query(models.SymmetricKey)\
        .filter(models.SymmetricKey.key_id == key_id)\
        .filter(models.SymmetricKey.safe_id == safe_id).first()


def search_password_entry(db: Session, keyword_raw: str, user_id: int):
    keyword = '%' + escape(keyword_raw) + '%'
    user_safes = db.query(models.UserSafeAssociation).filter(models.UserSafeAssociation.user_id == user_id).all()
    groups = set()
    for usa in user_safes:
        safe = db.query(models.Safe).filter(models.Safe.id == usa.safe_id).first()
        for gr_id in get_all_user_groups(get_group(db, safe.root_group_id)):
            groups.add(gr_id)

    return db.query(models.PasswordEntry).filter(
        and_(
            or_(
                models.PasswordEntry.title.ilike(keyword),
                models.PasswordEntry.notes.ilike(keyword)
            ),
            models.PasswordEntry.group_id.in_(groups)
        )
    ).all()
