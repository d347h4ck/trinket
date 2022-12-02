from __future__ import annotations
from pydantic import BaseModel
from pydantic.utils import GetterDict
from typing import List, Optional, Any
from datetime import datetime


class KeyBase(BaseModel):
    public_key: str
    private_key: str

    class Config:
        orm_mode = True


class KeyCreate(KeyBase):
    pass


class Key(KeyBase):
    id: int
    owner_id: int


class KeyReturn(KeyBase):
    id: int


class SymKey(BaseModel):
    ciphered_key: str
    key_id: int

    class Config:
        orm_mode = True


class PasswordEntryBase(BaseModel):
    password: str
    title: str
    login: str
    notes: Optional[str] = ''
    url: Optional[str] = ''
    group_id: int

    class Config:
        orm_mode = True


class PasswordEntryCreate(PasswordEntryBase):
    pass


class PasswordEntryUpdate(PasswordEntryBase):
    pass


class PasswordEntry(PasswordEntryBase):
    id: int


# class Password(PasswordBase):
#     id: int
#     key_id: int
#     mdata_id: int
#
#     class Config:
#         orm_mode = True


# class PasswordMetaBase(BaseModel):
#     title: str
#     login: str
#     notes: Optional[str] = ''
#     url: Optional[str] = ''
#
#
# class PasswordMetaCreate(PasswordMetaBase):
#     encrypted_pwd: str
#
#
# class PasswordMeta(PasswordMetaBase):
#     id: int
#     passwords: List[Password]
#
#     class Config:
#         orm_mode = True
#
#
# class PasswordMetaReturn(PasswordMetaBase):
#     id: int
#     password: str
#     access_level: int


class SafeBase(BaseModel):
    title: str
    description: str

    class Config:
        orm_mode = True


class SafeMinimal(SafeBase):
    id: int
    access_level: int


class Safe(SafeMinimal):
    root_group_id: int
    ciphered_key: str
    # sym_key: List[SymKey]


class SafeCreate(SafeBase):
    ciphered_key: str


class SafeShare(BaseModel):
    ciphered_key: str
    to_user: int
    access_level: int

    class Config:
        orm_mode = True


class UserSafe(BaseModel):
    access_level: int
    safe: Optional[Safe]

    class Config:
        orm_mode = True


class UserBase(BaseModel):
    email: str

    class Config:
        orm_mode = True


class UserCreate(UserBase):
    password: str
    hashed_master_password: str
    public_key: str
    private_key_enc: str


class User(UserBase):
    id: int
    hashed_master_password: str
    key: Key
    # safes: List[UserSafe]
    pwd_ts: datetime

    # def dict(self, **kwargs):
    #     data = super(User, self).dict(**kwargs)
    #     # print(data)
    #     # for s in data['safes']:
    #     #     s['id'] = s['safe']['id']
    #     #     s['title'] = s['safe']['title']
    #     #     s['description'] = s['safe']['description']
    #     #     s['root_group_id'] = s['safe']['root_group_id']
    #     #     for sym_key in s['safe']['sym_key']:
    #     #         if sym_key['key_id'] == data['key']['id']:
    #     #             del sym_key['key_id']
    #     #             s['sym_key'] = sym_key['ciphered_key']
    #     #     del s['safe']
    #
    #     return data


class UserInDB(User):
    hashed_password: str


# class UserWithPasswords(User):
#     passwords: List[PasswordMeta]


class UserIdLogin(UserBase):
    id: int


class UserShare(UserIdLogin):
    public_key: str


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None


class GroupBase(BaseModel):
    title: str

    class Config:
        orm_mode = True


class GroupCreate(GroupBase):
    parent_id: int


class GroupUpdate(GroupBase):
    parent_id: Optional[int]


class Group(GroupBase):
    id: int
    children: List[Group]


class SymmetricKey(BaseModel):
    ciphered_key: str

    class Config:
        orm_mode = True
