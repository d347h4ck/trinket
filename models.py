from sqlalchemy import Column, ForeignKey, Integer, String, DateTime
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship, backref
from database import Base


class User(Base):
    """
    Объект пользователя

    Поля
        id                      - int         - идентификатор
        login                   - text        - логин
        hashed_password         - text        - хешированный пароль, сохраненный в base64
        hashed_master_password  - text        - хешированный мастер пароль
        key                     - Key         - ссылка на ключ пользователя
        pwd_ts                  - unix ts     - время последнего изменения пароля
        created                 - unix ts     - время создания пользователя
    """

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    login = Column(String)
    hashed_password = Column(String)
    hashed_master_password = Column(String)
    key = relationship("AsymmetricKey", back_populates="owner", uselist=False)
    safes = relationship("UserSafeAssociation", back_populates="user")
    pwd_ts = Column(DateTime(timezone=True), server_default=func.now())
    created = Column(DateTime(timezone=True), server_default=func.now())


class Safe(Base):
    """
    Объект сейфа

    Поля
        id              - int       - идентификатор сейфа
        title           - text      - наименование сейфа
        description     - text      - описание сейфа
        root_group_id   - int       - идентификатор корневой группы сейфа
    """

    __tablename__ = "safes"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String)
    description = Column(String)
    root_group_id = Column(Integer, ForeignKey("groups.id"), index=True)
    sym_key = relationship("SymmetricKey", back_populates="safe")
    users = relationship("UserSafeAssociation", back_populates="safe")


class AsymmetricKey(Base):
    """
    Объект ключа

    Поля
        id           - int      - идентификатор ключа
        public_key   - text     - публичная часть ключа в base64
        private_key  - text     - зашифрованная приватная часть ключа в base64
        owner        - User     - ссылка на владельца
    """

    __tablename__ = "asymmetric_keys"

    id = Column(Integer, primary_key=True, index=True)
    public_key = Column(String)
    private_key = Column(String)
    owner_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))  # При удалении пользователя ключ удаляется
    owner = relationship("User", back_populates="key")


class SymmetricKey(Base):
    """
    Объект зашифрованного симметричного сеансового ключа

    Поля
        id              - int        - идентификатор ключа
        safe_id         - int        - идентификатор сейфа, что зашифрован этим ключом
        key_id          - int        - идентификатор ассиметричного ключа, которым зашифрован данный ключ
        ciphered_key    - int        - зашифрованный ключ
    """

    __tablename__ = "symmetric_keys"

    id = Column(Integer, primary_key=True, index=True)
    safe_id = Column(Integer, ForeignKey("safes.id", ondelete="CASCADE"))
    safe = relationship('Safe', back_populates="sym_key")
    key_id = Column(Integer, ForeignKey("asymmetric_keys.id", ondelete="CASCADE"))
    ciphered_key = Column(String)


class Group(Base):
    """
    Объект группы
    Поля
        id          - int                   - идентификатор группы паролей
        title       - text                  - название группы
        children    - List[PasswordGroup]   - список дочерних групп
    """

    __tablename__ = "groups"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String)
    parent_id = Column(Integer, ForeignKey("groups.id", ondelete="CASCADE"), nullable=True, index=True)
    children = relationship("Group",
                            cascade="all",
                            backref=backref("parent", remote_side=[id]),
                            )


class PasswordEntry(Base):
    """
    Объект пароля
    Поля
        id          - int       - идентификатор пароля
        group_id    - int       - идентификатор группы
        title       - text      - название пароля
        description - text      - описание
        login       - text      - логин
        url         - text      - адрес
        notes       - text      - заметки
        password    - text      - зашифрованный пароль
    """

    __tablename__ = "password_entries"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String)
    login = Column(String)
    url = Column(String)
    notes = Column(String)
    group_id = Column(Integer, ForeignKey('groups.id', ondelete='CASCADE'))
    password = Column(String)


class UserSafeAssociation(Base):

    __tablename__ = 'user_safe_link'

    user_id = Column(Integer, ForeignKey('users.id'), primary_key=True)
    safe_id = Column(Integer, ForeignKey('safes.id'), primary_key=True)
    user = relationship("User", back_populates='safes')
    safe = relationship("Safe", back_populates='users')
    access_level = Column(Integer)

#
# class UserPasswordMetaAssociation(Base):
#
#     __tablename__ = 'user_password_meta_link'
#
#     user_id = Column(ForeignKey('users.id'), primary_key=True)
#     password_meta_id = Column(ForeignKey('password_meta.id'), primary_key=True)
#
#     access_level = Column(Integer)
#     user = relationship("User", back_populates='password_metadatas', uselist=False)
#     password_metadata = relationship("PasswordMeta", back_populates='users')
