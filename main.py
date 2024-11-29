from __future__ import annotations
from datetime import datetime
import argparse
from enum import Enum, auto
import os
import getpass
import string
import random
from platform import system
from argon2 import PasswordHasher
from typing import Dict, List
from sqlalchemy import Column, ForeignKey, Integer, String, create_engine, select
from sqlalchemy.exc import IntegrityError
from typing_extensions import Annotated
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, computed_field
from sqlalchemy.orm import (
    Mapped,
    declarative_base,
    mapped_column,
    relationship,
    sessionmaker,
)


class EnumComplexity(Enum):
    BASIC = auto()
    INTERMEDIO = auto()
    AVANZADO = auto()


path_db = (
    f"C:\\Users\\{os.getlogin()}"
    if system().lower() == "windows"
    else f"/home/{getpass.getuser()}"
)

Base = declarative_base()


configuration: Dict[str, bool] = {
    "upper_case": True,
    "lower_case": True,
    "simbols": True,
    "numbers": True,
}


# services/
def saved_account(args: argparse.Namespace):
    user = None
    try:
        user = AccountTransaction.getting_account(args)
    except AssertionError as e:
        print(e.args[0])

    if user != None and hasattr(args, "update"):

        if int(args.c) == 1:
            configuration["numbers"] = False
            configuration["simbols"] = False
            configuration["upper_case"] = False
        elif int(args.c) == 2:
            configuration["simbols"] = False
            configuration["numbers"] = False
        elif int(args.c) == 3:
            configuration["simbols"] = False
        else:
            pass

        if args.update:
            AccountTransaction.add_new_passgwn(args)

    elif user == None:
        AccountTransaction.saved_account(args)

    print(configuration)


def get_account(args: argparse.Namespace) -> UserOrm | None:

    try:
        print(AccountTransaction.getting_account(args))
    except AssertionError as e:
        print(e.args[0])


class AccountTransaction:

    _conection: Conection

    @classmethod
    def set_conection(cls, conection: Conection):
        cls._conection = conection

    @classmethod
    def get_all_accounte(cls):
        stmt = select(UserOrm)
        return cls._conection.sesion.scalars(stmt)

    @classmethod
    def find_account_by_id(cls, args: argparse.Namespace):
        return cls._conection.sesion.query(UserOrm).get(args.id)

    @classmethod
    def add_new_passgwn(cls, args: argparse.Namespace):

        if hasattr(args, "length"):
            obj_passgen = PasswordGenerator(length=args.length)
        else:
            obj_passgen = PasswordGenerator()

        user = cls.getting_account(args)
        passgen1 = PasswordGeneratorOrm(
            generated_password=obj_passgen.model_dump()["generated_password"],
            platform=args.platform,
        )
        if user != None:
            user.generated_passwords.append(passgen1)
            cls._conection.sesion.commit()
            print("Usuario " + user.username + " actualizado con exito.")

    @classmethod
    def getting_account(cls, args: argparse.Namespace) -> UserOrm:
        #     print(user)
        get_account_stmt = select(UserOrm).where(UserOrm.username == args.username)
        user = cls._conection.sesion.scalars(get_account_stmt).first()

        ph = PasswordHasher()

        if user != None and ph.verify(hash=user.password, password=args.password):
            print(
                "Verificacion --> ",
                ph.verify(hash=user.password, password=args.password),
            )
        else:
            raise AssertionError(
                "Usuario no existente o usuario y/o contraseña incorrectos username=",
                args.username,
            )
        return user

    @classmethod
    def saved_account(cls, args: argparse.Namespace):

        if hasattr(args, "length"):
            obj_passgen = PasswordGenerator(length=args.length)
        else:
            obj_passgen = PasswordGenerator()

        ph = PasswordHasher()

        user = UserOrm(
            username=args.username,
            password=ph.hash(args.password),
            generated_passwords=[
                PasswordGeneratorOrm(
                    generated_password=obj_passgen.model_dump()["generated_password"],
                    platform=args.platform,
                )
            ],
        )

        cls._conection.sesion.add(user)
        try:
            cls._conection.sesion.commit()
            print("Usuario " + args.username + " persistido con exito.")
        except IntegrityError:
            print("Nombre de usuario ya existente.")


# bootstrap
def start_commands() -> argparse.Namespace:
    parse = argparse.ArgumentParser()

    subparse = parse.add_subparsers(required=True)

    saved = subparse.add_parser("save", help="Comando para guardar un usuario.")
    saved.add_argument(
        "--username", "-u", type=str, help="Username a autenticar.", required=True
    )
    saved.add_argument(
        "--password", "-p", type=str, help="Password del username", required=True
    )
    saved.add_argument(
        "-c",
        help="Elige la complegidad del password a generar (max=-ccc).",
        default=0,
        action="count",
        required=False,
    )
    saved.add_argument(
        "--update",
        help="Elige la complegidad del password a generar (max=-ccc).",
        default=0,
        action="store_true",
        required=False,
    )
    saved.add_argument(
        "--platform",
        "-m",
        type=str,
        help="Liga una plataforma a una contraseña.",
        required=True,
    )
    saved.add_argument(
        "--length",
        "-l",
        help="La longitud de la contraseña.",
        type=int,
        required=False,
    )
    saved.set_defaults(func=saved_account)

    getting = subparse.add_parser("get", help="Comando para recuperar un usuario.")
    getting.add_argument(
        "--username", "-u", type=str, help="Usuario autenticado.", required=True
    )
    getting.add_argument(
        "--password",
        "-p",
        type=str,
        help="Password del Usuario authneticado",
        required=True,
    )
    getting.add_argument(
        "--platform",
        "-m",
        type=str,
        help="Liga una plataforma a una contraseña.",
        required=False,
        default="all",
    )
    getting.add_argument(
        "--shell",
        help="Opcion para activar la shell con el usuario autenticado.",
        action="store_true",
    )
    getting.set_defaults(func=get_account)

    return parse.parse_args()


# connection/
class Conection:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        self.engine = create_engine(
            os.path.join("sqlite:///" + path_db, "password_generator.db"), echo=False
        )
        Sesion = sessionmaker(bind=self.engine)
        self.sesion = Sesion()


class PasswordGenerator(BaseModel):
    configuration: Dict[str, bool] = Field(default=configuration)
    length: int = Field(default=15)

    @computed_field
    @property
    def generated_password(self) -> str:
        """Genera una contraseña de la longitud y complejidad especificadas."""
        caracteres = "".join(
            [
                string.digits if self.configuration["numbers"] else "",
                string.ascii_uppercase if self.configuration["upper_case"] else "",
                string.ascii_lowercase if self.configuration["lower_case"] else "",
                "!@#$%^&*()" if self.configuration["simbols"] else "",
            ]
        )

        return "".join(random.choice(caracteres) for _ in range(self.length))


# models/persist
class PasswordGeneratorOrm(Base):
    __tablename__ = "passwords"

    id: Mapped[int] = mapped_column(
        primary_key=True, nullable=False, autoincrement=True
    )
    generated_password: Mapped[str] = mapped_column(String(50))
    platform: Mapped[str] = mapped_column(String(20), nullable=False)
    # configuration: Dict[str, bool] = Field(default=configuration)

    user_id = Column(Integer, ForeignKey("users.id"))

    users = relationship("UserOrm", back_populates="generated_passwords")

    def __repr__(self) -> str:
        return f"Password(id={self.id!r}, generated_password={self.generated_password!r}, platform={self.platform!r}, user_id={self.user_id!r})"


class UserOrm(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(
        primary_key=True, nullable=False, autoincrement=True
    )
    username: Mapped[str] = mapped_column(
        String(20), index=True, nullable=False, unique=True
    )
    password: Mapped[str] = mapped_column(String(50), nullable=False)
    generated_passwords = relationship(
        "PasswordGeneratorOrm", back_populates="users", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"User(id={self.id!r}, username={self.username!r}, password={self.password!r}, generated_passwords={self.generated_passwords!r})"


# models/
class User(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    _created_at: datetime = PrivateAttr(default_factory=datetime.now)

    id: int
    username: Annotated[str, Field(max_length=20)]
    password: Annotated[str, Field(max_length=50, repr=False)]
    generated_passwords: List[PasswordGenerator]


def main() -> None:

    conection = Conection()

    Base.metadata.create_all(conection.engine)
    AccountTransaction.set_conection(conection)

    s_commands = start_commands()
    s_commands.func(s_commands)


if __name__ == "__main__":
    main()
