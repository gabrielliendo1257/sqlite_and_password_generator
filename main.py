from __future__ import annotations
from datetime import datetime
import argparse
from enum import Enum, auto
import os
import getpass
import string
import random
from platform import system
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

lenth_password: int = 17

configuration: Dict[str, bool] = {
    "upper_case": True,
    "lower_case": True,
    "simbols": True,
    "numbers": True,
}

def saved_account(args: argparse.Namespace):

    if args.update:
        AccountTransaction.add_new_passgwn(args)
    elif not args.update:
        if int(args.c) == 0:
            configuration["numbers"] = False
            configuration["simbols"] = False
        elif int(args.c) == 1:
            configuration["simbols"] = False
        elif int(args.c) == 2 and args.c > 1:
            pass
        else:
            print("[ERROR] No se encontro el parametro -c.")

        AccountTransaction.saved_account(args)

def get_account(args: argparse.Namespace):
    return AccountTransaction.getting_account(args)


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
        user = cls.getting_account(args)
        passgen1 = PasswordGeneratorOrm(
            generated_password=PasswordGenerator().model_dump()["generated_password"],
            platform=args.platform,
        )
        if user != None:
            user.generated_passwords.append(passgen1)

    @classmethod
    def getting_account(cls, args: argparse.Namespace) -> UserOrm | None:
        # stmt = select(UserOrm).where(UserOrm.username.in_([args.account]))
        #
        # for user in cls._conection.sesion.scalars(stmt):
        #     print(user)
        get_account_stmt = (
            select(UserOrm)
            .where(UserOrm.username == args.username)
            .where(UserOrm.password == args.password)
        )
        # get_account_atmt = select(UserOrm).where(UserOrm.username.in_([args.account]))
        user = cls._conection.sesion.scalars(get_account_stmt).first()

        if user:
            print(user)
            return user
        elif not user:
            print("Usuaurio o contraseña incorrecto.")
        # return cls._conection.sesion.scalars(stmt).one()

    @classmethod
    def saved_account(cls, args: argparse.Namespace):

        user = UserOrm(
            username=args.username,
            password=args.password,
            generated_passwords=[
                PasswordGeneratorOrm(
                    generated_password=PasswordGenerator().model_dump()[
                        "generated_password"
                    ],
                    platform=args.platform,
                )
            ],
        )

        cls._conection.sesion.add(user)
        try:
            cls._conection.sesion.commit()
        except IntegrityError:
            print("Nombre de usuario ya existente.")


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
        default=lenth_password,
    )
    saved.set_defaults(func=AccountTransaction.saved_account)

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
    getting.set_defaults(func=AccountTransaction.getting_account)

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
    length: int = Field(default=lenth_password)
    # configuration: Dict[str, bool] = Field(default=configuration)

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
    generated_password: Mapped[str] = mapped_column(String(lenth_password))
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
    password: Mapped[str] = mapped_column(String(50), nullable=False, unique=True)
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

    # print(co_orm_user)
    conection = Conection()

    Base.metadata.create_all(conection.engine)
    AccountTransaction.set_conection(conection)

    # with Session(conection.engine) as sesion:
    #     sesion.add_all([piter, paco])
    #     sesion.commit()

    # stmt = select(UserOrm).where(UserOrm.username.in_(["juan"]))
    #
    # for user in conection.sesion.scalars(stmt):
    #     print(user)

    # co_model_user = User.model_validate(co_orm_user)
    # print(co_model_user)
    s_commands = start_commands()
    s_commands.func(s_commands)


if __name__ == "__main__":
    main()
