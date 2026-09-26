import os
import asyncpg
import bcrypt
from fastapi import FastAPI, HTTPException
from contextlib import asynccontextmanager
from pydantic import BaseModel, ConfigDict, Field, field_validator
from dotenv import load_dotenv

# Import libraries for CSV
import csv
from io import StringIO
from fastapi.responses import Response

load_dotenv()

DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME")

if not all([DB_USER, DB_PASSWORD, DB_HOST, DB_PORT, DB_NAME]):
    raise RuntimeError("Database configuration is incomplete. Please check your .env file.")

DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.pool = await asyncpg.create_pool(
        DATABASE_URL,
        min_size=1,
        max_size=10,
        statement_cache_size=0,
    )
    yield
    await app.state.pool.close()


app = FastAPI(lifespan=lifespan)

class UserCreate(BaseModel):
    """What a client is allowed to send when CREATING a user."""

    model_config = ConfigDict(str_strip_whitespace=True)

    first_name: str = Field(min_length=1, max_length=50)

    middle_name: str | None = Field(default=None, max_length=50)

    last_name: str = Field(min_length=1, max_length=50)

    password_hash: str = Field(min_length=8, max_length=72)

    @field_validator("first_name", "middle_name", "last_name")
    @classmethod
    def names_must_not_contain_digits(cls, v: str | None) -> str | None:
        if v is None:
            return None

        if v == "":
            return None

        if any(character.isdigit() for character in v):
            raise ValueError("A name cannot contain numbers")

        return v


class UserUpdate(BaseModel):
    """What a client is allowed to send when UPDATING a user."""

    model_config = ConfigDict(str_strip_whitespace=True)

    first_name: str = Field(min_length=1, max_length=50)
    middle_name: str | None = Field(default=None, max_length=50)
    last_name: str = Field(min_length=1, max_length=50)

    @field_validator("first_name", "middle_name", "last_name")
    @classmethod
    def names_must_not_contain_digits(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if v == "":
            return None
        if any(character.isdigit() for character in v):
            raise ValueError("A name cannot contain numbers")
        return v


class UserResponse(BaseModel):
    """What the server is allowed to send BACK."""

    user_id: int
    first_name: str
    middle_name: str | None
    last_name: str


@app.get("/")
def read_root():
    return {"Hello": "World"}