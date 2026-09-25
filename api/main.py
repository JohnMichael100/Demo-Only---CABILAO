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


@app.get("/users", response_model=list[UserResponse])
async def get_users():
    """Return every user."""

    async with app.state.pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT user_id, first_name, middle_name, last_name FROM users ORDER BY user_id"
        )
        return [dict(row) for row in rows]


@app.get("/users/{user_id}", response_model=UserResponse)
async def get_user(user_id: int):
    """Return one user by ID."""

    async with app.state.pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT user_id, first_name, middle_name, last_name FROM users WHERE user_id = $1",
            user_id,
        )
        if row is None:
            raise HTTPException(status_code=404, detail="User not found")
        return dict(row)


@app.post("/users", status_code=201, response_model=UserResponse)
async def create_user(user: UserCreate):
    """Create a new user."""

    password_hash = bcrypt.hashpw(
        user.password_hash.encode("utf-8"),
        bcrypt.gensalt(),
    ).decode("utf-8")

    async with app.state.pool.acquire() as conn:
        result = await conn.fetchrow(
            """
            INSERT INTO users (first_name, middle_name, last_name, password_hash)
            VALUES ($1, $2, $3, $4)
            RETURNING user_id, first_name, middle_name, last_name
            """,
            user.first_name,
            user.middle_name,
            user.last_name,
            password_hash,
        )
        return dict(result)


@app.put("/users/{user_id}", response_model=UserResponse)
async def update_user(user_id: int, user: UserUpdate):
    """Update an existing user's name fields."""

    async with app.state.pool.acquire() as conn:
        result = await conn.fetchrow(
            """
            UPDATE users
            SET first_name = $1, middle_name = $2, last_name = $3
            WHERE user_id = $4
            RETURNING user_id, first_name, middle_name, last_name
            """,
            user.first_name,
            user.middle_name,
            user.last_name,
            user_id,
        )
        if result is None:
            raise HTTPException(status_code=404, detail="User not found")
        return dict(result)


@app.delete("/users/{user_id}", status_code=204)
async def delete_user(user_id: int):
    """Delete a user."""

    async with app.state.pool.acquire() as conn:
        status = await conn.execute("DELETE FROM users WHERE user_id = $1", user_id)

        if status.split()[-1] == "0":
            raise HTTPException(status_code=404, detail="User not found")

        return None

@app.get("/users/export/csv")
async def export_users_csv():
    """Export all users as a downloadable CSV file."""

    async with app.state.pool.acquire() as conn:
        # Same explicit-columns habit as everywhere else — password_hash
        # never gets loaded in the first place.
        rows = await conn.fetch(
            "SELECT user_id, first_name, middle_name, last_name FROM users ORDER BY user_id"
        )

    # Build the CSV in memory. StringIO acts like a text file that lives
    # in RAM instead of on disk — nothing is written to the filesystem.
    buffer = StringIO()
    writer = csv.writer(buffer)

    # Header row
    writer.writerow(["user_id", "first_name", "middle_name", "last_name"])

    # One row per user
    for row in rows:
        writer.writerow([
            row["user_id"],
            row["first_name"],
            row["middle_name"] or "",   # avoid writing the literal word "None"
            row["last_name"],
        ])

    buffer.seek(0)

    return Response(
        content=buffer.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=users.csv"},
    )