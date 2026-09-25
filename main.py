import os
import asyncpg
import bcrypt  # new import — used to hash passwords on the server
from fastapi import FastAPI, HTTPException
from contextlib import asynccontextmanager

# [CHANGE] We now import more tools from pydantic:
#   Field           -> lets us add rules like min_length and max_length
#   ConfigDict      -> lets us turn on automatic whitespace trimming
#   field_validator -> lets us write our own rule in Python
from pydantic import BaseModel, ConfigDict, Field, field_validator

from dotenv import load_dotenv

load_dotenv()

# -----------------------------------------------------------------------------
# DATABASE CONNECTION SETTINGS
# -----------------------------------------------------------------------------
# Unchanged. These read your .env file so passwords are never typed into code.

DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME")

# This is a validation check too — just on configuration instead of user input.
# Same idea as the whole unit: fail early and loudly, before anything runs.
#
# Small note for class: DB_PORT can never be missing here, because the line
# above gives it a default of "5432". So it is always truthy and this check
# never actually tests it. Harmless, but a good example of a check that looks
# like it does more than it does.
if not all([DB_USER, DB_PASSWORD, DB_HOST, DB_PORT, DB_NAME]):
    raise RuntimeError("Database configuration is incomplete. Please check your .env file.")

DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"


# -----------------------------------------------------------------------------
# STARTUP AND SHUTDOWN
# -----------------------------------------------------------------------------
# Unchanged. A "pool" is a set of ready-made database connections that get
# reused, because opening a new connection for every request is slow.

@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.pool = await asyncpg.create_pool(
        DATABASE_URL,
        min_size=1,            # keep at least 1 connection open
        max_size=10,           # never open more than 10 at once
        statement_cache_size=0,  # needed when connecting through a pooler
    )
    yield                      # the app runs here
    await app.state.pool.close()  # then we close the pool cleanly


app = FastAPI(lifespan=lifespan)


# =============================================================================
#  THE DATA MODELS — this is where validation lives
# =============================================================================
# Remember the guard analogy: these classes are the guard at the door.
# FastAPI runs them BEFORE your endpoint function starts. If the data fails,
# your SQL never runs at all and the client gets a 422.


class UserCreate(BaseModel):
    """What a client is allowed to send when CREATING a user."""

    # [CHANGE 3] Trim whitespace off every string field in this model.
    #
    # Why: "  Juan  " becomes "Juan" before anything else happens.
    # The order matters and it helps us: trimming runs BEFORE the length
    # check, so a name of three spaces "   " becomes "" and then fails
    # min_length=1. Without this line, a name made only of spaces would pass
    # every check and land in the database looking empty.
    model_config = ConfigDict(str_strip_whitespace=True)

    # [CHANGE 1] Length limits added to every text field.
    #
    # Before: first_name: str
    #   A plain `str` still allows "" (empty) and a 10,000-character name.
    #   The type is a floor, not a ceiling.
    #
    # After: min_length=1 blocks empty, max_length=50 blocks absurd.
    #
    # IMPORTANT: max_length must match your database column. If the column is
    # VARCHAR(50) but we allow 200 here, PostgreSQL rejects it instead of
    # Pydantic — and a database error turns into an ugly 500 with no useful
    # message. Pydantic gives a clear 422 instead. Same rule, very different
    # experience for whoever is using your API.
    first_name: str = Field(min_length=1, max_length=50)

    # [CHANGE 2] middle_name is now optional.
    #
    # Before: middle_name: str   -> required, and could not be null
    # After:  middle_name: str | None = None
    #
    # Read it aloud as: "a string, or nothing at all — and if you don't send
    # it, I'll use nothing."
    #
    # Two separate questions are being answered on this one line:
    #   Can the value be null?     -> decided by the TYPE      (str | None)
    #   Must the client send it?   -> decided by the DEFAULT   (= None)
    #
    # Plenty of people genuinely have no middle name on their records, so this
    # is a fact about the world, not a technicality.
    middle_name: str | None = Field(default=None, max_length=50)

    last_name: str = Field(min_length=1, max_length=50)

    # [CHANGE 5] The big security fix. Read this one carefully.
    #
    # Before: password_hash: str
    #   The CLIENT sent the hash. That means the client decided what the hash
    #   was. An attacker could send literally any string and it would be
    #   stored as that account's password hash. The server was trusting the
    #   client with a job the server is responsible for.
    #
    # After: we accept a PLAIN password and hash it ourselves, below, in
    # create_user(). The client can no longer choose the hash.
    #
    # About the limits:
    #   min_length=8  -> a basic floor so passwords are not trivially short
    #   max_length=72 -> bcrypt only looks at the first 72 bytes. Anything
    #                    past that is silently ignored, so we reject it here
    #                    rather than pretend it counted.
    password_hash: str = Field(min_length=8, max_length=72)

    # [CHANGE 4] Our own rule, written in Python.
    #
    # Field() covers common rules like length and range. When the rule is
    # specific to your project, you write a validator.
    #
    # Two things to notice:
    #   1. Raising ValueError becomes a clean 422 automatically. You never
    #      build the error response yourself.
    #   2. Whatever you RETURN replaces the data. So a validator can clean,
    #      not just reject. That is the moment validation turns into
    #      sanitization — the same tool doing both jobs.
    @field_validator("first_name", "middle_name", "last_name") # @field_validator means "this function is a validator for the fields named here"
    @classmethod # @classmethod means this is a class method, not an instance method. It runs on the class itself, not on a specific instance of the class.
    # cls inside the parameters is a convention for class methods. It is like self for instance methods.
    # v inside the parameters is a convention for the value being validated. It is like self for instance methods.
    # str | None means the value can be a string or None. The return type is also str | None, meaning the validator can return a string or None.
    # -> str | None means the return type of the function is either a string or None.
    def names_must_not_contain_digits(cls, v: str | None) -> str | None:
        # middle_name may be None, so check that first or we crash.
        if v is None:
            return None

        # If the client sent "" or only spaces, treat it as "no middle name"
        # instead of storing an empty string. This keeps the database tidy:
        # one clear way to say "missing" (NULL) instead of two.
        if v == "":
            return None

        if any(character.isdigit() for character in v):
            raise ValueError("A name cannot contain numbers")

        # NOTE ON WHAT WE DELIBERATELY DO NOT DO HERE:
        #
        # The slides showed `return v.strip().title()` as an example of a
        # validator that transforms data. Do NOT use .title() on real names.
        # It quietly corrupts them:
        #
        #     "McDonald"    -> "Mcdonald"      (wrong)
        #     "dela Cruz"   -> "Dela Cruz"     (changed without asking)
        #     "O'BRIEN"     -> "O'Brien"       (maybe right, maybe not)
        #
        # This is exactly the over-cleaning mistake from slide 20. Trimming is
        # safe because it removes nothing meaningful. Re-capitalising is not,
        # because it overwrites a choice the person made about their own name.
        # So we trim (via str_strip_whitespace above) and otherwise store the
        # name exactly as it was typed.
        return v


class UserUpdate(BaseModel):
    """What a client is allowed to send when UPDATING a user."""

    # Same protections as UserCreate. A common bug is to carefully validate
    # the create endpoint and then forget the update endpoint, leaving a side
    # door wide open into the same table.
    model_config = ConfigDict(str_strip_whitespace=True)

    first_name: str = Field(min_length=1, max_length=50)
    middle_name: str | None = Field(default=None, max_length=50)
    last_name: str = Field(min_length=1, max_length=50)

    # Notice there is NO password field here, and that is on purpose.
    # Changing a password should be its own endpoint that asks for the current
    # password first. Bundling it into a general "edit my name" request means
    # anyone who can edit a profile can silently take over the account.

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
    """
    [CHANGE 6] What the server is allowed to send BACK.

    Validation is not only about incoming data. This model is a guard on the
    way out.

    The problem it fixes: every endpoint used to `return dict(row)` after a
    `SELECT *`. That row includes password_hash. So every request for
    somebody's name was also handing out their password hash.

    How this fixes it: anything not listed in this class gets stripped out
    before the response leaves the server. password_hash is not listed, so it
    cannot escape — even by accident, even if someone later adds a stray
    SELECT * somewhere.
    """

    user_id: int
    first_name: str
    middle_name: str | None
    last_name: str


# =============================================================================
#  ENDPOINTS
# =============================================================================

@app.get("/")
def read_root():
    # Unchanged. A simple "is the server awake?" check.
    return {"Hello": "World"}


@app.get("/users", response_model=list[UserResponse])
async def get_users():
    """Return every user."""
    # [CHANGE 6] response_model=list[UserResponse] above means "a list of
    # users, each one filtered through UserResponse."

    async with app.state.pool.acquire() as conn:
        # [CHANGE 7] No more SELECT *.
        #
        # Before: "SELECT * FROM users"
        #   * means "every column", which includes password_hash. The safest
        #   habit is to never load a secret you do not need in the first
        #   place. The response_model would have filtered it out anyway, but
        #   two layers of protection is the right amount for a password hash.
        rows = await conn.fetch(
            "SELECT user_id, first_name, middle_name, last_name FROM users ORDER BY user_id"
        )
        return [dict(row) for row in rows]


@app.get("/users/{user_id}", response_model=UserResponse)
async def get_user(user_id: int):
    """Return one user by ID."""

    # Worth pointing out to the class: `user_id: int` in the function
    # signature is validation too. If someone visits /users/abc, FastAPI
    # rejects it with a 422 and this function never runs. You did not write
    # an if-statement for that — the type annotation did it.

    async with app.state.pool.acquire() as conn:
        # [CHANGE 7] Explicit columns again, and [CHANGE 8] the $1 placeholder
        # is unchanged because it was already right.
        row = await conn.fetchrow(
            "SELECT user_id, first_name, middle_name, last_name FROM users WHERE user_id = $1",
            user_id,
        )
        if row is None:
            # 404 means "your request was fine, but there is no such user."
            # Different from 422, which means "your request itself was wrong."
            raise HTTPException(status_code=404, detail="User not found")
        return dict(row)


@app.post("/users", status_code=201, response_model=UserResponse)
async def create_user(user: UserCreate):
    """Create a new user."""

    # By the time this line runs, every rule in UserCreate has already passed.
    # Names are trimmed, non-empty, under 50 characters, and contain no
    # digits. The password is between 8 and 72 characters. There is nothing
    # left to check by hand.

    # [CHANGE 5] The server hashes the password. This is the line that takes
    # the decision away from the client.
    #
    # Step by step:
    #   .encode("utf-8")   bcrypt works on bytes, not text, so convert first
    #   bcrypt.gensalt()   makes a fresh random "salt" for THIS password
    #   bcrypt.hashpw()    combines password + salt into the stored hash
    #   .decode("utf-8")   convert the resulting bytes back to text for the DB
    #
    # Why the salt matters: two people who both choose "password123" will get
    # two completely different hashes. An attacker who steals the table
    # cannot spot repeated passwords, and cannot reuse a precomputed list of
    # hashes to reverse them.
    #
    # Also note this is a ONE-WAY operation. There is no "unhash" function.
    # To check a login later you hash the attempt and compare:
    #     bcrypt.checkpw(attempt.encode("utf-8"), stored_hash.encode("utf-8"))
    password_hash = bcrypt.hashpw(
        user.password_hash.encode("utf-8"),
        bcrypt.gensalt(),
    ).decode("utf-8")

    async with app.state.pool.acquire() as conn:
        # [CHANGE 8] THE MOST IMPORTANT SECURITY FEATURE IN THIS FILE, and it
        # was already here in the original. It is these: $1, $2, $3, $4.
        #
        # They are called parameter placeholders. Here is what happens:
        #   1. The SQL TEXT goes to PostgreSQL first. PostgreSQL reads it and
        #      builds the plan. The structure of the command is now FINAL.
        #   2. The VALUES are sent separately, as data.
        #   3. PostgreSQL slots the values into the already-finished plan.
        #
        # A value can never become part of the command, because the command
        # was finished before the value arrived.
        #
        # NEVER build SQL with an f-string, like this:
        #
        #     await conn.fetch(f"SELECT * FROM users WHERE first_name = '{name}'")
        #
        # There the value is glued into the text before PostgreSQL ever sees
        # it, so the database cannot tell your words from a stranger's. Send
        # the name  '; DROP TABLE users; --  and the table is gone.
        #
        # With $1, that exact same text is stored harmlessly as somebody's
        # name. And notice: Pydantic did NOT save us there. That attack string
        # is a perfectly valid `str` and passes every length check. SQL
        # injection is stopped by placeholders, never by cleaning the input.
        #
        # [CHANGE 7] RETURNING also names its columns now instead of using *,
        # so the hash we just created never even travels back out of the
        # database into our Python code.
        result = await conn.fetchrow(
            """
            INSERT INTO users (first_name, middle_name, last_name, password_hash)
            VALUES ($1, $2, $3, $4)
            RETURNING user_id, first_name, middle_name, last_name
            """,
            user.first_name,
            user.middle_name,
            user.last_name,
            password_hash,  # our own hash, not one the client chose
        )
        return dict(result)


@app.put("/users/{user_id}", response_model=UserResponse)
async def update_user(user_id: int, user: UserUpdate):
    """Update an existing user's name fields."""

    async with app.state.pool.acquire() as conn:
        # [CHANGE 7] Explicit RETURNING columns. [CHANGE 8] Placeholders kept.
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
        # conn.execute() returns a status string like "DELETE 1" or "DELETE 0"
        # telling us how many rows were affected.
        status = await conn.execute("DELETE FROM users WHERE user_id = $1", user_id)

        # Slightly sturdier than comparing to the exact text "DELETE 0":
        # we split off the last word and read the number. If the wording ever
        # changes, this still works.
        if status.split()[-1] == "0":
            raise HTTPException(status_code=404, detail="User not found")

        # status_code=204 means "success, and there is no content to send."
        # A 204 response must have an empty body, so we return None.
        return None


# =============================================================================
#  OPTIONAL NEXT STEP — adding an email field
# =============================================================================
#
# The slides showed EmailStr, but the users table in this project has no email
# column, so adding it to the model would break every insert. If you want to
# add it in class, do it in two steps.
#
# STEP 1 — change the database first:
#
#     ALTER TABLE users ADD COLUMN email VARCHAR(255) UNIQUE;
#
# STEP 2 — then add it to the models. You will also need:
#
#     pip install "pydantic[email]"
#
# and then inside UserCreate:
#
#     from pydantic import EmailStr
#
#     email: EmailStr
#
#     @field_validator("email")
#     @classmethod
#     def normalize_email(cls, v: str) -> str:
#         # Lowercasing prevents JUAN@Gmail.COM and juan@gmail.com from
#         # becoming two separate accounts for one person. This is a
#         # CORRECTNESS fix, not a security fix — and it is safe to do
#         # because the local part of an email is treated as
#         # case-insensitive by every mail provider people actually use.
#         return v.lower()
#
# Do not forget to add "email" to UserResponse and to every SELECT and
# RETURNING column list above, or it will simply never appear in responses.
#
# =============================================================================
#  THINGS STILL MISSING FROM THIS FILE
# =============================================================================
#
# Good to say out loud so students do not think one unit makes an API safe:
#
#   * No login endpoint, so nothing checks WHO is making the request. Right
#     now anyone can edit or delete anyone. Validation answers "is this data
#     acceptable"; authentication answers "who are you"; authorization answers
#     "are you allowed to do this". They are three different jobs.
#   * No rate limiting, so someone can hammer the endpoints.
#   * No logging, so you cannot tell afterwards what happened.
#   * Errors from the database are not caught, so a duplicate-key violation
#     would surface as a 500 rather than a helpful message.
#
# =============================================================================