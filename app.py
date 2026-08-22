import os
import sqlite3
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta
from typing import Optional

import jwt
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr

DB = "data/partnerhub.db"
os.makedirs("data", exist_ok=True)

SECRET = os.getenv("SECRET_KEY", "change-this-secret-in-render")

app = FastAPI(title="PartnerHub API", version="1.0")

app.mount("/static", StaticFiles(directory="static"), name="static")


def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)

    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        310000
    )

    return "pbkdf2$" + salt.hex() + "$" + hashed.hex()


def verify_password(password: str, stored: str) -> bool:
    try:
        if not stored.startswith("pbkdf2$"):
            return False

        _, salt_hex, hash_hex = stored.split("$")

        new_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            bytes.fromhex(salt_hex),
            310000
        )

        return hmac.compare_digest(
            new_hash.hex(),
            hash_hex
        )

    except Exception:
        return False


def init():
    c = db()

    c.executescript("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        city TEXT DEFAULT '',
        skills TEXT DEFAULT '',
        investment INTEGER DEFAULT 0,
        interests TEXT DEFAULT '',
        role TEXT DEFAULT 'partner',
        verified INTEGER DEFAULT 0,
        blocked INTEGER DEFAULT 0,
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS businesses(
        id INTEGER PRIMARY KEY,
        owner_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        category TEXT DEFAULT '',
        city TEXT DEFAULT '',
        investment_required INTEGER DEFAULT 0,
        partner_investment INTEGER DEFAULT 0,
        partnership_pct REAL DEFAULT 0,
        profit_share REAL DEFAULT 0,
        description TEXT DEFAULT '',
        status TEXT DEFAULT 'active',
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS interests(
        id INTEGER PRIMARY KEY,
        user_id INTEGER,
        business_id INTEGER,
        status TEXT DEFAULT 'pending',
        created_at TEXT NOT NULL,
        UNIQUE(user_id, business_id)
    );

    CREATE TABLE IF NOT EXISTS messages(
        id INTEGER PRIMARY KEY,
        sender_id INTEGER,
        receiver_id INTEGER,
        body TEXT NOT NULL,
        created_at TEXT NOT NULL,
        read INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS notifications(
        id INTEGER PRIMARY KEY,
        user_id INTEGER,
        text TEXT,
        created_at TEXT NOT NULL,
        read INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS reports(
        id INTEGER PRIMARY KEY,
        reporter_id INTEGER,
        reported_user_id INTEGER,
        reason TEXT,
        status TEXT DEFAULT 'open',
        created_at TEXT NOT NULL
    );
    """)

    admin = c.execute(
        "SELECT id FROM users WHERE email=?",
        ("admin@partnerhub.local",)
    ).fetchone()

    if not admin:
        c.execute(
            """
            INSERT INTO users
            (name,email,password,role,verified,created_at)
            VALUES(?,?,?,?,?,?)
            """,
            (
                "PartnerHub Admin",
                "admin@partnerhub.local",
                hash_password("ChangeMe123!"),
                "admin",
                1,
                datetime.utcnow().isoformat()
            )
        )

    c.commit()
    c.close()


init()


class Register(BaseModel):
    name: str
    email: EmailStr
    password: str
    city: str = ""
    skills: str = ""
    investment: int = 0
    interests: str = ""
    role: str = "partner"


class Login(BaseModel):
    email: EmailStr
    password: str


class Profile(BaseModel):
    name: Optional[str] = None
    city: Optional[str] = None
    skills: Optional[str] = None
    investment: Optional[int] = None
    interests: Optional[str] = None


class BusinessIn(BaseModel):
    name: str
    category: str = ""
    city: str = ""
    investment_required: int = 0
    partner_investment: int = 0
    partnership_pct: float = 0
    profit_share: float = 0
    description: str = ""


class MessageIn(BaseModel):
    receiver_id: int
    body: str


class InterestIn(BaseModel):
    business_id: int


class ReportIn(BaseModel):
    reported_user_id: int
    reason: str


def create_token(uid: int):
    payload = {
        "sub": str(uid),
        "exp": datetime.utcnow() + timedelta(days=7)
    }

    return jwt.encode(
        payload,
        SECRET,
        algorithm="HS256"
    )


def current_user(
    authorization: Optional[str] = Header(None)
):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            401,
            "Login required"
        )

    try:
        payload = jwt.decode(
            authorization[7:],
            SECRET,
            algorithms=["HS256"]
        )

        uid = int(payload["sub"])

    except Exception:
        raise HTTPException(
            401,
            "Invalid or expired token"
        )

    c = db()

    user = c.execute(
        """
        SELECT * FROM users
        WHERE id=? AND blocked=0
        """,
        (uid,)
    ).fetchone()

    c.close()

    if not user:
        raise HTTPException(
            401,
            "User unavailable"
        )

    return dict(user)


def match_score(user, business):
    score = 0

    if (
        user["city"]
        and business["city"]
        and user["city"].lower()
        == business["city"].lower()
    ):
        score += 25

    if (
        user["investment"]
        >= business["partner_investment"]
        > 0
    ):
        score += 35

    user_interests = set(
        x.strip().lower()
        for x in (user["interests"] or "").split(",")
        if x.strip()
    )

    business_categories = set(
        x.strip().lower()
        for x in (business["category"] or "").split(",")
        if x.strip()
    )

    if user_interests & business_categories:
        score += 25

    if user["skills"]:
        score += 15

    return min(score, 100)


@app.get("/")
def home():
    return FileResponse("static/index.html")


@app.post("/api/register")
def register(data: Register):

    if len(data.password) < 8:
        raise HTTPException(
            400,
            "Password must be at least 8 characters"
        )

    if len(data.password.encode("utf-8")) > 72:
        raise HTTPException(
            400,
            "Password must be 72 bytes or less"
        )

    if data.role not in ("partner", "owner"):
        raise HTTPException(
            400,
            "Invalid role"
        )

    c = db()

    try:
        cur = c.execute(
            """
            INSERT INTO users
            (
                name,email,password,city,skills,
                investment,interests,role,created_at
            )
            VALUES(?,?,?,?,?,?,?,?,?)
            """,
            (
                data.name,
                str(data.email),
                hash_password(data.password),
                data.city,
                data.skills,
                data.investment,
                data.interests,
                data.role,
                datetime.utcnow().isoformat()
            )
        )

        uid = cur.lastrowid
        c.commit()

    except sqlite3.IntegrityError:
        c.close()
        raise HTTPException(
            409,
            "Email already registered"
        )

    c.close()

    return {
        "token": create_token(uid),
        "user_id": uid
    }


@app.post("/api/login")
def login(data: Login):

    c = db()

    user = c.execute(
        """
        SELECT * FROM users
        WHERE email=? AND blocked=0
        """,
        (str(data.email),)
    ).fetchone()

    c.close()

    if not user:
        raise HTTPException(
            401,
            "Wrong email or password"
        )

    if not verify_password(
        data.password,
        user["password"]
    ):
        raise HTTPException(
            401,
            "Wrong email or password"
        )

    return {
        "token": create_token(user["id"]),
        "user": dict(user)
    }


@app.get("/api/me")
def get_me(user=Depends(current_user)):
    return {
        key: value
        for key, value in user.items()
        if key != "password"
    }


@app.put("/api/me")
def update_profile(
    data: Profile,
    user=Depends(current_user)
):

    values = {
        key: value
        for key, value in data.model_dump().items()
        if value is not None
    }

    if not values:
        return {"ok": True}

    c = db()

    sets = ",".join(
        f"{key}=?"
        for key in values
    )

    c.execute(
        f"UPDATE users SET {sets} WHERE id=?",
        [
            *values.values(),
            user["id"]
        ]
    )

    c.commit()
    c.close()

    return {"ok": True}


@app.post("/api/businesses")
def create_business(
    data
