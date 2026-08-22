import os, sqlite3, secrets
from datetime import datetime, timedelta
from typing import Optional

import jwt
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext

DB = "data/partnerhub.db"
os.makedirs("data", exist_ok=True)

SECRET = os.getenv("SECRET_KEY", "dev-only-change-this-secret")

pwd = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto"
)

app = FastAPI(
    title="PartnerHub API",
    version="1.0"
)

app.mount(
    "/static",
    StaticFiles(directory="static"),
    name="static"
)


def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c


def init():
    c = db()

    c.executescript("""
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      city TEXT,
      skills TEXT,
      investment INTEGER DEFAULT 0,
      interests TEXT,
     
