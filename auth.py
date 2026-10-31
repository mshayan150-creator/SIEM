"""Shared-organization identities. SQLite persists identities; Redis holds short-lived sessions.

One host with a local persistent disk is supported. Do not put SQLite on NFS or
run independent copies across hosts. Passwords use OWASP's scrypt N=2^14/r=8/p=5.
"""
import asyncio
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from fastapi import HTTPException, Request

from cache import PREFIX

COOKIE = "siem_session"
USERNAME = re.compile(r"[a-z0-9][a-z0-9_.-]{2,63}")
HOSTNAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,252}")
RATE_LUA = "local n=redis.call('INCR',KEYS[1]); if n==1 then redis.call('EXPIRE',KEYS[1],60) end; return n"


def password_hash(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=5, dklen=32)
    return salt + ":" + digest.hex()


def password_matches(password: str, stored: str) -> bool:
    return hmac.compare_digest(password_hash(password, stored.split(":")[0]), stored)


def validate_password(password: str) -> None:
    if not 15 <= len(password) <= 128 or len(set(password)) < 6:
        raise ValueError("Use a unique password of 15–128 characters with at least six distinct characters")


class IdentityStore:
    def __init__(self, path: str) -> None:
        self.path = path

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            yield db
        finally:
            db.close()

    def initialize(self) -> None:
        Path(self.path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self.connection() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript('''
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY, password TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('admin','viewer')),
                    enabled INTEGER NOT NULL DEFAULT 1, version INTEGER NOT NULL DEFAULT 1);
                CREATE TABLE IF NOT EXISTS collectors (
                    id TEXT PRIMARY KEY, host TEXT NOT NULL, token_hash TEXT UNIQUE NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1);
                CREATE TABLE IF NOT EXISTS audit (
                    id INTEGER PRIMARY KEY, at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
                    actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL);
            ''')
        os.chmod(self.path, 0o600)

    @staticmethod
    def audit(db: sqlite3.Connection, actor: str, action: str, target: str) -> None:
        db.execute("INSERT INTO audit(actor,action,target) VALUES(?,?,?)", (actor, action, target))
        db.execute("DELETE FROM audit WHERE id <= (SELECT COALESCE(MAX(id),0)-10000 FROM audit)")

    def create_user(self, username: str, password: str, role: str, actor: str = "operator") -> None:
        if not USERNAME.fullmatch(username) or role not in {"admin", "viewer"}:
            raise ValueError("Username must be 3–64 lowercase letters, digits, dots, underscores or hyphens; role admin/viewer")
        validate_password(password)
        hashed = password_hash(password)
        with self.connection() as db, db:
            try:
                db.execute("INSERT INTO users(username,password,role) VALUES(?,?,?)", (username, hashed, role))
            except sqlite3.IntegrityError:
                raise ValueError("Username already exists") from None
            self.audit(db, actor, "user_created", username)

    def user(self, username: str) -> dict[str, Any] | None:
        with self.connection() as db:
            row = db.execute("SELECT username,role,enabled,version FROM users WHERE username=?", (username,)).fetchone()
            return dict(row) if row else None

    def authenticate(self, username: str, password: str) -> dict[str, Any] | None:
        with self.connection() as db:
            row = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        # Same expensive hash operation for unknown usernames, disabled accounts and bad passwords.
        stored = row["password"] if row else "00" * 16 + ":" + "00" * 32
        valid = password_matches(password, stored)
        if not row or not row["enabled"] or not valid:
            return None
        return {k: row[k] for k in ("username", "role", "version")}

    def update_user(self, username: str, enabled: bool | None = None, password: str | None = None,
                    actor: str = "operator") -> None:
        hashed = None
        if password is not None:
            validate_password(password)
            hashed = password_hash(password)
        with self.connection() as db, db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            if not row:
                raise ValueError("User not found")
            if enabled is False and row["enabled"] and row["role"] == "admin":
                count = db.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND enabled=1").fetchone()[0]
                if count <= 1:
                    raise ValueError("Cannot disable the last active administrator")
            db.execute("UPDATE users SET enabled=?, password=?, version=version+1 WHERE username=?",
                       (row["enabled"] if enabled is None else int(enabled), hashed or row["password"], username))
            self.audit(db, actor, "user_updated_sessions_revoked", username)

    def create_collector(self, host: str, actor: str = "operator") -> dict[str, str]:
        if not HOSTNAME.fullmatch(host):
            raise ValueError("Use the computer's hostname: letters, digits, dots, underscores and hyphens")
        identity, secret = secrets.token_hex(16), secrets.token_urlsafe(32)
        token = identity + "." + secret
        with self.connection() as db, db:
            db.execute("INSERT INTO collectors(id,host,token_hash) VALUES(?,?,?)",
                       (identity, host, hashlib.sha256(token.encode()).hexdigest()))
            self.audit(db, actor, "collector_created", identity)
        return {"collector_id": identity, "host": host, "token": token}

    def collector(self, token: str) -> dict[str, Any] | None:
        if len(token) > 256:
            return None
        with self.connection() as db:
            row = db.execute("SELECT id,host FROM collectors WHERE token_hash=? AND enabled=1",
                             (hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
            return dict(row) if row else None

    def revoke_collector(self, identity: str, actor: str = "operator") -> None:
        with self.connection() as db, db:
            cursor = db.execute("UPDATE collectors SET enabled=0 WHERE id=?", (identity,))
            if not cursor.rowcount:
                raise ValueError("Collector not found")
            self.audit(db, actor, "collector_revoked", identity)

    def inventory(self) -> dict[str, Any]:
        with self.connection() as db:
            return {
                "users": [dict(r) for r in db.execute("SELECT username,role,enabled FROM users ORDER BY username")],
                "collectors": [dict(r) for r in db.execute("SELECT id,host,enabled FROM collectors ORDER BY host")],
                "audit": [dict(r) for r in db.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 100")],
            }


async def small_body(request: Request, maximum: int = 8192) -> bytes:
    body = bytearray()
    try:
        async with asyncio.timeout(10):
            async for chunk in request.stream():
                if len(body) + len(chunk) > maximum:
                    raise HTTPException(413, "Body too large")
                body.extend(chunk)
    except TimeoutError:
        raise HTTPException(408, "Request body timeout") from None
    return bytes(body)


def same_origin(request: Request) -> None:
    configured = request.app.state.settings.public_origin
    expected = configured or str(request.base_url).rstrip("/")
    if request.headers.get("origin") != expected:
        raise HTTPException(403, "Same-origin browser request required")


async def rate_limit(request: Request, namespace: str, identity: str, maximum: int) -> None:
    key = PREFIX + "rate:" + namespace + ":" + hashlib.sha256(identity.encode()).hexdigest()
    count = await request.app.state.cache.redis.register_script(RATE_LUA)(keys=[key], args=[])
    if int(count) > maximum:
        raise HTTPException(429, "Too many requests; try again in one minute", headers={"Retry-After": "60"})


async def session(request: Request) -> dict[str, Any]:
    token = request.cookies.get(COOKIE, "")
    if not token or len(token) > 128:
        raise HTTPException(401, "Sign in to the dashboard")
    key = PREFIX + "session:" + hashlib.sha256(token.encode()).hexdigest()
    raw = await request.app.state.cache.redis.get(key)
    if not raw:
        raise HTTPException(401, "Session expired")
    try:
        saved = json.loads(raw)
        user = await asyncio.to_thread(request.app.state.identities.user, saved["username"])
        if user and user["enabled"] and user["version"] == saved["version"]:
            return user
    except (ValueError, KeyError, TypeError):
        pass
    raise HTTPException(401, "Session revoked; sign in again")


async def admin(request: Request) -> dict[str, Any]:
    user = await session(request)
    if user["role"] != "admin":
        raise HTTPException(403, "Administrator access required")
    if request.method != "GET":
        same_origin(request)
    return user


async def collector_auth(request: Request) -> dict[str, Any]:
    authorization = request.headers.get("authorization", "")
    if not authorization.startswith("Bearer ") or len(authorization) > 263:
        raise HTTPException(401, "Invalid collector credentials")
    collector = await asyncio.to_thread(request.app.state.identities.collector, authorization[7:])
    if collector is None:
        raise HTTPException(401, "Invalid or revoked collector credentials")
    return collector
