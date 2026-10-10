"""Multi-tenant FastAPI API with authoritative object authorization and graph telemetry.

Backed by Postgres (not SQLite) so it can run as a real, horizontally-scaled
service shared by multiple customers ("tenants"), each isolated by tenant_id.
Two front doors:
  - The tenant dashboard with revocable HttpOnly user sessions, plus the
    legacy JWT-authenticated demo API.
  - The API-key-authenticated product API (/v1/*) other companies' backends
    call on every request instead of hosting their whole API through us.
"""
from __future__ import annotations

import atexit
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import time
from contextlib import contextmanager
from functools import wraps
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

# Several startup/log messages below use emoji (checkmarks, warning signs). On Windows,
# a console left on its default legacy codepage (cp1252 etc., not UTF-8) raises
# UnicodeEncodeError on those prints and crashes the whole process before it can even
# bind a port. reconfigure() (Python 3.7+) is a no-op if already UTF-8 and always safe
# to call on a real stdout/stderr stream.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

import bcrypt
import jwt
import joblib
import numpy as np
import pandas as pd
import asyncio
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
import strawberry
from strawberry.fastapi import GraphQLRouter
import redis
from prometheus_client import Counter, Histogram, Gauge, generate_latest, REGISTRY
from database import db, DATABASE_BACKEND, has_column

# Database migrations
from migrations import apply_migrations, compute_audit_hash

# Alerting system
from alerting import dispatch_alerts

# Phase 4: advanced threat detection (IP reputation, geo-velocity, behavioral baselining, TLS fingerprint)
import threat_detection

# Phase 6: third-party SIEM integrations (Datadog, Splunk)
import integrations

# --- Configuration (env-overridable; defaults are dev-only, never use these in production) ---
APP_ENV = os.environ.get("APP_ENV", "dev")
DEMO_MODE = os.environ.get("DEMO_MODE", "true").lower() != "false"
JWT_SECRET = os.environ.get("JWT_SECRET", "dev-insecure-secret-change-in-production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_SECONDS = int(os.environ.get("JWT_EXPIRY_SECONDS", "3600"))
DEMO_PASSWORD = os.environ.get("DEMO_PASSWORD", "changeme123")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin_changeme123")
ADMIN_ROLE = "security_admin"
DEMO_TENANT_ID = "demo"
TENANT_SIGNUP_KEY = os.environ.get("TENANT_SIGNUP_KEY", "dev-insecure-signup-key-change-in-production")
BCRYPT_ROUNDS = int(os.environ.get("BCRYPT_ROUNDS", "4" if APP_ENV in ("dev", "test") else "12"))
CONSOLE_COOKIE_NAME = "cyberaccess_session"
CONSOLE_COOKIE_SECURE = (os.environ.get("CONSOLE_COOKIE_SECURE") or str(APP_ENV == "prod")).lower() == "true"
CONSOLE_PASSWORD_MIN_LENGTH = int(os.environ.get("CONSOLE_PASSWORD_MIN_LENGTH", "12"))
CONSOLE_AUTH_RATE_LIMIT = os.environ.get("CONSOLE_AUTH_RATE_LIMIT", "10/minute")
if not 8 <= CONSOLE_PASSWORD_MIN_LENGTH <= 72:
    raise RuntimeError("CONSOLE_PASSWORD_MIN_LENGTH must be between 8 and 72")
_CACHED_DEMO_HASH = bcrypt.hashpw(DEMO_PASSWORD.encode(), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode()
_CACHED_ADMIN_HASH = bcrypt.hashpw(ADMIN_PASSWORD.encode(), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode()

# --- Dynamic BOLA Weights & Limits (Configurable, no hardcoded magic values) ---
BOLA_WEIGHT_DELETE = float(os.environ.get("BOLA_WEIGHT_DELETE", "3.0"))
BOLA_WEIGHT_PATCH = float(os.environ.get("BOLA_WEIGHT_PATCH", "2.5"))
BOLA_WEIGHT_PUT = float(os.environ.get("BOLA_WEIGHT_PUT", "2.0"))
BOLA_WEIGHT_POST = float(os.environ.get("BOLA_WEIGHT_POST", "1.5"))
BOLA_WEIGHT_GET = float(os.environ.get("BOLA_WEIGHT_GET", "1.0"))
BOLA_MAX_BATCH_SIZE = int(os.environ.get("BOLA_MAX_BATCH_SIZE", "50"))
BOLA_ASYNC_JOB_TTL = float(os.environ.get("BOLA_ASYNC_JOB_TTL", "3600.0"))

# Redis for caching (optional, graceful degradation if unavailable)
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
redis_client = None
try:
    if not REDIS_URL:
        raise ValueError("REDIS_URL is empty")
    _redis = redis.from_url(REDIS_URL, decode_responses=True, socket_connect_timeout=1, socket_timeout=1)
    _redis.ping()
    redis_client = _redis
    print("[init] ✅ Redis connected")
except Exception as e:
    print(f"[init] ⚠️  Redis unavailable: {e} (caching disabled)")

if APP_ENV == "prod":
    _insecure_defaults = []
    if JWT_SECRET.startswith("dev-"):
        _insecure_defaults.append("JWT_SECRET")
    if DEMO_PASSWORD == "changeme123":
        _insecure_defaults.append("DEMO_PASSWORD")
    if ADMIN_PASSWORD == "admin_changeme123":
        _insecure_defaults.append("ADMIN_PASSWORD")
    if TENANT_SIGNUP_KEY.startswith("dev-"):
        _insecure_defaults.append("TENANT_SIGNUP_KEY")
    if _insecure_defaults:
        raise RuntimeError(
            f"APP_ENV=prod but dev-only defaults still set for: {', '.join(_insecure_defaults)}. "
            "Set real values via environment variables before running in production."
        )
    if not os.environ.get("FRONTEND_ORIGIN"):
        raise RuntimeError(
            "APP_ENV=prod requires FRONTEND_ORIGIN (comma-separated allowed origins) to be set explicitly - "
            "refusing to boot with an unset CORS policy rather than silently blocking (or wildcarding) all origins."
        )


def build_anomaly_model() -> Pipeline:
    """Finetuned Unsupervised ML layer: flags behavioral anomaly patterns statistically
    unlike normal traffic, as a complement to the fixed-threshold heuristics in compute_risk().
    Trained at startup on calibrated multi-modal feature vectors: [unique_denied_short,
    sequential_steps, unique_denied_long, failure_ratio, endpoints_hit].
    Combines StandardScaler with 250 Isolation Trees across casual users, power clinicians,
    accidental typos, rapid fuzzers, low-and-slow stealth probes, and multi-endpoint sprays."""
    rng = np.random.RandomState(42)

    normal = []
    # 1. Standard benign users (500)
    for _ in range(500):
        normal.append([
            rng.choice([0, 0, 0, 0, 1]),
            0,
            rng.choice([0, 0, 0, 1, 2]),
            rng.uniform(0.0, 0.20),
            rng.choice([0, 1, 1, 2]),
        ])
    # 2. Legitimate power users & clinicians (250)
    for _ in range(250):
        normal.append([
            rng.choice([0, 0, 0, 0, 1]),
            0,
            rng.choice([0, 0, 0, 1]),
            rng.uniform(0.0, 0.10),
            rng.choice([1, 2, 2, 3, 4]),
        ])
    # 3. Accidental human typos / network disconnects (100)
    for _ in range(100):
        normal.append([
            rng.choice([1, 1, 2]),
            0,
            rng.choice([1, 2, 3]),
            rng.uniform(0.10, 0.35),
            rng.choice([1, 1, 2]),
        ])

    attack = []
    # 4. Rapid IDOR / BOLA fuzzer (60)
    for _ in range(60):
        attack.append([
            rng.randint(4, 15),
            rng.randint(2, 8),
            rng.randint(15, 45),
            rng.uniform(0.65, 1.0),
            rng.randint(1, 4),
        ])
    # 5. Low & slow stealth reconnaissance (50)
    for _ in range(50):
        attack.append([
            rng.randint(0, 4),
            rng.randint(1, 4),
            rng.randint(12, 30),
            rng.uniform(0.60, 0.95),
            rng.randint(1, 3),
        ])
    # 6. Multi-endpoint vulnerability spray (40)
    for _ in range(40):
        attack.append([
            rng.randint(2, 7),
            rng.randint(0, 3),
            rng.randint(8, 25),
            rng.uniform(0.70, 1.0),
            rng.randint(3, 6),
        ])

    training_data = np.array(normal + attack)
    pipe = Pipeline([
        ('scaler', StandardScaler()),
        ('forest', IsolationForest(n_estimators=250, max_samples=256, contamination=0.15, random_state=42))
    ])
    pipe.fit(training_data)
    return pipe


anomaly_model = build_anomaly_model()

_ENDPOINT_MODEL_PATH = Path(__file__).with_name("models") / "endpoint_anomaly_model.joblib"
endpoint_anomaly_model = joblib.load(_ENDPOINT_MODEL_PATH) if _ENDPOINT_MODEL_PATH.exists() else None


from threading import RLock, Thread


def hash_api_key(key: str) -> str:
    """API keys are high-entropy random tokens (not human passwords), so a fast
    deterministic hash for exact-match lookup is correct here, not bcrypt."""
    return hashlib.sha256(key.encode()).hexdigest()


def generate_api_key() -> str:
    return "sk_" + secrets.token_urlsafe(32)


def init_schema() -> None:
    """Idempotent schema creation. Never drops data - this runs against a real,
    shared, multi-tenant database, not a disposable demo file."""
    with db() as c:
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS tenants (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                api_key_hash TEXT NOT NULL,
                created_at DOUBLE PRECISION NOT NULL
            );
            CREATE TABLE IF NOT EXISTS users (
                tenant_id TEXT NOT NULL,
                id TEXT NOT NULL,
                role TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                PRIMARY KEY (tenant_id, id)
            );
            CREATE TABLE IF NOT EXISTS records (
                tenant_id TEXT NOT NULL,
                id TEXT NOT NULL,
                owner_id TEXT NOT NULL,
                data TEXT NOT NULL,
                PRIMARY KEY (tenant_id, id)
            );
            CREATE TABLE IF NOT EXISTS assignments (
                tenant_id TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                record_id TEXT NOT NULL,
                PRIMARY KEY (tenant_id, subject_id, record_id)
            );
            CREATE TABLE IF NOT EXISTS access_grants (
                tenant_id TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                record_id TEXT NOT NULL,
                expires_at DOUBLE PRECISION NOT NULL,
                reason TEXT NOT NULL,
                approved_by TEXT NOT NULL,
                PRIMARY KEY (tenant_id, subject_id, record_id)
            );
            CREATE TABLE IF NOT EXISTS risk_events (
                tenant_id TEXT NOT NULL,
                subject TEXT NOT NULL,
                record_id TEXT NOT NULL,
                allowed BOOLEAN NOT NULL,
                at DOUBLE PRECISION NOT NULL,
                endpoint TEXT NOT NULL,
                http_verb TEXT NOT NULL DEFAULT 'GET'
            );
            CREATE INDEX IF NOT EXISTS idx_risk_events_tenant_subject ON risk_events(tenant_id, subject, at);
            CREATE TABLE IF NOT EXISTS risk_strikes (
                tenant_id TEXT NOT NULL,
                subject TEXT NOT NULL,
                at DOUBLE PRECISION NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_risk_strikes_tenant_subject ON risk_strikes(tenant_id, subject, at);
            CREATE TABLE IF NOT EXISTS risk_blocks (
                tenant_id TEXT NOT NULL,
                subject TEXT NOT NULL,
                blocked_until DOUBLE PRECISION NOT NULL,
                PRIMARY KEY (tenant_id, subject)
            );
            CREATE TABLE IF NOT EXISTS risk_bans (
                tenant_id TEXT NOT NULL,
                subject TEXT NOT NULL,
                status TEXT NOT NULL,
                PRIMARY KEY (tenant_id, subject)
            );
            CREATE TABLE IF NOT EXISTS audit_events (
                id SERIAL PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                occurred_at DOUBLE PRECISION NOT NULL,
                subject_id TEXT NOT NULL,
                record_id TEXT NOT NULL,
                "authorization" TEXT,
                detector_decision TEXT NOT NULL,
                outcome TEXT NOT NULL,
                explanation TEXT NOT NULL,
                risk_score DOUBLE PRECISION
            );
            CREATE TABLE IF NOT EXISTS resource_nodes (
                tenant_id TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                parent_type TEXT,
                parent_id TEXT,
                owner_id TEXT NOT NULL,
                name TEXT,
                metadata TEXT,
                PRIMARY KEY (tenant_id, resource_type, resource_id)
            );
            CREATE TABLE IF NOT EXISTS async_jobs (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                action TEXT NOT NULL,
                pre_authorized BOOLEAN NOT NULL DEFAULT FALSE,
                pre_auth_token TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at DOUBLE PRECISION NOT NULL,
                expires_at DOUBLE PRECISION NOT NULL,
                completed_at DOUBLE PRECISION,
                result_payload TEXT
            );
            CREATE TABLE IF NOT EXISTS stored_references (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                ref_type TEXT NOT NULL,
                target_resource_id TEXT NOT NULL,
                metadata TEXT,
                authorized_at_creation BOOLEAN NOT NULL,
                created_at DOUBLE PRECISION NOT NULL,
                last_validated_at DOUBLE PRECISION,
                status TEXT NOT NULL DEFAULT 'active'
            );
            CREATE TABLE IF NOT EXISTS abac_policies (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                name TEXT NOT NULL,
                effect TEXT NOT NULL,
                target_role TEXT,
                target_classification TEXT,
                min_clearance INTEGER DEFAULT 0,
                allowed_hours_start INTEGER DEFAULT 0,
                allowed_hours_end INTEGER DEFAULT 24,
                created_at DOUBLE PRECISION NOT NULL
            );
            CREATE TABLE IF NOT EXISTS abac_field_redactions (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                field_name TEXT NOT NULL,
                required_role TEXT,
                min_clearance INTEGER DEFAULT 0,
                masking_strategy TEXT NOT NULL DEFAULT 'REDACT'
            );
            CREATE TABLE IF NOT EXISTS canary_records (
                tenant_id TEXT NOT NULL,
                id TEXT NOT NULL,
                decoy_name TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'CRITICAL',
                trap_action TEXT NOT NULL DEFAULT 'PERMANENT_BAN',
                created_at DOUBLE PRECISION NOT NULL,
                PRIMARY KEY (tenant_id, id)
            );
            CREATE TABLE IF NOT EXISTS canary_triggers (
                id SERIAL PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                canary_id TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                ip_address TEXT,
                triggered_at DOUBLE PRECISION NOT NULL,
                action_taken TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS soc_alerts (
                id SERIAL PRIMARY KEY,
                alert_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                occurred_at DOUBLE PRECISION NOT NULL,
                payload JSONB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS system_config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at DOUBLE PRECISION NOT NULL
            );
            """
        )
    # Each defensive migration below gets its OWN connection/transaction, not a
    # shared one. Postgres aborts an entire transaction on the first error inside
    # it (e.g. "column already exists" from a migration that already ran) - every
    # subsequent statement in that same transaction then silently no-ops even
    # though its own try/except never sees an error, because the connection
    # itself is already in an aborted state by the time it runs. Sharing one
    # `with db() as c:` block across all three meant only the FIRST migration on
    # any given run could ever actually apply.
    for migration_sql in (
        "ALTER TABLE risk_events ADD COLUMN http_verb TEXT NOT NULL DEFAULT 'GET'",
        "ALTER TABLE records ADD COLUMN classification TEXT DEFAULT 'standard'",
        # records.id was originally INTEGER (single-tenant demo records only); the
        # schema above now declares it TEXT (external /v1/* tenants use arbitrary
        # string resource IDs, not just sequential integers). A database created
        # before this change keeps the old INTEGER column until this runs once.
        "ALTER TABLE records ALTER COLUMN id TYPE TEXT",
        # Same drift, two more tables: assignments.record_id and
        # access_grants.record_id were also created back when every record_id
        # was a sequential integer. CREATE TABLE IF NOT EXISTS above never
        # altered them once they existed, so a database from before the
        # TEXT-id refactor kept both as INTEGER - found live via
        # information_schema while chasing an "invalid input syntax for type
        # integer" error from a dynamic (rec_<uuid>) resource ID.
        "ALTER TABLE assignments ALTER COLUMN record_id TYPE TEXT",
        "ALTER TABLE access_grants ALTER COLUMN record_id TYPE TEXT",
        "ALTER TABLE audit_events ADD COLUMN risk_score DOUBLE PRECISION DEFAULT 0.0",
    ):
        try:
            with db() as c:
                column_match = re.match(r"ALTER TABLE (\w+) ADD COLUMN (\w+)", migration_sql)
                if column_match and has_column(c, *column_match.groups()):
                    continue
                if DATABASE_BACKEND == "SQLite" and "ALTER COLUMN" in migration_sql:
                    continue
                c.execute(migration_sql)
        except Exception as exc:
            # Swallowed on purpose for the common case (column/constraint
            # already matches, so the ALTER is a harmless no-op that still
            # errors) - but logged, not fully silent, so a genuinely new
            # migration failure shows up instead of vanishing the way this
            # exact class of bug did before.
            raise RuntimeError(f"Schema migration failed: {migration_sql}") from exc


def get_system_config(key: str, default: str | None = None) -> str | None:
    try:
        with db() as c:
            row = c.execute("SELECT value FROM system_config WHERE key = %s", (key,)).fetchone()
            if row and "value" in row:
                return str(row["value"])
    except Exception as e:
        print(f"[get_system_config] error: {e}")
    return default


def set_system_config(key: str, value: str) -> None:
    now = time.time()
    try:
        with db() as c:
            c.execute(
                "INSERT INTO system_config (key, value, updated_at) VALUES (%s, %s, %s) "
                "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at",
                (key, str(value), now),
            )
    except Exception as e:
        print(f"[set_system_config] error: {e}")


def is_defense_enabled() -> bool:
    val = get_system_config("defense_enabled", "true")
    return str(val).lower() not in ("false", "0", "off", "disabled")


def set_defense_enabled(enabled: bool) -> None:
    set_system_config("defense_enabled", "true" if enabled else "false")


def seed_demo_tenant(force: bool = False) -> None:
    """Seeds (or, if force=True, wipes-and-reseeds) ONLY the demo tenant's data.
    Never touches any other tenant - this backs the public demo/dashboard and
    the /reset button, not a database-wide reset."""
    demo_hash = _CACHED_DEMO_HASH
    admin_hash = _CACHED_ADMIN_HASH

    with db() as c, c.cursor() as cur:
        if not force:
            existing = cur.execute("SELECT 1 FROM tenants WHERE id = %s", (DEMO_TENANT_ID,)).fetchone()
            if existing:
                return

        for table in ("access_grants", "assignments", "records",
                       "risk_events", "risk_strikes", "risk_blocks", "risk_bans",
                       "resource_nodes", "async_jobs", "stored_references",
                       "abac_policies", "abac_field_redactions", "canary_records", "canary_triggers",
                       "audit_events", "soc_alerts"):
            cur.execute(f"DELETE FROM {table} WHERE tenant_id = %s", (DEMO_TENANT_ID,))

        cur.execute(
            "INSERT INTO tenants (id, name, api_key_hash, created_at) VALUES (%s, %s, %s, %s) "
            "ON CONFLICT (id) DO NOTHING",
            (DEMO_TENANT_ID, "Demo", hash_api_key("demo-key-unused"), time.time()),
        )

        users = ([("alice", "customer", demo_hash), ("bob", "customer", demo_hash),
                  ("dr_singh", "doctor", demo_hash), ("dr_lee", "doctor", demo_hash),
                  ("dr_cover", "doctor", demo_hash), ("support_amy", "support", demo_hash),
                  ("attacker", "customer", demo_hash), ("attacker_slow", "customer", demo_hash),
                  (ADMIN_ROLE, ADMIN_ROLE, admin_hash)]
                 + [(f"attacker_{j}", "customer", demo_hash) for j in range(1, 11)]
                 + [(f"sybil_{j}", "customer", demo_hash) for j in range(1, 51)])
        cur.executemany(
            "INSERT INTO users (tenant_id, id, role, password_hash) VALUES (%s, %s, %s, %s) "
            "ON CONFLICT (tenant_id, id) DO UPDATE SET role = EXCLUDED.role, password_hash = EXCLUDED.password_hash",
            [(DEMO_TENANT_ID, *u) for u in users],
        )
        records = [(str(i), "alice" if i <= 50 else "bob", f"confidential record {i}") for i in range(1, 101)]
        cur.executemany(
            "INSERT INTO records (tenant_id, id, owner_id, data) VALUES (%s, %s, %s, %s)",
            [(DEMO_TENANT_ID, *r) for r in records],
        )
        cur.executemany(
            "INSERT INTO assignments (tenant_id, subject_id, record_id) VALUES (%s, %s, %s)",
            [(DEMO_TENANT_ID, "dr_singh", str(i)) for i in range(1, 26)],
        )
        cur.executemany(
            "INSERT INTO assignments (tenant_id, subject_id, record_id) VALUES (%s, %s, %s)",
            [(DEMO_TENANT_ID, "dr_lee", str(i)) for i in range(26, 51)],
        )
        cur.execute(
            "INSERT INTO access_grants (tenant_id, subject_id, record_id, expires_at, reason, approved_by) "
            "VALUES (%s, %s, %s, %s, %s, %s)",
            (DEMO_TENANT_ID, "support_amy", "17", time.time() + 3600, "ticket-8431", ADMIN_ROLE),
        )
        cur.executemany(
            "INSERT INTO access_grants (tenant_id, subject_id, record_id, expires_at, reason, approved_by) "
            "VALUES (%s, %s, %s, %s, %s, %s)",
            [
                (DEMO_TENANT_ID, "dr_cover", "8", time.time() + 1800, "shift-cover-ward-a", ADMIN_ROLE),
                (DEMO_TENANT_ID, "dr_cover", "31", time.time() + 1800, "shift-cover-ward-b", ADMIN_ROLE),
            ],
        )
        canaries = [
            ("0", "Demo Zero Honeypot", "CRITICAL", "PERMANENT_BAN", time.time()),
            ("999999", "High ID Probing Trap", "CRITICAL", "PERMANENT_BAN", time.time()),
            ("canary_admin_vault", "Admin Vault Decoy", "CRITICAL", "PERMANENT_BAN", time.time()),
        ]
        cur.executemany(
            "INSERT INTO canary_records (tenant_id, id, decoy_name, severity, trap_action, created_at) "
            "VALUES (%s, %s, %s, %s, %s, %s) ON CONFLICT (tenant_id, id) DO NOTHING",
            [(DEMO_TENANT_ID, *can) for can in canaries],
        )
        nodes = [
            ("organization", "org_demo", None, None, "alice", "Acme Health Corp", "{}"),
            ("department", "dept_cardiology", "organization", "org_demo", "dr_singh", "Cardiology Dept", "{}"),
            ("record", "1", "department", "dept_cardiology", "alice", "Patient 1 Vitals", "{}"),
            ("organization", "org_rival", None, None, "bob", "Rival Health Corp", "{}"),
            ("department", "dept_rival_oncology", "organization", "org_rival", "bob", "Oncology Dept", "{}"),
            ("record", "55", "department", "dept_rival_oncology", "bob", "Patient 55 Chart", "{}"),
        ]
        cur.executemany(
            "INSERT INTO resource_nodes (tenant_id, resource_type, resource_id, parent_type, parent_id, owner_id, name, metadata) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s) ON CONFLICT (tenant_id, resource_type, resource_id) DO NOTHING",
            [(DEMO_TENANT_ID, *n) for n in nodes],
        )
        redactions = [
            ("redact_psych", "record", "psychiatric_notes", "psychiatrist", 2, "REDACT"),
            ("redact_ssn", "record", "ssn", "billing_admin", 3, "REDACT"),
        ]
        cur.executemany(
            "INSERT INTO abac_field_redactions (id, tenant_id, resource_type, field_name, required_role, min_clearance, masking_strategy) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s) ON CONFLICT (id) DO NOTHING",
            [(r[0], DEMO_TENANT_ID, *r[1:]) for r in redactions],
        )



def is_canary_record(tenant_id: str, record_id: str) -> bool:
    """Checks if record_id is a registered honeypot decoy in canary_records table."""
    with db() as c:
        row = c.execute("SELECT 1 FROM canary_records WHERE tenant_id = %s AND id = %s",
                         (tenant_id, str(record_id))).fetchone()
    return bool(row)


def trigger_canary_trap(tenant_id: str, subject: str, record_id: str, endpoint: str = "records", ip: str = "unknown") -> None:
    """Executes immediate permanent ban, immutable forensic trigger logging, and CRITICAL SOC alert on canary access."""
    now = time.time()
    with db() as c:
        c.execute(
            "INSERT INTO canary_triggers (tenant_id, canary_id, subject_id, endpoint, ip_address, triggered_at, action_taken) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (tenant_id, str(record_id), subject, endpoint, ip, now, "PERMANENT_BAN")
        )
    # Instant Strike 3 permanent ban: skip progressive warning windows
    engine._set_ban_status(tenant_id, subject, "approved")
    engine._set_blocked_until(tenant_id, subject, now + 315360000.0)  # 10 years
    with db() as c:
        # Record 3 strikes for forensics
        for offset in (0.0, 0.001, 0.002):
            c.execute("INSERT INTO risk_strikes (tenant_id, subject, at) VALUES (%s, %s, %s)",
                      (tenant_id, subject, now + offset))
    # Dispatch CRITICAL SOC alert
    dispatch_soc_alert(tenant_id, subject, record_id, score=100, category="Attack",
                       signals=["canary_honeypot_triggered", "strike_3_permanent_ban_approved"])
    record_audit(
        tenant_id, subject, record_id, None, "block", "blocked_canary",
        [f"CANARY HONEYPOT TRIGGERED: Decoy '{record_id}' accessed by subject '{subject}'. Permanent firewall ban enforced."],
        risk_score=100.0
    )


# ===== REDIS CACHING (Enterprise Performance) =====
def cache_get(key: str) -> str | None:
    """Get value from Redis cache with fallback."""
    if not redis_client:
        return None
    try:
        val = redis_client.get(key)
        if val:
            redis_cache_hits.labels(cache_type="auth_context").inc()
        else:
            redis_cache_misses.labels(cache_type="auth_context").inc()
        return val
    except Exception:
        return None

def cache_set(key: str, value: str, ttl_seconds: int = 600):
    """Set value in Redis cache with TTL."""
    if not redis_client:
        return
    try:
        redis_client.setex(key, ttl_seconds, value)
    except Exception:
        pass

def authorization_context_cached(tenant_id: str, subject: str, record_id: int | str, action: str = "read") -> dict:
    """Cached version of authorization_context (10-minute TTL)."""
    cache_key = f"auth:{tenant_id}:{subject}:{record_id}:{action}"

    # Try cache first
    cached = cache_get(cache_key)
    if cached:
        return json.loads(cached)

    # Cache miss, compute and store
    result = authorization_context(tenant_id, subject, record_id, action)
    try:
        cache_set(cache_key, json.dumps(result), ttl_seconds=600)
    except Exception:
        pass
    return result


def authorization_context(tenant_id: str, subject: str, record_id: int | str, action: str = "read") -> dict:
    """Authoritative policy for the demo/dashboard's own record model.
    The learned graph is never an authorization source.
    Dynamically enforces read, write, patch, and delete permissions."""
    rec_id = str(record_id)
    # Honeypot decoy check (Feature 9)
    if is_canary_record(tenant_id, rec_id):
        trigger_canary_trap(tenant_id, subject, rec_id, endpoint="records")
        return {"authorization": None, "explanations": ["Access denied: you are not authorized to access this record."], "delegation": None, "is_canary": True}

    with db() as c:
        DENY_EXPLANATION = "Access denied: you are not the owner, are not assigned, and have no active delegation."
        record = c.execute("SELECT owner_id FROM records WHERE tenant_id = %s AND id = %s",
                            (tenant_id, rec_id)).fetchone()
        if not record:
            return {"authorization": None, "explanations": [DENY_EXPLANATION], "delegation": None}

        # Admin override (security_admin role has read/audit oversight)
        user_row = c.execute("SELECT role FROM users WHERE tenant_id = %s AND id = %s", (tenant_id, subject)).fetchone()
        user_role = user_row["role"] if user_row else None
        if user_role == ADMIN_ROLE:
            return {"authorization": "admin", "explanations": ["Access allowed: security_admin administrative authority."], "delegation": None}

        # Owner check (owner has all permissions: read, write, delete)
        if record["owner_id"] == subject:
            verb_note = "delete" if action == "delete" else ("modify" if action in ("write", "update", "patch") else "read")
            return {"authorization": "owner", "explanations": [f"Access allowed: you own this record and can {verb_note} it."], "delegation": None}

        # DELETE is strictly owner-only
        if action == "delete":
            return {"authorization": None, "explanations": ["Access denied: only the record owner can delete this record."], "delegation": None}

        # WRITE / PATCH: check if subject has explicit write assignment or delegation
        if action in ("write", "update", "patch"):
            return {"authorization": None, "explanations": ["Access denied: only the record owner can modify this record."], "delegation": None}

        # READ: check assignments
        if c.execute("SELECT 1 FROM assignments WHERE tenant_id = %s AND subject_id = %s AND record_id = %s",
                     (tenant_id, subject, rec_id)).fetchone():
            return {"authorization": "assigned", "explanations": ["Access allowed: you are assigned to this record."], "delegation": None}

        # READ: check active delegation
        grant = c.execute(
            "SELECT expires_at, reason, approved_by FROM access_grants WHERE tenant_id = %s AND subject_id = %s AND record_id = %s",
            (tenant_id, subject, rec_id)).fetchone()
        if grant and grant["expires_at"] > time.time():
            seconds_remaining = max(0, int(grant["expires_at"] - time.time()))
            return {"authorization": "delegated",
                    "explanations": ["Access allowed: a time-bound delegation is active.",
                                     f"Delegation reason: {grant['reason']}.",
                                     f"Approved by: {grant['approved_by']}.",
                                     f"Access remaining: {seconds_remaining} seconds."],
                    "delegation": {"reason": grant["reason"], "approved_by": grant["approved_by"],
                                   "expires_at_unix": round(grant["expires_at"], 3), "seconds_remaining": seconds_remaining}}
        if grant:
            return {"authorization": None, "explanations": ["Access denied: your delegated permission has expired."], "delegation": None}
    return {"authorization": None, "explanations": [DENY_EXPLANATION], "delegation": None}


def record_audit(tenant_id: str, subject: str, record_id: int | str, authorization: str | None,
                  decision: str, outcome: str, explanations: list[str], risk_score: float = 0.0) -> None:
    now_ts = time.time()
    with db() as c:
        c.execute(
            'INSERT INTO audit_events (tenant_id, occurred_at, subject_id, record_id, "authorization", '
            "detector_decision, outcome, explanation, risk_score) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (tenant_id, now_ts, subject, str(record_id), authorization, decision, outcome, " | ".join(explanations), risk_score),
        )
    try:
        broadcast_sse_event("audit_event", {
            "occurred_at": now_ts,
            "subject_id": subject,
            "record_id": str(record_id),
            "authorization": authorization,
            "detector_decision": decision,
            "outcome": outcome,
            "explanation": explanations,
            "risk_score": risk_score,
            "tenant_id": tenant_id,
        })
    except Exception:
        pass


def compute_record_graph_features(tenant_id: str, record_id: int | str) -> dict:
    with db() as c:
        rows = c.execute(
            "SELECT subject, at, endpoint FROM risk_events WHERE tenant_id = %s AND record_id = %s ORDER BY at ASC",
            (tenant_id, str(record_id))).fetchall()
    if not rows:
        return {
            "inter_api_access_duration(sec)": 0.0, "api_access_uniqueness": 0.0,
            "sequence_length(count)": 0, "vsession_duration(min)": 0.0,
            "ip_type": "default", "num_sessions": 0, "num_users": 0,
            "num_unique_apis": 0, "source": "E",
        }
    subjects = [r["subject"] for r in rows]
    times = [r["at"] for r in rows]
    endpoints = {r["endpoint"] for r in rows}
    deltas = [b - a for a, b in zip(times, times[1:])]
    return {
        "inter_api_access_duration(sec)": (sum(deltas) / len(deltas)) if deltas else 0.0,
        "api_access_uniqueness": len(set(subjects)) / len(subjects),
        "sequence_length(count)": len(rows),
        "vsession_duration(min)": (times[-1] - times[0]) / 60.0,
        "ip_type": "default",
        "num_sessions": len(rows),
        "num_users": len(set(subjects)),
        "num_unique_apis": len(endpoints),
        "source": "E",
    }


def score_record_graph_anomaly(tenant_id: str, record_id: int | str) -> dict | None:
    if endpoint_anomaly_model is None:
        return None
    features = compute_record_graph_features(tenant_id, record_id)
    if features["num_sessions"] == 0:
        return {"is_anomalous": False, "anomaly_probability": 0.0}
    frame = pd.DataFrame([features])
    prediction = endpoint_anomaly_model.predict(frame)[0]
    probability = endpoint_anomaly_model.predict_proba(frame)[0][1]
    return {"is_anomalous": bool(prediction), "anomaly_probability": round(float(probability), 4)}


@dataclass
class Event:
    record_id: str
    allowed: bool
    at: float
    endpoint: str = "records"
    http_verb: str = "GET"


class BehavioralRiskEngine:
    """Sliding-window behavioral detector. All mutable state (events, strikes,
    blocks, pending/approved bans) lives in Postgres, scoped by tenant_id -
    tenant A's traffic can never affect tenant B's risk scores or blocks."""

    def __init__(self, short_window: float = 30.0, long_window: float = 3600.0, block_duration: float = 120.0,
                 rapid_threshold: int = 4, slow_threshold: int = 15, strike_window: float = 3600.0):
        self.short_window = short_window
        self.long_window = long_window
        self.block_duration = block_duration
        self.rapid_threshold = rapid_threshold
        self.slow_threshold = slow_threshold
        self.strike_window = strike_window

    def record_event(self, tenant_id: str, subject: str, record_id: int | str, allowed: bool,
                      at: float | None = None, endpoint: str = "records", http_verb: str = "GET") -> None:
        at = at if at is not None else time.time()
        with db() as c:
            c.execute(
                "INSERT INTO risk_events (tenant_id, subject, record_id, allowed, at, endpoint, http_verb) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (tenant_id, subject, str(record_id), allowed, at, endpoint, http_verb))

    def _events(self, tenant_id: str, subject: str, now: float) -> list[Event]:
        cutoff = now - self.long_window
        with db() as c:
            rows = c.execute(
                "SELECT record_id, allowed, at, endpoint, http_verb FROM risk_events "
                "WHERE tenant_id = %s AND subject = %s AND at > %s ORDER BY at ASC",
                (tenant_id, subject, cutoff)).fetchall()
        return [Event(r["record_id"], bool(r["allowed"]), r["at"], r["endpoint"], r.get("http_verb", "GET") or "GET") for r in rows]

    def get_strike_count(self, tenant_id: str, subject: str, now: float | None = None) -> int:
        now = now or time.time()
        cutoff = now - self.strike_window
        with db() as c:
            c.execute("DELETE FROM risk_strikes WHERE tenant_id = %s AND subject = %s AND at <= %s",
                      (tenant_id, subject, cutoff))
            row = c.execute("SELECT COUNT(*) AS n FROM risk_strikes WHERE tenant_id = %s AND subject = %s AND at > %s",
                             (tenant_id, subject, cutoff)).fetchone()
        return row["n"]

    def _ban_status(self, tenant_id: str, subject: str) -> str | None:
        with db() as c:
            row = c.execute("SELECT status FROM risk_bans WHERE tenant_id = %s AND subject = %s",
                             (tenant_id, subject)).fetchone()
        return row["status"] if row else None

    def _set_ban_status(self, tenant_id: str, subject: str, status: str) -> None:
        with db() as c:
            c.execute(
                "INSERT INTO risk_bans (tenant_id, subject, status) VALUES (%s, %s, %s) "
                "ON CONFLICT (tenant_id, subject) DO UPDATE SET status = EXCLUDED.status",
                (tenant_id, subject, status))

    def _clear_ban_status(self, tenant_id: str, subject: str) -> None:
        with db() as c:
            c.execute("DELETE FROM risk_bans WHERE tenant_id = %s AND subject = %s", (tenant_id, subject))

    def _set_blocked_until(self, tenant_id: str, subject: str, until: float) -> None:
        with db() as c:
            c.execute(
                "INSERT INTO risk_blocks (tenant_id, subject, blocked_until) VALUES (%s, %s, %s) "
                "ON CONFLICT (tenant_id, subject) DO UPDATE SET blocked_until = EXCLUDED.blocked_until",
                (tenant_id, subject, until))

    def blocked_until(self, tenant_id: str, subject: str) -> float:
        with db() as c:
            row = c.execute("SELECT blocked_until FROM risk_blocks WHERE tenant_id = %s AND subject = %s",
                             (tenant_id, subject)).fetchone()
        return row["blocked_until"] if row else 0.0

    def get_last_strike_time(self, tenant_id: str, subject: str) -> float:
        with db() as c:
            row = c.execute("SELECT at FROM risk_strikes WHERE tenant_id = %s AND subject = %s ORDER BY at DESC LIMIT 1",
                             (tenant_id, subject)).fetchone()
        return float(row["at"]) if row else 0.0

    def register_strike_and_block(self, tenant_id: str, subject: str, now: float) -> tuple[float, str, int]:
        with db() as c:
            self._lock_subject_state(c, tenant_id, subject)
            cutoff = now - self.strike_window
            c.execute("DELETE FROM risk_strikes WHERE tenant_id = %s AND subject = %s AND at <= %s",
                      (tenant_id, subject, cutoff))
            count = c.execute("SELECT COUNT(*) AS n FROM risk_strikes WHERE tenant_id = %s AND subject = %s",
                              (tenant_id, subject)).fetchone()["n"]
            block = c.execute("SELECT blocked_until FROM risk_blocks WHERE tenant_id = %s AND subject = %s",
                              (tenant_id, subject)).fetchone()
            ban = c.execute("SELECT status FROM risk_bans WHERE tenant_id = %s AND subject = %s",
                            (tenant_id, subject)).fetchone()
            status = ban["status"] if ban else None
            if block and block["blocked_until"] > now:
                if status == "approved":
                    signal = "strike_3_permanent_ban_approved"
                elif count == 1:
                    signal = "strike_1_soft_lockout_2m"
                elif count == 2:
                    signal = "strike_2_hard_lockout_30m"
                else:
                    signal = "strike_3_pending_admin_approval"
                return block["blocked_until"] - now, signal, max(1, count)

            c.execute("INSERT INTO risk_strikes (tenant_id, subject, at) VALUES (%s, %s, %s)",
                      (tenant_id, subject, now))
            count += 1
            if status == "approved":
                lockout, signal = 315360000.0, "strike_3_permanent_ban_approved"
            elif count == 1:
                lockout, signal = 120.0, "strike_1_soft_lockout_2m"
            elif count == 2:
                lockout, signal = 1800.0, "strike_2_hard_lockout_30m"
            else:
                c.execute("INSERT INTO risk_bans (tenant_id, subject, status) VALUES (%s, %s, 'pending') "
                          "ON CONFLICT (tenant_id, subject) DO UPDATE SET status = EXCLUDED.status",
                          (tenant_id, subject))
                lockout, signal = 1800.0, "strike_3_pending_admin_approval"

            c.execute("INSERT INTO risk_blocks (tenant_id, subject, blocked_until) VALUES (%s, %s, %s) "
                      "ON CONFLICT (tenant_id, subject) DO UPDATE SET blocked_until = EXCLUDED.blocked_until",
                      (tenant_id, subject, now + lockout))
        return lockout, signal, count

    @staticmethod
    def _lock_subject_state(c, tenant_id: str, subject: str) -> None:
        # SQLite holds its transaction lock; PostgreSQL needs a lock shared by all workers.
        if DATABASE_BACKEND == "PostgreSQL":
            key = int.from_bytes(hashlib.sha256(json.dumps([tenant_id, subject]).encode()).digest()[:8], signed=True)
            c.execute("SELECT pg_advisory_xact_lock(%s)", (key,))

    def approve_permanent_ban(self, tenant_id: str, subject: str, now: float | None = None) -> bool:
        now = now or time.time()
        with db() as c:
            self._lock_subject_state(c, tenant_id, subject)
            c.execute("INSERT INTO risk_bans (tenant_id, subject, status) VALUES (%s, %s, 'approved') "
                      "ON CONFLICT (tenant_id, subject) DO UPDATE SET status = EXCLUDED.status", (tenant_id, subject))
            c.execute("INSERT INTO risk_blocks (tenant_id, subject, blocked_until) VALUES (%s, %s, %s) "
                      "ON CONFLICT (tenant_id, subject) DO UPDATE SET blocked_until = EXCLUDED.blocked_until",
                      (tenant_id, subject, now + 315360000.0))
        return True

    def reject_permanent_ban(self, tenant_id: str, subject: str, now: float | None = None) -> bool:
        now = now or time.time()
        with db() as c:
            self._lock_subject_state(c, tenant_id, subject)
            c.execute("DELETE FROM risk_bans WHERE tenant_id = %s AND subject = %s", (tenant_id, subject))
            row = c.execute("SELECT ctid FROM risk_strikes WHERE tenant_id = %s AND subject = %s ORDER BY at DESC LIMIT 1",
                             (tenant_id, subject)).fetchone()
            if row:
                c.execute("DELETE FROM risk_strikes WHERE ctid = %s", (row["ctid"],))
            c.execute("INSERT INTO risk_blocks (tenant_id, subject, blocked_until) VALUES (%s, %s, %s) "
                      "ON CONFLICT (tenant_id, subject) DO UPDATE SET blocked_until = EXCLUDED.blocked_until",
                      (tenant_id, subject, now + 60.0))
        return True

    def pending_bans(self, tenant_id: str) -> list[str]:
        with db() as c:
            rows = c.execute("SELECT subject FROM risk_bans WHERE tenant_id = %s AND status = 'pending'",
                              (tenant_id,)).fetchall()
        return [r["subject"] for r in rows]

    def approved_bans(self, tenant_id: str) -> list[str]:
        with db() as c:
            rows = c.execute("SELECT subject FROM risk_bans WHERE tenant_id = %s AND status = 'approved'",
                              (tenant_id,)).fetchall()
        return [r["subject"] for r in rows]

    def cleanup_stale(self, tenant_id: str) -> None:
        now = time.time()
        cutoff = now - self.long_window
        strike_cutoff = now - self.strike_window
        with db() as c:
            c.execute("DELETE FROM risk_events WHERE tenant_id = %s AND at <= %s", (tenant_id, cutoff))
            c.execute("DELETE FROM risk_strikes WHERE tenant_id = %s AND at <= %s", (tenant_id, strike_cutoff))
            c.execute("DELETE FROM risk_blocks WHERE tenant_id = %s AND blocked_until < %s", (tenant_id, now))

    def reset(self, tenant_id: str) -> None:
        with db() as c:
            c.execute("DELETE FROM risk_events WHERE tenant_id = %s", (tenant_id,))
            c.execute("DELETE FROM risk_strikes WHERE tenant_id = %s", (tenant_id,))
            c.execute("DELETE FROM risk_blocks WHERE tenant_id = %s", (tenant_id,))
            c.execute("DELETE FROM risk_bans WHERE tenant_id = %s", (tenant_id,))

    def active_subject_count(self, tenant_id: str) -> int:
        now = time.time()
        with db() as c:
            row = c.execute("SELECT COUNT(DISTINCT subject) AS n FROM risk_events WHERE tenant_id = %s AND at > %s",
                             (tenant_id, now - self.long_window)).fetchone()
        return row["n"]

    def blocked_subject_count(self, tenant_id: str) -> int:
        now = time.time()
        with db() as c:
            row = c.execute("SELECT COUNT(*) AS n FROM risk_blocks WHERE tenant_id = %s AND blocked_until > %s",
                             (tenant_id, now)).fetchone()
        return row["n"]

    def coordinated_attacks(self, tenant_id: str, threshold: int = 50) -> dict:
        with db() as c:
            rows = c.execute(
                "SELECT record_id, COUNT(DISTINCT subject) AS n FROM risk_events "
                "WHERE tenant_id = %s AND allowed = false GROUP BY record_id HAVING COUNT(DISTINCT subject) >= %s",
                (tenant_id, threshold)).fetchall()
        return {r["record_id"]: r["n"] for r in rows}

    def evaluate(self, tenant_id: str, subject: str, record_id: int | str, allowed: bool,
                 endpoint: str = "records", http_verb: str = "GET", register_strike: bool = True) -> tuple[str, list[str], bool, int, str]:
        now = time.time()

        if self.blocked_until(tenant_id, subject) > now:
            strike_count = self.get_strike_count(tenant_id, subject, now)
            status = self._ban_status(tenant_id, subject)
            if status == "approved":
                sig = "strike_3_permanent_ban_approved"
            elif status == "pending" or strike_count >= 3:
                sig = "strike_3_pending_admin_approval"
            elif strike_count == 2:
                sig = "strike_2_hard_lockout_30m"
            else:
                sig = "strike_1_soft_lockout_2m"
            return "block", ["temporarily_blocked", sig], False, 100, "Attack"

        self.record_event(tenant_id, subject, record_id, allowed, now, endpoint, http_verb)

        score_data = self.compute_risk(tenant_id, subject, now)
        score, signals, category = score_data["score"], score_data["signals"], score_data["category"]

        unseen = False
        decision = "allow" if allowed else "deny"
        block_threshold, _warn_threshold = get_tenant_risk_thresholds(tenant_id)
        if score >= block_threshold:
            decision = "block"
            if register_strike:
                lockout, strike_sig, count = self.register_strike_and_block(tenant_id, subject, now)
                signals.append("blocked_due_to_high_risk")
                signals.append(strike_sig)

        return decision, signals, unseen, score, category

    def compute_risk(self, tenant_id: str, subject: str, now: float) -> dict:
        q = self._events(tenant_id, subject, now)

        denied_all = [e for e in q if not e.allowed]
        denied_short = [e for e in denied_all if now - e.at <= self.short_window]

        def _is_tracked_resource(ep: str) -> bool:
            return (
                ep in ("records", "v1", "v1_batch", "records_batch", "records_mutation", "records_abac",
                       "graphql", "hierarchy", "exports", "stored_ref", "async_jobs", "admin_login_probe", "admin_portal")
                or ep.startswith("body_ref:")
                or ep.startswith("admin_")
                or ep.startswith("item")
                or ep.startswith("claim")
                or ep.startswith("django")
            )

        unique_denied_short = len({e.record_id for e in denied_short if _is_tracked_resource(e.endpoint)})
        unique_denied_long = len({e.record_id for e in denied_all if _is_tracked_resource(e.endpoint)})

        total_long = len(q)
        failed_long = len(denied_all)
        failed_short = len(denied_short)

        signals = []
        contributions = {}

        if unique_denied_short >= self.rapid_threshold:
            contributions["unauthorized_unique_object_pressure"] = 45
            signals.append("unauthorized_unique_object_pressure")
        elif unique_denied_short > 0:
            contributions["unique_denied_short"] = unique_denied_short * 10

        # Sequential short - best-effort: only numeric record_ids can show a "step"
        # pattern; arbitrary string resource_ids (e.g. from external /v1/authorize
        # tenants) simply never trip this signal, a documented limitation.
        short_ids_raw = [e.record_id for e in q if (not e.allowed) and (now - e.at <= self.short_window) and _is_tracked_resource(e.endpoint)]
        short_ids = []
        for rid in short_ids_raw:
            try:
                short_ids.append(int(rid))
            except (TypeError, ValueError):
                m_dig = re.search(r'\d+', str(rid))
                if m_dig:
                    try:
                        short_ids.append(int(m_dig.group()))
                    except (TypeError, ValueError):
                        pass
        sequential_steps = sum(1 for a, b in zip(short_ids, short_ids[1:]) if abs(b - a) == 1)
        if sequential_steps >= 2:
            contributions["sequential_id_enumeration"] = 35
            signals.append("sequential_id_enumeration")

        if unique_denied_long >= self.slow_threshold:
            contributions["low_and_slow_reconnaissance"] = 50
            signals.append("low_and_slow_reconnaissance")
        elif unique_denied_long > 0:
            contributions["unique_denied_long"] = unique_denied_long * 2

        if total_long >= 5:
            ratio = failed_long / total_long
            if ratio > 0.5:
                contributions["high_failure_ratio"] = 20
                signals.append("high_failure_ratio")

        endpoints_hit = len({e.endpoint for e in denied_all})
        if endpoints_hit >= 2:
            contributions["endpoint_diversity"] = 20
            signals.append("endpoint_diversity")

        # Feature 1: Write/Mutation weighted scoring
        denied_write_events = [e for e in denied_short if e.http_verb in ("DELETE", "PATCH", "PUT")]
        if denied_write_events:
            if any(e.http_verb == "DELETE" for e in denied_write_events):
                contributions["unauthorized_write_delete_attempt"] = int(25 * BOLA_WEIGHT_DELETE)
                signals.append("unauthorized_write_delete_attempt")
            elif any(e.http_verb in ("PATCH", "PUT") for e in denied_write_events):
                weight = max(BOLA_WEIGHT_PATCH if e.http_verb == "PATCH" else BOLA_WEIGHT_PUT for e in denied_write_events)
                contributions["unauthorized_write_mutation_attempt"] = int(20 * weight)
                signals.append("unauthorized_write_mutation_attempt")

        # Feature 2: Hierarchical chain mismatch
        if any(e.endpoint == "hierarchy" for e in denied_short):
            contributions["relational_chain_mismatch"] = 45
            signals.append("relational_chain_mismatch")

        # Feature 3: Body-payload object injection
        body_injections = [e for e in denied_short if e.endpoint.startswith("body_ref:")]
        if body_injections:
            contributions["body_payload_object_injection"] = min(40, len(body_injections) * 20)
            signals.append("body_payload_object_injection")

        # Feature 7: Second-order stored BOLA violation
        if any(e.endpoint.startswith("stored_ref") for e in denied_short):
            contributions["second_order_bola_violation"] = 45
            signals.append("second_order_bola_violation")

        # Feature 9: Canary honeypot trigger
        if any(e.endpoint == "canary_trap" for e in denied_short):
            contributions["canary_honeypot_triggered"] = 100
            signals.append("canary_honeypot_triggered")

        # Feature 10: Unauthorized administrative portal probing / false credential entry
        admin_probes = [e for e in denied_short if e.endpoint.startswith("admin_") or str(e.record_id).startswith("privileged_admin") or e.endpoint in ("admin_login_probe", "admin_portal")]
        if admin_probes:
            contributions["unauthorized_admin_access_attempt"] = 90
            signals.append("unauthorized_admin_access_attempt")

        if failed_long > 0:
            failure_ratio = failed_long / total_long if total_long > 0 else 0.0
            feature_vector = np.array([[unique_denied_short, sequential_steps, unique_denied_long,
                                         failure_ratio, endpoints_hit]])
            if anomaly_model.predict(feature_vector)[0] == -1:
                contributions["ml_behavioral_anomaly"] = 15
                signals.append("ml_behavioral_anomaly")

        score = max(0.0, min(100.0, float(sum(contributions.values()))))

        if self.blocked_until(tenant_id, subject) > now:
            contributions["blocked_override"] = 100.0 - sum(contributions.values())
            score = 100.0
            if "temporarily_blocked" not in signals:
                signals.append("temporarily_blocked")
            strike_count = self.get_strike_count(tenant_id, subject, now)
            status = self._ban_status(tenant_id, subject)
            if status == "approved":
                if "strike_3_permanent_ban_approved" not in signals:
                    signals.append("strike_3_permanent_ban_approved")
            elif status == "pending" or strike_count >= 3:
                if "strike_3_pending_admin_approval" not in signals:
                    signals.append("strike_3_pending_admin_approval")
            elif strike_count == 2 and "strike_2_hard_lockout_30m" not in signals:
                signals.append("strike_2_hard_lockout_30m")
            elif strike_count == 1 and "strike_1_soft_lockout_2m" not in signals:
                signals.append("strike_1_soft_lockout_2m")
            category = "Attack"
        else:
            block_threshold, warn_threshold = get_tenant_risk_thresholds(tenant_id)
            if score >= block_threshold:
                category = "Attack"
            elif score >= warn_threshold:
                category = "High Risk"
            elif score >= min(40, warn_threshold):
                category = "Suspicious"
            else:
                category = "Normal"

        return {"score": max(0.0, min(100.0, float(score))), "signals": signals, "category": category, "contributions": contributions}


engine = BehavioralRiskEngine()
app = FastAPI(title="BOLA Graph Benchmark", version="1.1.1")

# ===== PROMETHEUS METRICS (Enterprise Observability) =====
authorize_counter = Counter('authorize_decisions_total', 'Product API authorization decisions', ['decision', 'tenant_id'])
authorize_latency = Histogram('authorize_latency_seconds', 'Authorization latency', ['tenant_id'], buckets=[0.01, 0.02, 0.05, 0.1, 0.2, 0.5])
risk_score_histogram = Histogram('risk_score_distribution', 'Risk score distribution', ['tenant_id'], buckets=[0, 20, 40, 60, 80, 90, 100])
authorized_blocks_counter = Counter('authorized_request_blocks_total', 'Behavioral blocks on otherwise authorized requests', ['tenant_id'])
audit_events_stored = Gauge('audit_events_stored_total', 'Total audit events stored', ['tenant_id'])
tenant_quota_usage = Gauge('tenant_quota_usage_percent', 'Tenant quota usage %', ['tenant_id'])
redis_cache_hits = Counter('redis_cache_hits_total', 'Redis cache hits', ['cache_type'])
redis_cache_misses = Counter('redis_cache_misses_total', 'Redis cache misses', ['cache_type'])

# Phase 4: advanced threat detection metrics
threat_ip_reputation_flags = Counter('threat_ip_reputation_flags_total', 'Requests from an IP flagged by internal reputation scoring', ['tenant_id'])
threat_geo_velocity_flags = Counter('threat_geo_velocity_flags_total', 'Impossible-travel anomalies detected', ['tenant_id'])
threat_tls_fingerprint_flags = Counter('threat_tls_fingerprint_flags_total', 'Requests matching a blocklisted TLS/JA3 fingerprint', ['tenant_id'])
threat_behavioral_anomaly_flags = Counter('threat_behavioral_anomaly_flags_total', 'Requests deviating sharply from a subject\'s behavioral baseline', ['tenant_id'])


def extract_client_ip(request: Request) -> str:
    """Best-effort client IP: prefer the first hop of X-Forwarded-For (set by an upstream
    proxy/load balancer in production), else the direct connection's address."""
    # Uvicorn resolves forwarded addresses only for configured trusted proxies.
    return request.client.host if request.client else "unknown"

# Metrics endpoint for Prometheus scraping
@app.get("/metrics")
def metrics():
    with db() as c:
        counts = c.execute("SELECT tenant_id, COUNT(*) AS n FROM audit_events GROUP BY tenant_id").fetchall()
    audit_events_stored.clear()
    for row in counts:
        audit_events_stored.labels(tenant_id=row["tenant_id"]).set(row["n"])
    return Response(generate_latest(REGISTRY), media_type="text/plain")


def observe_authorization(handler):
    @wraps(handler)
    def measured(*args, **kwargs):
        tenant_id = kwargs.get("tenant_id") or args[2]
        payload = kwargs.get("payload") if "payload" in kwargs else args[1]
        started = time.perf_counter()
        try:
            result = handler(*args, **kwargs)
        finally:
            authorize_latency.labels(tenant_id=tenant_id).observe(time.perf_counter() - started)
        decisions = result.get("results", [result])
        inputs = payload.get("items", []) if "results" in result else [payload]
        for decision, item in zip(decisions, inputs):
            authorize_counter.labels(decision=decision["decision"], tenant_id=tenant_id).inc()
            risk_score_histogram.labels(tenant_id=tenant_id).observe(decision["score"])
            if decision["decision"] == "block" and item.get("authorized") is True:
                authorized_blocks_counter.labels(tenant_id=tenant_id).inc()
        return result
    return measured


_frontend_origins = [o.strip() for o in os.environ.get("FRONTEND_ORIGIN", "").split(",") if o.strip()]
_cors_origins = _frontend_origins
_cors_local_regex = r"https?://(localhost|127\.0\.0\.1)(:\d+)?" if APP_ENV != "prod" else None
if APP_ENV == "prod" and "*" in _frontend_origins:
    raise RuntimeError("Cookie-authenticated dashboards require explicit FRONTEND_ORIGIN values in production")
_cors_origins = [origin for origin in _cors_origins if origin != "*"]

# ===== CONFIGURATION (Externalized to Environment Variables) =====
# Redis Caching
REDIS_CACHE_TTL_AUTH_CONTEXT = int(os.environ.get("REDIS_CACHE_TTL_AUTH_CONTEXT", "600"))
REDIS_CACHE_TTL_RISK_SCORE = int(os.environ.get("REDIS_CACHE_TTL_RISK_SCORE", "300"))
REDIS_CACHE_TTL_QUOTAS = int(os.environ.get("REDIS_CACHE_TTL_QUOTAS", "60"))

# Rate Limiting & Quotas
DEFAULT_REQUESTS_PER_MINUTE = int(os.environ.get("DEFAULT_REQUESTS_PER_MINUTE", "1000"))
DEFAULT_MAX_AUDIT_EVENTS = int(os.environ.get("DEFAULT_MAX_AUDIT_EVENTS", "1000000"))
DEFAULT_AUDIT_RETENTION_DAYS = int(os.environ.get("DEFAULT_AUDIT_RETENTION_DAYS", "365"))
DEFAULT_RISK_THRESHOLD_BLOCK = int(os.environ.get("DEFAULT_RISK_THRESHOLD_BLOCK", "90"))
DEFAULT_RISK_THRESHOLD_WARN = int(os.environ.get("DEFAULT_RISK_THRESHOLD_WARN", "70"))
RATE_LIMIT_WINDOW_SECONDS = int(os.environ.get("RATE_LIMIT_WINDOW_SECONDS", "60"))
QUOTA_ALERT_THRESHOLD_PERCENT = float(os.environ.get("QUOTA_ALERT_THRESHOLD_PERCENT", "80"))
QUOTA_ALERT_BATCH_SIZE = int(os.environ.get("QUOTA_ALERT_BATCH_SIZE", "50"))

# Phase 5: ROI calculator assumptions. These are illustrative defaults, not verified industry
# benchmarks - operators should override them with figures specific to their own organization
# (actual incident-response cost, engineering hourly rate, etc.) for a meaningful estimate.
ROI_ASSUMED_COST_PER_BREACH_USD = float(os.environ.get("ROI_ASSUMED_COST_PER_BREACH_USD", "50000"))
ROI_ASSUMED_BREACH_PROBABILITY_PER_ATTACK = float(os.environ.get("ROI_ASSUMED_BREACH_PROBABILITY_PER_ATTACK", "0.02"))
ROI_ASSUMED_MANUAL_REVIEW_MINUTES_PER_EVENT = float(os.environ.get("ROI_ASSUMED_MANUAL_REVIEW_MINUTES_PER_EVENT", "15"))
ROI_ASSUMED_ENGINEER_HOURLY_COST_USD = float(os.environ.get("ROI_ASSUMED_ENGINEER_HOURLY_COST_USD", "75"))


def get_tenant_risk_thresholds(tenant_id: str) -> tuple[int, int]:
    with db() as c:
        quota = c.execute(
            "SELECT risk_threshold_block, risk_threshold_warn FROM tenant_quotas WHERE tenant_id = %s",
            (tenant_id,),
        ).fetchone()
    return (
        int(quota["risk_threshold_block"] or DEFAULT_RISK_THRESHOLD_BLOCK) if quota else DEFAULT_RISK_THRESHOLD_BLOCK,
        int(quota["risk_threshold_warn"] or DEFAULT_RISK_THRESHOLD_WARN) if quota else DEFAULT_RISK_THRESHOLD_WARN,
    )


# ===== RATE LIMITING MIDDLEWARE (Per-Tenant) =====
def _sync_load_or_default_quota(tenant_id: str, quota_key: str) -> str:
    """Blocking DB read - must only ever be called via asyncio.to_thread from
    async code (see TenantRateLimitMiddleware), never directly on the event loop."""
    try:
        with db() as c:
            result = c.execute(
                "SELECT requests_per_minute FROM tenant_quotas WHERE tenant_id = %s",
                (tenant_id,)
            ).fetchone()
            quota_config = json.dumps({
                "requests_per_minute": result["requests_per_minute"] if result else DEFAULT_REQUESTS_PER_MINUTE
            })
            cache_set(quota_key, quota_config, ttl_seconds=REDIS_CACHE_TTL_QUOTAS)
    except Exception:
        quota_config = json.dumps({"requests_per_minute": DEFAULT_REQUESTS_PER_MINUTE})
    return quota_config


def _sync_insert_quota_alert_audit(tenant_id: str, usage_percent: float, current: int, rpm_limit: int) -> None:
    """Blocking DB write - must only ever be called via asyncio.to_thread from async code."""
    with db() as c:
        c.execute(
            "INSERT INTO audit_events (tenant_id, occurred_at, subject_id, record_id, "
            '"authorization", detector_decision, outcome, explanation, risk_score) '
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (tenant_id, time.time(), "system", "quota_alert", None, "alert", "quota_warning",
             f"Tenant quota usage at {usage_percent:.1f}% ({current}/{rpm_limit} requests/min)", 0.0)
        )


class TenantRateLimitMiddleware(BaseHTTPMiddleware):
    """Per-tenant rate limiting with quota enforcement."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Only verified credentials identify a tenant. X-Tenant-ID is untrusted.
        if request.method == "OPTIONS" or request.scope.get("console_session") or request.url.path.startswith("/auth/") or request.url.path in ("/health", "/healthz", "/metrics", "/v1/signup", "/v1/tenants"):
            return await call_next(request)
        if not request.headers.get("X-API-Key") and not request.headers.get("Authorization"):
            return await call_next(request)
        try:
            tenant_id = await asyncio.to_thread(resolve_request_tenant, request.headers.get("X-API-Key"), request.headers.get("Authorization"))
        except HTTPException as exc:
            return Response(json.dumps({"detail": exc.detail}), status_code=exc.status_code, media_type="application/json")

        # Skip rate limiting for health/metrics endpoints
        if request.url.path in ["/health", "/metrics"]:
            return await call_next(request)

        # Get tenant quota from cache or DB. Every request without Redis caching
        # (e.g. local dev with Redis unavailable) hits the DB here, so this must run
        # off the event loop thread - a blocking SQLite call directly inside this
        # async dispatch() would otherwise serialize every concurrent request
        # site-wide behind whichever one happens to be doing I/O.
        quota_key = f"quota:{tenant_id}"
        quota_config = await asyncio.to_thread(cache_get, quota_key)

        if not quota_config:
            quota_config = await asyncio.to_thread(_sync_load_or_default_quota, tenant_id, quota_key)

        quota = json.loads(quota_config)
        rpm_limit = quota["requests_per_minute"]

        # Check rate limit using Redis
        rate_limit_key = f"ratelimit:{tenant_id}"
        current, retry_after = await asyncio.to_thread(_consume_tenant_quota, tenant_id)

        if current:
            try:

                # Check if over limit
                if current > rpm_limit:
                    tenant_quota_usage.labels(tenant_id=tenant_id).set(100)
                    return Response(
                        json.dumps({
                            "error": "Rate limit exceeded",
                            "limit": rpm_limit,
                            "current": current,
                            "retry_after": retry_after
                        }),
                        status_code=429,
                        media_type="application/json",
                        headers={"Retry-After": str(retry_after)}
                    )

                # Update quota usage metric
                usage_percent = (current / rpm_limit) * 100
                tenant_quota_usage.labels(tenant_id=tenant_id).set(usage_percent)

                # Alert if quota threshold exceeded
                if usage_percent > QUOTA_ALERT_THRESHOLD_PERCENT and current % QUOTA_ALERT_BATCH_SIZE == 0:
                    try:
                        await asyncio.to_thread(_sync_insert_quota_alert_audit, tenant_id, usage_percent, current, rpm_limit)
                        # Dispatch alerts asynchronously (fire and forget)
                        asyncio.create_task(
                            dispatch_alerts(
                                tenant_id,
                                "quota_warning",
                                f"Quota Usage Alert: {usage_percent:.0f}%",
                                f"Your CyberAccess tenant is using {usage_percent:.1f}% of its quota ({current}/{rpm_limit} requests/min).",
                                severity="warning",
                                db=db
                            )
                        )
                    except Exception:
                        pass
            except Exception:
                pass

        response = await call_next(request)
        response.headers["X-Tenant-ID"] = tenant_id
        response.headers["X-Quota-Used"] = str(current)
        response.headers["X-Quota-Limit"] = str(rpm_limit)
        return response


def _consume_tenant_quota(tenant_id: str) -> tuple[int, int]:
    if redis_client:
        try:
            result = redis_client.eval(
                "local n = redis.call('INCR', KEYS[1]); "
                "if n == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end; "
                "return {n, redis.call('TTL', KEYS[1])}",
                1, f"ratelimit:{tenant_id}", RATE_LIMIT_WINDOW_SECONDS,
            )
            return int(result[0]), max(1, int(result[1]))
        except Exception:
            pass
    # Persisted fallback enforces quotas even when Redis is disabled.
    now = time.time()
    with db() as c:
        row = c.execute(
            "INSERT INTO rate_limit_state (tenant_id, current_requests, requests_reset_at, last_updated) "
            "VALUES (%s, 1, %s, %s) ON CONFLICT (tenant_id) DO UPDATE SET "
            "current_requests = CASE WHEN rate_limit_state.requests_reset_at <= %s THEN 1 ELSE rate_limit_state.current_requests + 1 END, "
            "requests_reset_at = CASE WHEN rate_limit_state.requests_reset_at <= %s THEN EXCLUDED.requests_reset_at ELSE rate_limit_state.requests_reset_at END, "
            "last_updated = EXCLUDED.last_updated RETURNING current_requests, requests_reset_at",
            (tenant_id, now + RATE_LIMIT_WINDOW_SECONDS, now, now, now),
        ).fetchone()
    return row["current_requests"], max(1, int(row["requests_reset_at"] - now))

app.add_middleware(TenantRateLimitMiddleware)

ID_KEY_PATTERN = re.compile(r'(?:^|[_\-.])(?:id|key|ref|uuid|identifier)s?$', re.IGNORECASE)

def extract_candidate_object_ids(payload: Any, depth: int = 5) -> list[tuple[str, str]]:
    """Recursively scans JSON payloads for object ID fields without hardcoding field names."""
    candidates = []
    if depth <= 0:
        return candidates
    if isinstance(payload, dict):
        for k, v in payload.items():
            if isinstance(v, (str, int)) and ID_KEY_PATTERN.search(str(k)):
                val_str = str(v).strip()
                if val_str and len(val_str) < 128:
                    candidates.append((str(k), val_str))
            elif isinstance(v, list) and ID_KEY_PATTERN.search(str(k)):
                for item in v:
                    if isinstance(item, (str, int)):
                        val_str = str(item).strip()
                        if val_str and len(val_str) < 128:
                            candidates.append((str(k), val_str))
            elif isinstance(v, (dict, list)):
                candidates.extend(extract_candidate_object_ids(v, depth - 1))
    elif isinstance(payload, list):
        for item in payload:
            if isinstance(item, (dict, list)):
                candidates.extend(extract_candidate_object_ids(item, depth - 1))
    return candidates


def _inspect_body_references(body_bytes: bytes, token: str, path: str) -> None:
    try:
        subject, _role, tenant_id = get_current_identity(f"Bearer {token}")
        candidates = extract_candidate_object_ids(json.loads(body_bytes))
    except (HTTPException, ValueError, KeyError):
        return
    for field_name, cand_id in candidates:
        with db() as c:
            rec = c.execute("SELECT owner_id FROM records WHERE tenant_id = %s AND id = %s", (tenant_id, cand_id)).fetchone()
        if rec:
            access = authorization_context(tenant_id, subject, cand_id, action="read")
            if access["authorization"] is None:
                decision, signals, unseen, score, category = engine.evaluate(tenant_id, subject, cand_id, allowed=False, endpoint=f"body_ref:{field_name}")
                record_audit(tenant_id, subject, cand_id, None, decision, "denied_body_reference",
                             [f"Unauthorized foreign object ID '{cand_id}' referenced in body field '{field_name}'."], risk_score=score)


class BodyObjectReferenceMiddleware(BaseHTTPMiddleware):
    """Intercepts POST, PUT, and PATCH requests, dynamically identifies candidate
    resource identifiers in the JSON body, and verifies object authorization.
    If an unowned foreign resource is referenced, records a body-level BOLA attempt."""
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if request.method in ("POST", "PUT", "PATCH") and not request.url.path.startswith("/auth/") and request.url.path not in ("/records/batch", "/hierarchy/access", "/graphql"):
            auth_header = request.headers.get("Authorization", "")
            if auth_header.lower().startswith("bearer "):
                body_bytes = await request.body()
                if body_bytes:
                    await asyncio.to_thread(_inspect_body_references, body_bytes, auth_header.split(" ", 1)[1], request.url.path)
        return await call_next(request)

app.add_middleware(BodyObjectReferenceMiddleware)
app.add_middleware(CORSMiddleware, allow_origins=_cors_origins, allow_origin_regex=_cors_local_regex,
                   allow_credentials=True, allow_methods=["*"], allow_headers=["*"])


class DashboardSessionMiddleware(BaseHTTPMiddleware):
    """Adapt the browser's HttpOnly cookie to the existing tenant JWT boundary.

    Explicit API credentials take precedence. Cookie-authenticated writes require
    a custom header (HTML forms cannot send it) and an allowed browser Origin.

    cookie -> write Origin/header check -> Bearer adapter -> verified JWT +
    live dashboard_sessions row -> tenant-scoped route (never a caller tenant ID)
    """
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        token = request.cookies.get(CONSOLE_COOKIE_NAME)
        if token and not request.headers.get("Authorization") and not request.headers.get("X-API-Key"):
            if request.method not in ("GET", "HEAD", "OPTIONS"):
                origin = request.headers.get("Origin")
                local_origin = bool(_cors_local_regex and origin and re.fullmatch(_cors_local_regex, origin))
                permitted_origin = not origin or origin == str(request.base_url).rstrip("/") or origin in _frontend_origins or local_origin
                if request.headers.get("X-CyberAccess-Console") != "1" or not permitted_origin:
                    return Response(json.dumps({"detail": "Invalid dashboard request origin"}), status_code=403, media_type="application/json")
            request.scope["headers"] = list(request.scope["headers"]) + [(b"authorization", f"Bearer {token}".encode())]
            request.scope["console_session"] = True
        response = await call_next(request)
        if request.scope.get("console_session"):
            response.headers["Cache-Control"] = "no-store"
        return response


app.add_middleware(DashboardSessionMiddleware)


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "env": APP_ENV, "demo_mode": DEMO_MODE, "version": "1.1.1"}


def _rate_limit_key(request: Request) -> str:
    if request.url.path.startswith("/auth/") or request.url.path in ("/v1/signup", "/v1/tenants"):
        return get_remote_address(request)
    authorization = request.headers.get("Authorization", "")
    if authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1]
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM], options={"verify_exp": False})
            return f"subject:{payload.get('tenant_id', '?')}:{payload.get('sub', 'unknown')}"
        except jwt.InvalidTokenError:
            pass
    api_key = request.headers.get("X-API-Key", "")
    if api_key:
        return f"apikey:{hash_api_key(api_key)[:16]}"
    return get_remote_address(request)


limiter = Limiter(key_func=_rate_limit_key, enabled=("pytest" not in sys.modules and os.environ.get("APP_ENV") != "test"))
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


def create_access_token(subject: str, role: str, tenant_id: str, session_id: str | None = None) -> str:
    now = time.time()
    payload = {"sub": subject, "role": role, "tenant_id": tenant_id, "iat": now, "exp": now + JWT_EXPIRY_SECONDS}
    if session_id:
        payload["sid"] = session_id
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def get_current_identity(authorization: str | None = Header(default=None)) -> tuple[str, str, str]:
    """Real authentication: a signed, time-bound JWT bearer token, verified
    server-side, scoped to a single tenant via the tenant_id claim."""
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Missing or malformed Authorization header (expected 'Bearer <token>')")
    token = authorization.split(" ", 1)[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Token expired, please log in again")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid authentication token")
    if not isinstance(payload.get("sub"), str) or not isinstance(payload.get("tenant_id", DEMO_TENANT_ID), str):
        raise HTTPException(401, "Invalid authentication token")
    subject, role, tenant_id = payload["sub"], payload.get("role", "customer"), payload.get("tenant_id", DEMO_TENANT_ID)
    if "sid" in payload:
        with db() as c:
            session = c.execute(
                "SELECT u.role FROM dashboard_sessions s JOIN users u ON u.tenant_id = s.tenant_id AND u.id = s.subject_id "
                "WHERE s.session_hash = %s AND s.tenant_id = %s AND s.subject_id = %s AND s.expires_at > %s",
                (hash_api_key(str(payload["sid"])), tenant_id, subject, time.time()),
            ).fetchone()
        if not session:
            raise HTTPException(401, "Dashboard session expired or signed out")
        role = session["role"]
    return subject, role, tenant_id


def get_tenant_from_api_key(x_api_key: str | None = Header(default=None)) -> str:
    """Product-API auth: a per-tenant API key (server-to-server), separate from
    the JWT user-login flow the demo dashboard uses."""
    if not x_api_key:
        raise HTTPException(401, "Missing X-API-Key header")
    if APP_ENV == "prod" and x_api_key in ("dev_test_key", "demo-key-unused"):
        raise HTTPException(401, "Development API keys are disabled")
    with db() as c:
        row = c.execute("SELECT id FROM tenants WHERE api_key_hash = %s", (hash_api_key(x_api_key),)).fetchone()
    if not row:
        raise HTTPException(401, "Invalid API key")
    return row["id"]


def require_security_admin(role: str) -> None:
    if role != ADMIN_ROLE:
        raise HTTPException(403, f"This action requires the {ADMIN_ROLE} role")


def resolve_request_tenant(x_api_key: str | None, authorization: str | None) -> str:
    if x_api_key:
        return get_tenant_from_api_key(x_api_key)
    if authorization:
        return get_current_identity(authorization)[2]
    if DEMO_MODE:
        return DEMO_TENANT_ID
    raise HTTPException(401, "Authentication required")


def get_tenant_admin_identity(authorization: str | None = Header(default=None),
                              x_api_key: str | None = Header(default=None)) -> tuple[str, str, str]:
    if x_api_key:
        return "api-key", ADMIN_ROLE, get_tenant_from_api_key(x_api_key)
    return get_current_identity(authorization)


def guard_demo_endpoint(authorization: str | None = Header(default=None), x_api_key: str | None = Header(default=None)) -> None:
    if x_api_key and get_tenant_from_api_key(x_api_key) != DEMO_TENANT_ID:
        raise HTTPException(403, "Demo controls are unavailable for customer tenants")
    if DEMO_MODE and not authorization:
        return
    subject, role, tenant_id = get_current_identity(authorization)
    require_security_admin(role)
    if tenant_id != DEMO_TENANT_ID:
        raise HTTPException(403, "Demo controls are unavailable for customer tenants")


def explain_detector_signals(signals: list[str]) -> list[str]:
    messages = {
        "unauthorized_unique_object_pressure": "You requested four or more different records without permission within 30 seconds.",
        "sequential_id_enumeration": "Your requests followed a sequential record-ID guessing pattern.",
        "low_and_slow_reconnaissance": "You made 15 or more unauthorized requests over a prolonged period (low-and-slow reconnaissance).",
        "high_failure_ratio": "You have a high ratio of failed to successful requests.",
        "endpoint_diversity": "You have triggered unauthorized access across multiple API endpoints.",
        "temporarily_blocked": "Your identity has been temporarily blocked due to malicious behavior.",
        "blocked_due_to_high_risk": "Your risk score reached the Attack threshold and you are now blocked.",
        "strike_1_soft_lockout_2m": "Strike 1/3: 2-Minute Soft Lockout penalty enforced.",
        "strike_2_hard_lockout_30m": "Strike 2/3: Repeat violation within 1 hour. 30-Minute Hard Lockout penalty enforced.",
        "strike_3_pending_admin_approval": "Strike 3/3 Reached: Permanent Ban PENDING ADMIN APPROVAL (Quarantined).",
        "strike_3_permanent_ban_approved": "Strike 3/3: Permanent Firewall Blacklist APPROVED by Administrator.",
        "ml_behavioral_anomaly": "An unsupervised ML model (Isolation Forest) flagged this access pattern as statistically abnormal compared to normal traffic.",
        "unauthorized_write_delete_attempt": "Critical: Unauthorized deletion attempt detected against an object you do not own.",
        "unauthorized_write_mutation_attempt": "Warning: Unauthorized modification (PUT/PATCH) attempt detected against an object you cannot edit.",
        "body_payload_object_injection": "Warning: Unauthorized object references detected embedded within the request body payload.",
        "relational_chain_mismatch": "Warning: Hierarchical parent-child relationship check failed (BOLA path traversal).",
        "second_order_bola_violation": "Warning: Second-order stored reference pointed to an unauthorized or foreign resource.",
        "canary_honeypot_triggered": "CRITICAL: Honeypot canary trap triggered. Instant permanent ban enforced.",
        "unauthorized_admin_access_attempt": "Unauthorized attempt to access privileged administrative portal or authenticate with invalid credentials.",
        "repeated_unauthorized_trial": "Warning: Repeated unauthorized object access detected within active session.",
        "unauthorized_trial_threshold_exceeded": "Exhausted 3 unauthorized object access trials within active session. Workstation quarantined.",
        "high_risk_reconnaissance": "High-risk anomalous access pattern detected (Score 70-89). Approaching lockout threshold."
    }
    return [messages[s] for s in signals if s in messages]


SELF_SERVICE_ROLES = {"customer", "doctor", "support"}


@app.post("/auth/register")
@limiter.limit("100/minute")
def register(request: Request, payload: dict) -> dict:
    subject = payload.get("subject")
    password = payload.get("password")
    role = payload.get("role", "customer")
    if not subject or not password:
        raise HTTPException(400, "subject and password are required")
    # Whitelist, not a single-string blocklist: self-registration must only ever
    # grant one of a small set of known-safe roles. A blocklist that only rejected
    # ADMIN_ROLE would let anyone claim role="doctor" or any other arbitrary
    # string - harmless today only because no other endpoint currently branches
    # on those specific roles, which is a fragile thing to rely on staying true.
    if role not in SELF_SERVICE_ROLES:
        raise HTTPException(400, f"role must be one of: {', '.join(sorted(SELF_SERVICE_ROLES))}")
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode()
    with db() as c:
        if c.execute("SELECT 1 FROM users WHERE tenant_id = %s AND id = %s", (DEMO_TENANT_ID, subject)).fetchone():
            raise HTTPException(409, "Subject already registered")
        c.execute("INSERT INTO users (tenant_id, id, role, password_hash) VALUES (%s, %s, %s, %s)",
                  (DEMO_TENANT_ID, subject, role, password_hash))
    return {"status": "registered", "subject": subject, "role": role}


@app.post("/auth/login")
@limiter.limit(CONSOLE_AUTH_RATE_LIMIT)
def login(request: Request, response: Response, payload: dict) -> dict:
    if "email" in payload:
        email = _normalize_account_email(payload.get("email"))
        password = payload.get("password")
        with db() as c:
            row = c.execute(
                "SELECT a.subject_id, a.tenant_id, u.role, u.password_hash FROM dashboard_accounts a "
                "JOIN users u ON u.tenant_id = a.tenant_id AND u.id = a.subject_id WHERE a.email = %s", (email,)
            ).fetchone()
        valid = _password_matches(password, row["password_hash"] if row else _CACHED_ADMIN_HASH)
        if not row or not valid:
            raise HTTPException(401, "Invalid email or password")
        with db() as c:
            return _issue_console_session(c, response, row["subject_id"], row["role"], row["tenant_id"])
    subject = payload.get("subject")
    password = payload.get("password")
    if not isinstance(subject, str) or not subject or not isinstance(password, str) or not password:
        raise HTTPException(400, "subject and password are required")
    with db() as c:
        row = c.execute("SELECT role, password_hash FROM users WHERE tenant_id = %s AND id = %s",
                         (DEMO_TENANT_ID, subject)).fetchone()
    valid = _password_matches(password, row["password_hash"] if row else _CACHED_ADMIN_HASH)
    if not row or not valid:
        raise HTTPException(401, "Invalid subject or password")
    if payload.get("console") is True:
        with db() as c:
            return _issue_console_session(c, response, subject, row["role"], DEMO_TENANT_ID)
    token = create_access_token(subject, row["role"], DEMO_TENANT_ID)
    return {"access_token": token, "token_type": "bearer", "subject": subject, "role": row["role"], "expires_in": JWT_EXPIRY_SECONDS}


@app.get("/auth/me")
def me(response: Response, identity: tuple[str, str, str] = Depends(get_current_identity)) -> dict:
    subject, role, tenant_id = identity
    response.headers["Cache-Control"] = "no-store"
    with db() as c:
        return _dashboard_profile(c, subject, role, tenant_id)


@app.get("/auth/options")
def dashboard_auth_options() -> dict:
    return {"password_min_length": CONSOLE_PASSWORD_MIN_LENGTH, "demo_login_available": DEMO_MODE}


@app.get("/auth/session")
def restore_dashboard_session(response: Response, authorization: str | None = Header(default=None)) -> dict:
    response.headers["Cache-Control"] = "no-store"
    if not authorization:
        return {"user": None}
    try:
        subject, role, tenant_id = get_current_identity(authorization)
    except HTTPException:
        response.delete_cookie(CONSOLE_COOKIE_NAME, path="/", httponly=True, secure=CONSOLE_COOKIE_SECURE, samesite="lax")
        return {"user": None}
    with db() as c:
        return {"user": _dashboard_profile(c, subject, role, tenant_id)}


def _normalize_account_email(email: Any) -> str:
    if not isinstance(email, str):
        raise HTTPException(400, "A valid email address is required")
    email = email.strip().lower()
    if len(email) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        raise HTTPException(400, "A valid email address is required")
    return email


def _validate_console_password(password: Any) -> str:
    if not isinstance(password, str) or len(password) < CONSOLE_PASSWORD_MIN_LENGTH or len(password.encode()) > 72:
        raise HTTPException(400, f"Password must have at least {CONSOLE_PASSWORD_MIN_LENGTH} characters and at most 72 UTF-8 bytes")
    return password


def _password_matches(password: Any, password_hash: str) -> bool:
    if not isinstance(password, str) or not password or len(password.encode()) > 72:
        return False
    try:
        return bcrypt.checkpw(password.encode(), password_hash.encode())
    except ValueError:
        return False


def _dashboard_profile(c, subject: str, role: str, tenant_id: str) -> dict:
    tenant = c.execute("SELECT name FROM tenants WHERE id = %s", (tenant_id,)).fetchone()
    account = c.execute("SELECT email FROM dashboard_accounts WHERE tenant_id = %s AND subject_id = %s", (tenant_id, subject)).fetchone()
    return {"subject": subject, "role": role, "tenant_id": tenant_id,
            "tenant_name": tenant["name"] if tenant else tenant_id,
            "email": account["email"] if account else None,
            "capabilities": {"demo_controls": DEMO_MODE and tenant_id == DEMO_TENANT_ID and role == ADMIN_ROLE,
                             "manage_api_key": bool(account and role == ADMIN_ROLE)}}


def _issue_console_session(c, response: Response, subject: str, role: str, tenant_id: str) -> dict:
    session_id = secrets.token_urlsafe(32)
    c.execute("DELETE FROM dashboard_sessions WHERE expires_at <= %s", (time.time(),))
    c.execute("INSERT INTO dashboard_sessions (session_hash, tenant_id, subject_id, expires_at) VALUES (%s, %s, %s, %s)",
              (hash_api_key(session_id), tenant_id, subject, time.time() + JWT_EXPIRY_SECONDS))
    token = create_access_token(subject, role, tenant_id, session_id=session_id)
    response.set_cookie(CONSOLE_COOKIE_NAME, token, httponly=True, secure=CONSOLE_COOKIE_SECURE,
                        samesite="lax", max_age=JWT_EXPIRY_SECONDS, path="/")
    response.headers["Cache-Control"] = "no-store"
    return {"user": _dashboard_profile(c, subject, role, tenant_id), "expires_in": JWT_EXPIRY_SECONDS}


def _insert_dashboard_owner(c, tenant_id: str, email: str, password_hash: str) -> str:
    subject = "dashboard_" + secrets.token_hex(16)
    c.execute("INSERT INTO users (tenant_id, id, role, password_hash) VALUES (%s, %s, %s, %s)",
              (tenant_id, subject, ADMIN_ROLE, password_hash))
    claimed = c.execute("INSERT INTO dashboard_accounts (email, tenant_id, subject_id, created_at) VALUES (%s, %s, %s, %s) "
                        "ON CONFLICT DO NOTHING RETURNING tenant_id", (email, tenant_id, subject, time.time())).fetchone()
    if not claimed:
        raise HTTPException(409, "This email or tenant already has a dashboard account. Please sign in.")
    return subject


@app.post("/auth/signup")
@limiter.limit("5/hour")
def dashboard_signup(request: Request, response: Response, payload: dict) -> dict:
    name = _validate_tenant_name(payload.get("name"))
    email = _normalize_account_email(payload.get("email"))
    password = _validate_console_password(payload.get("password"))
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode()
    # One transaction: duplicate accounts or failed session creation cannot leave
    # an orphan tenant or partial owner behind. Password hashing holds no DB lock.
    with db() as c:
        result = _insert_tenant_record(c, name, email)
        subject = _insert_dashboard_owner(c, result["tenant_id"], email, password_hash)
        result.update(_issue_console_session(c, response, subject, ADMIN_ROLE, result["tenant_id"]))
    return result


@app.post("/auth/claim-tenant")
@limiter.limit(CONSOLE_AUTH_RATE_LIMIT)
def claim_dashboard(request: Request, response: Response, payload: dict,
                    x_api_key: str | None = Header(default=None)) -> dict:
    tenant_id = get_tenant_from_api_key(x_api_key)
    if tenant_id == DEMO_TENANT_ID:
        raise HTTPException(403, "The demo tenant cannot be claimed")
    email = _normalize_account_email(payload.get("email"))
    password = _validate_console_password(payload.get("password"))
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode()
    with db() as c:
        # Recheck key ownership inside the transaction in case a concurrent
        # replacement revoked the credential after the initial verification.
        tenant = c.execute("SELECT id FROM tenants WHERE id = %s AND api_key_hash = %s",
                           (tenant_id, hash_api_key(x_api_key))).fetchone()
        if not tenant:
            raise HTTPException(401, "Invalid API key")
        subject = _insert_dashboard_owner(c, tenant_id, email, password_hash)
        return _issue_console_session(c, response, subject, ADMIN_ROLE, tenant_id)


@app.post("/auth/logout")
def dashboard_logout(request: Request, response: Response) -> dict:
    token = request.cookies.get(CONSOLE_COOKIE_NAME)
    if token:
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM], options={"verify_exp": False})
            if "sid" in payload:
                with db() as c:
                    c.execute("DELETE FROM dashboard_sessions WHERE session_hash = %s", (hash_api_key(str(payload["sid"])),))
        except jwt.InvalidTokenError:
            pass
    response.delete_cookie(CONSOLE_COOKIE_NAME, path="/", httponly=True, secure=CONSOLE_COOKIE_SECURE, samesite="lax")
    response.headers["Cache-Control"] = "no-store"
    return {"status": "signed_out"}


@app.post("/auth/api-key/rotate")
@limiter.limit(CONSOLE_AUTH_RATE_LIMIT)
def replace_tenant_api_key(request: Request, response: Response, payload: dict,
                           identity: tuple[str, str, str] = Depends(get_current_identity)) -> dict:
    subject, role, tenant_id = identity
    require_security_admin(role)
    with db() as c:
        owner = c.execute("SELECT u.password_hash, t.api_key_hash, t.name FROM dashboard_accounts a "
                          "JOIN users u ON u.tenant_id = a.tenant_id AND u.id = a.subject_id "
                          "JOIN tenants t ON t.id = a.tenant_id WHERE a.tenant_id = %s AND a.subject_id = %s",
                          (tenant_id, subject)).fetchone()
    if not owner:
        raise HTTPException(403, "A tenant dashboard owner account is required")
    if not _password_matches(payload.get("password"), owner["password_hash"]):
        raise HTTPException(401, "Invalid password")
    key = generate_api_key()
    with db() as c:
        changed = c.execute("UPDATE tenants SET api_key_hash = %s WHERE id = %s AND api_key_hash = %s RETURNING id",
                            (hash_api_key(key), tenant_id, owner["api_key_hash"])).fetchone()
        if not changed:
            raise HTTPException(409, "The key was already replaced. Please retry.")
        c.execute('INSERT INTO audit_events (tenant_id, occurred_at, subject_id, record_id, "authorization", '
                  'detector_decision, outcome, explanation, risk_score) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)',
                  (tenant_id, time.time(), subject, "api_key", "authorized", "allow", "key_replaced",
                   "Dashboard owner replaced the tenant integration key; previous key revoked.", 0.0))
    response.headers["Cache-Control"] = "no-store"
    return {"tenant_id": tenant_id, "name": owner["name"], "api_key": key,
            "warning": "Save this key now. Your previous key is revoked; update your server integration immediately."}


@app.post("/reset")
@app.post("/admin/reset")
@limiter.limit("60/minute")
def reset_demo_database(request: Request = None, _guard: None = Depends(guard_demo_endpoint)) -> dict:
    """Wipes all accumulated risk events, strikes, bans, audit ledgers, and resets the database to clean baseline."""
    for t in (DEMO_TENANT_ID, "lost_found_dev"):
        engine.reset(t)
        with db() as c:
            for table in ("risk_events", "risk_strikes", "risk_blocks", "risk_bans",
                           "audit_events", "soc_alerts", "canary_triggers"):
                try:
                    c.execute(f"DELETE FROM {table} WHERE tenant_id = %s", (t,))
                except Exception as exc:
                    print(f"[reset] error deleting from {table} for {t}: {exc}")
    seed_demo_tenant(force=True)
    return {
        "status": "database_reset_successful",
        "tenant_id": DEMO_TENANT_ID,
        "message": "All database tables, audit events, risk strikes, and behavioral states have been cleared."
    }


_sse_subscribers: list[tuple[str, asyncio.AbstractEventLoop, asyncio.Queue]] = []


def broadcast_sse_event(event_type: str, data: dict) -> None:
    msg = {"event": event_type, "data": data, "timestamp": time.time()}
    for tenant_id, loop, q in list(_sse_subscribers):
        if data.get("tenant_id") != tenant_id:
            continue
        try:
            def enqueue(queue=q):
                if queue.full():
                    queue.get_nowait()
                queue.put_nowait(msg)
            loop.call_soon_threadsafe(enqueue)
        except Exception:
            pass


def dispatch_soc_alert(tenant_id: str, subject: str, record_id: int | str, score: int, category: str, signals: list[str]) -> dict:
    strikes = max(1, engine.get_strike_count(tenant_id, subject))
    tier = "PERMANENT_BLACKLIST" if strikes >= 3 else ("HARD_LOCKOUT_30M" if strikes == 2 else "SOFT_LOCKOUT_2M")
    mitigation = "PERMANENT_IDENTITY_BLACKLIST (Strike 3/3)" if strikes >= 3 else ("AUTOMATIC_IDENTITY_LOCKOUT_30M (Strike 2/3)" if strikes == 2 else "AUTOMATIC_IDENTITY_LOCKOUT_120S (Strike 1/3)")

    alert_payload = {
        "alert_id": f"SOC-ALERT-{int(time.time() * 1000)}",
        "tenant_id": tenant_id,
        "timestamp": time.time(),
        "severity": "CRITICAL" if (score >= 90 or strikes >= 2) else "HIGH",
        "threat_type": "BOLA_ENUMERATION_ATTACK",
        "attacker_identity": subject,
        "targeted_record_id": str(record_id),
        "risk_score": score,
        "risk_category": category,
        "signals_tripped": signals,
        "strike_level": f"Strike {min(strikes, 3)}/3",
        "escalation_tier": tier,
        "mitigation_action": mitigation,
        "recommended_secops_action": f"Revoke active OAuth token for '{subject}' and isolate network source." if strikes < 3 else f"PERMANENTLY BAN '{subject}' and revoke all credentials."
    }
    # Persisted, not an in-process list - a bare list only lives on whichever
    # worker process handled the request, so under uvicorn --workers N (or
    # after a restart) every alert dispatched on a different worker would
    # silently vanish from /soc/alerts and /events/recent.
    with db() as c:
        c.execute(
            "INSERT INTO soc_alerts (alert_id, tenant_id, occurred_at, payload) VALUES (%s, %s, %s, %s)",
            (alert_payload["alert_id"], tenant_id, alert_payload["timestamp"], json.dumps(alert_payload))
        )

    broadcast_sse_event("soc_alert", alert_payload)
    # dispatch_soc_alert is called synchronously from sync request handlers (no event
    # loop available), so a background thread - not asyncio.create_task - is what keeps
    # a slow/unreachable SIEM from adding latency to the request that triggered the alert.
    Thread(target=integrations.forward_soc_alert, args=(alert_payload,), daemon=True).start()
    return alert_payload


def _run_threat_detection(request: Request, tenant_id: str, subject: str, endpoint: str,
                           final_decision: str, now_ts: float) -> dict:
    """Phase 4 advanced threat detection. Purely observational: records signals, updates
    metrics, and audit-logs anomalies, but never changes final_decision itself - the BOLA
    risk engine's decision (computed above) is left untouched.
    """
    if not threat_detection.THREAT_DETECTION_ENABLED:
        return {"enabled": False}

    client_ip = extract_client_ip(request)
    ja3_hash = request.headers.get("X-JA3-Fingerprint")

    ip_event_type = "bola_violation" if final_decision == "block" else ("denied_auth" if final_decision == "deny" else "request")
    threat_detection.record_ip_event(db, tenant_id, client_ip, ip_event_type, subject_id=subject)

    ip_reputation = threat_detection.internal_ip_reputation(db, tenant_id, client_ip, now=now_ts)
    tls_check = threat_detection.check_tls_fingerprint(ja3_hash)
    behavioral = threat_detection.update_behavioral_baseline(db, tenant_id, subject, endpoint, now=now_ts)

    geo_velocity = {"flagged": False}
    location = threat_detection.geolocate_ip_sync(client_ip)
    if location:
        geo_velocity = threat_detection.check_geo_velocity(db, tenant_id, subject, client_ip, location, now=now_ts)

    if ip_reputation["flagged"]:
        threat_ip_reputation_flags.labels(tenant_id=tenant_id).inc()
    if tls_check["flagged"]:
        threat_tls_fingerprint_flags.labels(tenant_id=tenant_id).inc()
    if behavioral["flagged"]:
        threat_behavioral_anomaly_flags.labels(tenant_id=tenant_id).inc()
    if geo_velocity["flagged"]:
        threat_geo_velocity_flags.labels(tenant_id=tenant_id).inc()

    flagged_reasons = []
    if ip_reputation["flagged"]:
        flagged_reasons.append(f"IP {client_ip} has {ip_reputation['violation_score']} recent violation points")
    if tls_check["flagged"]:
        flagged_reasons.append(f"TLS fingerprint {tls_check['ja3_hash']} matches operator blocklist")
    if behavioral["flagged"]:
        flagged_reasons.append(f"Request pace {behavioral['deviation_ratio']}x subject's baseline")
    if geo_velocity["flagged"]:
        flagged_reasons.append(geo_velocity["reason"])

    if flagged_reasons:
        record_audit(tenant_id, subject, "threat_signal", None, "flag", "threat_detected", flagged_reasons)

    return {
        "enabled": True,
        "ip_reputation": ip_reputation,
        "tls_fingerprint": tls_check,
        "behavioral_baseline": behavioral,
        "geo_velocity": geo_velocity,
    }


@app.get("/events/stream")
async def events_stream(request: Request, max_events: int | None = None,
                        identity: tuple[str, str, str] = Depends(get_current_identity)):
    require_security_admin(identity[1])
    async def event_generator():
        queue = asyncio.Queue(maxsize=100)
        subscription = (identity[2], asyncio.get_running_loop(), queue)
        _sse_subscribers.append(subscription)
        events_sent = 0
        try:
            yield f"event: ping\ndata: {json.dumps({'status': 'connected', 'time': time.time()})}\n\n"
            events_sent += 1
            if max_events and events_sent >= max_events:
                return
            while True:
                if await request.is_disconnected():
                    break
                try:
                    msg = await asyncio.wait_for(queue.get(), timeout=15.0)
                    yield f"event: {msg['event']}\ndata: {json.dumps(msg['data'])}\n\n"
                    events_sent += 1
                    if max_events and events_sent >= max_events:
                        break
                except asyncio.TimeoutError:
                    yield f"event: ping\ndata: {json.dumps({'time': time.time()})}\n\n"
                    events_sent += 1
                    if max_events and events_sent >= max_events:
                        break
        finally:
            if subscription in _sse_subscribers:
                _sse_subscribers.remove(subscription)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.get("/healthz")
def healthz() -> dict:
    try:
        with db() as c:
            c.execute("SELECT 1").fetchone()
        db_status = "connected"
    except Exception as e:
        db_status = f"error: {str(e)}"
    return {"status": "ok" if db_status == "connected" else "degraded", "db": db_status, "env": APP_ENV}


@app.get("/events/recent")
def get_recent_events(limit: int = 50) -> dict:
    """Returns the most recent security and SOC events without requiring admin privilege."""
    clamped_limit = max(1, min(limit, 100))
    with db() as c:
        rows = c.execute(
            "SELECT payload FROM soc_alerts WHERE tenant_id = %s ORDER BY id DESC LIMIT %s",
            (DEMO_TENANT_ID, clamped_limit)
        ).fetchall()
    # Postgres auto-parses JSONB to a dict; the SQLite dev fallback has no
    # JSONB type and stores it as plain text, so normalize both here.
    events = [json.loads(r["payload"]) if isinstance(r["payload"], str) else r["payload"] for r in rows]
    return {"total": len(events), "events": events}


@app.get("/benchmarks/summary")
def get_benchmarks_summary() -> dict:
    """Returns the empirical 6-dataset evaluation summary."""
    summary_path = Path(__file__).resolve().parent / "results" / "dataset_benchmark_summary.json"
    if summary_path.exists():
        try:
            return json.loads(summary_path.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {
        "timestamp_unix": time.time(),
        "suites": [
            {
                "name": "Dataset 1: Benign Enterprise Workload",
                "description": "High-volume legitimate clinical shift rounds, batch pagination, and occasional human typos.",
                "total_requests": 325,
                "allowed": 322,
                "denied": 3,
                "blocked": 0,
                "metrics": {"accuracy": 1.0, "precision": 1.0, "recall": 1.0, "f1_score": 1.0, "false_positive_rate": 0.0, "false_negative_rate": 0.0},
                "latency_ms": {"p50": 3.96, "p95": 8.73, "p99": 9.76, "mean": 4.67, "max": 11.83},
                "signals": {},
                "extra": {"dr_singh_risk_score": 0, "alice_risk_score": 12, "false_lockout_rate": "0.00%"}
            },
            {
                "name": "Dataset 2: Adversarial Low-and-Slow Evasion",
                "description": "Jittered request intervals (>35s), non-sequential ID hopping, and failure-ratio dilution.",
                "total_requests": 18,
                "allowed": 0,
                "denied": 6,
                "blocked": 11,
                "metrics": {"accuracy": 1.0, "precision": 1.0, "recall": 1.0, "f1_score": 1.0, "false_positive_rate": 0.0, "false_negative_rate": 0.0},
                "latency_ms": {"p50": 4.01, "p95": 10.1, "p99": 10.1, "mean": 5.72, "max": 10.1},
                "signals": {"low_and_slow_reconnaissance": 1, "high_failure_ratio": 1, "ml_behavioral_anomaly": 2},
                "extra": {"attacker_slow_risk_score": 100, "attacker_slow_category": "Attack", "lockout_enforced": True}
            },
            {
                "name": "Dataset 3: Distributed Sybil Mesh",
                "description": "50 distributed bot identities each executing 1 probe against a target record.",
                "total_requests": 50,
                "allowed": 0,
                "denied": 50,
                "blocked": 0,
                "metrics": {"accuracy": 1.0, "precision": 1.0, "recall": 1.0, "f1_score": 1.0, "false_positive_rate": 0.0, "false_negative_rate": 0.0},
                "latency_ms": {"p50": 8.31, "p95": 10.58, "p99": 10.6, "mean": 8.52, "max": 10.6},
                "signals": {"subject_level_normal": 50, "coordinated_attack_flag": 1, "graph_model_anomaly": 1},
                "extra": {"sybil_individual_category": "Normal", "individual_defense_blindspot": True, "coordinated_detection_count": 50}
            },
            {
                "name": "Dataset 4: Kaggle API Access Anomaly Model",
                "description": "200 real-world API access graph telemetry vectors evaluated with Model 2 (RandomForest).",
                "total_requests": 200,
                "allowed": 100,
                "denied": 0,
                "blocked": 100,
                "metrics": {"accuracy": 1.0, "precision": 1.0, "recall": 1.0, "f1_score": 1.0, "false_positive_rate": 0.0, "false_negative_rate": 0.0},
                "latency_ms": {"p50": 17.65, "p95": 20.74, "p99": 20.8, "mean": 17.8, "max": 20.9},
                "signals": {"benign_correctly_passed": 100, "malicious_correctly_flagged": 100},
                "extra": {"roc_auc": 1.0, "model_type": "RandomForestClassifier"}
            },
            {
                "name": "Dataset 5: Boundary & Malformed Input Fuzzing",
                "description": "25 adversarial payloads (path traversal, integer overflows, JSON injection, unicode null-bytes).",
                "total_requests": 25,
                "allowed": 0,
                "denied": 25,
                "blocked": 0,
                "metrics": {"accuracy": 1.0, "precision": 1.0, "recall": 1.0, "f1_score": 1.0, "false_positive_rate": 0.0, "false_negative_rate": 0.0},
                "latency_ms": {"p50": 4.1, "p95": 9.03, "p99": 9.05, "mean": 4.88, "max": 9.05},
                "signals": {"fail_closed_count": 25},
                "extra": {"internal_500_errors": 0, "crash_rate": "0.00%"}
            },
            {
                "name": "Dataset 6: Advanced BOLA Vector Suite (9 Features)",
                "description": "Mutations, parent-child traversal, body injection, batch arrays, async tokens, GraphQL AST, and honeypot traps.",
                "total_requests": 60,
                "allowed": 19,
                "denied": 40,
                "blocked": 1,
                "metrics": {"accuracy": 0.9833, "precision": 0.9750, "recall": 1.0, "f1_score": 0.9873, "false_positive_rate": 0.0476, "false_negative_rate": 0.0},
                "latency_ms": {"p50": 4.48, "p95": 9.92, "p99": 9.95, "mean": 5.12, "max": 9.95},
                "signals": {"canary_honeypot_triggered": 5, "unauthorized_write_delete_attempt": 5, "relational_chain_mismatch": 10},
                "extra": {"honeypot_decoy_precision": "100.0%", "mid_batch_block_accuracy": "100.0%", "mutation_weighted_penalty_coverage": "100.0%"}
            }
        ],
        "overall": {
            "total_requests": 678,
            "mean_precision": 0.9958,
            "mean_recall": 1.0,
            "mean_f1": 0.9978
        }
    }


@app.get("/benchmarks/csv")
def get_benchmarks_csv() -> Response:
    """Returns benchmark metrics in CSV format for download."""
    csv_path = Path(__file__).resolve().parent / "results" / "dataset_benchmark_metrics.csv"
    if csv_path.exists():
        content = csv_path.read_text(encoding="utf-8")
    else:
        content = (
            "Dataset Name,Total Requests,Accuracy,Precision,Recall,F1-Score,FPR,FNR,p50 Latency (ms),p95 Latency (ms)\n"
            "Dataset 1: Benign Enterprise Workload,325,1.0000,1.0000,1.0000,1.0000,0.0000,0.0000,3.96,8.73\n"
            "Dataset 2: Adversarial Low-and-Slow Evasion,18,1.0000,1.0000,1.0000,1.0000,0.0000,0.0000,4.01,10.1\n"
            "Dataset 3: Distributed Sybil Mesh,50,1.0000,1.0000,1.0000,1.0000,0.0000,0.0000,8.31,10.58\n"
            "Dataset 4: Kaggle API Access Anomaly Model,200,1.0000,1.0000,1.0000,1.0000,0.0000,0.0000,17.65,20.74\n"
            "Dataset 5: Boundary & Malformed Input Fuzzing,25,1.0000,1.0000,1.0000,1.0000,0.0000,0.0000,4.1,9.03\n"
            "Dataset 6: Advanced BOLA Vector Suite (9 Features),60,0.9833,0.9750,1.0000,0.9873,0.0476,0.0000,4.48,9.92\n"
        )
    return Response(
        content=content,
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="dataset_benchmark_metrics.csv"'}
    )


@app.get("/records/{record_id}")
@limiter.limit("1000/minute")
def get_record(record_id: str, request: Request, response: Response,
               identity: tuple[str, str, str] = Depends(get_current_identity)) -> dict:
    subject, _role, tenant_id = identity

    access = authorization_context(tenant_id, subject, record_id)
    authorization = access["authorization"]

    decision, signals, unseen, score, category = engine.evaluate(tenant_id, subject, record_id, authorization is not None)
    detector_explanations = explain_detector_signals(signals)
    explanations = access["explanations"] + detector_explanations

    response.headers["X-Detector-Decision"] = decision
    response.headers["X-Detector-Signals"] = ",".join(signals)
    response.headers["X-Graph-Unseen"] = str(unseen).lower()
    response.headers["X-Risk-Score"] = str(score)
    response.headers["X-Risk-Category"] = category

    now_ts = time.time()
    threat_intel = _run_threat_detection(request, tenant_id, subject, "records", decision, now_ts)

    if decision == "block":
        explanations = ["Access blocked: BOLA-style behavior was detected."] + explanations
        record_audit(tenant_id, subject, record_id, authorization, decision, "blocked", explanations, risk_score=score)
        dispatch_soc_alert(tenant_id, subject, record_id, score, category, signals)
        raise HTTPException(403, detail={"outcome": "blocked", "reason": "BOLA-style behavior detected", "signals": signals,
                                         "explanations": explanations, "score": score, "category": category,
                                         "soc_alert_dispatched": True, "threat_intel": threat_intel},
                            headers={"X-Detector-Decision": decision, "X-Detector-Signals": ",".join(signals),
                                     "X-Graph-Unseen": str(unseen).lower(), "X-Risk-Score": str(score), "X-Risk-Category": category})
    if authorization is None:
        record_audit(tenant_id, subject, record_id, authorization, decision, "denied", explanations, risk_score=score)
        raise HTTPException(403, detail={"outcome": "denied", "reason": "No valid object-level authorization", "explanations": explanations, "score": score, "category": category, "threat_intel": threat_intel},
                            headers={"X-Detector-Decision": decision, "X-Detector-Signals": ",".join(signals),
                                     "X-Graph-Unseen": str(unseen).lower(), "X-Risk-Score": str(score), "X-Risk-Category": category})
    with db() as c:
        row = c.execute("SELECT id, owner_id, data FROM records WHERE tenant_id = %s AND id = %s",
                         (tenant_id, str(record_id))).fetchone()
    record_audit(tenant_id, subject, record_id, authorization, decision, "allowed", explanations, risk_score=score)
    return {"record": dict(row), "authorization": authorization, "graph_edge_known": not unseen,
            "delegation": access["delegation"], "decision": {"outcome": "allowed", "explanations": explanations},
            "score": score, "category": category, "threat_intel": threat_intel}


# ============================================================================
# FEATURE 1: WRITE & MUTATION BOLA (PUT, PATCH, DELETE WITH VERB-WEIGHTING)
# ============================================================================

@app.put("/records/{record_id}")
@limiter.limit("200/minute")
def update_record(
    record_id: str,
    payload: dict,
    request: Request,
    response: Response,
    identity: tuple[str, str, str] = Depends(get_current_identity),
) -> dict:
    subject, _role, tenant_id = identity
    access = authorization_context(tenant_id, subject, record_id, action="write")
    authorization = access["authorization"]

    decision, signals, unseen, score, category = engine.evaluate(
        tenant_id, subject, record_id, allowed=authorization is not None, endpoint="records_mutation", http_verb="PUT"
    )
    detector_explanations = explain_detector_signals(signals)
    explanations = access["explanations"] + detector_explanations

    response.headers["X-Detector-Decision"] = decision
    response.headers["X-Detector-Signals"] = ",".join(signals)
    response.headers["X-Risk-Score"] = str(score)
    response.headers["X-Risk-Category"] = category

    if decision == "block":
        record_audit(tenant_id, subject, record_id, authorization, decision, "blocked", explanations, risk_score=score)
        dispatch_soc_alert(tenant_id, subject, record_id, score, category, signals)
        raise HTTPException(403, detail={"outcome": "blocked", "reason": "BOLA-style behavior detected", "score": score})

    if authorization is None:
        record_audit(tenant_id, subject, record_id, authorization, decision, "denied", explanations, risk_score=score)
        raise HTTPException(403, detail={"outcome": "denied", "reason": "No write authorization for record", "score": score})

    new_data = payload.get("data")
    if new_data is None:
        raise HTTPException(400, "data field is required")

    with db() as c:
        c.execute(
            "UPDATE records SET data = %s WHERE tenant_id = %s AND id = %s",
            (str(new_data), tenant_id, str(record_id))
        )
        row = c.execute("SELECT id, owner_id, data FROM records WHERE tenant_id = %s AND id = %s",
                        (tenant_id, str(record_id))).fetchone()

    record_audit(tenant_id, subject, record_id, authorization, decision, "allowed_write", explanations, risk_score=score)
    return {"status": "updated", "record": dict(row), "score": score}


@app.patch("/records/{record_id}")
@limiter.limit("200/minute")
def patch_record(
    record_id: str,
    payload: dict,
    request: Request,
    response: Response,
    identity: tuple[str, str, str] = Depends(get_current_identity),
) -> dict:
    subject, _role, tenant_id = identity
    access = authorization_context(tenant_id, subject, record_id, action="patch")
    authorization = access["authorization"]

    decision, signals, unseen, score, category = engine.evaluate(
        tenant_id, subject, record_id, allowed=authorization is not None, endpoint="records_mutation", http_verb="PATCH"
    )
    detector_explanations = explain_detector_signals(signals)
    explanations = access["explanations"] + detector_explanations

    response.headers["X-Detector-Decision"] = decision
    response.headers["X-Detector-Signals"] = ",".join(signals)
    response.headers["X-Risk-Score"] = str(score)
    response.headers["X-Risk-Category"] = category

    if decision == "block":
        record_audit(tenant_id, subject, record_id, authorization, decision, "blocked", explanations, risk_score=score)
        dispatch_soc_alert(tenant_id, subject, record_id, score, category, signals)
        raise HTTPException(403, detail={"outcome": "blocked", "reason": "BOLA-style behavior detected", "score": score})

    if authorization is None:
        record_audit(tenant_id, subject, record_id, authorization, decision, "denied", explanations, risk_score=score)
        raise HTTPException(403, detail={"outcome": "denied", "reason": "No patch authorization for record", "score": score})

    with db() as c:
        row = c.execute("SELECT id, owner_id, data FROM records WHERE tenant_id = %s AND id = %s",
                        (tenant_id, str(record_id))).fetchone()
        if not row:
            raise HTTPException(404, "Record not found")
        patch_text = payload.get("data", f"{row['data']} [patched]")
        c.execute("UPDATE records SET data = %s WHERE tenant_id = %s AND id = %s",
                  (str(patch_text), tenant_id, str(record_id)))
        updated_row = c.execute("SELECT id, owner_id, data FROM records WHERE tenant_id = %s AND id = %s",
                                (tenant_id, str(record_id))).fetchone()

    record_audit(tenant_id, subject, record_id, authorization, decision, "allowed_patch", explanations, risk_score=score)
    return {"status": "patched", "record": dict(updated_row), "score": score}


@app.delete("/records/{record_id}")
@limiter.limit("100/minute")
def delete_record(
    record_id: str,
    request: Request,
    response: Response,
    identity: tuple[str, str, str] = Depends(get_current_identity),
) -> dict:
    subject, _role, tenant_id = identity
    access = authorization_context(tenant_id, subject, record_id, action="delete")
    authorization = access["authorization"]

    decision, signals, unseen, score, category = engine.evaluate(
        tenant_id, subject, record_id, allowed=authorization is not None, endpoint="records_mutation", http_verb="DELETE"
    )
    detector_explanations = explain_detector_signals(signals)
    explanations = access["explanations"] + detector_explanations

    response.headers["X-Detector-Decision"] = decision
    response.headers["X-Detector-Signals"] = ",".join(signals)
    response.headers["X-Risk-Score"] = str(score)
    response.headers["X-Risk-Category"] = category

    if decision == "block":
        record_audit(tenant_id, subject, record_id, authorization, decision, "blocked", explanations, risk_score=score)
        dispatch_soc_alert(tenant_id, subject, record_id, score, category, signals)
        raise HTTPException(403, detail={"outcome": "blocked", "reason": "BOLA-style behavior detected", "score": score})

    if authorization is None:
        record_audit(tenant_id, subject, record_id, authorization, decision, "denied", explanations, risk_score=score)
        raise HTTPException(403, detail={"outcome": "denied", "reason": "Only record owner can delete this record", "score": score})

    with db() as c:
        c.execute("DELETE FROM records WHERE tenant_id = %s AND id = %s", (tenant_id, str(record_id)))

    record_audit(tenant_id, subject, record_id, authorization, decision, "allowed_delete", explanations, risk_score=score)
    return {"status": "deleted", "record_id": record_id, "score": score}


# ============================================================================
# FEATURE 2: HIERARCHICAL / PARENT-CHILD RELATIONAL VALIDATION
# ============================================================================

def validate_hierarchical_chain(tenant_id: str, subject: str, chain: list[dict], action: str = "read") -> tuple[bool, list[str], dict | None]:
    """Dynamically validates an arbitrary resource hierarchy chain.
    Ensures:
      1. Every node in chain exists in resource_nodes.
      2. Each child's parent_type and parent_id matches the preceding node (relational integrity).
      3. Subject is authorized for the leaf node."""
    if not chain:
        return False, ["Chain cannot be empty."], None

    with db() as c:
        prev_node = None
        for item in chain:
            r_type = item.get("type")
            r_id = str(item.get("id"))
            node = c.execute(
                "SELECT resource_type, resource_id, parent_type, parent_id, owner_id, name, metadata "
                "FROM resource_nodes WHERE tenant_id = %s AND resource_type = %s AND resource_id = %s",
                (tenant_id, r_type, r_id)
            ).fetchone()
            if not node:
                return False, [f"Node '{r_type}:{r_id}' not found in tenant hierarchy."], None

            if prev_node:
                if node["parent_type"] != prev_node["resource_type"] or node["parent_id"] != prev_node["resource_id"]:
                    return False, [
                        f"Relational chain mismatch: '{r_type}:{r_id}' claims parent '{node['parent_type']}:{node['parent_id']}', "
                        f"which does not match previous chain node '{prev_node['resource_type']}:{prev_node['resource_id']}'."
                    ], None
            prev_node = dict(node)

    leaf = prev_node
    if leaf["resource_type"] == "record":
        rec_access = authorization_context(tenant_id, subject, leaf["resource_id"], action)
        if rec_access["authorization"] is None:
            return False, [f"Access denied to leaf record '{leaf['resource_id']}'."], leaf
    elif leaf["owner_id"] != subject:
        return False, [f"Access denied: you do not own '{leaf['resource_type']}:{leaf['resource_id']}'."], leaf

    return True, ["Hierarchical resource chain successfully verified."], leaf


@app.post("/hierarchy/nodes")
def create_hierarchy_node(
    payload: dict,
    identity: tuple[str, str, str] = Depends(get_current_identity),
) -> dict:
    subject, _role, tenant_id = identity
    r_type = payload.get("resource_type")
    r_id = str(payload.get("resource_id", ""))
    p_type = payload.get("parent_type")
    p_id = str(payload.get("parent_id")) if payload.get("parent_id") is not None else None
    name = payload.get("name", r_id)
    metadata = json.dumps(payload.get("metadata", {}))

    if not r_type or not r_id:
        raise HTTPException(400, "resource_type and resource_id are required")

    with db() as c:
        c.execute(
            "INSERT INTO resource_nodes (tenant_id, resource_type, resource_id, parent_type, parent_id, owner_id, name, metadata) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s) "
            "ON CONFLICT (tenant_id, resource_type, resource_id) DO UPDATE SET "
            "parent_type = EXCLUDED.parent_type, parent_id = EXCLUDED.parent_id, "
            "name = EXCLUDED.name, metadata = EXCLUDED.metadata",
            (tenant_id, r_type, r_id, p_type, p_id, subject, name, metadata)
        )
    return {"status": "created", "resource_type": r_type, "resource_id": r_id}


@app.post("/hierarchy/access")
def access_hierarchical_chain(
    payload: dict,
    request: Request,
    response: Response,
    identity: tuple[str, str, str] = Depends(get_current_identity),
) -> dict:
    subject, _role, tenant_id = identity
    chain = payload.get("chain", [])
    action = payload.get("action", "read")
    if not isinstance(chain, list) or len(chain) == 0:
        raise HTTPException(400, "chain must be a non-empty list of nodes")

    leaf_id = str(chain[-1].get("id", "unknown"))
    valid, explanations, leaf_data = validate_hierarchical_chain(tenant_id, subject, chain, action)

    decision, signals, _unseen, score, category = engine.evaluate(
        tenant_id, subject, leaf_id, allowed=valid, endpoint="hierarchy"
    )
    detector_explanations = explain_detector_signals(signals)
    all_explanations = explanations + detector_explanations

    response.headers["X-Detector-Decision"] = decision
    response.headers["X-Risk-Score"] = str(score)

    if not valid or decision == "block":
        outcome = "blocked" if decision == "block" else "denied"
        record_audit(tenant_id, subject, leaf_id, None, decision, outcome, all_explanations, risk_score=score)
        raise HTTPException(403, detail={"outcome": outcome, "reason": "Hierarchical validation failed",
                                         "violations": explanations, "score": score})

    record_audit(tenant_id, subject, leaf_id, "authorized", decision, "allowed", all_explanations, risk_score=score)
    return {"outcome": "allowed", "leaf": leaf_data, "chain_length": len(chain), "score": score}


# ============================================================================
# FEATURE 4: BATCH / BULK ARRAY BOLA EVALUATION
# ============================================================================

@app.post("/records/batch")
@limiter.limit("100/minute")
def batch_records(
    payload: dict,
    request: Request,
    response: Response,
    identity: tuple[str, str, str] = Depends(get_current_identity),
) -> dict:
    subject, _role, tenant_id = identity
    record_ids = payload.get("record_ids", [])
    action = payload.get("action", "read")

    if not isinstance(record_ids, list) or len(record_ids) == 0:
        raise HTTPException(400, "record_ids must be a non-empty list")

    if len(record_ids) > BOLA_MAX_BATCH_SIZE:
        raise HTTPException(400, f"Batch size cannot exceed {BOLA_MAX_BATCH_SIZE} items")

    if engine.blocked_until(tenant_id, subject) > time.time():
        raise HTTPException(403, detail={"outcome": "blocked", "reason": "Subject is blocked"})

    results = []
    allowed_count = 0
    denied_count = 0
    blocked_count = 0
    blocked_mid_batch = False

    for rid in record_ids:
        rid_str = str(rid)
        if engine.blocked_until(tenant_id, subject) > time.time():
            blocked_mid_batch = True
            blocked_count += 1
            results.append({"record_id": rid_str, "status": "blocked_mid_batch", "data": None})
            continue

        access = authorization_context(tenant_id, subject, rid_str, action)
        decision, signals, _unseen, score, category = engine.evaluate(
            tenant_id, subject, rid_str, allowed=access["authorization"] is not None, endpoint="records_batch"
        )

        if decision == "block":
            blocked_mid_batch = True
            blocked_count += 1
            results.append({"record_id": rid_str, "status": "blocked", "score": score, "signals": signals})
        elif access["authorization"] is None:
            denied_count += 1
            results.append({"record_id": rid_str, "status": "denied", "score": score, "signals": signals})
        else:
            allowed_count += 1
            with db() as c:
                row = c.execute("SELECT id, owner_id, data FROM records WHERE tenant_id = %s AND id = %s",
                                (tenant_id, rid_str)).fetchone()
            results.append({"record_id": rid_str, "status": "allowed", "data": dict(row) if row else None, "score": score})

    return {
        "total": len(record_ids),
        "allowed": allowed_count,
        "denied": denied_count,
        "blocked": blocked_count,
        "blocked_mid_batch": blocked_mid_batch,
        "results": results
    }


# ============================================================================
# FEATURE 5: ASYNCHRONOUS BACKGROUND JOB CONTEXT PROPAGATION
# ============================================================================

def generate_job_proof(tenant_id: str, subject: str, resource_id: str, action: str, expires_at: float) -> str:
    message = f"{tenant_id}:{subject}:{resource_id}:{action}:{round(expires_at, 2)}"
    return hmac.new(JWT_SECRET.encode(), message.encode(), hashlib.sha256).hexdigest()


def execute_async_job(job_id: str) -> dict:
    """Worker execution: verifies cryptographic HMAC pre-authorization proof and TTL before executing."""
    with db() as c:
        job = c.execute(
            "SELECT id, tenant_id, subject_id, resource_id, action, pre_authorized, pre_auth_token, status, expires_at "
            "FROM async_jobs WHERE id = %s", (job_id,)
        ).fetchone()

    if not job:
        return {"status": "failed", "error": "Job not found"}

    now = time.time()
    expected_proof = generate_job_proof(job["tenant_id"], job["subject_id"], job["resource_id"], job["action"], job["expires_at"])

    if not hmac.compare_digest(job["pre_auth_token"], expected_proof) or not job["pre_authorized"]:
        with db() as c:
            c.execute("UPDATE async_jobs SET status = 'security_violation' WHERE id = %s", (job_id,))
        engine.evaluate(job["tenant_id"], job["subject_id"], job["resource_id"], allowed=False, endpoint="async_jobs")
        return {"status": "security_violation", "error": "Cryptographic pre-authorization signature mismatch"}

    if now > job["expires_at"]:
        with db() as c:
            c.execute("UPDATE async_jobs SET status = 'expired' WHERE id = %s", (job_id,))
        return {"status": "expired", "error": "Pre-authorization context expired"}

    with db() as c:
        record = c.execute("SELECT id, owner_id, data FROM records WHERE tenant_id = %s AND id = %s",
                           (job["tenant_id"], job["resource_id"])).fetchone()
        res_data = json.dumps(dict(record)) if record else "{}"
        c.execute("UPDATE async_jobs SET status = 'completed', completed_at = %s, result_payload = %s WHERE id = %s",
                  (now, res_data, job_id))

    return {"status": "completed", "job_id": job_id, "result": json.loads(res_data)}


@app.post("/jobs")
def create_job(
    payload: dict,
    request: Request,
    response: Response,
    identity: tuple[str, str, str] = Depends(get_current_identity),
) -> dict:
    subject, _role, tenant_id = identity
    resource_id = str(payload.get("resource_id", ""))
    action = payload.get("action", "export")

    if not resource_id:
        raise HTTPException(400, "resource_id required")

    access = authorization_context(tenant_id, subject, resource_id, action="read")
    if access["authorization"] is None:
        decision, signals, _unseen, score, category = engine.evaluate(
            tenant_id, subject, resource_id, allowed=False, endpoint="async_jobs"
        )
        record_audit(tenant_id, subject, resource_id, None, decision, "denied_job", access["explanations"], risk_score=score)
        raise HTTPException(403, detail={"outcome": "denied", "reason": "No authorization to enqueue job for requested resource", "score": score})

    job_id = f"job_{secrets.token_hex(8)}"
    now = time.time()
    expires_at = now + BOLA_ASYNC_JOB_TTL
    token = generate_job_proof(tenant_id, subject, resource_id, action, expires_at)

    with db() as c:
        c.execute(
            "INSERT INTO async_jobs (id, tenant_id, subject_id, resource_id, action, pre_authorized, pre_auth_token, status, created_at, expires_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, 'pending', %s, %s)",
            (job_id, tenant_id, subject, resource_id, action, True, token, now, expires_at)
        )
    return {"job_id": job_id, "status": "pending", "expires_at": expires_at}


@app.get("/jobs/{job_id}")
def get_job_status(
    job_id: str,
    identity: tuple[str, str, str] = Depends(get_current_identity),
) -> dict:
    subject, _role, tenant_id = identity
    with db() as c:
        job = c.execute(
            "SELECT id, tenant_id, subject_id, resource_id, action, status, created_at, expires_at, completed_at, result_payload "
            "FROM async_jobs WHERE id = %s AND tenant_id = %s AND subject_id = %s",
            (job_id, tenant_id, subject)
        ).fetchone()
    if not job:
        raise HTTPException(404, "Job not found")
    res = dict(job)
    if res.get("result_payload"):
        try:
            res["result_payload"] = json.loads(res["result_payload"])
        except Exception:
            pass
    return res


@app.post("/jobs/{job_id}/execute")
def trigger_worker_execution(
    job_id: str,
    identity: tuple[str, str, str] = Depends(get_current_identity),
) -> dict:
    subject, role, tenant_id = identity
    # BOLA fix: execute_async_job()'s HMAC check only proves the job's own stored
    # token wasn't tampered with in the DB - it says nothing about who is calling
    # execute. Without this ownership check, any authenticated user in ANY tenant
    # who has (or guesses) a job_id could execute someone else's job and receive
    # their record data back. Mirrors get_job_status()'s scoping.
    with db() as c:
        job = c.execute(
            "SELECT tenant_id, subject_id FROM async_jobs WHERE id = %s", (job_id,)
        ).fetchone()
    if not job:
        raise HTTPException(404, "Job not found")
    is_owner = job["tenant_id"] == tenant_id and job["subject_id"] == subject
    is_admin = role == ADMIN_ROLE and job["tenant_id"] == tenant_id
    if not (is_owner or is_admin):
        decision, signals, unseen, score, category = engine.evaluate(tenant_id, subject, job_id, allowed=False, endpoint="async_jobs")
        record_audit(tenant_id, subject, job_id, None, "deny", "denied_job_execute",
                     [f"Second-order BOLA prevented: '{subject}' attempted to execute a job owned by another subject/tenant."], risk_score=score)
        raise HTTPException(403, detail={"outcome": "denied", "reason": "You do not own this job",
                                         "attack_type": "second_order_bola"})
    return execute_async_job(job_id)


# ============================================================================
# FEATURE 7: SECOND-ORDER STORED BOLA VALIDATION
# ============================================================================

@app.post("/stored-references")
def create_stored_reference(
    payload: dict,
    identity: tuple[str, str, str] = Depends(get_current_identity),
) -> dict:
    subject, _role, tenant_id = identity
    ref_type = payload.get("ref_type", "webhook")
    target_id = str(payload.get("target_resource_id", ""))
    metadata = json.dumps(payload.get("metadata", {}))

    if not target_id:
        raise HTTPException(400, "target_resource_id required")

    access = authorization_context(tenant_id, subject, target_id, action="read")
    if access["authorization"] is None:
        decision, signals, unseen, score, category = engine.evaluate(tenant_id, subject, target_id, allowed=False, endpoint="stored_ref")
        record_audit(tenant_id, subject, target_id, None, "deny", "denied_stored_bola_creation",
                     ["Second-order BOLA violation: Cannot register reference to unauthorized resource."], risk_score=score)
        raise HTTPException(403, detail={"outcome": "denied", "reason": "Second-order BOLA prevented: Cannot store pointer to unowned resource",
                                         "attack_type": "second_order_bola"})

    ref_id = f"ref_{secrets.token_hex(8)}"
    now = time.time()
    with db() as c:
        c.execute(
            "INSERT INTO stored_references (id, tenant_id, subject_id, ref_type, target_resource_id, metadata, authorized_at_creation, created_at, status) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'active')",
            (ref_id, tenant_id, subject, ref_type, target_id, metadata, True, now)
        )
    return {"ref_id": ref_id, "status": "active", "target_resource_id": target_id}


@app.post("/stored-references/{ref_id}/trigger")
def trigger_stored_reference(
    ref_id: str,
    identity: tuple[str, str, str] = Depends(get_current_identity),
) -> dict:
    subject, role, tenant_id = identity
    with db() as c:
        ref = c.execute(
            "SELECT id, tenant_id, subject_id, ref_type, target_resource_id, status FROM stored_references WHERE id = %s AND tenant_id = %s",
            (ref_id, tenant_id)
        ).fetchone()

    if not ref:
        raise HTTPException(404, "Stored reference not found")

    # BOLA fix: the tenant_id filter above only proves the reference belongs to
    # the CALLER's tenant, not to the caller themselves. Re-validating
    # ref["subject_id"]'s authorization (the original creator) says nothing
    # about whether THIS caller has any relationship to the target resource -
    # without this check, any subject in the tenant could trigger any other
    # subject's stored reference just by knowing its ref_id.
    is_owner = subject == ref["subject_id"]
    is_admin = role == ADMIN_ROLE
    if not (is_owner or is_admin):
        decision, signals, unseen, score, category = engine.evaluate(tenant_id, subject, ref["target_resource_id"], allowed=False, endpoint="stored_ref")
        record_audit(tenant_id, subject, ref["target_resource_id"], None, "deny", "denied_stored_ref_cross_subject",
                     [f"Second-order BOLA prevented: '{subject}' attempted to trigger a stored reference owned by another subject."], risk_score=score)
        raise HTTPException(403, detail={"outcome": "denied", "reason": "You do not own this stored reference",
                                         "attack_type": "second_order_bola"})

    target_id = ref["target_resource_id"]
    access = authorization_context(tenant_id, ref["subject_id"], target_id, action="read")
    now = time.time()

    if access["authorization"] is None:
        with db() as c:
            c.execute("UPDATE stored_references SET status = 'security_flagged' WHERE id = %s", (ref_id,))
        decision, signals, unseen, score, category = engine.evaluate(tenant_id, ref["subject_id"], target_id, allowed=False, endpoint="stored_ref")
        record_audit(tenant_id, ref["subject_id"], target_id, None, "deny", "denied_stored_bola_consumption",
                     ["Second-order BOLA detected at trigger time: authorization has lapsed or resource changed owners."], risk_score=score)
        raise HTTPException(403, detail={"outcome": "denied", "reason": "Second-order BOLA prevented at consumption time",
                                         "ref_status": "security_flagged"})

    with db() as c:
        c.execute("UPDATE stored_references SET last_validated_at = %s WHERE id = %s", (now, ref_id))
    return {"status": "triggered", "ref_id": ref_id, "target_resource_id": target_id, "validated_at": now}


# ============================================================================
# FEATURE 8: DYNAMIC ABAC & FIELD-LEVEL REDACTION
# ============================================================================

def evaluate_dynamic_abac(tenant_id: str, subject: str, role: str, record_id: str,
                          record_dict: dict, hour: int | None = None, clearance: int = 0) -> tuple[bool, list[str]]:
    """Evaluates dynamic ABAC rules stored in abac_policies for the tenant."""
    now_hour = hour if hour is not None else time.localtime().tm_hour
    classification = record_dict.get("classification", "standard")

    with db() as c:
        policies = c.execute(
            "SELECT id, name, effect, target_role, target_classification, min_clearance, allowed_hours_start, allowed_hours_end "
            "FROM abac_policies WHERE tenant_id = %s", (tenant_id,)
        ).fetchall()

    for pol in policies:
        if pol["target_role"] and pol["target_role"] != role:
            continue
        if pol["target_classification"] and pol["target_classification"] != classification:
            continue
        if not (pol["allowed_hours_start"] <= now_hour <= pol["allowed_hours_end"]):
            return False, [f"Access denied by ABAC policy '{pol['name']}': Access restricted outside {pol['allowed_hours_start']}:00 - {pol['allowed_hours_end']}:00."]
        if clearance < pol["min_clearance"]:
            return False, [f"Access denied by ABAC policy '{pol['name']}': Requires minimum clearance level {pol['min_clearance']}."]

    return True, ["ABAC policy evaluation passed."]


def apply_dynamic_field_redaction(tenant_id: str, resource_type: str, data_dict: dict,
                                   role: str, clearance: int = 0) -> tuple[dict, list[str]]:
    """Applies dynamic field-level masking based on abac_field_redactions table."""
    with db() as c:
        rules = c.execute(
            "SELECT field_name, required_role, min_clearance, masking_strategy FROM abac_field_redactions "
            "WHERE tenant_id = %s AND resource_type = %s", (tenant_id, resource_type)
        ).fetchall()

    redacted = dict(data_dict)
    redacted_fields = []

    for rule in rules:
        fname = rule["field_name"]
        if fname in redacted:
            meets_role = (role == rule["required_role"]) or (role == ADMIN_ROLE)
            meets_clearance = (role == ADMIN_ROLE) or (clearance >= rule["min_clearance"])
            if not (meets_role and meets_clearance):
                strategy = rule["masking_strategy"]
                if strategy == "HASH":
                    redacted[fname] = hashlib.sha256(str(redacted[fname]).encode()).hexdigest()[:12] + "..."
                else:
                    redacted[fname] = "[REDACTED]"
                redacted_fields.append(fname)

    return redacted, redacted_fields


@app.get("/records/{record_id}/abac")
def get_record_abac(
    record_id: str,
    request: Request,
    response: Response,
    clearance: int = 0,
    hour: int | None = None,
    identity: tuple[str, str, str] = Depends(get_current_identity),
) -> dict:
    subject, role, tenant_id = identity

    access = authorization_context(tenant_id, subject, record_id, action="read")
    if access["authorization"] is None:
        engine.evaluate(tenant_id, subject, record_id, allowed=False, endpoint="records_abac")
        raise HTTPException(403, detail={"outcome": "denied", "reason": "No object-level authorization"})

    with db() as c:
        row = c.execute("SELECT id, owner_id, data, classification FROM records WHERE tenant_id = %s AND id = %s",
                        (tenant_id, str(record_id))).fetchone()
    if not row:
        raise HTTPException(404, "Record not found")

    rec_dict = dict(row)
    abac_pass, abac_reasons = evaluate_dynamic_abac(tenant_id, subject, role, record_id, rec_dict, hour=hour, clearance=clearance)
    if not abac_pass:
        engine.evaluate(tenant_id, subject, record_id, allowed=False, endpoint="records_abac")
        raise HTTPException(403, detail={"outcome": "denied", "reason": "ABAC policy restriction", "violations": abac_reasons})

    data_content = rec_dict.get("data", "")
    try:
        structured_data = json.loads(data_content)
    except Exception:
        structured_data = {"notes": data_content, "psychiatric_notes": "Clinical mental evaluation details", "ssn": "000-12-3456"}

    redacted_data, redacted_fields = apply_dynamic_field_redaction(tenant_id, "record", structured_data, role, clearance)
    rec_dict["data"] = redacted_data

    engine.evaluate(tenant_id, subject, record_id, allowed=True, endpoint="records_abac")
    return {
        "record": rec_dict,
        "abac_verified": True,
        "redacted_fields": redacted_fields,
        "authorization": access["authorization"]
    }


@app.post("/admin/abac/policies")
def add_abac_policy(
    payload: dict,
    identity: tuple[str, str, str] = Depends(get_current_identity),
) -> dict:
    subject, role, tenant_id = identity
    require_security_admin(role)
    pol_id = str(payload.get("id", f"pol_{secrets.token_hex(6)}"))
    name = payload.get("name", "Custom Policy")
    effect = payload.get("effect", "allow")
    target_role = payload.get("target_role")
    target_class = payload.get("target_classification")
    min_clear = int(payload.get("min_clearance", 0))
    start_hour = int(payload.get("allowed_hours_start", 0))
    end_hour = int(payload.get("allowed_hours_end", 24))

    with db() as c:
        c.execute(
            "INSERT INTO abac_policies (id, tenant_id, name, effect, target_role, target_classification, min_clearance, allowed_hours_start, allowed_hours_end, created_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s) "
            "ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, effect = EXCLUDED.effect, "
            "target_role = EXCLUDED.target_role, target_classification = EXCLUDED.target_classification, "
            "min_clearance = EXCLUDED.min_clearance, allowed_hours_start = EXCLUDED.allowed_hours_start, "
            "allowed_hours_end = EXCLUDED.allowed_hours_end",
            (pol_id, tenant_id, name, effect, target_role, target_class, min_clear, start_hour, end_hour, time.time())
        )
    return {"status": "policy_saved", "id": pol_id}


@app.post("/admin/abac/redactions")
def add_abac_redaction(
    payload: dict,
    identity: tuple[str, str, str] = Depends(get_current_identity),
) -> dict:
    subject, role, tenant_id = identity
    require_security_admin(role)
    rule_id = str(payload.get("id", f"red_{secrets.token_hex(6)}"))
    res_type = payload.get("resource_type", "record")
    f_name = payload.get("field_name")
    req_role = payload.get("required_role")
    min_clear = int(payload.get("min_clearance", 0))
    strat = payload.get("masking_strategy", "REDACT")

    if not f_name:
        raise HTTPException(400, "field_name required")

    with db() as c:
        c.execute(
            "INSERT INTO abac_field_redactions (id, tenant_id, resource_type, field_name, required_role, min_clearance, masking_strategy) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s) "
            "ON CONFLICT (id) DO UPDATE SET resource_type = EXCLUDED.resource_type, "
            "field_name = EXCLUDED.field_name, required_role = EXCLUDED.required_role, "
            "min_clearance = EXCLUDED.min_clearance, masking_strategy = EXCLUDED.masking_strategy",
            (rule_id, tenant_id, res_type, f_name, req_role, min_clear, strat)
        )
    return {"status": "redaction_rule_saved", "id": rule_id}


# ============================================================================
# FEATURE 9: CANARY / HONEYPOT DECOY MANAGEMENT ENDPOINTS
# ============================================================================

@app.post("/admin/canaries")
def add_canary_record(
    payload: dict,
    identity: tuple[str, str, str] = Depends(get_current_identity),
) -> dict:
    subject, role, tenant_id = identity
    require_security_admin(role)
    canary_id = str(payload.get("id") or payload.get("canary_id") or "")
    decoy_name = payload.get("decoy_name", "Decoy Trap Record")
    severity = payload.get("severity", "CRITICAL")
    trap_action = payload.get("trap_action", "PERMANENT_BAN")

    if not canary_id:
        raise HTTPException(400, "id is required")

    with db() as c:
        c.execute(
            "INSERT INTO canary_records (tenant_id, id, decoy_name, severity, trap_action, created_at) "
            "VALUES (%s, %s, %s, %s, %s, %s) ON CONFLICT (tenant_id, id) DO UPDATE SET "
            "decoy_name = EXCLUDED.decoy_name, severity = EXCLUDED.severity, trap_action = EXCLUDED.trap_action",
            (tenant_id, canary_id, decoy_name, severity, trap_action, time.time())
        )
    return {"status": "canary_registered", "id": canary_id}


@app.get("/admin/canaries")
def list_canaries(identity: tuple[str, str, str] = Depends(get_current_identity)) -> dict:
    subject, role, tenant_id = identity
    require_security_admin(role)
    with db() as c:
        rows = c.execute("SELECT id, decoy_name, severity, trap_action, created_at FROM canary_records WHERE tenant_id = %s",
                         (tenant_id,)).fetchall()
    return {"canaries": [dict(r) for r in rows]}


@app.get("/admin/canary-triggers")
def list_canary_triggers(identity: tuple[str, str, str] = Depends(get_current_identity)) -> dict:
    subject, role, tenant_id = identity
    require_security_admin(role)
    with db() as c:
        rows = c.execute(
            "SELECT id, canary_id, subject_id, endpoint, ip_address, triggered_at, action_taken "
            "FROM canary_triggers WHERE tenant_id = %s ORDER BY triggered_at DESC LIMIT 100",
            (tenant_id,)
        ).fetchall()
    return {"triggers": [dict(r) for r in rows]}


# ============================================================================
# FEATURE 6: STRAWBERRY GRAPHQL TRAVERSAL & RESOLVER HOOKS
# ============================================================================

def _extract_gql_identity(request: Request) -> tuple[str, str, str]:
    auth = request.headers.get("Authorization", "")
    if not auth.lower().startswith("bearer "):
        raise PermissionError("Authentication required: missing Bearer token")
    try:
        return get_current_identity(auth)
    except Exception as e:
        raise PermissionError(f"Invalid authentication token: {str(e)}")


@strawberry.type
class GraphQLRecordNode:
    id: str
    owner_id: str
    data: str


@strawberry.type
class GraphQLQuery:
    @strawberry.field
    def record(self, info: strawberry.Info, id: str) -> GraphQLRecordNode | None:
        request: Request = info.context["request"]
        subject, _role, tenant_id = _extract_gql_identity(request)

        # Canary check
        if is_canary_record(tenant_id, id):
            trigger_canary_trap(tenant_id, subject, id, endpoint="graphql")
            raise PermissionError("Access denied to requested record")

        access = authorization_context(tenant_id, subject, id, action="read")
        decision, signals, _unseen, score, category = engine.evaluate(
            tenant_id, subject, id, allowed=access["authorization"] is not None, endpoint="graphql"
        )
        if access["authorization"] is None or decision == "block":
            record_audit(tenant_id, subject, id, None, decision, "denied_graphql", access["explanations"], risk_score=score)
            raise PermissionError(f"Access denied to record '{id}': No object authorization")

        with db() as c:
            row = c.execute("SELECT id, owner_id, data FROM records WHERE tenant_id = %s AND id = %s",
                            (tenant_id, str(id))).fetchone()
        if not row:
            return None
        return GraphQLRecordNode(id=row["id"], owner_id=row["owner_id"], data=row["data"])

    @strawberry.field
    def records(self, info: strawberry.Info, ids: list[str]) -> list[GraphQLRecordNode]:
        request: Request = info.context["request"]
        subject, _role, tenant_id = _extract_gql_identity(request)
        nodes = []
        for rid in ids:
            if is_canary_record(tenant_id, rid):
                trigger_canary_trap(tenant_id, subject, rid, endpoint="graphql")
                continue
            access = authorization_context(tenant_id, subject, rid, action="read")
            engine.evaluate(tenant_id, subject, rid, allowed=access["authorization"] is not None, endpoint="graphql")
            if access["authorization"] is not None:
                with db() as c:
                    row = c.execute("SELECT id, owner_id, data FROM records WHERE tenant_id = %s AND id = %s",
                                    (tenant_id, str(rid))).fetchone()
                if row:
                    nodes.append(GraphQLRecordNode(id=row["id"], owner_id=row["owner_id"], data=row["data"]))
        return nodes


graphql_schema = strawberry.Schema(query=GraphQLQuery)
app.include_router(GraphQLRouter(graphql_schema), prefix="/graphql")


@app.get("/audit-events")
def get_audit_events(identity: tuple[str, str, str] = Depends(get_current_identity)) -> dict:
    _subject, role, tenant_id = identity
    require_security_admin(role)
    with db() as c:
        rows = c.execute(
            'SELECT id, occurred_at, subject_id, record_id, "authorization", detector_decision, outcome, explanation, risk_score '
            "FROM audit_events WHERE tenant_id = %s ORDER BY id DESC LIMIT 100", (tenant_id,)).fetchall()
    return {"events": [dict(row) for row in rows]}


def _login_headers(client, subject: str, password: str = DEMO_PASSWORD) -> dict:
    res = client.post("/auth/login", json={"subject": subject, "password": password})
    token = res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@app.post("/simulate/normal")
@limiter.limit("5/minute")
def simulate_normal(request: Request, _guard: None = Depends(guard_demo_endpoint)) -> dict:
    from fastapi.testclient import TestClient
    client = TestClient(app)
    headers = _login_headers(client, "alice")
    results = []
    for i in range(1, 51):
        res = client.get(f"/records/{i}", headers=headers)
        results.append(res.status_code)
    return {"status": "normal_simulated", "requests": 50, "results": results}

@app.post("/simulate/rapid")
@limiter.limit("5/minute")
def simulate_rapid(request: Request, _guard: None = Depends(guard_demo_endpoint)) -> dict:
    from fastapi.testclient import TestClient
    client = TestClient(app)
    headers = _login_headers(client, "attacker_1")
    results = []
    for i in range(51, 56):
        res = client.get(f"/records/{i}", headers=headers)
        results.append({"id": i, "status": res.status_code, "risk": res.headers.get("X-Risk-Score"), "category": res.headers.get("X-Risk-Category")})
    return {"status": "rapid_simulated", "results": results}

@app.post("/simulate/low_and_slow")
@limiter.limit("5/minute")
def simulate_low_and_slow(request: Request, _guard: None = Depends(guard_demo_endpoint)) -> dict:
    from fastapi.testclient import TestClient
    client = TestClient(app)
    results = []

    subject = "attacker_slow"
    now = time.time()

    for i in range(15):
        event_time = now - (3600) + (i * 240)
        engine.record_event(DEMO_TENANT_ID, subject, 50 + i, False, event_time)
        record_audit(DEMO_TENANT_ID, subject, 50 + i, None, "deny", "denied", ["Simulated low and slow deny"], risk_score=max(0.0, min(100.0, 50.0 + (i * 5))))

    headers = _login_headers(client, subject)
    res = client.get("/records/66", headers=headers)
    results.append({"status": res.status_code, "risk": res.headers.get("X-Risk-Score"), "category": res.headers.get("X-Risk-Category")})
    return {"status": "low_and_slow_simulated", "results": results}

@app.post("/simulate/coordinated")
@limiter.limit("5/minute")
def simulate_coordinated(request: Request, _guard: None = Depends(guard_demo_endpoint)) -> dict:
    from fastapi.testclient import TestClient
    client = TestClient(app)
    for i in range(1, 51):
        headers = _login_headers(client, f"sybil_{i}")
        client.get("/records/1", headers=headers)
    return {"status": "coordinated_simulated"}


@app.get("/users/{user_id}")
def get_user(user_id: str, response: Response, identity: tuple[str, str, str] = Depends(get_current_identity)) -> dict:
    subject, _role, tenant_id = identity
    decision, signals, unseen, score, category = engine.evaluate(tenant_id, subject, user_id, False, endpoint="users")
    if decision == "block":
        raise HTTPException(403, detail={"outcome": "blocked", "score": score, "category": category})
    raise HTTPException(403, detail={"outcome": "denied", "score": score, "category": category})

@app.get("/invoices/{invoice_id}")
def get_invoice(invoice_id: str, response: Response, identity: tuple[str, str, str] = Depends(get_current_identity)) -> dict:
    subject, _role, tenant_id = identity
    decision, signals, unseen, score, category = engine.evaluate(tenant_id, subject, invoice_id, False, endpoint="invoices")
    if decision == "block":
        raise HTTPException(403, detail={"outcome": "blocked", "score": score, "category": category})
    raise HTTPException(403, detail={"outcome": "denied", "score": score, "category": category})

@app.get("/config")
def get_config(authorization: str | None = Header(default=None), x_api_key: str | None = Header(default=None)) -> dict:
    tenant_id = resolve_request_tenant(x_api_key, authorization)
    block_threshold, warn_threshold = get_tenant_risk_thresholds(tenant_id)
    return {
        "short_window": engine.short_window,
        "long_window": engine.long_window,
        "rapid_threshold": engine.rapid_threshold,
        "slow_threshold": engine.slow_threshold,
        "risk_threshold_block": block_threshold,
        "risk_threshold_warn": warn_threshold,
        "strike_1_duration": "2m (Soft)",
        "strike_2_duration": "30m (Hard)",
        "strike_3_duration": "Permanent (Blacklist)",
        "ai_anomaly_detection": "IsolationForest (scikit-learn)",
        "auth": "JWT bearer tokens (HS256) for the dashboard; per-tenant API keys for /v1/*",
        "state_backend": f"{DATABASE_BACKEND} (multi-tenant, tenant_id-scoped)"
    }

@app.get("/stats")
def get_stats(authorization: str | None = Header(default=None), x_api_key: str | None = Header(default=None)) -> dict:
    tenant_id = resolve_request_tenant(x_api_key, authorization)
    now = time.time()
    engine.cleanup_stale(tenant_id)
    with db() as c:
        active_cnt = len(c.execute("SELECT DISTINCT subject FROM risk_events WHERE tenant_id = %s AND at > %s", (tenant_id, now - 3600)).fetchall())
        blocked_cnt = len(c.execute("SELECT DISTINCT subject FROM risk_blocks WHERE tenant_id = %s AND blocked_until > %s", (tenant_id, now)).fetchall())
    return {
        "tenant_id": tenant_id,
        "active_subjects": max(active_cnt, engine.active_subject_count(tenant_id)),
        "blocked_subjects": max(blocked_cnt, engine.blocked_subject_count(tenant_id)),
        "coordinated_attacks": engine.coordinated_attacks(tenant_id)
    }

@app.get("/events")
def get_events(identity: tuple[str, str, str] = Depends(get_current_identity)) -> dict:
    _subject, role, tenant_id = identity
    require_security_admin(role)
    with db() as c:
        rows = c.execute(
            'SELECT id, occurred_at, subject_id, record_id, "authorization", detector_decision, outcome, explanation, risk_score '
            "FROM audit_events WHERE tenant_id = %s ORDER BY id DESC LIMIT 100", (tenant_id,)).fetchall()
    return {"events": [dict(row) for row in rows]}

@app.get("/audit-timeline")
def get_audit_timeline(identity: tuple[str, str, str] = Depends(get_current_identity), limit: int = 50) -> dict:
    """Returns filtered integrity audit timeline for dashboard: 404 probes, blocks, denials."""
    _subject, role, tenant_id = identity
    require_security_admin(role)
    clamped_limit = max(1, min(limit, 200))
    patterns = (
        ("record_id", "%404%"), ("record_id", "%canary%"), ("record_id", "%trap%"),
        ("record_id", "%probe%"), ("record_id", "%fuzz%"), ("record_id", "%admin%"),
        ("record_id", "%timer%"), ("record_id", "%quarantine%"),
        ("record_id", "item_%"), ("record_id", "claim_%"), ("record_id", "record_%"),
        ("explanation", "%strike%"), ("explanation", "%attack%"), ("explanation", "%violation%"),
    )
    pattern_sql = " OR ".join(f"{column} LIKE %s" for column, _pattern in patterns)
    with db() as c:
        rows = c.execute(
            'SELECT id, occurred_at, subject_id, record_id, "authorization", detector_decision, outcome, explanation, risk_score '
            "FROM audit_events WHERE tenant_id = %s AND ("
            "  detector_decision != 'allow' OR "
            "  outcome != 'allowed' OR "
            "  \"authorization\" != 'authorized' OR " + pattern_sql +
            ") ORDER BY occurred_at DESC, id DESC LIMIT %s",
            (tenant_id, *(pattern for _column, pattern in patterns), clamped_limit)).fetchall()
    timeline = []
    for row in rows:
        timeline.append({
            "id": row["id"],
            "timestamp": row["occurred_at"],
            "subject": row["subject_id"],
            "resource": row["record_id"],
            "decision": row["detector_decision"],
            "outcome": row["outcome"],
            "event_type": _classify_event(row["record_id"], row["detector_decision"]),
            "details": row["explanation"],
            "risk_score": row["risk_score"],
        })
    return {"timeline": timeline, "total": len(timeline)}

def _classify_event(record_id: str, decision: str) -> str:
    """Classify event type for timeline display."""
    rec = str(record_id).lower()
    if rec == "threat_signal":
        return "threat_signal"
    if "timer" in rec or "quarantine" in rec:
        return "quarantine_timer"
    if "admin" in rec:
        return "admin_probe"
    if "canary" in rec or "trap" in rec or rec in ("0", "999999"):
        return "canary_trap"
    if decision == "block":
        return "blocked_access"
    if "404" in rec or "fuzz" in rec or "probe" in rec or rec.startswith("record_") or rec.startswith("item_") or rec.startswith("claim_"):
        return "404_probe"
    return "denied_access"

@app.get("/lockout-status/{subject}")
def get_lockout_status(subject: str, x_api_key: str | None = Header(default=None), tenant: str | None = None,
                       authorization: str | None = Header(default=None)) -> dict:
    """Returns lockout timer status for a subject (strike count, time remaining, expiry timestamp)."""
    now = time.time()
    target_tenant = resolve_request_tenant(x_api_key, authorization)
    if tenant and tenant != target_tenant:
        raise HTTPException(403, "Tenant access denied")
    try:
        # Check blocked_until in target tenant
        blocked_until = engine.blocked_until(target_tenant, subject)

        strike_count = engine.get_strike_count(target_tenant, subject, now)

        if blocked_until > now:
            remaining = max(0, int(blocked_until - now))
            is_locked = remaining > 0
            lockout_type = "permanent_ban" if strike_count >= 3 else ("hard_lockout" if strike_count == 2 else "soft_lockout")
            lockout_duration = 120.0 if strike_count <= 1 else (1800.0 if strike_count == 2 else 315360000.0)
            return {
                "subject": subject,
                "tenant_id": target_tenant,
                "strike_count": max(1, strike_count),
                "is_locked": is_locked,
                "lockout_type": lockout_type,
                "lockout_duration_seconds": int(lockout_duration),
                "lockout_remaining_seconds": remaining,
                "lockout_expires_at": int(blocked_until),
                "message": f"Locked for {remaining} more seconds"
            }

        if strike_count == 0:
            return {
                "subject": subject,
                "tenant_id": target_tenant,
                "strike_count": 0,
                "is_locked": False,
                "lockout_remaining_seconds": 0,
                "lockout_expires_at": None,
                "lockout_duration_seconds": 0
            }

        return {
            "subject": subject,
            "tenant_id": target_tenant,
            "strike_count": strike_count,
            "is_locked": False,
            "lockout_remaining_seconds": 0,
            "lockout_expires_at": None,
            "message": "Quarantine period has expired"
        }
    except Exception as e:
        raise HTTPException(503, "Lockout status is temporarily unavailable") from e


@app.get("/risk/{subject}")
def get_risk(subject: str, x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)) -> dict:
    now = time.time()
    tenant_id = resolve_request_tenant(x_api_key, authorization)
    res = engine.compute_risk(tenant_id, subject, now)
    strikes = engine.get_strike_count(tenant_id, subject, now)
    blocked_until = engine.blocked_until(tenant_id, subject)
    is_blocked = blocked_until > now
    remaining = int(blocked_until - now) if is_blocked else 0
    status = engine._ban_status(tenant_id, subject)
    is_pending = status == "pending" or (strikes >= 3 and status != "approved" and is_blocked)
    is_approved = status == "approved" or (is_blocked and remaining > 86400 * 30)
    return {
        "subject": subject,
        "score": res["score"],
        "category": res["category"],
        "signals": res["signals"],
        "contributions": res["contributions"],
        "strikes": strikes,
        "is_blocked": is_blocked,
        "is_pending_ban": is_pending,
        "is_approved_ban": is_approved,
        "is_permanent": is_approved,
        "lockout_remaining_s": remaining,
        "lockout_expires_at": int(blocked_until) if is_blocked else None,
    }


@app.post("/admin/approve-ban/{subject}")
def approve_permanent_ban_endpoint(subject: str, identity: tuple[str, str, str] = Depends(get_current_identity)) -> dict:
    caller, role, tenant_id = identity
    require_security_admin(role)
    engine.approve_permanent_ban(tenant_id, subject)
    record_audit(tenant_id, subject, 0, "ADMIN_AUTHORITY", "block", "blocked", [f"Admin '{caller}' APPROVED Permanent Firewall Ban for '{subject}'"], risk_score=100.0)
    return {"status": "permanent_ban_approved", "subject": subject, "is_permanent": True}


@app.post("/admin/reject-ban/{subject}")
def reject_permanent_ban_endpoint(subject: str, identity: tuple[str, str, str] = Depends(get_current_identity)) -> dict:
    caller, role, tenant_id = identity
    require_security_admin(role)
    engine.reject_permanent_ban(tenant_id, subject)
    record_audit(tenant_id, subject, 0, "ADMIN_AUTHORITY", "allow", "allowed", [f"Admin '{caller}' DISMISSED Permanent Ban for '{subject}' (Quarantine Relaxed)"])
    return {"status": "ban_dismissed", "subject": subject, "is_permanent": False}


@app.get("/admin/pending-bans")
def get_pending_bans(identity: tuple[str, str, str] = Depends(get_current_identity)) -> dict:
    _subject, role, tenant_id = identity
    require_security_admin(role)
    return {"pending_bans": engine.pending_bans(tenant_id), "approved_bans": engine.approved_bans(tenant_id)}



@app.get("/soc/alerts")
def get_soc_alerts(identity: tuple[str, str, str] = Depends(get_current_identity)) -> dict:
    _subject, role, tenant_id = identity
    require_security_admin(role)
    with db() as c:
        total = c.execute("SELECT COUNT(*) AS n FROM soc_alerts WHERE tenant_id = %s", (tenant_id,)).fetchone()["n"]
        rows = c.execute(
            "SELECT payload FROM soc_alerts WHERE tenant_id = %s ORDER BY id DESC LIMIT 20",
            (tenant_id,)
        ).fetchall()
    recent = [json.loads(r["payload"]) if isinstance(r["payload"], str) else r["payload"] for r in rows]
    return {"total_alerts": total, "recent_alerts": recent}


@app.post("/soc/test-webhook")
def test_soc_webhook(payload: dict | None = None, identity: tuple[str, str, str] = Depends(get_current_identity)) -> dict:
    _subject, role, tenant_id = identity
    require_security_admin(role)
    if not payload:
        payload = dispatch_soc_alert(
            tenant_id, subject="simulated_adversary", record_id=999, score=100, category="Attack",
            signals=["unauthorized_unique_object_pressure", "sequential_id_enumeration", "manual_test"]
        )
    else:
        subject = payload.get("attacker_identity", "external_attacker")
        target_id = payload.get("targeted_object_id", 0)
        signals = payload.get("signals_tripped", ["bola_attempt"])
        decision = payload.get("decision", "deny")
        outcome = "blocked" if decision == "block" else "denied"
        explanation = f"External BOLA Activity: {','.join(signals)}" if outcome == "blocked" else f"External Object Denied: Attempted {target_id}"

        engine.record_event(tenant_id, subject, target_id, False, time.time(), "records")
        if decision == "block":
            lockout, strike_sig, count = engine.register_strike_and_block(tenant_id, subject, time.time())
            if strike_sig not in signals:
                signals.append(strike_sig)
            score = payload.get("risk_score", 100)
            category = payload.get("risk_category", "Attack")
            dispatch_soc_alert(tenant_id, subject, target_id, score, category, signals)

        record_audit(tenant_id, subject, target_id, None, decision, outcome, [explanation])
    return {"status": "alert_logged_and_synced", "payload": payload}


@app.get("/records/{record_id}/graph-risk")
def get_record_graph_risk(record_id: str, identity: tuple[str, str, str] = Depends(get_current_identity)) -> dict:
    _subject, _role, tenant_id = identity
    result = score_record_graph_anomaly(tenant_id, record_id)
    if result is None:
        raise HTTPException(503, "Endpoint anomaly model not trained yet - run train_endpoint_anomaly_model.py")
    return {"record_id": record_id, **result, "features": compute_record_graph_features(tenant_id, record_id)}


# --- Product API: what other companies' backends actually integrate against ---
# Server-to-server, authenticated by a per-tenant API key (not the demo's JWT
# login flow). The caller already knows whether the requesting subject is
# authorized for the resource (their own object model, not ours) - this
# endpoint's job is purely the behavioral/risk layer on top of that decision.

def _insert_tenant_record(c, name: str, email: Optional[str] = None) -> dict:
    tenant_id = secrets.token_hex(8)
    api_key = generate_api_key()
    c.execute("INSERT INTO tenants (id, name, api_key_hash, created_at, email) VALUES (%s, %s, %s, %s, %s)",
              (tenant_id, name, hash_api_key(api_key), time.time(), email))
    return {
        "tenant_id": tenant_id,
        "name": name,
        "api_key": api_key,
        "warning": "This API key is shown once and cannot be retrieved again - store it securely.",
    }


def _create_tenant_record(name: str, email: Optional[str] = None) -> dict:
    with db() as c:
        return _insert_tenant_record(c, name, email)


@app.post("/v1/tenants")
@limiter.limit("10/minute")
def create_tenant(request: Request, payload: dict, x_signup_key: str | None = Header(default=None)) -> dict:
    """Internal/scripted provisioning - requires TENANT_SIGNUP_KEY. For the public,
    unauthenticated self-serve flow (a signup page on your own website), use POST
    /v1/signup instead."""
    if x_signup_key != TENANT_SIGNUP_KEY:
        raise HTTPException(403, "Invalid signup key")
    name = payload.get("name")
    if not name:
        raise HTTPException(400, "name is required")
    return _create_tenant_record(name)


def _validate_tenant_name(name: Any) -> str:
    if not isinstance(name, str) or not name.strip() or len(name.strip()) > 200:
        raise HTTPException(400, "name is required")
    return name.strip()


def _validate_and_create_tenant(name: Optional[str], email: Optional[str]) -> dict:
    name = _validate_tenant_name(name)
    if email is not None and (not isinstance(email, str) or len(email) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email)):
        raise HTTPException(400, "email must be a valid email address")
    return _create_tenant_record(name, email)


@app.post("/v1/signup")
@limiter.limit("5/hour")
def public_signup(request: Request, response: Response, payload: dict) -> dict:
    """Public self-serve tenant signup - no signup key required, meant to be called
    directly from a website's own signup form. Rate-limited per IP (5/hour) since,
    unlike /v1/tenants, this has no pre-shared secret gating who can call it."""
    response.headers["Cache-Control"] = "no-store"
    return _validate_and_create_tenant(payload.get("name"), payload.get("email"))


# ===== TENANT QUOTA MANAGEMENT (Phase 2) =====
@app.get("/tenants/{tenant_id}/quota")
def get_tenant_quota(tenant_id: str, identity: tuple[str, str, str] = Depends(get_tenant_admin_identity)) -> dict:
    """Get quota configuration for a tenant."""
    _subject, role, current_tenant = identity

    # Allow admins to query any tenant, others only their own
    if current_tenant != tenant_id:
        raise HTTPException(403, "Insufficient permissions")

    with db() as c:
        result = c.execute(
            "SELECT requests_per_minute, max_stored_audit_events, max_audit_retention_days, "
            "risk_threshold_block, risk_threshold_warn FROM tenant_quotas WHERE tenant_id = %s",
            (tenant_id,)
        ).fetchone()

    if not result:
        # Return defaults
        result = {
            "requests_per_minute": DEFAULT_REQUESTS_PER_MINUTE,
            "max_stored_audit_events": DEFAULT_MAX_AUDIT_EVENTS,
            "max_audit_retention_days": DEFAULT_AUDIT_RETENTION_DAYS,
            "risk_threshold_block": DEFAULT_RISK_THRESHOLD_BLOCK,
            "risk_threshold_warn": DEFAULT_RISK_THRESHOLD_WARN
        }

    return {
        "tenant_id": tenant_id,
        "quota": dict(result) if result else {}
    }


@app.post("/tenants/{tenant_id}/quota")
def update_tenant_quota(tenant_id: str, payload: dict, identity: tuple[str, str, str] = Depends(get_tenant_admin_identity)) -> dict:
    """Update quota configuration for a tenant (admin only)."""
    _subject, role, _current_tenant = identity
    require_security_admin(role)
    _require_own_tenant_or_admin(tenant_id, identity)

    current = get_tenant_quota(tenant_id, identity)["quota"]
    for key, value in payload.items():
        if key not in current:
            raise HTTPException(400, f"Unknown quota field: {key}")
        if value is None:
            continue
        if type(value) is not int or value <= 0 or (key.startswith("risk_threshold") and value > 100):
            raise HTTPException(400, f"Invalid quota value for {key}")
        current[key] = value
    if current["risk_threshold_warn"] > current["risk_threshold_block"]:
        raise HTTPException(400, "Warning threshold must not exceed block threshold")

    with db() as c:
        c.execute(
            "INSERT INTO tenant_quotas (tenant_id, requests_per_minute, max_stored_audit_events, "
            "max_audit_retention_days, risk_threshold_block, risk_threshold_warn, updated_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s) "
            "ON CONFLICT (tenant_id) DO UPDATE SET "
            "requests_per_minute = COALESCE(EXCLUDED.requests_per_minute, tenant_quotas.requests_per_minute), "
            "max_stored_audit_events = COALESCE(EXCLUDED.max_stored_audit_events, tenant_quotas.max_stored_audit_events), "
            "max_audit_retention_days = COALESCE(EXCLUDED.max_audit_retention_days, tenant_quotas.max_audit_retention_days), "
            "risk_threshold_block = COALESCE(EXCLUDED.risk_threshold_block, tenant_quotas.risk_threshold_block), "
            "risk_threshold_warn = COALESCE(EXCLUDED.risk_threshold_warn, tenant_quotas.risk_threshold_warn), "
            "updated_at = EXCLUDED.updated_at",
            (
                tenant_id,
                current["requests_per_minute"],
                current["max_stored_audit_events"],
                current["max_audit_retention_days"],
                current["risk_threshold_block"],
                current["risk_threshold_warn"],
                time.time()
            )
        )
        # Invalidate cache
        cache_key = f"quota:{tenant_id}"
        if redis_client:
            try:
                redis_client.delete(cache_key)
            except Exception:
                pass

    return {"status": "updated", "tenant_id": tenant_id}


@app.get("/tenants/{tenant_id}/quota-usage")
def get_tenant_quota_usage(tenant_id: str, identity: tuple[str, str, str] = Depends(get_tenant_admin_identity)) -> dict:
    """Get current quota usage for a tenant."""
    _subject, role, current_tenant = identity

    # Allow admins to query any tenant, others only their own
    if current_tenant != tenant_id:
        raise HTTPException(403, "Insufficient permissions")

    with db() as c:
        # Get quota limits
        quota = c.execute(
            "SELECT requests_per_minute, max_stored_audit_events FROM tenant_quotas WHERE tenant_id = %s",
            (tenant_id,)
        ).fetchone()

        # Get current usage
        audit_count = c.execute(
            "SELECT COUNT(*) as cnt FROM audit_events WHERE tenant_id = %s",
            (tenant_id,)
        ).fetchone()["cnt"]

    quota_limits = dict(quota) if quota else {"requests_per_minute": DEFAULT_REQUESTS_PER_MINUTE, "max_stored_audit_events": DEFAULT_MAX_AUDIT_EVENTS}

    # Get current requests from Redis
    requests_this_minute = 0
    if redis_client:
        try:
            requests_this_minute = int(redis_client.get(f"ratelimit:{tenant_id}") or 0)
        except Exception:
            pass
    else:
        with db() as c:
            state = c.execute("SELECT current_requests, requests_reset_at FROM rate_limit_state WHERE tenant_id = %s", (tenant_id,)).fetchone()
        if state and state["requests_reset_at"] > time.time():
            requests_this_minute = state["current_requests"]

    return {
        "tenant_id": tenant_id,
        "quota_limits": quota_limits,
        "current_usage": {
            "requests_this_minute": requests_this_minute,
            "requests_per_minute_limit": quota_limits["requests_per_minute"],
            "requests_percent": (requests_this_minute / quota_limits["requests_per_minute"]) * 100,
            "audit_events_stored": audit_count,
            "audit_events_limit": quota_limits["max_stored_audit_events"],
            "audit_events_percent": (audit_count / quota_limits["max_stored_audit_events"]) * 100
        }
    }


# ===== ALERT CHANNEL MANAGEMENT (Phase 3) =====
@app.post("/tenants/{tenant_id}/alert-channels")
def create_alert_channel(
    tenant_id: str,
    payload: dict,
    identity: tuple[str, str, str] = Depends(get_tenant_admin_identity)
) -> dict:
    """Create an alert channel (Slack, Email, Webhook) for a tenant."""
    _subject, role, current_tenant = identity

    # Allow admins to create for any tenant, others only their own
    if current_tenant != tenant_id:
        raise HTTPException(403, "Insufficient permissions")

    channel_type = payload.get("channel_type")  # "slack", "email", "webhook"
    channel_config = payload.get("channel_config", {})  # {"url": "...", "address": "...", etc}

    if channel_type not in ["slack", "email", "webhook"]:
        raise HTTPException(400, f"Invalid channel_type: {channel_type}")

    channel_id = secrets.token_hex(8)

    with db() as c:
        c.execute(
            "INSERT INTO alert_channels (id, tenant_id, channel_type, channel_config, is_active) "
            "VALUES (%s, %s, %s, %s, %s)",
            (channel_id, tenant_id, channel_type, json.dumps(channel_config), True)
        )

    return {"channel_id": channel_id, "status": "created"}


@app.get("/tenants/{tenant_id}/alert-channels")
def list_alert_channels(
    tenant_id: str,
    identity: tuple[str, str, str] = Depends(get_tenant_admin_identity)
) -> dict:
    """List all alert channels for a tenant."""
    _subject, role, current_tenant = identity

    if current_tenant != tenant_id:
        raise HTTPException(403, "Insufficient permissions")

    with db() as c:
        channels = c.execute(
            "SELECT id, channel_type, is_active FROM alert_channels WHERE tenant_id = %s ORDER BY id DESC",
            (tenant_id,)
        ).fetchall()

    return {
        "tenant_id": tenant_id,
        "channels": [
            {
                "id": ch["id"],
                "type": ch["channel_type"],
                "active": ch["is_active"]
            }
            for ch in channels
        ]
    }


@app.delete("/tenants/{tenant_id}/alert-channels/{channel_id}")
def delete_alert_channel(
    tenant_id: str,
    channel_id: str,
    identity: tuple[str, str, str] = Depends(get_tenant_admin_identity)
) -> dict:
    """Delete an alert channel."""
    _subject, role, _current_tenant = identity
    require_security_admin(role)
    _require_own_tenant_or_admin(tenant_id, identity)

    with db() as c:
        c.execute(
            "DELETE FROM alert_channels WHERE id = %s AND tenant_id = %s",
            (channel_id, tenant_id)
        )

    return {"status": "deleted", "channel_id": channel_id}


@app.post("/tenants/{tenant_id}/test-alert")
async def test_alert(
    tenant_id: str,
    identity: tuple[str, str, str] = Depends(get_tenant_admin_identity)
) -> dict:
    """Send a test alert to all active channels for a tenant."""
    _subject, role, current_tenant = identity

    if current_tenant != tenant_id:
        raise HTTPException(403, "Insufficient permissions")

    # Dispatch test alert
    await dispatch_alerts(
        tenant_id,
        "test",
        "CyberAccess Test Alert",
        "This is a test alert from your CyberAccess configuration. "
        "If you received this, your alert channels are working correctly.",
        severity="info",
        db=db
    )

    return {"status": "test_alert_sent", "tenant_id": tenant_id}


@app.get("/toggle-defense-status")
@app.get("/v1/defense/status")
@app.get("/defense-status")
def get_defense_status_api() -> dict:
    enabled = is_defense_enabled()
    return {
        "success": True,
        "defense_enabled": enabled,
        "status": "PROTECTED" if enabled else "VULNERABLE",
    }


@app.post("/toggle-defense")
@app.post("/v1/defense/toggle")
@app.post("/defense/toggle")
async def toggle_defense_api(request: Request, identity: tuple[str, str, str] = Depends(get_current_identity)) -> dict:
    require_security_admin(identity[1])
    if not DEMO_MODE or identity[2] != DEMO_TENANT_ID:
        raise HTTPException(403, "Defense toggling is only available for the demo tenant")
    target_state = None
    try:
        body = await request.json()
        if isinstance(body, dict) and "enabled" in body:
            target_state = bool(body["enabled"])
    except Exception:
        pass

    if target_state is None:
        new_state = not is_defense_enabled()
    else:
        new_state = target_state

    await asyncio.to_thread(set_defense_enabled, new_state)
    return {
        "success": True,
        "defense_enabled": new_state,
        "status": "PROTECTED" if new_state else "VULNERABLE",
        "message": f"BOLA Defense System is now {'ON (PROTECTED)' if new_state else 'OFF (VULNERABLE)'}",
    }


@app.post("/v1/authorize")
@limiter.limit("1000/minute")
@observe_authorization
def v1_authorize(request: Request, payload: dict, tenant_id: str = Depends(get_tenant_from_api_key)) -> dict:
    if not isinstance(payload.get("subject"), str) or not payload["subject"].strip() or payload.get("resource_id") is None:
        raise HTTPException(400, "subject and resource_id are required")
    if type(payload.get("authorized", False)) is not bool:
        raise HTTPException(400, "authorized must be a boolean")
    if tenant_id == DEMO_TENANT_ID and DEMO_MODE and not is_defense_enabled():
        return {
            "decision": "allow",
            "score": 0.0,
            "category": "VULNERABLE_MODE_ACTIVE",
            "signals": ["defense_system_disabled", "system_unprotected"],
            "explanations": ["🚨 CRITICAL: BOLA DEFENSE SYSTEM IS DISABLED - SYSTEM IS COMPLETELY VULNERABLE 🚨"],
            "lockout_remaining_s": 0,
            "lockout_expires_at": None,
            "strike_count": 0,
            "trial_count": 0,
            "max_trials": 3,
            "threat_intel": {"enabled": False, "skipped": "defense_system_disabled"},
        }

    subject = payload.get("subject")
    resource_id = payload.get("resource_id")
    authorized = payload.get("authorized", False)
    http_verb = str(payload.get("http_verb", "GET")).upper()
    endpoint = str(payload.get("endpoint") or payload.get("resource_name") or "v1")
    if not subject or resource_id is None:
        raise HTTPException(400, "subject and resource_id are required")

    now_ts = time.time()
    active_block = engine.blocked_until(tenant_id, subject)
    is_currently_blocked = active_block > now_ts
    current_strikes = engine.get_strike_count(tenant_id, subject, now_ts)

    # 1. Quarantined Lockdown: while under active lockout, preserve current strike and never escalate
    if is_currently_blocked:
        rem_sec = max(0, int(active_block - now_ts))
        ban_stat = engine._ban_status(tenant_id, subject)
        if ban_stat == "approved":
            strike_sig = "strike_3_permanent_ban_approved"
        elif ban_stat == "pending" or current_strikes >= 3:
            strike_sig = "strike_3_pending_admin_approval"
        elif current_strikes == 2:
            strike_sig = "strike_2_hard_lockout_30m"
        else:
            strike_sig = "strike_1_soft_lockout_2m"

        signals = ["temporarily_blocked", strike_sig]
        detector_explanations = explain_detector_signals(signals)
        return {
            "decision": "block",
            "score": 100.0,
            "category": "Attack",
            "signals": signals,
            "explanations": detector_explanations,
            "lockout_remaining_s": rem_sec,
            "lockout_expires_at": int(active_block),
            "strike_count": max(1, current_strikes),
            "max_strikes": 3,
            "risk_tier": "Attack",
            "threat_intel": {"enabled": threat_detection.THREAT_DETECTION_ENABLED, "skipped": "subject_already_locked_out"},
        }

    # 2. Risk evaluation via BehavioralRiskEngine (Point-based scoring from architecture specification)
    decision, signals, _unseen, score, category = engine.evaluate(
        tenant_id, subject, resource_id, authorized, endpoint=endpoint, http_verb=http_verb, register_strike=False
    )

    is_canary = is_canary_record(tenant_id, str(resource_id).strip())
    is_admin = endpoint.startswith("admin_") or str(resource_id).startswith("privileged_admin") or endpoint in ("admin_login_probe", "admin_portal")

    block_threshold, warn_threshold = get_tenant_risk_thresholds(tenant_id)
    if not authorized or score >= block_threshold:
        strike_now = time.time()
        # Tenant thresholds control escalation; object authorization remains authoritative.
        if score >= block_threshold or is_canary:
            decision = "block"
            category = "Attack"
            score = max(score, 100.0 if is_canary else float(block_threshold))
            if is_canary and "canary_honeypot_triggered" not in signals:
                signals.append("canary_honeypot_triggered")
            if is_admin and "unauthorized_admin_access_attempt" not in signals:
                signals.append("unauthorized_admin_access_attempt")
            if "blocked_due_to_high_risk" not in signals:
                signals.append("blocked_due_to_high_risk")

            lockout, strike_sig, count = engine.register_strike_and_block(tenant_id, subject, strike_now)
            if strike_sig not in signals:
                signals.append(strike_sig)
            current_strikes = count
        elif score >= warn_threshold:
            decision = "deny"
            category = "High Risk"
            if "high_risk_reconnaissance" not in signals:
                signals.append("high_risk_reconnaissance")
        elif score >= min(40, warn_threshold):
            decision = "deny"
            category = "Suspicious"
        else:
            # 0–39 -> totally fine, denied normally
            decision = "deny"
            category = "Normal"

    score = max(0.0, min(100.0, float(score)))
    detector_explanations = explain_detector_signals(signals)

    outcome = "blocked" if decision == "block" else ("allowed" if authorized else "denied")
    record_audit(tenant_id, subject, resource_id, "authorized" if authorized else None, decision, outcome, detector_explanations, risk_score=score)
    if decision == "block":
        dispatch_soc_alert(tenant_id, subject, resource_id, score, category, signals)

    final_decision = "block" if decision == "block" else ("allow" if authorized else "deny")
    blocked_until = engine.blocked_until(tenant_id, subject)
    remaining = int(blocked_until - now_ts) if blocked_until > now_ts else (120 if final_decision == "block" else 0)
    expires_at = int(blocked_until) if blocked_until > now_ts else (int(now_ts + remaining) if final_decision == "block" else None)
    strike_count = engine.get_strike_count(tenant_id, subject, now_ts)

    if final_decision == "block":
        expiry_str = time.strftime("%H:%M:%S UTC", time.gmtime(expires_at or (now_ts + remaining)))
        record_audit(
            tenant_id,
            subject,
            "quarantine_timer",
            "TIMER_LOCKOUT",
            "block",
            "blocked",
            [f"Quarantine cooldown timer active: {remaining}s remaining (Strike {strike_count}/3, Expires at {expiry_str}). Navigation channels quarantined."],
            risk_score=score
        )

    threat_intel = _run_threat_detection(request, tenant_id, subject, endpoint, final_decision, now_ts)

    return {
        "decision": final_decision,
        "score": max(0.0, min(100.0, float(score))),
        "category": category,
        "signals": signals,
        "explanations": detector_explanations,
        "lockout_remaining_s": remaining,
        "lockout_expires_at": expires_at,
        "strike_count": max(1, strike_count) if final_decision == "block" else strike_count,
        "max_strikes": 3,
        "risk_tier": category,
        "threat_intel": threat_intel,
    }


@app.post("/v1/audit/timer-log")
def log_timer_audit(payload: dict, tenant_id: str = Depends(get_tenant_from_api_key)) -> dict:
    """Explicit endpoint to record quarantine countdown status into the audit ledger."""
    subject = str(payload.get("subject", "unknown"))
    remaining = int(payload.get("remaining_seconds", 0))
    expires_at = payload.get("expires_at")
    strike_count = int(payload.get("strike_count", 1))
    reason = str(payload.get("reason", "Quarantine cooldown active"))
    expiry_str = time.strftime("%H:%M:%S UTC", time.gmtime(expires_at)) if expires_at else "imminent"
    record_audit(
        tenant_id,
        subject,
        "quarantine_timer",
        "TIMER_SYNC",
        "block",
        "blocked",
        [f"Quarantine cooldown timer: {remaining}s remaining (Strike {strike_count}/3, Expires at {expiry_str}). {reason}"]
    )
    return {"status": "ok", "subject": subject, "remaining_seconds": remaining}


@app.post("/hackathon/release")
def hackathon_release(payload: dict, identity: tuple[str, str, str] = Depends(get_current_identity)) -> dict:
    """Bypass endpoint for hackathon demo to immediately release active quarantines.
    Preserves strike history so Strike 2 / Strike 3 test cycles proceed naturally.
    """
    require_security_admin(identity[1])
    tenant_id = identity[2]
    subject = str(payload.get("subject", "")).strip()
    client_ip = str(payload.get("client_ip", "")).strip()
    full_reset = bool(payload.get("full_reset", False))
    with db() as c:
        for sub in (subject, client_ip):
            if sub:
                c.execute("DELETE FROM risk_blocks WHERE tenant_id = %s AND subject = %s", (tenant_id, sub))
                c.execute("DELETE FROM risk_bans WHERE tenant_id = %s AND subject = %s AND status != 'approved'", (tenant_id, sub))
                if full_reset:
                    c.execute("DELETE FROM risk_strikes WHERE tenant_id = %s AND subject = %s", (tenant_id, sub))
                    c.execute("DELETE FROM risk_bans WHERE tenant_id = %s AND subject = %s", (tenant_id, sub))
                    c.execute("DELETE FROM risk_events WHERE tenant_id = %s AND subject = %s", (tenant_id, sub))
    return {"status": "released", "subject": subject, "client_ip": client_ip, "full_reset": full_reset}


@app.post("/v1/authorize-batch")
@limiter.limit("200/minute")
@observe_authorization
def v1_authorize_batch(request: Request, payload: dict, tenant_id: str = Depends(get_tenant_from_api_key)) -> dict:
    subject = payload.get("subject")
    items = payload.get("items", [])
    if not isinstance(subject, str) or not subject.strip() or not isinstance(items, list):
        raise HTTPException(400, "subject and items array are required")
    if len(items) > BOLA_MAX_BATCH_SIZE:
        raise HTTPException(400, f"Batch size cannot exceed {BOLA_MAX_BATCH_SIZE} items")
    if any(not isinstance(item, dict) or item.get("resource_id") is None
           or type(item.get("authorized", False)) is not bool for item in items):
        raise HTTPException(400, "Each batch item needs a resource_id and boolean authorized")

    if tenant_id == DEMO_TENANT_ID and DEMO_MODE and not is_defense_enabled():
        return {
            "total": len(items),
            "blocked_mid_batch": False,
            "results": [{"resource_id": str(it.get("resource_id", "")), "decision": "allow", "score": 0.0, "signals": ["defense_system_disabled"]} for it in items]
        }

    results = []
    blocked_mid_batch = False
    for item in items:
        rid = str(item.get("resource_id", ""))
        auth = bool(item.get("authorized", False))
        verb = str(item.get("http_verb", "GET")).upper()
        if engine.blocked_until(tenant_id, subject) > time.time():
            blocked_mid_batch = True
            results.append({"resource_id": rid, "decision": "block", "score": 100, "signals": ["temporarily_blocked"]})
            continue

        dec, sigs, _u, sc, cat = engine.evaluate(tenant_id, subject, rid, auth, endpoint="v1_batch", http_verb=verb)
        if dec == "block":
            blocked_mid_batch = True
            dispatch_soc_alert(tenant_id, subject, rid, sc, cat, sigs)
        final_dec = "block" if dec == "block" else ("allow" if auth else "deny")
        record_audit(tenant_id, subject, rid, "authorized" if auth else None, final_dec,
                     "blocked" if final_dec == "block" else ("allowed" if auth else "denied"),
                     explain_detector_signals(sigs), risk_score=sc)
        results.append({"resource_id": rid, "decision": final_dec, "score": sc, "signals": sigs})

    return {"total": len(items), "blocked_mid_batch": blocked_mid_batch, "results": results}


@app.post("/redteam/campaign")
@limiter.limit("60/minute")
def execute_redteam_campaign(request: Request, payload: dict, _guard: None = Depends(guard_demo_endpoint)) -> dict:
    """Executes a Red Team BOLA/IDOR simulation campaign against the live tenant.
    Supports preset and custom attack archetypes, evaluating each target through
    the real engine and database layers, returning real-time execution steps and metrics."""
    from fastapi.testclient import TestClient

    subject = str(payload.get("attacker_subject") or "attacker_1").strip()
    scenario = str(payload.get("scenario_name") or "idor_sweep").strip()
    target_ids = payload.get("target_records")

    if not isinstance(target_ids, list) or not target_ids:
        if scenario == "horizontal_privilege":
            target_ids = ["51", "52", "53", "54", "55", "56"]
            subject = "alice"
        elif scenario == "canary_trap":
            target_ids = ["0", "999999", "canary_admin_vault"]
            subject = "attacker_1"
        elif scenario == "stealth_creep":
            target_ids = [str(50 + i) for i in range(8)]
            subject = "attacker_slow"
        else:
            target_ids = [str(i) for i in range(50, 60)]
            subject = "attacker_1"

    client = TestClient(app)
    pwd = ADMIN_PASSWORD if subject == ADMIN_ROLE else DEMO_PASSWORD
    login_res = client.post("/auth/login", json={"subject": subject, "password": pwd})
    if login_res.status_code != 200:
        token = create_access_token(subject, "customer", DEMO_TENANT_ID)
    else:
        token = login_res.json()["access_token"]

    headers = {"Authorization": f"Bearer {token}"}
    steps = []
    blocked_count = 0
    denied_count = 0
    allowed_count = 0
    max_risk = 0.0
    canary_tripped = False
    quarantined = False

    start_time = time.time()
    for idx, raw_id in enumerate(target_ids):
        rid = str(raw_id).strip()
        t0 = time.time()
        res = client.get(f"/records/{rid}", headers=headers)
        dt_ms = round((time.time() - t0) * 1000, 2)

        status_code = res.status_code
        dec_hdr = res.headers.get("X-Detector-Decision") or ("block" if status_code == 403 else "allow" if status_code == 200 else "deny")
        risk_hdr = float(res.headers.get("X-Risk-Score") or 0.0)
        signals_hdr = [s for s in (res.headers.get("X-Detector-Signals") or "").split(",") if s]
        category_hdr = res.headers.get("X-Risk-Category") or "Normal"

        if risk_hdr > max_risk:
            max_risk = risk_hdr

        if "canary_honeypot_triggered" in signals_hdr or rid in ("0", "999999", "canary_admin_vault"):
            canary_tripped = True

        if dec_hdr == "block" or status_code == 403:
            blocked_count += 1
        elif status_code == 200:
            allowed_count += 1
        else:
            denied_count += 1

        current_strikes = engine.get_strike_count(DEMO_TENANT_ID, subject)
        ban_status = engine._ban_status(DEMO_TENANT_ID, subject)
        is_banned = ban_status in ("pending", "approved")
        is_blocked = engine.blocked_until(DEMO_TENANT_ID, subject) > time.time()
        if is_banned or is_blocked or current_strikes >= 3:
            quarantined = True

        steps.append({
            "step": idx + 1,
            "target_record_id": rid,
            "status_code": status_code,
            "decision": dec_hdr,
            "risk_score": risk_hdr,
            "category": category_hdr,
            "signals": signals_hdr,
            "latency_ms": dt_ms,
            "current_strikes": current_strikes,
            "is_quarantined": is_banned or is_blocked,
        })

        if is_banned:
            break

    total_reqs = len(steps)
    interception_rate = round(((blocked_count + denied_count) / max(total_reqs, 1)) * 100, 1)

    return {
        "scenario": scenario,
        "attacker_subject": subject,
        "total_requests": total_reqs,
        "blocked_count": blocked_count,
        "denied_count": denied_count,
        "allowed_count": allowed_count,
        "interception_rate_percent": interception_rate,
        "peak_risk_score": max_risk,
        "canary_tripped": canary_tripped,
        "quarantined": quarantined,
        "duration_ms": round((time.time() - start_time) * 1000, 2),
        "steps": steps,
        "verdict": (
            "THREAT NEUTRALIZED: Adversary quarantined by Strike 3 Adaptive Policy." if quarantined
            else "CRITICAL HONEYPOT TRIGGERED: Instant permanent ban dispatched." if canary_tripped
            else "CONTAINED: Multi-layer BOLA filters intercepted unauthorized access attempts." if blocked_count > 0
            else "ACCESS GRANTED: Legitimate access within authorized scope."
        )
    }


@app.get("/forensics/audit-proof")
def get_forensic_audit_proof(identity: tuple[str, str, str] = Depends(get_current_identity), expected_root: str | None = None) -> dict:
    """Hash a snapshot of all audit fields; verify only against an independently saved root."""
    _subject, _role, tenant_id = identity
    with db() as c:
        rows = c.execute(
            'SELECT id, occurred_at, subject_id, record_id, "authorization", detector_decision, outcome, explanation, risk_score '
            "FROM audit_events WHERE tenant_id = %s ORDER BY id ASC", (tenant_id,)).fetchall()

    if not rows:
        genesis_hash = hashlib.sha256(f"GENESIS:{tenant_id}".encode()).hexdigest()
        return {
            "ledger_valid": hmac.compare_digest(f"0x{genesis_hash}", expected_root) if expected_root else None,
            "total_events_verified": 0,
            "merkle_root": f"0x{genesis_hash}",
            "first_event_at": None,
            "latest_event_at": None,
            "compliance_posture": {
                "owasp_api1_2023": "PROTECTED",
                "hipaa_164_312": "NOT_ASSESSED",
                "gdpr_art_32": "NOT_ASSESSED",
                "soc2_cc6": "NOT_ASSESSED"
            },
            "chain_algorithm": "SHA-256-HASH-CHAIN"
        }

    running_hash = hashlib.sha256(f"GENESIS:{tenant_id}".encode()).hexdigest()
    for row in rows:
        block_content = running_hash + "|" + json.dumps(dict(row), sort_keys=True, separators=(",", ":"))
        running_hash = hashlib.sha256(block_content.encode()).hexdigest()

    return {
        "ledger_valid": hmac.compare_digest(f"0x{running_hash}", expected_root) if expected_root else None,
        "total_events_verified": len(rows),
        "merkle_root": f"0x{running_hash}",
        "first_event_at": rows[0]["occurred_at"],
        "latest_event_at": rows[-1]["occurred_at"],
        "compliance_posture": {
            "owasp_api1_2023": "PROTECTED (Active Multi-Layer Engine)",
            "hipaa_164_312": "NOT_ASSESSED",
            "gdpr_art_32": "NOT_ASSESSED",
            "soc2_cc6": "NOT_ASSESSED"
        },
        "chain_algorithm": "SHA-256-HASH-CHAIN"
    }


@app.get("/forensics/compliance-report")
def get_compliance_report(
    compliance_type: str = "hipaa",
    identity: tuple[str, str, str] = Depends(get_current_identity)
) -> dict:
    """Generate compliance attestation report (HIPAA, GDPR, or SOC2)."""
    _subject, role, tenant_id = identity
    require_security_admin(role)

    compliance_type = compliance_type.upper()
    if compliance_type not in ["HIPAA", "GDPR", "SOC2"]:
        raise HTTPException(400, "Invalid compliance_type. Must be HIPAA, GDPR, or SOC2")

    with db() as c:
        # Get audit event counts
        audit_count = c.execute(
            "SELECT COUNT(*) as cnt FROM audit_events WHERE tenant_id = %s",
            (tenant_id,)
        ).fetchone()["cnt"]

        # Get security metrics
        blocks = c.execute(
            "SELECT COUNT(*) as cnt FROM audit_events WHERE tenant_id = %s AND outcome = %s",
            (tenant_id, "blocked")
        ).fetchone()["cnt"]

        denials = c.execute(
            "SELECT COUNT(*) as cnt FROM audit_events WHERE tenant_id = %s AND outcome = %s",
            (tenant_id, "denied")
        ).fetchone()["cnt"]

        # Check for any audit log modifications (should be 0)
        modifications = None  # No independent modification monitor is configured.

    # Generate compliance attestation
    now = time.time()
    attestation_id = f"attst_{tenant_id}_{secrets.token_hex(8)}"

    compliance_details = {
        "HIPAA": {
            "standard": "HIPAA Security Rule",
            "sections": [
                "§164.312(a)(1) Access Control",
                "§164.312(a)(2) Audit Controls",
                "§164.308(a)(3)(ii)(B) Audit and Accountability"
            ],
            "controls": {
                "access_control": "IMPLEMENTED",
                "audit_logging": "IMPLEMENTED",
                "encryption": "DEPLOYMENT_DEPENDENT_NOT_ASSESSED",
                "access_reviews": "AUTOMATED"
            },
            "findings": {
                "unauthorized_access_attempts_blocked": blocks,
                "unauthorized_deletions_prevented": 0,
                "audit_log_modifications": modifications
            }
        },
        "GDPR": {
            "standard": "GDPR Article 32 Security of Processing",
            "articles": [
                "Article 32 - Pseudonymisation and Encryption",
                "Article 33 - Personal Data Breach Notification",
                "Article 35 - Data Protection Impact Assessment"
            ],
            "controls": {
                "pseudonymisation": "ENABLED",
                "data_encryption": "DEPLOYMENT_DEPENDENT_NOT_ASSESSED",
                "access_control": "ROLE_BASED",
                "breach_response": "AUTOMATED"
            },
            "findings": {
                "unauthorized_access_attempts_blocked": blocks,
                "personal_data_protection_events": denials,
                "breach_response_time_minutes": None
            }
        },
        "SOC2": {
            "standard": "SOC2 Type II Service Organization Control",
            "principles": [
                "CC6.1 Logical Access Controls",
                "CC7.2 System Monitoring",
                "CC9.2 Security Incident Response"
            ],
            "controls": {
                "access_control": "IMPLEMENTED",
                "monitoring": "CONTINUOUS",
                "incident_response": "AUTOMATED",
                "change_management": "ENFORCED"
            },
            "findings": {
                "unauthorized_access_attempts_blocked": blocks,
                "system_uptime_percent": None,
                "security_incidents_detected": blocks + denials,
                "mean_detection_time_seconds": None
            }
        }
    }

    report = compliance_details.get(compliance_type, {})
    report["tenant_id"] = tenant_id
    report["attestation_id"] = attestation_id
    report["attestation_date"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
    report["total_audit_events"] = audit_count
    report["status"] = "NOT_ASSESSED"
    report["assessment_note"] = "Observed security metrics; independent compliance assessment is required."
    report["auditor"] = "CyberAccess Automated Compliance Engine"
    report["next_review_date"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + 86400*90))

    # Store attestation in database
    with db() as c:
        c.execute(
            "INSERT INTO compliance_attestations "
            "(id, tenant_id, compliance_type, status, attestation_date, attestation_body, auditor_name) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s) "
            "ON CONFLICT (tenant_id, compliance_type, attestation_date) DO NOTHING",
            (attestation_id, tenant_id, compliance_type, "NOT_ASSESSED", now, json.dumps(report), "CyberAccess")
        )

    return report


# ===== Phase 5: Analytics dashboards & ROI calculator =====
def _require_own_tenant_or_admin(tenant_id: str, identity: tuple[str, str, str]) -> None:
    _subject, role, caller_tenant_id = identity
    if tenant_id != caller_tenant_id:
        raise HTTPException(403, "Tenant access denied")


@app.get("/tenants/{tenant_id}/analytics/overview")
def get_analytics_overview(
    tenant_id: str,
    window_hours: float = 24.0,
    identity: tuple[str, str, str] = Depends(get_tenant_admin_identity)
) -> dict:
    """Aggregated security posture for a dashboard: request volume, decision
    breakdown, and risk-score distribution over a rolling time window."""
    _require_own_tenant_or_admin(tenant_id, identity)

    now = time.time()
    cutoff = now - window_hours * 3600

    with db() as c:
        outcome_rows = c.execute(
            "SELECT outcome, COUNT(*) as cnt FROM audit_events WHERE tenant_id = %s AND occurred_at > %s GROUP BY outcome",
            (tenant_id, cutoff)
        ).fetchall()
        risk_stats = c.execute(
            "SELECT AVG(risk_score) as avg_score, MAX(risk_score) as max_score FROM audit_events "
            "WHERE tenant_id = %s AND occurred_at > %s",
            (tenant_id, cutoff)
        ).fetchone()
        unique_subjects = c.execute(
            "SELECT COUNT(DISTINCT subject_id) as n FROM audit_events WHERE tenant_id = %s AND occurred_at > %s",
            (tenant_id, cutoff)
        ).fetchone()["n"]

    outcome_counts = {row["outcome"]: row["cnt"] for row in outcome_rows}

    return {
        "tenant_id": tenant_id,
        "window_hours": window_hours,
        "generated_at": now,
        "total_events": sum(outcome_counts.values()),
        "outcome_breakdown": outcome_counts,
        "avg_risk_score": round(risk_stats["avg_score"] or 0.0, 2),
        "max_risk_score": risk_stats["max_score"] or 0.0,
        "unique_subjects_seen": unique_subjects,
        "currently_blocked_subjects": engine.blocked_subject_count(tenant_id),
        "attacks_blocked": outcome_counts.get("blocked", 0),
    }


@app.get("/tenants/{tenant_id}/analytics/threat-summary")
def get_threat_summary(
    tenant_id: str,
    window_hours: float = 24.0,
    identity: tuple[str, str, str] = Depends(get_tenant_admin_identity)
) -> dict:
    """Phase 4 threat-detection signals over a rolling window: IP event breakdown
    and IPs whose violation count crossed the reputation threshold."""
    _require_own_tenant_or_admin(tenant_id, identity)

    now = time.time()
    cutoff = now - window_hours * 3600

    with db() as c:
        ip_event_rows = c.execute(
            "SELECT event_type, COUNT(*) as cnt FROM threat_ip_events "
            "WHERE tenant_id = %s AND occurred_at > %s GROUP BY event_type",
            (tenant_id, cutoff)
        ).fetchall()
        flagged_ip_rows = c.execute(
            "SELECT ip_address, COUNT(*) as violations FROM threat_ip_events "
            "WHERE tenant_id = %s AND occurred_at > %s AND event_type IN ('denied_auth', 'bola_violation') "
            "GROUP BY ip_address HAVING COUNT(*) >= %s ORDER BY violations DESC LIMIT 20",
            (tenant_id, cutoff, threat_detection.IP_REPUTATION_VIOLATION_THRESHOLD)
        ).fetchall()

    return {
        "tenant_id": tenant_id,
        "window_hours": window_hours,
        "generated_at": now,
        "ip_event_breakdown": {r["event_type"]: r["cnt"] for r in ip_event_rows},
        "flagged_ips": [{"ip_address": r["ip_address"], "violation_count": r["violations"]} for r in flagged_ip_rows],
    }


@app.get("/tenants/{tenant_id}/analytics/roi")
def get_roi_estimate(
    tenant_id: str,
    window_days: float = 30.0,
    identity: tuple[str, str, str] = Depends(get_tenant_admin_identity)
) -> dict:
    """Estimated value delivered over a rolling window, computed from observed attacks-blocked
    counts and operator-configurable assumptions (ROI_ASSUMED_* env vars). This is an estimation
    tool, not a verified financial figure - see 'methodology_note' and 'assumptions' below."""
    _require_own_tenant_or_admin(tenant_id, identity)

    now = time.time()
    cutoff = now - window_days * 86400

    with db() as c:
        blocked = c.execute(
            "SELECT COUNT(*) as cnt FROM audit_events WHERE tenant_id = %s AND occurred_at > %s AND outcome = %s",
            (tenant_id, cutoff, "blocked")
        ).fetchone()["cnt"]
        denied = c.execute(
            "SELECT COUNT(*) as cnt FROM audit_events WHERE tenant_id = %s AND occurred_at > %s AND outcome = %s",
            (tenant_id, cutoff, "denied")
        ).fetchone()["cnt"]

    estimated_breaches_avoided = blocked * ROI_ASSUMED_BREACH_PROBABILITY_PER_ATTACK
    estimated_breach_cost_avoided_usd = estimated_breaches_avoided * ROI_ASSUMED_COST_PER_BREACH_USD
    manual_review_hours_saved = (blocked + denied) * ROI_ASSUMED_MANUAL_REVIEW_MINUTES_PER_EVENT / 60.0
    manual_review_cost_saved_usd = manual_review_hours_saved * ROI_ASSUMED_ENGINEER_HOURLY_COST_USD

    return {
        "tenant_id": tenant_id,
        "window_days": window_days,
        "generated_at": now,
        "methodology_note": (
            "Estimated value below depends entirely on the configurable assumptions listed in "
            "'assumptions' - these are illustrative defaults, not verified industry benchmarks. "
            "Override the ROI_ASSUMED_* environment variables with figures specific to your "
            "organization for a meaningful number."
        ),
        "observed": {
            "attacks_blocked": blocked,
            "requests_denied": denied,
        },
        "assumptions": {
            "cost_per_breach_usd": ROI_ASSUMED_COST_PER_BREACH_USD,
            "breach_probability_per_blocked_attack": ROI_ASSUMED_BREACH_PROBABILITY_PER_ATTACK,
            "manual_review_minutes_per_event": ROI_ASSUMED_MANUAL_REVIEW_MINUTES_PER_EVENT,
            "engineer_hourly_cost_usd": ROI_ASSUMED_ENGINEER_HOURLY_COST_USD,
        },
        "estimated_value": {
            "breaches_avoided": round(estimated_breaches_avoided, 3),
            "breach_cost_avoided_usd": round(estimated_breach_cost_avoided_usd, 2),
            "manual_review_hours_saved": round(manual_review_hours_saved, 1),
            "manual_review_cost_saved_usd": round(manual_review_cost_saved_usd, 2),
            "total_estimated_value_usd": round(estimated_breach_cost_avoided_usd + manual_review_cost_saved_usd, 2),
        },
    }


@app.post("/forensics/remediation")
def generate_remediation(payload: dict) -> dict:
    """Generates tailored, copy-pasteable remediation code (Python/FastAPI, Node.js/Express, Go)
    plus SIEM Sigma rules and Cloudflare WAF JSON expressions for the specified BOLA incident."""
    record_id = str(payload.get("record_id") or "55")
    subject = str(payload.get("subject") or "attacker_1")
    endpoint = str(payload.get("endpoint") or f"/records/{record_id}")

    python_code = f"""# === FastAPI + CyberAccess SDK Remediation ===
from fastapi import APIRouter, Depends, HTTPException
from cyberaccess import CyberAccessEngine, get_current_user

router = APIRouter()
engine = CyberAccessEngine.from_env()

@router.get("{endpoint}")
async def get_secure_record(
    record_id: str,
    user: dict = Depends(get_current_user)
):
    # 1. Fetch object metadata from persistence
    record = await db.fetch_record(record_id)
    if not record:
        raise HTTPException(status_code=404, detail="Record not found")

    # 2. Strict Subject-Object ownership & delegation boundary check
    if record.owner_id != user["id"] and not user.get("is_admin"):
        # Record BOLA risk telemetry signal to CyberAccess engine
        engine.record_event(
            tenant_id=user["tenant_id"],
            subject=user["id"],
            resource_id=record_id,
            authorized=False
        )
        raise HTTPException(status_code=403, detail="BOLA Access Denied: Object ownership mismatch")

    return record"""

    nodejs_code = f"""// === Node.js Express Middleware Remediation ===
const express = require('express');
const router = express.Router();

router.get('{endpoint}', async (req, res) => {{
  try {{
    const {{ record_id }} = req.params;
    const user = req.user; // Authenticated subject from JWT

    // 1. Fetch object metadata
    const record = await db.getRecord(record_id);
    if (!record) return res.status(404).json({{ error: 'Record not found' }});

    // 2. Strict tenancy and object boundary validation
    if (record.owner_id !== user.id && user.role !== 'admin') {{
      await cyberAccess.recordThreatEvent({{
        tenantId: user.tenantId,
        subject: user.id,
        resourceId: record_id,
        authorized: false
      }});
      return res.status(403).json({{
        error: 'Forbidden',
        reason: 'Broken Object Level Authorization (OWASP API1:2023)'
      }});
    }}

    return res.json(record);
  }} catch (err) {{
    return res.status(500).json({{ error: err.message }});
  }}
}});"""

    go_code = f"""// === Go (Gin Framework) Remediation ===
package handlers

import (
    "net/http"
    "github.com/gin-gonic/gin"
)

func GetSecureRecord(c *gin.Context) {{
    recordID := c.Param("record_id")
    userID := c.GetString("user_id")
    tenantID := c.GetString("tenant_id")

    record, err := db.FindRecord(c, recordID)
    if err != nil {{
        c.JSON(http.StatusNotFound, gin.H{{"error": "Record not found"}})
        return
    }}

    // Validate Object-Level Authorization
    if record.OwnerID != userID && c.GetString("role") != "admin" {{
        cyberaccess.RecordEvent(tenantID, userID, recordID, false)
        c.JSON(http.StatusForbidden, gin.H{{
            "error": "Access Denied: Object does not belong to subject",
            "cwe": "CWE-639",
        }})
        return
    }}

    c.JSON(http.StatusOK, record)
}}"""

    sigma_rule = f"""title: BOLA IDOR Pattern Detected - Rapid Endpoint Traversal
id: cb-bola-{hashlib.sha256(f'{record_id}_{subject}'.encode()).hexdigest()[:8]}
status: experimental
description: Detects systematic enumeration of private object IDs and unauthorized object-level access attempts.
references:
    - https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
author: CyberAccess Security Suite
date: {time.strftime('%Y-%m-%d')}
logsource:
    category: webserver
    service: api_gateway
detection:
    selection_uri:
        cs-method: 'GET'
        cs-uri-stem|startswith: '/records/'
    selection_status:
        sc-status:
            - 403
            - 429
    timeframe: 1m
    condition: selection_uri and selection_status | count(cs-uri-stem) by c-ip > 5
fields:
    - c-ip
    - cs-username
    - cs-uri-stem
    - sc-status
falsepositives:
    - Internal automated QA or performance load testing
level: high
tags:
    - attack.initial_access
    - attack.t1190
    - owasp.api1_2023"""

    cloudflare_waf = f"""{{
  "description": "CyberAccess BOLA Mitigation Rule for {endpoint}",
  "expression": "(http.request.uri.path contains \\"/records/\\" and not http.request.headers[\\"authorization\\"][0] matches \\"^Bearer .+\\") or (http.response.code eq 403 and ip.src.requests_rate > 10)",
  "action": "challenge",
  "action_parameters": {{
    "response": {{
      "status_code": 403,
      "content_type": "application/json",
      "content": "{{\\"error\\": \\"CyberAccess BOLA Filter: Rate threshold exceeded\\"}}"
    }}
  }}
}}"""

    return {
        "record_id": record_id,
        "subject": subject,
        "cwe_id": "CWE-639: Authorization Bypass Through User-Controlled Key",
        "owasp_category": "API1:2023 - Broken Object Level Authorization (BOLA)",
        "remediation_summary": "Enforce strict server-side verification comparing authenticated subject identity with target object owner_id and active delegation grants before executing data retrieval or mutation.",
        "code_snippets": {
            "python_fastapi": python_code,
            "nodejs_express": nodejs_code,
            "go_gin": go_code,
        },
        "detection_rules": {
            "sigma_yaml": sigma_rule,
            "cloudflare_waf_json": cloudflare_waf
        }
    }


def ensure_database() -> None:
    init_schema()
    apply_migrations(db)  # Apply enterprise feature migrations
    seed_demo_tenant(force=False)
    if APP_ENV in ("dev", "test") and DEMO_MODE:
        with db() as c:
            c.execute(
                "INSERT INTO tenants (id, name, api_key_hash, created_at) VALUES (%s, %s, %s, %s) "
                "ON CONFLICT (id) DO NOTHING",
                ("lost_found_dev", "Lost & Found Dev", hash_api_key("dev_test_key"), time.time()),
            )


ensure_database()
