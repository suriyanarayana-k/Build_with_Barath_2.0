"""Tenant console lifecycle and security boundaries, on both database backends."""
import secrets
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

import app as backend

PASSWORD = "disposable-test-password"
CONSOLE = {"X-CyberAccess-Console": "1", "Origin": "http://localhost:5177"}


def new_account():
    client = TestClient(backend.app)
    email = secrets.token_hex(12) + "@example.test"
    response = client.post("/auth/signup", json={"name": "Customer", "email": email, "password": PASSWORD})
    assert response.status_code == 200, response.text
    return client, response.json(), email, response


def test_signup_issues_separate_key_and_http_only_session():
    client, account, email, response = new_account()
    assert account["api_key"].startswith("sk_")
    assert "access_token" not in account
    assert response.headers["cache-control"] == "no-store"
    cookie = response.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=lax" in cookie
    me = client.get("/auth/me").json()
    assert me["email"] == email
    assert me["tenant_id"] == account["tenant_id"]
    assert me["capabilities"] == {"demo_controls": False, "manage_api_key": True}
    assert account["api_key"] not in client.get("/auth/me").text
    assert "api_key" not in me
    with backend.db() as c:
        stored = c.execute("SELECT api_key_hash FROM tenants WHERE id = %s", (account["tenant_id"],)).fetchone()
        assert stored["api_key_hash"] == backend.hash_api_key(account["api_key"])


def test_returning_login_and_signout_revoke_copied_session():
    client, account, email, response = new_account()
    stolen_copy = client.cookies.get(backend.CONSOLE_COOKIE_NAME)
    assert client.post("/auth/logout", headers=CONSOLE).status_code == 200
    assert client.get("/auth/me").status_code == 401
    replay = TestClient(backend.app)
    replay.cookies.set(backend.CONSOLE_COOKIE_NAME, stolen_copy)
    assert replay.get("/auth/me").status_code == 401
    login = client.post("/auth/login", json={"email": " " + email.upper() + " ", "password": PASSWORD})
    assert login.status_code == 200
    assert login.json()["user"]["tenant_id"] == account["tenant_id"]
    assert client.get("/auth/me").status_code == 200


def test_session_restore_returns_guest_without_a_failed_http_request():
    guest = TestClient(backend.app)
    assert guest.get("/auth/session").json() == {"user": None}
    client, account, email, response = new_account()
    restored = client.get("/auth/session")
    assert restored.headers["cache-control"] == "no-store"
    assert restored.json()["user"]["tenant_id"] == account["tenant_id"]
    assert client.post("/auth/logout", headers=CONSOLE).status_code == 200
    assert client.get("/auth/session").json() == {"user": None}


@pytest.mark.parametrize("password", ["wrong", None, [], "x" * 73])
def test_bad_passwords_cannot_open_an_account(password):
    client, account, email, response = new_account()
    other = TestClient(backend.app)
    assert other.post("/auth/login", json={"email": email, "password": password}).status_code == 401
    assert other.get("/auth/me").status_code == 401


@pytest.mark.parametrize("password", ["short", "🔥" * 19, None, []])
def test_signup_rejects_invalid_password_before_creating_tenant(password):
    with backend.db() as c:
        count = c.execute("SELECT COUNT(*) AS n FROM tenants").fetchone()["n"]
    client = TestClient(backend.app)
    assert client.post("/auth/signup", json={"name": "Invalid", "email": "x@example.test", "password": password}).status_code == 400
    with backend.db() as c:
        assert c.execute("SELECT COUNT(*) AS n FROM tenants").fetchone()["n"] == count


def test_duplicate_email_rolls_back_tenant_and_user():
    client, account, email, response = new_account()
    with backend.db() as c:
        before = {table: c.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()["n"] for table in ("tenants", "users", "dashboard_sessions")}
    assert TestClient(backend.app).post("/auth/signup", json={"name": "Duplicate", "email": email.upper(), "password": PASSWORD}).status_code == 409
    with backend.db() as c:
        for table, count in before.items():
            assert c.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()["n"] == count


def test_existing_tenant_claim_requires_current_key_and_cannot_overwrite_owner():
    tenant = backend._create_tenant_record("Existing", "public-contact@example.test")
    client = TestClient(backend.app)
    payload = {"email": secrets.token_hex(12) + "@example.test", "password": PASSWORD}
    assert client.post("/auth/claim-tenant", json=payload).status_code == 401
    assert client.post("/auth/claim-tenant", headers={"X-API-Key": "invalid"}, json=payload).status_code == 401
    claimed = client.post("/auth/claim-tenant", headers={"X-API-Key": tenant["api_key"]}, json=payload)
    assert claimed.status_code == 200
    assert claimed.json()["user"]["tenant_id"] == tenant["tenant_id"]
    takeover = TestClient(backend.app).post("/auth/claim-tenant", headers={"X-API-Key": tenant["api_key"]}, json={**payload, "email": "other@example.test"})
    assert takeover.status_code == 409
    assert backend.get_tenant_from_api_key(tenant["api_key"]) == tenant["tenant_id"]


def test_concurrent_claims_create_exactly_one_owner():
    tenant = backend._create_tenant_record("Race")
    def claim(index):
        return TestClient(backend.app).post("/auth/claim-tenant", headers={"X-API-Key": tenant["api_key"]},
            json={"email": secrets.token_hex(12) + "@example.test", "password": PASSWORD}).status_code
    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(claim, range(4)))
    assert sorted(results) == [200, 409, 409, 409]
    with backend.db() as c:
        assert c.execute("SELECT COUNT(*) AS n FROM users WHERE tenant_id = %s", (tenant["tenant_id"],)).fetchone()["n"] == 1


def test_dashboard_reads_show_own_real_activity_and_reject_foreign_tenants():
    client, account, email, response = new_account()
    foreign = backend._create_tenant_record("Foreign")
    backend.record_audit(foreign["tenant_id"], "foreign-subject", "foreign-secret", None, "deny", "denied", ["private"], 80)
    backend.engine._set_blocked_until(foreign["tenant_id"], "foreign-subject", time.time() + 60)
    product = TestClient(backend.app)
    assert product.post("/v1/authorize", headers={"X-API-Key": account["api_key"]},
        json={"subject": "own-user", "resource_id": "own-resource", "authorized": True}).status_code == 200
    for path in ("/events", "/audit-events", "/audit-timeline", "/stats", "/risk/own-user"):
        result = client.get(path)
        assert result.status_code == 200, result.text
        assert result.headers["cache-control"] == "no-store"
        assert "foreign-secret" not in result.text
        assert "foreign-subject" not in result.text
    assert client.get("/events").json()["events"][0]["subject_id"] == "own-user"
    stats = client.get("/stats").json()
    assert stats["tenant_id"] == account["tenant_id"]
    assert stats["active_subjects"] == 1
    assert stats["blocked_subjects"] == 0
    for suffix in ("quota", "quota-usage", "analytics/overview", "analytics/threat-summary", "analytics/roi", "alert-channels"):
        assert client.get(f'/tenants/{account["tenant_id"]}/{suffix}').status_code == 200
        assert client.get(f'/tenants/{foreign["tenant_id"]}/{suffix}').status_code == 403
    assert client.get(f'/tenants/{account["tenant_id"]}/analytics/overview').json()["total_events"] == 1


def test_dashboard_stays_accessible_when_product_quota_is_exhausted():
    client, account, email, response = new_account()
    tenant_id = account["tenant_id"]
    assert client.post(f"/tenants/{tenant_id}/quota", headers=CONSOLE, json={"requests_per_minute": 1}).status_code == 200
    product = TestClient(backend.app)
    payload = {"subject": "user", "resource_id": "resource", "authorized": True}
    assert product.post("/v1/authorize", headers={"X-API-Key": account["api_key"]}, json=payload).status_code == 200
    assert product.post("/v1/authorize", headers={"X-API-Key": account["api_key"]}, json=payload).status_code == 429
    assert client.get("/events").status_code == 200
    usage = client.get(f"/tenants/{tenant_id}/quota-usage").json()["current_usage"]
    assert usage["requests_this_minute"] == 2


def test_cookie_writes_require_console_header_and_permitted_origin():
    client, account, email, response = new_account()
    path = f'/tenants/{account["tenant_id"]}/quota'
    assert client.post(path, json={"requests_per_minute": 10}).status_code == 403
    assert client.post(path, headers={**CONSOLE, "Origin": "https://evil.example"}, json={"requests_per_minute": 10}).status_code == 403
    assert client.post(path, headers=CONSOLE, json={"requests_per_minute": 10}).status_code == 200
    assert client.get("/events", headers={"Origin": "https://evil.example"}).headers.get("access-control-allow-origin") is None


def test_tenant_owner_cannot_reset_shared_demo():
    client, account, email, response = new_account()
    assert client.post("/reset", headers=CONSOLE).status_code == 403
    assert client.post("/redteam/campaign", headers=CONSOLE, json={"scenario_name": "idor_sweep"}).status_code == 403


def test_key_replacement_requires_owner_password_and_revokes_old_key():
    client, account, email, response = new_account()
    old_key = account["api_key"]
    wrong = client.post("/auth/api-key/rotate", headers=CONSOLE, json={"password": "wrong"})
    assert wrong.status_code == 401
    assert client.get("/auth/me").status_code == 200
    replaced = client.post("/auth/api-key/rotate", headers=CONSOLE, json={"password": PASSWORD})
    assert replaced.status_code == 200
    assert replaced.headers["cache-control"] == "no-store"
    key = replaced.json()["api_key"]
    assert key != old_key
    with pytest.raises(backend.HTTPException):
        backend.get_tenant_from_api_key(old_key)
    assert backend.get_tenant_from_api_key(key) == account["tenant_id"]
    assert key not in client.get("/auth/me").text
    events = client.get("/events").json()["events"]
    assert events[0]["outcome"] == "key_replaced"
    assert old_key not in str(events) and key not in str(events)


def test_expired_or_deleted_session_is_rejected():
    client, account, email, response = new_account()
    with backend.db() as c:
        c.execute("UPDATE dashboard_sessions SET expires_at = %s WHERE tenant_id = %s", (time.time() - 1, account["tenant_id"]))
    assert client.get("/auth/me").status_code == 401


def test_secure_cookie_configuration(monkeypatch):
    monkeypatch.setattr(backend, "CONSOLE_COOKIE_SECURE", True)
    client, account, email, response = new_account()
    assert "; Secure" in response.headers["set-cookie"]


def test_demo_console_preserves_session_after_reset():
    client = TestClient(backend.app)
    login = client.post("/auth/login", json={"subject": backend.ADMIN_ROLE, "password": backend.ADMIN_PASSWORD, "console": True})
    assert login.status_code == 200
    assert login.json()["user"]["capabilities"]["demo_controls"] is True
    assert client.post("/reset", headers=CONSOLE).status_code == 200
    assert client.get("/auth/me").status_code == 200


def test_revoked_cookie_cannot_access_graphql_or_write_body_reference_audits():
    client = TestClient(backend.app)
    assert client.post("/auth/login", json={"subject": "alice", "password": backend.DEMO_PASSWORD, "console": True}).status_code == 200
    cookie = client.cookies.get(backend.CONSOLE_COOKIE_NAME)
    assert client.post("/auth/logout", headers=CONSOLE).status_code == 200
    replay = TestClient(backend.app)
    replay.cookies.set(backend.CONSOLE_COOKIE_NAME, cookie)
    with backend.db() as c:
        count = c.execute("SELECT COUNT(*) AS n FROM audit_events WHERE tenant_id = %s", (backend.DEMO_TENANT_ID,)).fetchone()["n"]
    assert replay.put("/records/55", headers=CONSOLE, json={"record_id": "55", "data": "unauthorized"}).status_code == 401
    with backend.db() as c:
        assert c.execute("SELECT COUNT(*) AS n FROM audit_events WHERE tenant_id = %s", (backend.DEMO_TENANT_ID,)).fetchone()["n"] == count
    result = replay.post("/graphql", headers=CONSOLE, json={"query": '{ record(id: "1") { id data } }'})
    assert result.status_code == 200
    assert result.json().get("errors")
    assert not result.json().get("data") or result.json()["data"]["record"] is None


def test_dashboard_config_uses_tenant_risk_thresholds():
    client, account, email, response = new_account()
    assert client.post(f'/tenants/{account["tenant_id"]}/quota', headers=CONSOLE,
                       json={"risk_threshold_block": 60, "risk_threshold_warn": 40}).status_code == 200
    config = client.get("/config").json()
    assert config["risk_threshold_block"] == 60 and config["risk_threshold_warn"] == 40
