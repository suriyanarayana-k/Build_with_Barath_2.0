import threading
import time
import socket
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest
import uvicorn
from fastapi.testclient import TestClient

import app as backend

client = TestClient(backend.app)


@pytest.fixture
def tenants():
    a = backend._create_tenant_record("regression-a")
    b = backend._create_tenant_record("regression-b")
    backend.record_audit(b["tenant_id"], "shared-subject", "foreign-marker", None, "deny", "denied", ["private"], 37)
    backend.engine._set_blocked_until(b["tenant_id"], "shared-subject", time.time() + 60)
    return a, b


def admin_headers(tenant):
    return {"Authorization": "Bearer " + backend.create_access_token("admin", backend.ADMIN_ROLE, tenant)}


def test_audit_readers_do_not_include_foreign_tenants(tenants):
    for tenant in (backend.DEMO_TENANT_ID, tenants[0]["tenant_id"]):
        for path in ("/audit-events", "/events", "/audit-timeline"):
            response = client.get(path, headers=admin_headers(tenant))
            assert response.status_code == 200
            assert "foreign-marker" not in response.text


def test_lockout_and_risk_do_not_search_other_tenants(tenants):
    a, b = tenants
    response = client.get("/lockout-status/shared-subject", headers={"X-API-Key": a["api_key"]})
    assert response.status_code == 200
    assert response.json()["is_locked"] is False
    assert client.get("/lockout-status/shared-subject", headers={"X-API-Key": "invalid"}).status_code == 401
    assert client.get("/lockout-status/shared-subject", params={"tenant": b["tenant_id"]}).status_code == 403
    assert client.get("/risk/shared-subject").json()["is_blocked"] is False


def test_tenant_admin_cannot_manage_another_tenant(tenants):
    a, b = tenants
    headers = admin_headers(a["tenant_id"])
    for suffix in ("quota", "quota-usage", "alert-channels", "analytics/overview"):
        assert client.get(f'/tenants/{b["tenant_id"]}/{suffix}', headers=headers).status_code == 403
    assert client.post(f'/tenants/{b["tenant_id"]}/quota', json={}, headers=headers).status_code == 403


def test_authorized_requires_a_boolean(tenants):
    headers = {"X-API-Key": tenants[0]["api_key"]}
    for value in ("false", 1, [], None):
        response = client.post("/v1/authorize", headers=headers, json={"subject": "u", "resource_id": "r", "authorized": value})
        assert response.status_code == 400


def test_quota_patch_preserves_existing_and_rejects_zero(tenants):
    tenant = tenants[0]["tenant_id"]
    headers = admin_headers(tenant)
    path = f"/tenants/{tenant}/quota"
    assert client.post(path, headers=headers, json={"requests_per_minute": 10}).status_code == 200
    assert client.post(path, headers=headers, json={"risk_threshold_warn": 60}).status_code == 200
    assert client.get(path, headers=headers).json()["quota"]["requests_per_minute"] == 10
    assert client.post(path, headers=headers, json={"requests_per_minute": 0}).status_code == 400


def test_get_signup_does_not_create_tenants():
    assert client.get("/v1/signup", params={"name": "prefetch"}).status_code == 405


def test_tenant_risk_threshold_changes_are_enforced(tenants, monkeypatch):
    a, b = tenants
    headers = {"X-API-Key": a["api_key"]}
    assert client.post(f'/tenants/{a["tenant_id"]}/quota', headers=headers,
                       json={"risk_threshold_block": 50, "risk_threshold_warn": 40}).status_code == 200
    monkeypatch.setattr(backend.engine, "compute_risk", lambda *args: {
        "score": 55, "signals": [], "category": "Suspicious", "contributions": {}
    })
    payload = {"subject": "threshold-user", "resource_id": "r", "authorized": True}
    response = client.post("/v1/authorize", headers=headers, json=payload)
    assert response.json()["decision"] == "block"
    assert response.json()["strike_count"] == 1
    response = client.post("/v1/authorize", headers={"X-API-Key": b["api_key"]}, json=payload)
    assert response.json()["decision"] == "allow"


def test_invalid_batch_is_rejected_before_recording_decisions(tenants):
    a = tenants[0]
    response = client.post("/v1/authorize-batch", headers={"X-API-Key": a["api_key"]},
                           json={"subject": "batch-validation", "items": [
                               {"resource_id": "r", "authorized": True}, {"authorized": "false"}
                           ]})
    assert response.status_code == 400
    with backend.db() as c:
        assert c.execute("SELECT COUNT(*) AS n FROM audit_events WHERE tenant_id = %s",
                         (a["tenant_id"],)).fetchone()["n"] == 0
        assert c.execute("SELECT COUNT(*) AS n FROM risk_events WHERE tenant_id = %s",
                         (a["tenant_id"],)).fetchone()["n"] == 0


def test_demo_canary_ids_do_not_create_customer_honeypots(tenants):
    a = tenants[0]
    response = client.post("/v1/authorize", headers={"X-API-Key": a["api_key"]},
                           json={"subject": "customer-user", "resource_id": 0, "authorized": False})
    assert response.status_code == 200
    assert response.json()["decision"] == "deny"
    assert "canary_honeypot_triggered" not in response.json()["signals"]


def test_signup_key_can_read_its_analytics(tenants):
    a, b = tenants
    for suffix in ("overview", "threat-summary", "roi"):
        response = client.get(f'/tenants/{a["tenant_id"]}/analytics/{suffix}', headers={"X-API-Key": a["api_key"]})
        assert response.status_code == 200
        assert client.get(f'/tenants/{b["tenant_id"]}/analytics/{suffix}', headers={"X-API-Key": a["api_key"]}).status_code == 403


def test_product_authorization_updates_prometheus_metrics(tenants):
    a = tenants[0]
    response = client.post("/v1/authorize", headers={"X-API-Key": a["api_key"]},
                           json={"subject": "metric-user", "resource_id": "r", "authorized": True})
    assert response.status_code == 200
    tenant_labels = {"tenant_id": a["tenant_id"]}
    assert backend.REGISTRY.get_sample_value("authorize_decisions_total", {**tenant_labels, "decision": "allow"}) == 1
    assert backend.REGISTRY.get_sample_value("authorize_latency_seconds_count", tenant_labels) == 1
    assert backend.REGISTRY.get_sample_value("risk_score_distribution_count", tenant_labels) == 1
    assert client.get("/metrics").status_code == 200
    assert backend.REGISTRY.get_sample_value("audit_events_stored_total", tenant_labels) == 1
    response = client.post("/v1/authorize-batch", headers={"X-API-Key": a["api_key"]},
                           json={"subject": "metric-user", "items": [
                               {"resource_id": "a", "authorized": True}, {"resource_id": "b", "authorized": True}
                           ]})
    assert response.status_code == 200
    assert backend.REGISTRY.get_sample_value("authorize_decisions_total", {**tenant_labels, "decision": "allow"}) == 3


def test_concurrent_requests_cannot_escalate_an_active_lockout(tenants):
    tenant = tenants[0]["tenant_id"]
    subject = "concurrent-strikes"
    barrier = threading.Barrier(8)
    now = time.time()

    def strike(_):
        barrier.wait(timeout=5)
        return backend.engine.register_strike_and_block(tenant, subject, now)

    with ThreadPoolExecutor(max_workers=8) as workers:
        results = list(workers.map(strike, range(8)))
    assert backend.engine.get_strike_count(tenant, subject, now) == 1
    assert all(result[2] == 1 for result in results)
    assert backend.engine._ban_status(tenant, subject) is None


def test_quota_uses_authenticated_tenant_even_without_redis(tenants, monkeypatch):
    a, b = tenants
    monkeypatch.setattr(backend, "redis_client", None)
    with backend.db() as c:
        c.execute("INSERT INTO tenant_quotas (tenant_id, requests_per_minute) VALUES (%s, 1)", (a["tenant_id"],))
    headers = {"X-API-Key": a["api_key"], "X-Tenant-ID": b["tenant_id"], "Origin": "http://localhost:5173"}
    payload = {"subject": "u", "resource_id": "r", "authorized": True}
    assert client.post("/v1/authorize", headers=headers, json=payload).status_code == 200
    limited = client.post("/v1/authorize", headers=headers, json=payload)
    assert limited.status_code == 429
    assert limited.headers["access-control-allow-origin"] == headers["Origin"]
    assert "retry-after" in limited.headers
    assert client.post("/v1/authorize", headers={"X-API-Key": b["api_key"]}, json=payload).status_code == 200


def test_signup_key_can_manage_only_its_tenant(tenants):
    a, b = tenants
    headers = {"X-API-Key": a["api_key"]}
    assert client.post(f'/tenants/{a["tenant_id"]}/quota', headers=headers, json={"requests_per_minute": 30}).status_code == 200
    assert client.post(f'/tenants/{b["tenant_id"]}/quota', headers=headers, json={}).status_code == 403


def test_global_demo_toggle_does_not_disable_customer_authorization(tenants):
    assert client.post("/defense/toggle", json={"enabled": False}).status_code == 401
    assert client.post("/hackathon/release", json={"subject": "shared-subject"}).status_code == 401
    backend.set_defense_enabled(False)
    try:
        response = client.post("/v1/authorize", headers={"X-API-Key": tenants[0]["api_key"]},
                               json={"subject": "u", "resource_id": "r", "authorized": False})
        assert response.json()["decision"] == "deny"
    finally:
        backend.set_defense_enabled(True)


def test_audit_proof_detects_changes_to_explanations(tenants):
    headers = admin_headers(tenants[1]["tenant_id"])
    proof = client.get("/forensics/audit-proof", headers=headers).json()
    assert proof["ledger_valid"] is None
    with backend.db() as c:
        c.execute("UPDATE audit_events SET explanation = %s WHERE tenant_id = %s", ("tampered", tenants[1]["tenant_id"]))
    response = client.get("/forensics/audit-proof", headers=headers, params={"expected_root": proof["merkle_root"]})
    assert response.json()["ledger_valid"] is False


def test_migration_failure_rolls_back_schema_changes():
    with pytest.raises(Exception):
        with backend.db() as c:
            c.execute("CREATE TABLE rollback_probe (id INT); INVALID SQL;")
    with pytest.raises(Exception):
        with backend.db() as c:
            c.execute("SELECT * FROM rollback_probe")


def test_migrations_can_run_repeatedly():
    backend.ensure_database()
    backend.ensure_database()
    with backend.db() as c:
        assert c.execute("SELECT email FROM tenants LIMIT 1").fetchone() is not None
        from migrations import SCHEMA_VERSION
        assert c.execute("SELECT value FROM system_config WHERE key = %s", ("schema_version",)).fetchone()["value"] == str(SCHEMA_VERSION)


def test_smtp_uses_one_authenticated_tls_connection(monkeypatch):
    import asyncio
    import alerting
    calls = []

    class SMTP:
        def __init__(self, host, port, timeout):
            calls.append((host, port, timeout))
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def starttls(self):
            calls.append("tls")
        def login(self, user, password):
            calls.append("login")
        def sendmail(self, sender, recipient, message):
            calls.append("send")
            assert "&lt;script&gt;" in message

    monkeypatch.setattr(alerting, "SMTP_ENABLED", True)
    monkeypatch.setattr(alerting, "SMTP_PASSWORD", "test-password")
    monkeypatch.setattr(alerting.smtplib, "SMTP", SMTP)
    assert asyncio.run(alerting.AlertDispatcher.send_email_alert("test@example.com", "Test", "<script>"))
    assert calls[1:] == ["tls", "login", "send"]


def test_real_socket_post_requests_finish():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    server = uvicorn.Server(uvicorn.Config(backend.app, log_level="error", lifespan="off"))
    worker = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    worker.start()
    deadline = time.monotonic() + 5
    try:
        while not server.started and time.monotonic() < deadline:
            time.sleep(0.01)
        assert server.started
        base = f"http://127.0.0.1:{sock.getsockname()[1]}"
        with httpx.Client(base_url=base, timeout=3) as network:
            assert network.post("/v1/signup", json={"name": "socket-test"}).status_code == 200
            login = network.post("/auth/login", json={"subject": "alice", "password": backend.DEMO_PASSWORD})
            assert login.status_code == 200
            headers = {"Authorization": "Bearer " + login.json()["access_token"]}
            assert network.patch("/records/1", headers=headers, json={"data": "updated"}).status_code == 200
    finally:
        server.should_exit = True
        worker.join(timeout=5)
        sock.close()
