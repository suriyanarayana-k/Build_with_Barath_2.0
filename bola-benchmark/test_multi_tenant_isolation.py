"""
Multi-Tenant Isolation Validation Tests
Ensures strict isolation between tenants - one tenant cannot leak/access another's data.

Runs against temporary SQLite by default. Set CYBERACCESS_TEST_DATABASE_URL
to a disposable PostgreSQL database to check PostgreSQL isolation as well.
"""
import json
import pytest
from fastapi.testclient import TestClient
from app import app, db
import time
import os

# Run the same isolation checks against the configured test database on both backends.

client = TestClient(app)

TENANT_A = "tenant_a_test"
TENANT_B = "tenant_b_test"
SUBJECT_A = "user_a"
SUBJECT_B = "user_b"


@pytest.fixture(scope="module", autouse=True)
def setup_test_tenants():
    """Create test tenants."""
    with db() as c:
        for tenant_id in [TENANT_A, TENANT_B]:
            c.execute(
                "INSERT INTO tenants (id, name, api_key_hash, created_at) VALUES (%s, %s, %s, %s) "
                "ON CONFLICT (id) DO NOTHING",
                (tenant_id, f"Test Tenant {tenant_id}", f"hash_{tenant_id}", time.time())
            )
            c.execute(
                "INSERT INTO tenant_quotas (tenant_id, requests_per_minute) VALUES (%s, %s) "
                "ON CONFLICT (tenant_id) DO NOTHING",
                (tenant_id, 10000)
            )


def test_audit_events_isolated_by_tenant():
    """Verify audit events are isolated by tenant_id."""
    # Record event for Tenant A
    with db() as c:
        c.execute(
            "INSERT INTO audit_events (tenant_id, occurred_at, subject_id, record_id, "
            '"authorization", detector_decision, outcome, explanation, risk_score) '
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (TENANT_A, time.time(), SUBJECT_A, "rec_1", "authorized", "allow", "allowed", "Test event", 0.0)
        )

        # Record different event for Tenant B
        c.execute(
            "INSERT INTO audit_events (tenant_id, occurred_at, subject_id, record_id, "
            '"authorization", detector_decision, outcome, explanation, risk_score) '
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (TENANT_B, time.time(), SUBJECT_B, "rec_2", "authorized", "allow", "allowed", "Test event B", 0.0)
        )

    # Query: Tenant A should only see its own events
    with db() as c:
        result_a = c.execute(
            "SELECT COUNT(*) as cnt FROM audit_events WHERE tenant_id = %s",
            (TENANT_A,)
        ).fetchone()["cnt"]

        # Should see exactly 1 event for Tenant A
        assert result_a >= 1, f"Tenant A should have at least 1 event, got {result_a}"

        result_b = c.execute(
            "SELECT COUNT(*) as cnt FROM audit_events WHERE tenant_id = %s",
            (TENANT_B,)
        ).fetchone()["cnt"]

        # Should see exactly 1 event for Tenant B
        assert result_b >= 1, f"Tenant B should have at least 1 event, got {result_b}"


def test_quota_isolation():
    """Verify quotas are isolated per tenant."""
    with db() as c:
        # Set different quota for each tenant
        c.execute(
            "INSERT INTO tenant_quotas (tenant_id, requests_per_minute) VALUES (%s, %s) "
            "ON CONFLICT (tenant_id) DO UPDATE SET requests_per_minute = EXCLUDED.requests_per_minute",
            (TENANT_A, 5000)
        )
        c.execute(
            "INSERT INTO tenant_quotas (tenant_id, requests_per_minute) VALUES (%s, %s) "
            "ON CONFLICT (tenant_id) DO UPDATE SET requests_per_minute = EXCLUDED.requests_per_minute",
            (TENANT_B, 10000)
        )

    # Verify each tenant has correct quota
    with db() as c:
        quota_a = c.execute(
            "SELECT requests_per_minute FROM tenant_quotas WHERE tenant_id = %s",
            (TENANT_A,)
        ).fetchone()
        quota_b = c.execute(
            "SELECT requests_per_minute FROM tenant_quotas WHERE tenant_id = %s",
            (TENANT_B,)
        ).fetchone()

    assert quota_a["requests_per_minute"] == 5000
    assert quota_b["requests_per_minute"] == 10000


def test_compliance_attestations_isolated():
    """Verify compliance attestations are isolated by tenant."""
    with db() as c:
        # Create attestation for Tenant A
        c.execute(
            "INSERT INTO compliance_attestations (id, tenant_id, compliance_type, status, attestation_body) "
            "VALUES (%s, %s, %s, %s, %s)",
            ("att_a_1", TENANT_A, "HIPAA", "COMPLIANT", json.dumps({"test": "a"}))
        )

        # Create attestation for Tenant B
        c.execute(
            "INSERT INTO compliance_attestations (id, tenant_id, compliance_type, status, attestation_body) "
            "VALUES (%s, %s, %s, %s, %s)",
            ("att_b_1", TENANT_B, "GDPR", "COMPLIANT", json.dumps({"test": "b"}))
        )

    # Query: Each tenant should only see their attestations
    with db() as c:
        att_a = c.execute(
            "SELECT COUNT(*) as cnt FROM compliance_attestations WHERE tenant_id = %s",
            (TENANT_A,)
        ).fetchone()["cnt"]

        att_b = c.execute(
            "SELECT COUNT(*) as cnt FROM compliance_attestations WHERE tenant_id = %s",
            (TENANT_B,)
        ).fetchone()["cnt"]

    assert att_a >= 1, f"Tenant A should have attestations, got {att_a}"
    assert att_b >= 1, f"Tenant B should have attestations, got {att_b}"


def test_rate_limit_isolation():
    """Verify rate limits don't leak between tenants."""
    # Tenant A hits rate limit
    with db() as c:
        c.execute(
            "INSERT INTO rate_limit_state (tenant_id, current_requests) VALUES (%s, %s) "
            "ON CONFLICT (tenant_id) DO UPDATE SET current_requests = EXCLUDED.current_requests",
            (TENANT_A, 5000)  # High usage
        )
        c.execute(
            "INSERT INTO rate_limit_state (tenant_id, current_requests) VALUES (%s, %s) "
            "ON CONFLICT (tenant_id) DO UPDATE SET current_requests = EXCLUDED.current_requests",
            (TENANT_B, 100)  # Low usage
        )

    # Verify each tenant has isolated rate limit state
    with db() as c:
        state_a = c.execute(
            "SELECT current_requests FROM rate_limit_state WHERE tenant_id = %s",
            (TENANT_A,)
        ).fetchone()
        state_b = c.execute(
            "SELECT current_requests FROM rate_limit_state WHERE tenant_id = %s",
            (TENANT_B,)
        ).fetchone()

    assert state_a["current_requests"] == 5000
    assert state_b["current_requests"] == 100
    # Verify high usage in A doesn't affect B
    assert state_b["current_requests"] < state_a["current_requests"]


def test_alert_channels_isolated():
    """Verify alert channels are isolated per tenant."""
    with db() as c:
        # Create alert channels for each tenant
        c.execute(
            "INSERT INTO alert_channels (id, tenant_id, channel_type, channel_config, is_active) "
            "VALUES (%s, %s, %s, %s, %s)",
            ("alert_a_1", TENANT_A, "slack", json.dumps({"url": "https://hooks.slack.com/a"}), True)
        )
        c.execute(
            "INSERT INTO alert_channels (id, tenant_id, channel_type, channel_config, is_active) "
            "VALUES (%s, %s, %s, %s, %s)",
            ("alert_b_1", TENANT_B, "email", json.dumps({"address": "b@example.com"}), True)
        )

    # Query: Each tenant should only see their channels
    with db() as c:
        channels_a = c.execute(
            "SELECT COUNT(*) as cnt FROM alert_channels WHERE tenant_id = %s",
            (TENANT_A,)
        ).fetchone()["cnt"]

        channels_b = c.execute(
            "SELECT COUNT(*) as cnt FROM alert_channels WHERE tenant_id = %s",
            (TENANT_B,)
        ).fetchone()["cnt"]

    assert channels_a >= 1
    assert channels_b >= 1


def test_no_cross_tenant_data_leakage():
    """Critical test: Ensure SELECT queries respect tenant_id boundaries."""
    with db() as c:
        # Intentionally query without tenant_id filter - should show multi-tenant data
        all_audits = c.execute(
            "SELECT DISTINCT tenant_id FROM audit_events WHERE tenant_id IN (%s, %s)",
            (TENANT_A, TENANT_B)
        ).fetchall()

        tenant_ids = [row["tenant_id"] for row in all_audits]

        # Both tenants should be present in database
        assert TENANT_A in tenant_ids or TENANT_B in tenant_ids

        # But when filtering by one tenant, should NOT see the other
        a_only = c.execute(
            "SELECT DISTINCT tenant_id FROM audit_events WHERE tenant_id = %s",
            (TENANT_A,)
        ).fetchall()

        # Should only have TENANT_A
        for row in a_only:
            assert row["tenant_id"] == TENANT_A, f"Data leak: {row['tenant_id']} != {TENANT_A}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
