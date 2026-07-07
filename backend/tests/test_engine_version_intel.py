"""Integration tests: version intelligence findings produced by run_analysis().

Verifies that when a policy has a linked device, run_analysis() calls the
version_intel module and stores the resulting advisory findings in the DB.
"""
import app.models  # noqa: F401 — register all models before create_all

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models.customer import Customer
from app.models.device import FirewallDevice
from app.models.finding import Finding
from app.models.policy import FirewallPolicy, FirewallRule
from app.models.version_catalog import VersionCatalogEntry
from app.analysis.engine import run_analysis


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(engine)


def _seed(db, *, vendor="FortiGate", os_version="7.2.5", ha_peer="",
          catalog_recommended="7.2.10", catalog_eol=None,
          catalog_support_status="supported"):
    """Minimal seed: customer → device → policy → one allow rule + version catalog."""
    cust = Customer(id="c1", name="Test Corp")
    db.add(cust)

    device = FirewallDevice(
        id="dev1", customer_id="c1", name="HQ FW",
        vendor=vendor, host="10.0.0.1",
        os_version=os_version, ha_peer=ha_peer,
    )
    db.add(device)

    policy = FirewallPolicy(
        id="pol1", customer_id="c1", device_id="dev1",
        firewall_name="HQ", vendor=vendor, analysis_status="pending",
    )
    db.add(policy)

    rule = FirewallRule(
        id="rule1", policy_id="pol1", vendor=vendor, rule_number=1,
        sources=["any"], destinations=["any"], services=["any"], action="accept",
    )
    db.add(rule)

    if catalog_recommended:
        entry = VersionCatalogEntry(
            id="cat1", vendor=vendor, product="FortiOS",
            release_train="7.2",
            recommended_version=catalog_recommended,
            eol_versions=catalog_eol or [],
            support_status=catalog_support_status,
        )
        db.add(entry)

    db.commit()
    return policy.id


# ── version_outdated ─────────────────────────────────────────────────────────

def test_version_outdated_finding_stored_in_db(db):
    """7.2.5 behind recommended 7.2.10 → version_outdated stored in findings."""
    pid = _seed(db, os_version="7.2.5", catalog_recommended="7.2.10")
    run_analysis(pid, db)

    types = {f.finding_type for f in db.query(Finding).filter(Finding.policy_id == pid).all()}
    assert "version_outdated" in types


def test_version_outdated_is_medium_severity(db):
    pid = _seed(db, os_version="7.2.5", catalog_recommended="7.2.10")
    run_analysis(pid, db)

    f = db.query(Finding).filter(
        Finding.policy_id == pid,
        Finding.finding_type == "version_outdated",
    ).first()
    assert f is not None
    assert f.severity == "Medium"


# ── version_end_of_support ───────────────────────────────────────────────────

def test_eol_version_produces_end_of_support_finding(db):
    """An explicit EOL version entry → version_end_of_support (High)."""
    pid = _seed(
        db, os_version="7.0.2",
        catalog_recommended="7.0.16",
        catalog_eol=["7.0.0", "7.0.1", "7.0.2"],
        catalog_support_status="end-of-support",
    )
    # adjust catalog entry to match 7.0 train
    cat = db.query(VersionCatalogEntry).first()
    cat.release_train = "7.0"
    db.commit()

    run_analysis(pid, db)

    f = db.query(Finding).filter(
        Finding.policy_id == pid,
        Finding.finding_type == "version_end_of_support",
    ).first()
    assert f is not None
    assert f.severity == "High"


# ── no catalog entry ─────────────────────────────────────────────────────────

def test_no_catalog_entry_produces_informational_finding(db):
    """No catalog data → version_catalog_unavailable (Informational, not a false High/Medium)."""
    pid = _seed(db, os_version="7.2.5", catalog_recommended=None)
    run_analysis(pid, db)

    types = {f.finding_type for f in db.query(Finding).filter(Finding.policy_id == pid).all()}
    assert "version_catalog_unavailable" in types
    # Must not claim outdated/EOL without catalog evidence
    assert "version_outdated" not in types
    assert "version_end_of_support" not in types

    f = db.query(Finding).filter(
        Finding.policy_id == pid,
        Finding.finding_type == "version_catalog_unavailable",
    ).first()
    assert f.severity == "Informational"


# ── HA mismatch ──────────────────────────────────────────────────────────────

def test_ha_version_mismatch_finding_stored(db):
    """HA peer on a different version → version_ha_mismatch (Medium)."""
    pid = _seed(db, os_version="7.2.5", ha_peer="7.2.3", catalog_recommended="7.2.10")
    run_analysis(pid, db)

    f = db.query(Finding).filter(
        Finding.policy_id == pid,
        Finding.finding_type == "version_ha_mismatch",
    ).first()
    assert f is not None
    assert f.severity == "Medium"


def test_ha_peer_ip_address_does_not_trigger_mismatch(db):
    """ha_peer normally stores the peer's IP/hostname — must not be treated as
    a version and compared against os_version."""
    pid = _seed(db, os_version="7.2.5", ha_peer="192.168.1.2", catalog_recommended="7.2.5")
    run_analysis(pid, db)

    types = {f.finding_type for f in db.query(Finding).filter(Finding.policy_id == pid).all()}
    assert "version_ha_mismatch" not in types


# ── no device_id ─────────────────────────────────────────────────────────────

def test_no_device_produces_no_version_findings(db):
    """A file-upload policy (no device_id) must not generate version findings."""
    cust = Customer(id="c2", name="Corp 2")
    db.add(cust)
    policy = FirewallPolicy(
        id="pol2", customer_id="c2", device_id=None,
        firewall_name="HQ", vendor="FortiGate", analysis_status="pending",
    )
    db.add(policy)
    rule = FirewallRule(
        id="r2", policy_id="pol2", vendor="FortiGate", rule_number=1,
        sources=["any"], destinations=["any"], services=["any"], action="accept",
    )
    db.add(rule)
    db.commit()

    run_analysis("pol2", db)

    version_types = {"version_outdated", "version_end_of_support",
                     "version_catalog_unavailable", "version_ha_mismatch", "version_unknown"}
    found_types = {f.finding_type for f in db.query(Finding).filter(Finding.policy_id == "pol2").all()}
    assert version_types.isdisjoint(found_types), \
        f"Unexpected version findings on file-upload policy: {found_types & version_types}"
