import io
import hashlib

import pytest
from fastapi import BackgroundTasks, HTTPException, UploadFile
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.models  # noqa: F401
from app.api import findings, policies, upload
from app.database import Base
from app.models.customer import Customer
from app.models.finding import Finding
from app.models.policy import FirewallPolicy, FirewallRule
from app.models.user import ROLE_ENGINEER, User, UserCustomerAccess


@pytest.fixture()
def db(tmp_path, monkeypatch):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()
    monkeypatch.setattr(upload.settings, "upload_dir", str(tmp_path))
    monkeypatch.setattr(upload, "audit_log", lambda *args, **kwargs: None)
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(engine)


@pytest.fixture()
def user_and_customer(db):
    customer = Customer(id="cust-1", name="ACME")
    user = User(
        id="user-1",
        email="engineer@example.com",
        password_hash="hash",
        role=ROLE_ENGINEER,
        is_active=True,
    )
    db.add_all([customer, user, UserCustomerAccess(user_id=user.id, customer_id=customer.id)])
    db.commit()
    return user, customer


def _file(content: bytes, filename: str) -> UploadFile:
    return UploadFile(file=io.BytesIO(content), filename=filename)


@pytest.mark.asyncio
async def test_upload_rejects_vendor_specific_unsupported_file_type(db, user_and_customer):
    user, customer = user_and_customer

    with pytest.raises(HTTPException) as exc:
        await upload.upload_policy(
            BackgroundTasks(),
            customer_id=customer.id,
            vendor="PaloAlto",
            firewall_name="PA-EDGE",
            file=_file(b"<config/>", "policy.txt"),
            db=db,
            user=user,
        )

    assert exc.value.status_code == 400
    assert "not valid for PaloAlto" in exc.value.detail
    assert ".xml" in exc.value.detail


@pytest.mark.asyncio
@pytest.mark.parametrize("filename", ["policy.json", "policy.conf"])
async def test_palo_alto_upload_only_accepts_supported_xml_format(db, user_and_customer, filename):
    user, customer = user_and_customer
    with pytest.raises(HTTPException) as exc:
        await upload.upload_policy(
            BackgroundTasks(), customer_id=customer.id, vendor="PaloAlto",
            firewall_name="PA-EDGE", file=_file(b"{}", filename), db=db, user=user,
        )
    assert exc.value.status_code == 400


@pytest.mark.asyncio
async def test_upload_parse_exception_returns_generic_message(db, user_and_customer, monkeypatch):
    user, customer = user_and_customer

    class BrokenParser:
        def parse(self, content):
            raise RuntimeError("password=SuperSecret parser internals leaked")

    monkeypatch.setattr(upload, "get_parser", lambda vendor: BrokenParser())

    with pytest.raises(HTTPException) as exc:
        await upload.upload_policy(
            BackgroundTasks(),
            customer_id=customer.id,
            vendor="FortiGate",
            firewall_name="FGT-EDGE",
            file=_file(b"config firewall policy\nend\n", "policy.conf"),
            db=db,
            user=user,
        )

    assert exc.value.status_code == 422
    assert "SuperSecret" not in exc.value.detail
    assert "Verify the selected vendor" in exc.value.detail


@pytest.mark.asyncio
async def test_successful_upload_reports_missing_objects_and_hit_counts(db, user_and_customer):
    user, customer = user_and_customer
    conf = b"""
config firewall policy
    edit 1
        set name "allow-all-without-hit-data"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set action accept
    next
end
"""

    result = await upload.upload_policy(
        BackgroundTasks(),
        customer_id=customer.id,
        vendor="FortiGate",
        firewall_name="FGT-EDGE",
        policy_package=None,
        notes=None,
        file=_file(conf, "policy.conf"),
        db=db,
        user=user,
    )

    assert result["rules_parsed"] == 1
    assert result["objects_parsed"] == 0
    quality = result["import_quality"]
    assert quality["rule_count"] == 1
    assert quality["object_count"] == 0
    assert quality["incomplete_import"] is True
    assert quality["has_hit_counts"] is False
    assert any("No objects/groups imported" in gap for gap in quality["data_gaps"])
    assert any("No hit count data" in gap for gap in quality["data_gaps"])
    policy = db.query(FirewallPolicy).filter(FirewallPolicy.id == result["policy_id"]).one()
    assert policy.source_sha256 == hashlib.sha256(conf).hexdigest()
    assert policy.parse_warnings == []
    rule = db.query(FirewallRule).filter(FirewallRule.policy_id == policy.id).one()
    assert rule.raw_data["source_ref"] == {
        "sha256": policy.source_sha256, "collection": "rules", "record_index": 0,
    }


@pytest.mark.asyncio
async def test_upload_rejects_invalid_utf8_instead_of_replacing_policy_bytes(db, user_and_customer):
    user, customer = user_and_customer
    with pytest.raises(HTTPException) as exc:
        await upload.upload_policy(
            BackgroundTasks(), customer_id=customer.id, vendor="FortiGate",
            firewall_name="FGT-EDGE", file=_file(b"config firewall policy\n\xff\nend", "bad.conf"),
            db=db, user=user,
        )
    assert exc.value.status_code == 422
    assert db.query(FirewallPolicy).count() == 0


@pytest.mark.asyncio
async def test_upload_persists_parser_warnings_for_later_review(db, user_and_customer):
    user, customer = user_and_customer
    conf = b'config firewall address\nedit "Host"\nset subnet 10.0.0.1 255.255.255.255\nnext\nend\n'
    result = await upload.upload_policy(
        BackgroundTasks(), customer_id=customer.id, vendor="FortiGate",
        firewall_name="FGT-EDGE", policy_package=None, notes=None,
        file=_file(conf, "objects.conf"), db=db, user=user,
    )
    policy = db.query(FirewallPolicy).filter(FirewallPolicy.id == result["policy_id"]).one()
    assert policy.parse_warnings == result["warnings"]
    assert any("No 'config firewall policy'" in warning for warning in policy.parse_warnings)
    obj = policy.objects[0]
    assert obj.raw_data["source_ref"]["sha256"] == policy.source_sha256
    assert obj.raw_data["source_ref"]["record_index"] == 0


@pytest.mark.asyncio
async def test_uploaded_policy_cannot_assert_verified_counter_history(db, user_and_customer, monkeypatch):
    user, customer = user_and_customer

    class Parser:
        def parse(self, content):
            return ([{
                "rule_id": "1", "rule_number": 1, "sources": ["any"],
                "destinations": ["any"], "services": ["any"], "action": "accept",
                "hit_count": 0,
                "raw_data": {"usage_observation": {
                    "start": "2025-01-01", "end": "2026-01-01", "complete": True,
                    "counter_reset": False, "source": "verified-device-counter-history",
                }},
            }], [], [])

    monkeypatch.setattr(upload, "get_parser", lambda vendor: Parser())
    result = await upload.upload_policy(
        BackgroundTasks(), customer_id=customer.id, vendor="FortiGate",
        firewall_name="FGT-EDGE", policy_package=None, notes=None,
        file=_file(b"untrusted policy", "policy.conf"), db=db, user=user,
    )
    rule = db.query(FirewallRule).filter(FirewallRule.policy_id == result["policy_id"]).one()
    assert "usage_observation" not in rule.raw_data
    assert any("Untrusted usage-observation" in warning for warning in result["warnings"])


def _add_policy(db, customer_id: str, idx: int, vendor="FortiGate", status="completed") -> FirewallPolicy:
    policy = FirewallPolicy(
        id=f"policy-{idx}",
        customer_id=customer_id,
        firewall_name=f"{vendor}-FW-{idx:02d}",
        vendor=vendor,
        policy_package="Production" if idx % 2 else "Branch",
        rule_count=idx,
        finding_count=idx % 3,
        high_finding_count=idx % 2,
        analysis_status=status,
    )
    db.add(policy)
    return policy


def test_policy_api_filtering_sorting_and_pagination(db, user_and_customer):
    user, customer = user_and_customer
    for i in range(1, 8):
        _add_policy(db, customer.id, i, vendor="FortiGate" if i <= 4 else "PaloAlto")
    db.commit()

    page = policies.list_policies(
        customer_id=customer.id,
        vendor="FortiGate",
        search="FW",
        sort_by="rule_count",
        sort_dir="desc",
        page=2,
        page_size=2,
        db=db,
        user=user,
    )

    assert page["total"] == 4
    assert page["page"] == 2
    assert page["page_size"] == 2
    assert [p["rule_count"] for p in page["policies"]] == [2, 1]


def test_raw_zero_counter_is_excluded_from_risk_and_usage_score(db, user_and_customer):
    user, customer = user_and_customer
    policy = _add_policy(db, customer.id, 1)
    db.flush()
    db.add(FirewallRule(
        id="zero-rule", policy_id=policy.id, vendor="FortiGate", rule_number=1,
        sources=["10.0.0.1"], destinations=["10.0.0.2"], services=["https"],
        action="accept", enabled=True, logging_enabled=True, hit_count=0,
    ))
    db.commit()
    risk = policies.get_policy_risk_score(policy.id, db=db, user=user)
    assert risk["breakdown"]["zero_hit_rule_count"] == 0
    scorecard = policies.get_policy_scorecard(policy.id, db=db, user=user)
    usage = next(d for d in scorecard["dimensions"] if d["key"] == "usage")
    assert usage["score"] is None
    assert usage["weight"] == 0
    assert "Insufficient" in usage["detail"]


@pytest.mark.parametrize("graph", ["complete", "missing_member", "cycle", "no_rules"])
def test_scorecard_uses_nested_and_nat_object_references(db, user_and_customer, graph):
    from app.models.policy import FirewallObject, ObjectMember
    user, customer = user_and_customer
    policy = _add_policy(db, customer.id, 1)
    policy.nat_rules = [{"translated_src": "nat-host"}]
    db.flush()
    for name, kind, members in [
        ("outer", "group", ["inner"]),
        ("inner", "group", []),
        ("host", "host", []),
        ("nat-host", "host", []),
    ]:
        db.add(FirewallObject(id=name, policy_id=policy.id, vendor="FortiGate",
                              object_name=name, object_type=kind,
                              value="10.0.0.1" if kind == "host" else "", members=members))
    db.flush()
    member = "missing" if graph == "missing_member" else "outer" if graph == "cycle" else "host"
    db.add(ObjectMember(parent_id="inner", member_name=member,
                        member_id=member if graph != "missing_member" else None))
    if graph != "no_rules":
        db.add(FirewallRule(id="group-rule", policy_id=policy.id, vendor="FortiGate",
                            rule_number=1, sources=["outer"], destinations=["any"],
                            services=["any"], action="accept", enabled=True))
    db.commit()
    result = policies.get_policy_scorecard(policy.id, db=db, user=user)
    objects = next(d for d in result["dimensions"] if d["key"] == "objects")
    assert not any(i["metric"] == "unused_objects" for i in result["improvements"])
    if graph == "complete":
        assert objects["score"] == 100
        assert objects["weight"] == 15
        assert "0 unattached" in objects["detail"]
    else:
        assert objects["score"] is None
        assert objects["weight"] == 0


def test_scorecard_does_not_treat_keyword_substrings_as_temporary(db, user_and_customer):
    user, customer = user_and_customer
    policy = _add_policy(db, customer.id, 1)
    db.flush()
    db.add(FirewallRule(id="rule", policy_id=policy.id, vendor="FortiGate",
                        rule_number=1, rule_name="Latest production access",
                        comments="Production threshold monitoring", action="accept", enabled=True))
    db.commit()
    result = policies.get_policy_scorecard(policy.id, db=db, user=user)
    assert not any(i["metric"] == "temporary_rules" for i in result["improvements"])


@pytest.mark.parametrize("second_protocol, expected", [("tcp", 1), ("udp", 0)])
def test_scorecard_duplicate_services_respect_protocol(db, user_and_customer, second_protocol, expected):
    from app.models.policy import FirewallObject
    user, customer = user_and_customer
    policy = _add_policy(db, customer.id, 1)
    db.flush()
    for index, protocol in enumerate(["tcp", second_protocol]):
        db.add(FirewallObject(id=f"svc-{index}", policy_id=policy.id,
                              vendor="FortiGate", object_name=f"dns-{index}",
                              object_type="service", value="53", protocol=protocol,
                              port_start=53, port_end=53))
    db.commit()
    result = policies.get_policy_scorecard(policy.id, db=db, user=user)
    duplicates = [i for i in result["improvements"] if i["metric"] == "duplicate_objects"]
    assert sum(i["count"] for i in duplicates) == expected


def test_findings_api_filters_severity_status_search_and_paginates(db, user_and_customer):
    user, customer = user_and_customer
    policy = _add_policy(db, customer.id, 1)
    db.flush()
    rows = [
        Finding(id="f1", policy_id=policy.id, vendor="FortiGate", finding_type="overly_permissive", severity="Critical", confidence="High", status="Review Required", title="Internet any any", description="public exposure"),
        Finding(id="f2", policy_id=policy.id, vendor="FortiGate", finding_type="risky_service", severity="High", confidence="High", status="Review Required", title="SSH from branch", description="ssh exposure"),
        Finding(id="f3", policy_id=policy.id, vendor="FortiGate", finding_type="unused_object", severity="Low", confidence="Medium", status="Accepted Risk", title="Unused host", description="cleanup"),
    ]
    db.add_all(rows)
    db.commit()

    result = findings.list_findings(
        customer_id=customer.id,
        severity="High",
        status="Review Required",
        search="ssh",
        page=1,
        page_size=1,
        db=db,
        user=user,
    )

    assert result["total"] == 1
    assert result["severity_counts"] == {"High": 1}
    assert result["findings"][0]["id"] == "f2"


def test_findings_api_finding_type_accepts_comma_list(db, user_and_customer):
    """The 'Shadowed Rules' preset queries all shadow variants at once —
    shadowed_rule alone misses same-action shadows stored as redundant_rule."""
    user, customer = user_and_customer
    policy = _add_policy(db, customer.id, 1)
    db.flush()
    db.add_all([
        Finding(id="s1", policy_id=policy.id, vendor="FortiGate", finding_type="shadowed_rule", severity="High", confidence="High", status="Review Required", title="conflict shadow", description="d"),
        Finding(id="s2", policy_id=policy.id, vendor="FortiGate", finding_type="redundant_rule", severity="Medium", confidence="High", status="Review Required", title="redundant", description="d"),
        Finding(id="s3", policy_id=policy.id, vendor="FortiGate", finding_type="partial_shadowed_rule", severity="Low", confidence="Medium", status="Review Required", title="partial", description="d"),
        Finding(id="x1", policy_id=policy.id, vendor="FortiGate", finding_type="no_logging", severity="Low", confidence="High", status="Review Required", title="no log", description="d"),
    ])
    db.commit()

    grouped = findings.list_findings(
        customer_id=customer.id,
        finding_type="shadowed_rule,redundant_rule,partial_shadowed_rule",
        page=1, page_size=50, db=db, user=user,
    )
    assert grouped["total"] == 3
    assert {f["id"] for f in grouped["findings"]} == {"s1", "s2", "s3"}

    # Single value still behaves as exact match.
    single = findings.list_findings(
        customer_id=customer.id, finding_type="redundant_rule",
        page=1, page_size=50, db=db, user=user,
    )
    assert {f["id"] for f in single["findings"]} == {"s2"}
