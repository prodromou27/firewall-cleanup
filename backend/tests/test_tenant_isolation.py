import io

import pytest
from fastapi import BackgroundTasks, HTTPException, UploadFile
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.models  # noqa: F401 - register all SQLAlchemy models before create_all
from app.api import devices, findings, objects, policies, reporting_v2, revisions, upload
from app.database import Base
from app.models.customer import Customer
from app.models.device import FirewallDevice
from app.models.finding import Finding
from app.models.policy import FirewallObject, FirewallPolicy, FirewallRule
from app.models.report import GeneratedReport, ReportTemplate
from app.models.revision import PolicyRevision
from app.models.user import ROLE_ENGINEER, User, UserCustomerAccess


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(engine)


@pytest.fixture()
def tenant_data(db):
    c1 = Customer(id="cust-1", name="Customer One")
    c2 = Customer(id="cust-2", name="Customer Two")
    user = User(
        id="user-1",
        email="engineer@example.com",
        password_hash="hash",
        role=ROLE_ENGINEER,
        is_active=True,
    )
    db.add_all([c1, c2, user, UserCustomerAccess(user_id=user.id, customer_id=c1.id)])

    p1 = FirewallPolicy(id="policy-1", customer_id=c1.id, firewall_name="FW One", vendor="FortiGate")
    p2 = FirewallPolicy(id="policy-2", customer_id=c2.id, firewall_name="FW Two", vendor="FortiGate")
    r1 = FirewallRule(id="rule-1", policy_id=p1.id, vendor="FortiGate", rule_number=1, action="accept")
    r2 = FirewallRule(id="rule-2", policy_id=p2.id, vendor="FortiGate", rule_number=1, action="accept")
    o1 = FirewallObject(id="object-1", policy_id=p1.id, vendor="FortiGate", object_name="host1", object_type="host")
    o2 = FirewallObject(id="object-2", policy_id=p2.id, vendor="FortiGate", object_name="host2", object_type="host")
    f1 = Finding(
        id="finding-1",
        policy_id=p1.id,
        vendor="FortiGate",
        finding_type="unused_object",
        severity="Low",
        confidence="High",
        title="Own finding",
        description="Own tenant",
    )
    f2 = Finding(
        id="finding-2",
        policy_id=p2.id,
        vendor="FortiGate",
        finding_type="unused_object",
        severity="Low",
        confidence="High",
        title="Other finding",
        description="Other tenant",
    )
    d1 = FirewallDevice(id="device-1", customer_id=c1.id, name="Device One", vendor="FortiGate", host="10.0.0.1")
    d2 = FirewallDevice(id="device-2", customer_id=c2.id, name="Device Two", vendor="FortiGate", host="10.0.0.2")
    gr1 = GeneratedReport(
        id="report-1",
        customer_id=c1.id,
        policy_id=p1.id,
        export_format="pdf",
        file_name="one.pdf",
        file_path="missing.pdf",
    )
    gr2 = GeneratedReport(
        id="report-2",
        customer_id=c2.id,
        policy_id=p2.id,
        export_format="pdf",
        file_name="two.pdf",
        file_path="missing.pdf",
    )
    legacy_gr2 = GeneratedReport(
        id="report-legacy-2",
        customer_id=None,
        policy_id=p2.id,
        export_format="pdf",
        file_name="legacy-two.pdf",
        file_path="missing.pdf",
    )
    t1 = ReportTemplate(id="template-1", name="Tenant Template", customer_id=c1.id, audience="customer")
    t2 = ReportTemplate(id="template-2", name="Other Template", customer_id=c2.id, audience="customer", is_default=True)
    global_template = ReportTemplate(id="template-global", name="Global Template", customer_id=None, audience="customer")
    rev1 = PolicyRevision(id="revision-1", policy_id=p1.id, device_id=d1.id, revision_number=1)
    rev2 = PolicyRevision(id="revision-2", policy_id=p2.id, device_id=d2.id, revision_number=1)

    db.add_all([p1, p2, r1, r2, o1, o2, f1, f2, d1, d2, gr1, gr2, legacy_gr2, t1, t2, global_template, rev1, rev2])
    db.commit()
    return user


def assert_forbidden(callable_, *args, **kwargs):
    with pytest.raises(HTTPException) as exc:
        callable_(*args, **kwargs)
    assert exc.value.status_code == 403


def test_direct_id_tampering_is_denied_across_tenants(db, tenant_data):
    user = tenant_data

    assert_forbidden(policies.get_policy, "policy-2", db=db, user=user)
    assert_forbidden(
        policies.get_rules,
        "policy-2",
        page=1,
        page_size=50,
        search=None,
        action=None,
        enabled=None,
        zero_hits=None,
        has_findings=None,
        has_any=None,
        min_risk=None,
        sort_by=None,
        sort_dir=None,
        export=None,
        db=db,
        user=user,
    )
    assert_forbidden(findings.get_finding, "finding-2", db=db, user=user)
    assert_forbidden(objects.get_object, "object-2", db=db, user=user)
    assert_forbidden(devices.get_device, "device-2", db=db, user=user)
    assert_forbidden(reporting_v2.get_report, "report-2", db=db, user=user)
    assert_forbidden(reporting_v2.download_report, "report-2", db=db, user=user)
    assert_forbidden(reporting_v2.get_report, "report-legacy-2", db=db, user=user)
    assert_forbidden(reporting_v2.download_report, "report-legacy-2", db=db, user=user)
    assert_forbidden(reporting_v2.get_template, "template-2", db=db, user=user)
    assert_forbidden(revisions.get_revision, "revision-2", db=db, user=user)


def test_collection_endpoints_only_return_assigned_customer_data(db, tenant_data):
    user = tenant_data

    policy_ids = {
        p["id"]
        for p in policies.list_policies(page=1, page_size=100, sort_by=None, sort_dir=None, db=db, user=user)["policies"]
    }
    assert policy_ids == {"policy-1"}

    device_ids = {d["id"] for d in devices.list_devices(db=db, user=user)}
    assert device_ids == {"device-1"}

    finding_ids = {
        f["id"]
        for f in findings.list_findings(page=1, page_size=50, db=db, user=user)["findings"]
    }
    assert finding_ids == {"finding-1"}

    object_ids = {
        o["id"]
        for o in objects.list_objects(page=1, page_size=100, db=db, user=user)["objects"]
    }
    assert object_ids == {"object-1"}

    report_ids = {r["id"] for r in reporting_v2.list_reports(limit=100, db=db, user=user)["reports"]}
    assert report_ids == {"report-1"}

    template_ids = {t["id"] for t in reporting_v2.list_templates(db=db, user=user)["templates"]}
    assert template_ids == {"template-1", "template-global"}

    revision_ids = {r["id"] for r in revisions.list_revisions(limit=50, db=db, user=user)}
    assert revision_ids == {"revision-1"}


@pytest.mark.asyncio
async def test_upload_denies_unauthorized_customer_before_file_processing(db, tenant_data):
    file = UploadFile(file=io.BytesIO(b"malformed config"), filename="policy.conf")

    with pytest.raises(HTTPException) as exc:
        await upload.upload_policy(
            BackgroundTasks(),
            customer_id="cust-2",
            vendor="FortiGate",
            firewall_name="Other Firewall",
            policy_package=None,
            notes=None,
            file=file,
            db=db,
            user=tenant_data,
        )

    assert exc.value.status_code == 403


def test_tenant_users_cannot_mutate_global_report_templates(db, tenant_data):
    user = tenant_data
    body = reporting_v2.TemplateIn(name="Changed Global", customer_id=None)

    assert_forbidden(reporting_v2.update_template, "template-global", body, db=db, user=user)
    assert_forbidden(reporting_v2.delete_template, "template-global", db=db, user=user)
    assert_forbidden(reporting_v2.clone_template, "template-global", db=db, user=user)
    assert_forbidden(reporting_v2.set_default, "template-global", db=db, user=user)
    assert_forbidden(reporting_v2.create_template, body, db=db, user=user)


def test_template_default_changes_are_scoped_to_same_customer(db, tenant_data):
    user = tenant_data

    reporting_v2.set_default("template-1", db=db, user=user)

    own_template = db.query(ReportTemplate).filter(ReportTemplate.id == "template-1").one()
    other_template = db.query(ReportTemplate).filter(ReportTemplate.id == "template-2").one()
    assert own_template.is_default is True
    assert other_template.is_default is True


def test_template_customer_id_cannot_be_changed(db, tenant_data):
    body = reporting_v2.TemplateIn(name="Move Attempt", customer_id="cust-2")

    with pytest.raises(HTTPException) as exc:
        reporting_v2.update_template("template-1", body, db=db, user=tenant_data)

    assert exc.value.status_code == 400
