"""Seed the database with a working demo environment.

Run from the backend/ directory:
    python seed_demo.py

Creates:
  - system_admin user  admin@policyinsight.local  / Demo#2024Secure
  - engineer user      engineer@policyinsight.local / Demo#2024Secure
  - Acme Corp customer
  - HQ FortiGate device (version 7.2.5 — intentionally behind catalog)
  - FortiGate policy with 12 rules covering key finding types
  - FortiGate and CheckPoint version catalog entries
  - Runs the analysis engine so findings appear immediately
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

import uuid
from datetime import datetime
from app.database import SessionLocal, engine, Base
from app.models.user import User, UserCustomerAccess, ROLE_SYSTEM_ADMIN, ROLE_ENGINEER
from app.models.customer import Customer
from app.models.device import FirewallDevice
from app.models.policy import FirewallPolicy, FirewallRule, FirewallObject
from app.models.version_catalog import VersionCatalogEntry
from app.security.passwords import hash_password
from app.analysis.engine import run_analysis


def _uuid():
    return str(uuid.uuid4())


def seed():
    db = SessionLocal()
    try:
        # ── Users ─────────────────────────────────────────────────────────────
        admin_email = "admin@policyinsight.local"
        eng_email   = "engineer@policyinsight.local"
        demo_pw     = "Demo#2024Secure"

        if not db.query(User).filter(User.email == admin_email).first():
            admin = User(
                id=_uuid(), email=admin_email, full_name="System Admin",
                password_hash=hash_password(demo_pw), role=ROLE_SYSTEM_ADMIN,
            )
            db.add(admin)
            print(f"  Created admin: {admin_email}")
        else:
            print(f"  Admin already exists: {admin_email}")

        if not db.query(User).filter(User.email == eng_email).first():
            engineer = User(
                id=_uuid(), email=eng_email, full_name="Demo Engineer",
                password_hash=hash_password(demo_pw), role=ROLE_ENGINEER,
            )
            db.add(engineer)
            print(f"  Created engineer: {eng_email}")
        else:
            print(f"  Engineer already exists: {eng_email}")

        db.commit()

        # ── Customer ──────────────────────────────────────────────────────────
        cust = db.query(Customer).filter(Customer.name == "Acme Corp").first()
        if not cust:
            cust = Customer(
                id=_uuid(), name="Acme Corp",
                description="Demo customer for PolicyInsight",
                contact_name="Jane Smith", contact_email="jsmith@acmecorp.example",
                industry="Financial Services", status="active",
            )
            db.add(cust)
            db.commit()
            print(f"  Created customer: Acme Corp ({cust.id})")
        else:
            print(f"  Customer already exists: Acme Corp")

        # Grant engineer access to the customer
        eng = db.query(User).filter(User.email == eng_email).first()
        if eng and not db.query(UserCustomerAccess).filter(
            UserCustomerAccess.user_id == eng.id,
            UserCustomerAccess.customer_id == cust.id
        ).first():
            db.add(UserCustomerAccess(id=_uuid(), user_id=eng.id, customer_id=cust.id))
            db.commit()

        # ── Version Catalog ───────────────────────────────────────────────────
        catalog_entries = [
            dict(vendor="FortiGate", product="FortiOS", release_train="7.4",
                 recommended_version="7.4.5", eol_versions=[], support_status="supported",
                 advisory_url="https://fortiguard.com/psirt"),
            dict(vendor="FortiGate", product="FortiOS", release_train="7.2",
                 recommended_version="7.2.10", eol_versions=[], support_status="supported",
                 advisory_url="https://fortiguard.com/psirt"),
            dict(vendor="FortiGate", product="FortiOS", release_train="7.0",
                 recommended_version="7.0.16", eol_versions=["7.0.0","7.0.1","7.0.2"],
                 support_status="end-of-support",
                 advisory_url="https://fortiguard.com/psirt"),
            dict(vendor="FortiGate", product="FortiOS", release_train="6.4",
                 recommended_version="6.4.15", eol_versions=["6.4.0","6.4.1"],
                 support_status="end-of-support",
                 advisory_url="https://fortiguard.com/psirt"),
            dict(vendor="CheckPoint", product="Gaia", release_train="R81",
                 recommended_version="R81.20", eol_versions=[],
                 support_status="supported",
                 advisory_url="https://support.checkpoint.com"),
            dict(vendor="CheckPoint", product="Gaia", release_train="R80",
                 recommended_version="R80.40", eol_versions=["R80","R80.10"],
                 support_status="end-of-support",
                 advisory_url="https://support.checkpoint.com"),
        ]
        for entry in catalog_entries:
            existing = db.query(VersionCatalogEntry).filter(
                VersionCatalogEntry.vendor == entry["vendor"],
                VersionCatalogEntry.release_train == entry["release_train"],
            ).first()
            if not existing:
                db.add(VersionCatalogEntry(id=_uuid(), **entry))
        db.commit()
        print(f"  Version catalog: {len(catalog_entries)} entries seeded")

        # ── Device ────────────────────────────────────────────────────────────
        device = db.query(FirewallDevice).filter(
            FirewallDevice.customer_id == cust.id,
            FirewallDevice.name == "HQ FortiGate"
        ).first()
        if not device:
            device = FirewallDevice(
                id=_uuid(), customer_id=cust.id,
                name="HQ FortiGate", vendor="FortiGate",
                host="192.168.1.1", port=443,
                fw_model="FortiGate-600F",
                os_version="7.2.5",   # behind 7.2.10 → version_outdated finding
                environment_type="production", location="HQ DataCenter",
                fw_role="perimeter", criticality="critical",
                ha_mode="active-passive", ha_peer="192.168.1.2",
                sync_status="ok",
            )
            db.add(device)
            db.commit()
            print(f"  Created device: HQ FortiGate ({device.id})")
        else:
            print(f"  Device already exists: HQ FortiGate")

        # ── Policy ────────────────────────────────────────────────────────────
        policy = db.query(FirewallPolicy).filter(
            FirewallPolicy.customer_id == cust.id,
            FirewallPolicy.firewall_name == "HQ-FortiGate-Policy"
        ).first()
        if policy:
            print(f"  Policy already exists: HQ-FortiGate-Policy — skipping rules/analysis")
            return

        policy = FirewallPolicy(
            id=_uuid(), customer_id=cust.id, device_id=device.id,
            firewall_name="HQ-FortiGate-Policy", vendor="FortiGate",
            policy_package="default", uploaded_by="seed_demo",
            original_filename="hq_forti_demo.conf",
            analysis_status="pending", rule_count=0, object_count=0,
        )
        db.add(policy)
        db.commit()
        print(f"  Created policy: HQ-FortiGate-Policy ({policy.id})")

        pid = policy.id

        # ── Objects ───────────────────────────────────────────────────────────
        def obj(name, otype, value=None, members=None, proto=None, port_s=None, port_e=None):
            return FirewallObject(
                id=_uuid(), policy_id=pid, vendor="FortiGate",
                object_name=name, object_type=otype,
                value=value, members=members or [],
                protocol=proto, port_start=port_s, port_end=port_e,
            )

        objects = [
            obj("NET-DMZ",       "network",  "10.10.10.0/24"),
            obj("NET-SERVERS",   "network",  "10.20.0.0/16"),
            obj("NET-MGMT",      "network",  "10.99.0.0/24"),
            obj("HOST-DC01",     "host",     "10.20.1.10"),
            obj("HOST-DB01",     "host",     "10.20.2.20"),
            obj("HOST-WEBPROXY", "host",     "10.10.10.5"),
            obj("GRP-SERVERS",   "group",    members=["HOST-DC01","HOST-DB01"]),
            obj("SVC-HTTPS",     "service",  proto="TCP", port_s=443, port_e=443),
            obj("SVC-RDP",       "service",  proto="TCP", port_s=3389, port_e=3389),
            obj("SVC-TELNET",    "service",  proto="TCP", port_s=23, port_e=23),
            obj("SVC-SSH",       "service",  proto="TCP", port_s=22, port_e=22),
            obj("SVC-MSSQL",     "service",  proto="TCP", port_s=1433, port_e=1433),
            obj("NET-ORPHAN",    "network",  "172.31.99.0/24"),  # unused object
        ]
        db.add_all(objects)
        db.commit()

        # ── Rules ─────────────────────────────────────────────────────────────
        def rule(num, name, src, dst, svc, action="accept", enabled=True, logging=True,
                 comments=None, hit=None):
            return FirewallRule(
                id=_uuid(), policy_id=pid, vendor="FortiGate",
                firewall_name="HQ-FortiGate-Policy", rule_number=num,
                rule_name=name, rule_id=str(num),
                sources=src if isinstance(src, list) else [src],
                destinations=dst if isinstance(dst, list) else [dst],
                services=svc if isinstance(svc, list) else [svc],
                action=action, enabled=enabled,
                logging_enabled=logging, comments=comments,
                hit_count=hit,
            )

        rules = [
            # 1. Any/Any/Allow — triggers any_to_any_allow (Critical)
            rule(1, "INTERNET-ANY",  ["any"], ["any"], ["any"],
                 comments="Legacy catch-all", hit=8721),

            # 2. RDP from any source — rdp_exposed (Critical)
            rule(2, "MGMT-RDP-IN",  ["any"], ["NET-MGMT"], ["SVC-RDP"],
                 hit=54),

            # 3. Telnet allowed — cleartext_service (Medium)
            rule(3, "LEGACY-TELNET", ["NET-DMZ"], ["NET-SERVERS"], ["SVC-TELNET"],
                 hit=12),

            # 4. SQL exposed to internet — database_exposed (High)
            rule(4, "DB-PUBLIC",    ["any"], ["HOST-DB01"], ["SVC-MSSQL"],
                 hit=3),

            # 5. Allow all server comms, no logging — no_logging + overly_permissive
            rule(5, "SRV-INTERNAL", ["NET-SERVERS"], ["any"], ["any"],
                 logging=False, hit=1204),

            # 6. Disabled rule — disabled_rule (Low)
            rule(6, "OLD-DMZ-ACCESS", ["NET-DMZ"], ["HOST-DC01"], ["SVC-HTTPS"],
                 enabled=False, hit=0),

            # 7. Zero-hit rule (never matched)
            rule(7, "BACKUP-RESTORE", ["NET-MGMT"], ["HOST-DB01"], ["SVC-MSSQL"],
                 hit=0),

            # 8. Duplicate of rule 4 — duplicate_rule
            rule(8, "DB-PUBLIC-DUP", ["any"], ["HOST-DB01"], ["SVC-MSSQL"],
                 hit=1),

            # 9. No documentation — no_documentation
            rule(9, "R9",            ["NET-DMZ"], ["HOST-WEBPROXY"], ["SVC-HTTPS"],
                 hit=412),

            # 10. Fully shadowed by rule 1 — redundant_rule (High confidence: zero hits)
            rule(10, "WEB-ALLOW",    ["NET-DMZ"], ["NET-SERVERS"], ["SVC-HTTPS"],
                 hit=0),

            # 11. Good rule — documented, specific, logged
            rule(11, "PROXY-EGRESS", ["HOST-WEBPROXY"], ["any"], ["SVC-HTTPS"],
                 comments="Proxy outbound HTTPS via web proxy HOST-WEBPROXY", hit=9823),

            # 12. Explicit deny/drop cleanup rule. Its 245 hits contradict the
            # shadowed_rule finding from rule 1, demonstrating the Low-confidence
            # hit-contradiction downgrade.
            rule(12, "DENY-ALL",     ["any"], ["any"], ["any"],
                 action="deny", logging=True, hit=245),
        ]
        db.add_all(rules)

        policy.rule_count = len(rules)
        policy.object_count = len(objects)
        db.commit()
        print(f"  Created {len(rules)} rules and {len(objects)} objects")

        # ── Analysis ──────────────────────────────────────────────────────────
        print("  Running analysis engine…")
        run_id = run_analysis(pid, db)
        print(f"  Analysis complete (run_id={run_id})")

        # Refresh to show final counts
        db.refresh(policy)
        print(f"  Findings generated: {policy.finding_count} "
              f"({policy.high_finding_count} High/Critical)")

    finally:
        db.close()


if __name__ == "__main__":
    print("Seeding demo data…")
    seed()
    print("\nDone!")
    print("  Login:  admin@policyinsight.local  /  Demo#2024Secure")
    print("  or:     engineer@policyinsight.local  /  Demo#2024Secure")
