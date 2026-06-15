"""Role-based access control capability matrix.

Capabilities gate *application* actions only. None of these grant any ability
to push, modify, delete, disable, reorder, or install firewall policy — the
tool is read-only by design and no role can change that.

A capability is granted if it appears in the role's set. System admins have all
capabilities implicitly.
"""
from app.models.user import (
    ROLE_SYSTEM_ADMIN,
    ROLE_TENANT_ADMIN,
    ROLE_ENGINEER,
    ROLE_REVIEWER,
    ROLE_REPORT_VIEWER,
    ROLE_READ_ONLY,
)

# ── Capability names ──────────────────────────────────────────────────────────
CAP_VIEW = "view"                         # read customer-scoped data
CAP_UPLOAD = "upload"                     # upload a policy file
CAP_MANAGE_DEVICES = "manage_devices"     # create/edit device records
CAP_STORE_CREDENTIALS = "store_credentials"  # set device credentials
CAP_RUN_SYNC = "run_sync"                 # trigger a (read-only) device sync
CAP_GENERATE_REPORT = "generate_report"   # generate a new report
CAP_DOWNLOAD_REPORT = "download_report"   # download an existing report
CAP_COMMENT = "comment"                   # comment on findings
CAP_DELETE_DATA = "delete_data"           # delete customers/policies/findings records
CAP_MANAGE_SETTINGS = "manage_settings"   # change app settings
CAP_MANAGE_CUSTOMERS = "manage_customers" # create/edit/delete customer (tenant) records
CAP_MANAGE_USERS = "manage_users"         # create/edit users, roles, access
CAP_VIEW_GLOBAL = "view_global"           # global (all-tenant) dashboard
CAP_DOWNLOAD_BACKUP = "download_backup"   # download full DB / settings backup
CAP_VIEW_AUDIT = "view_audit"             # view the audit trail / activity log

_ROLE_CAPS = {
    ROLE_SYSTEM_ADMIN: {"*"},
    ROLE_TENANT_ADMIN: {
        CAP_VIEW, CAP_UPLOAD, CAP_MANAGE_DEVICES, CAP_STORE_CREDENTIALS,
        CAP_RUN_SYNC, CAP_GENERATE_REPORT, CAP_DOWNLOAD_REPORT, CAP_COMMENT,
        CAP_DELETE_DATA, CAP_MANAGE_SETTINGS, CAP_MANAGE_USERS, CAP_MANAGE_CUSTOMERS,
        CAP_VIEW_AUDIT,
    },
    ROLE_ENGINEER: {
        CAP_VIEW, CAP_UPLOAD, CAP_MANAGE_DEVICES, CAP_STORE_CREDENTIALS,
        CAP_RUN_SYNC, CAP_GENERATE_REPORT, CAP_DOWNLOAD_REPORT, CAP_COMMENT,
    },
    ROLE_REVIEWER: {
        CAP_VIEW, CAP_GENERATE_REPORT, CAP_DOWNLOAD_REPORT, CAP_COMMENT,
    },
    ROLE_REPORT_VIEWER: {
        CAP_VIEW, CAP_DOWNLOAD_REPORT,
    },
    ROLE_READ_ONLY: {
        CAP_VIEW,
    },
}


def has_capability(role: str, capability: str) -> bool:
    caps = _ROLE_CAPS.get(role, set())
    return "*" in caps or capability in caps
