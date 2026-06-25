import secrets
from pydantic_settings import BaseSettings
from typing import List, Optional


class Settings(BaseSettings):
    app_name: str = "Firewall Policy Cleanup Assistant"
    database_url: str = "sqlite:///./firewall_cleanup.db"
    upload_dir: str = "./uploads"
    max_upload_size_mb: int = 100

    # ── Security ─────────────────────────────────────────────────────────────
    # SECRET_KEY: used to derive the Fernet encryption key for credentials at
    # rest (passwords, API tokens). Generate once and store in .env:
    #   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    # WARNING: changing this key will invalidate ALL stored credentials.
    secret_key: str = ""

    # NOTE: The legacy global API_KEY has been removed. Authentication is now
    # per-user via server-side sessions (see app.security.identity). Any API_KEY
    # left in .env is simply ignored.

    # CORS allowed origins — comma-separated list.
    # Default: localhost only. In production set to your actual frontend URL.
    allowed_origins: str = "http://localhost:3000,http://127.0.0.1:3000"

    # Additional allowed origins by IP subnet (comma-separated CIDRs), e.g.
    # "192.168.201.0/24". Any http(s) origin whose host IP falls in one of these
    # ranges is accepted by CORS and CSRF, on any port. Use for LAN access.
    allowed_origin_subnets: str = ""

    # Deployment environment. When set to "production", interactive API docs
    # (/docs, /redoc, /openapi.json) are disabled unless enable_docs is True.
    environment: str = "development"
    enable_docs: bool = False

    # General per-client API rate limit (requests per minute, per source IP).
    # In-process token bucket — effective for single-process deployments; back
    # with a shared store (Redis) for multi-worker/multi-node. Set 0 to disable.
    rate_limit_per_minute: int = 300

    # ── User authentication (Phase 1) ─────────────────────────────────────────
    # Session lifetime in hours for the HttpOnly session cookie (absolute cap).
    session_ttl_hours: int = 12
    # Idle timeout: a session with no activity for this many minutes is revoked
    # even if the absolute TTL has not elapsed. Set 0 to disable idle expiry.
    session_idle_timeout_minutes: int = 60

    @property
    def docs_enabled(self) -> bool:
        """Docs are on in non-production environments, or when explicitly enabled."""
        return self.enable_docs or self.environment.strip().lower() != "production"

    @property
    def is_production(self) -> bool:
        return self.environment.strip().lower() == "production"

    def validate_security_posture(self) -> None:
        """Fail closed for production deployments with unsafe security settings."""
        if not self.is_production:
            return

        errors = []
        if not self.secret_key.strip():
            errors.append("SECRET_KEY must be set in production to encrypt stored firewall credentials.")
        if not self.cookie_secure:
            errors.append("COOKIE_SECURE must be true in production so session cookies are HTTPS-only.")

        origins = [o.strip().lower() for o in self.allowed_origins.split(",") if o.strip()]
        if not origins:
            errors.append("ALLOWED_ORIGINS must include the production HTTPS origin.")
        if any(o == "*" for o in origins):
            errors.append("ALLOWED_ORIGINS must not contain '*'.")
        if any("://localhost" in o or "://127." in o for o in origins):
            errors.append("ALLOWED_ORIGINS must not use localhost/127.0.0.1 in production.")

        if errors:
            raise RuntimeError("Insecure production configuration: " + " ".join(errors))

    # Set cookies with the Secure flag (HTTPS only). Leave False for local dev
    # over http://localhost; set True in production behind TLS.
    cookie_secure: bool = False
    # Lab/dev escape hatch. Production blocks device targets that resolve to
    # local machine/link-local/metadata style addresses unless this is true.
    allow_unsafe_device_hosts: bool = False
    # Bootstrap admin — if no users exist at startup and both are set, a
    # system_admin is created. Change the password immediately after first login.
    bootstrap_admin_email: str = ""
    bootstrap_admin_password: str = ""

    # Analysis thresholds (days)
    inactivity_threshold_low: int = 90
    inactivity_threshold_medium: int = 180
    inactivity_threshold_high: int = 365

    # Analysis controls. Disable detector families only when a customer's data
    # source cannot support them reliably, e.g. "usage,unused_objects".
    analysis_disabled_detectors: str = ""
    analysis_max_findings_per_type: int = 100

    # Internal networks (for risk scoring)
    internal_networks: List[str] = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    sensitive_networks: List[str] = []

    # Risk scoring weights
    risk_any_source: int = 20
    risk_any_destination: int = 20
    risk_any_service: int = 25
    risk_risky_service: int = 15
    risk_internet_source: int = 20
    risk_sensitive_dest: int = 15
    risk_no_logging: int = 5
    risk_no_hits_180d: int = 10
    risk_disabled: int = 5
    risk_duplicate: int = 20
    risk_fully_shadowed: int = 25
    risk_temp_keyword: int = 10

    # Severity thresholds
    severity_critical_threshold: int = 90
    severity_high_threshold: int = 75
    severity_medium_threshold: int = 50
    severity_low_threshold: int = 25

    # Temporary rule keywords
    temp_keywords: List[str] = [
        "temp", "temporary", "test", "testing", "migration",
        "change", "old", "legacy", "backup", "delete", "remove",
        "debug", "tmp", "bak"
    ]

    # Risky services
    risky_services: List[dict] = [
        {"name": "Any", "protocol": "any", "port_start": 0, "port_end": 65535},
        {"name": "RDP", "protocol": "tcp", "port_start": 3389, "port_end": 3389},
        {"name": "SSH", "protocol": "tcp", "port_start": 22, "port_end": 22},
        {"name": "Telnet", "protocol": "tcp", "port_start": 23, "port_end": 23},
        {"name": "FTP", "protocol": "tcp", "port_start": 21, "port_end": 21},
        {"name": "SMB", "protocol": "tcp", "port_start": 445, "port_end": 445},
        {"name": "NetBIOS", "protocol": "tcp", "port_start": 137, "port_end": 139},
        {"name": "WinRM", "protocol": "tcp", "port_start": 5985, "port_end": 5986},
        {"name": "MSSQL", "protocol": "tcp", "port_start": 1433, "port_end": 1433},
        {"name": "MySQL", "protocol": "tcp", "port_start": 3306, "port_end": 3306},
        {"name": "PostgreSQL", "protocol": "tcp", "port_start": 5432, "port_end": 5432},
        {"name": "Oracle", "protocol": "tcp", "port_start": 1521, "port_end": 1521},
        {"name": "VNC", "protocol": "tcp", "port_start": 5900, "port_end": 5900},
        {"name": "SNMP", "protocol": "udp", "port_start": 161, "port_end": 161},
        {"name": "LDAP", "protocol": "tcp", "port_start": 389, "port_end": 389},
        {"name": "RADIUS", "protocol": "udp", "port_start": 1812, "port_end": 1813},
    ]

    class Config:
        env_file = ".env"


settings = Settings()
