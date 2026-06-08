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

    # API_KEY: bearer token that the frontend must send in X-API-Key header.
    # Generate once and store in .env:
    #   python -c "import secrets; print(secrets.token_urlsafe(32))"
    # Leave empty ("") to disable auth enforcement (dev mode only).
    api_key: str = ""

    # CORS allowed origins — comma-separated list.
    # Default: localhost only. In production set to your actual frontend URL.
    allowed_origins: str = "http://localhost:3000,http://127.0.0.1:3000"

    # Analysis thresholds (days)
    inactivity_threshold_low: int = 90
    inactivity_threshold_medium: int = 180
    inactivity_threshold_high: int = 365

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
    severity_high_threshold: int = 75
    severity_medium_threshold: int = 50
    severity_low_threshold: int = 25

    # Temporary rule keywords
    temp_keywords: List[str] = [
        "temp", "temporary", "test", "testing", "migration",
        "change", "old", "legacy", "backup", "delete", "remove",
        "cleanup", "tmp", "bak"
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
