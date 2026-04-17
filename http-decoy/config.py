"""
CI/CDecoy — HTTP Decoy Configuration

Reads configuration from environment variables with sensible defaults
for development. All settings are exposed via a single dataclass.
"""

import os
import secrets
from dataclasses import dataclass, field


@dataclass
class HttpDecoyConfig:
    """Configuration for the HTTP decoy honeypot."""

    host: str = "0.0.0.0"
    port: int = 8080
    decoy_name: str = "http-decoy-01"
    decoy_tier: int = 2
    nats_url: str = "nats://nats:4222"
    nats_subject: str = "cicdecoy.decoy.events"
    hostname: str = "webapp-prod-01"
    server_header: str = "nginx/1.24.0"
    login_portals: list[str] = field(default_factory=lambda: ["corporate", "aws", "gitlab"])
    company_name: str = "Acme Corp"
    session_secret: str = ""

    def __post_init__(self):
        if not self.session_secret:
            self.session_secret = secrets.token_urlsafe(32)

    @classmethod
    def from_env(cls) -> "HttpDecoyConfig":
        """Build config from environment variables."""
        portals_raw = os.getenv("LOGIN_PORTALS", "corporate,aws,gitlab")
        portals = [p.strip() for p in portals_raw.split(",") if p.strip()]

        return cls(
            host=os.getenv("HTTP_HOST", "0.0.0.0"),
            port=int(os.getenv("HTTP_PORT", "8080")),
            decoy_name=os.getenv("DECOY_NAME", "http-decoy-01"),
            decoy_tier=2,
            nats_url=os.getenv("NATS_URL", "nats://nats:4222"),
            nats_subject=os.getenv("NATS_SUBJECT", "cicdecoy.decoy.events"),
            hostname=os.getenv("DECOY_HOSTNAME", "webapp-prod-01"),
            server_header=os.getenv("SERVER_HEADER", "nginx/1.24.0"),
            login_portals=portals,
            company_name=os.getenv("COMPANY_NAME", "Acme Corp"),
            session_secret=os.getenv("SESSION_SECRET", ""),
        )
