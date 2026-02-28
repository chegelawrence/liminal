"""Configuration management using Pydantic Settings and YAML."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Optional

import yaml
from pydantic import BaseModel, Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class TargetConfig(BaseModel):
    domain: str
    program_name: str = "Unknown Program"
    platform: str = "HackerOne"
    in_scope: list[str] = Field(default_factory=list)
    out_of_scope: list[str] = Field(default_factory=list)


class NotificationsConfig(BaseModel):
    slack_webhook: str = ""
    discord_webhook: str = ""
    webhook_url: str = ""
    email_to: str = ""
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    notify_on_start: bool = False
    notify_on_complete: bool = True
    notify_on_critical: bool = True


class ScopeConfig(BaseModel):
    in_scope: list[str] = Field(default_factory=list)
    out_of_scope: list[str] = Field(default_factory=list)
    ip_ranges: list[str] = Field(default_factory=list)


class RateLimitsConfig(BaseModel):
    requests_per_second: int = 10
    concurrent_requests: int = 5
    nuclei_rate: int = 50
    ffuf_rate: int = 100


class SubfinderConfig(BaseModel):
    enabled: bool = True
    timeout: int = 120
    silent: bool = True


class AmassConfig(BaseModel):
    enabled: bool = True
    timeout: int = 300
    mode: str = "passive"


class DnsxConfig(BaseModel):
    enabled: bool = True
    resolvers: list[str] = Field(default_factory=lambda: ["1.1.1.1", "8.8.8.8"])


class HttpxConfig(BaseModel):
    enabled: bool = True
    timeout: int = 10
    follow_redirects: bool = True
    tech_detect: bool = True


class NaabuConfig(BaseModel):
    enabled: bool = True
    # Explicit port list (used when non-empty; overrides top_ports).
    # Covers web services, databases, message brokers, Kubernetes/containers,
    # monitoring stacks, and standard services across on-prem/cloud/hybrid.
    ports: list[int] = Field(default_factory=lambda: [
        # ── Standard web ──────────────────────────────────────────────
        80, 443,
        # ── HTTP alternate ────────────────────────────────────────────
        8000, 8001, 8008, 8009, 8080, 8081, 8082, 8083, 8088, 8090,
        8091, 8095, 8096, 8099, 8100, 8180, 8888, 8889,
        # ── HTTPS alternate ───────────────────────────────────────────
        4443, 8443, 9443,
        # ── Dev / framework servers ───────────────────────────────────
        3000, 3001, 4000, 4001, 4200, 5000, 5001,
        7000, 7001, 7070, 7071,
        9000, 9001, 9080, 9099, 9100, 10000,
        # ── Kubernetes ────────────────────────────────────────────────
        6443,   # K8s API server (HTTPS)
        2379,   # etcd client
        2380,   # etcd peer
        10250,  # Kubelet API (HTTPS)
        10255,  # Kubelet read-only (HTTP, deprecated but still common)
        10256,  # kube-proxy health
        8001,   # kubectl proxy
        # ── Container / Docker ────────────────────────────────────────
        2375,   # Docker daemon (unauthenticated, HTTP)
        2376,   # Docker daemon (TLS)
        9323,   # Docker metrics
        4194,   # cAdvisor
        # ── Relational databases ──────────────────────────────────────
        3306,   # MySQL / MariaDB
        5432,   # PostgreSQL
        # ── Key-value / cache ─────────────────────────────────────────
        6379,   # Redis
        6380,   # Redis TLS
        11211,  # Memcached
        # ── Document / search databases ───────────────────────────────
        27017, 27018,  # MongoDB
        9200, 9300,    # Elasticsearch
        5984,          # CouchDB
        8123,          # ClickHouse HTTP interface
        # ── Graph / time-series databases ─────────────────────────────
        7474, 7687,  # Neo4j HTTP / Bolt
        8086,        # InfluxDB
        # ── Wide-column / coordination ────────────────────────────────
        9042,  # Cassandra CQL
        2181,  # ZooKeeper
        # ── Message brokers ───────────────────────────────────────────
        5672,  15672,  # RabbitMQ AMQP / management HTTP
        9092,          # Kafka
        61616, 8161,   # ActiveMQ STOMP / web console
        4222,  8222,   # NATS client / monitoring HTTP
        6650,          # Apache Pulsar
        # ── Monitoring / observability ────────────────────────────────
        9090,  9091,  9093, 9094,  # Prometheus / Alertmanager
        5601,                      # Kibana
        16686, 14268,              # Jaeger UI / collector
        9411,                      # Zipkin
        4317,  4318,               # OTLP gRPC / HTTP
        # ── HashiCorp stack ───────────────────────────────────────────
        8200, 8201,  # Vault HTTP / cluster TLS
        8300, 8500,  # Consul RPC / HTTP
        4646,        # Nomad HTTP
        # ── CI/CD ─────────────────────────────────────────────────────
        9418,  # Git daemon
        2222,  # Gitea / alternative SSH
        # ── Standard services ─────────────────────────────────────────
        21,    # FTP
        22,    # SSH
        23,    # Telnet
        25,    # SMTP
        53,    # DNS
        110,   # POP3
        143,   # IMAP
        389,   # LDAP
        445,   # SMB
        3389,  # RDP
        5900,  # VNC
        111,   # RPC / NFS portmapper
        2049,  # NFS
    ])
    # Fallback: used only when ports list is empty
    top_ports: int = 1000
    timeout: int = 300


class NucleiConfig(BaseModel):
    enabled: bool = True
    severity: list[str] = Field(default_factory=lambda: ["critical", "high", "medium"])
    tags: list[str] = Field(default_factory=list)
    exclude_tags: list[str] = Field(default_factory=lambda: ["dos", "fuzz"])
    rate_limit: int = 50
    timeout: int = 30


class FfufConfig(BaseModel):
    enabled: bool = True
    wordlist: str = "/usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt"
    extensions: list[str] = Field(
        default_factory=lambda: ["php", "asp", "aspx", "jsp", "json", "yaml", "conf"]
    )
    rate: int = 100
    timeout: int = 10


class GauConfig(BaseModel):
    enabled: bool = True
    providers: list[str] = Field(
        default_factory=lambda: ["wayback", "commoncrawl", "otx", "urlscan"]
    )


class KatanaConfig(BaseModel):
    enabled: bool = True
    depth: int = 3
    timeout: int = 300
    headless: bool = False


class ToolsConfig(BaseModel):
    subfinder: SubfinderConfig = Field(default_factory=SubfinderConfig)
    amass: AmassConfig = Field(default_factory=AmassConfig)
    dnsx: DnsxConfig = Field(default_factory=DnsxConfig)
    httpx: HttpxConfig = Field(default_factory=HttpxConfig)
    naabu: NaabuConfig = Field(default_factory=NaabuConfig)
    nuclei: NucleiConfig = Field(default_factory=NucleiConfig)
    ffuf: FfufConfig = Field(default_factory=FfufConfig)
    gau: GauConfig = Field(default_factory=GauConfig)
    katana: KatanaConfig = Field(default_factory=KatanaConfig)


class SSRFConfig(BaseModel):
    enabled: bool = True
    interactsh_server: str = "oast.pro"
    oob_wait_seconds: float = 15.0
    concurrent: int = 5
    timeout: float = 10.0
    verify_findings: bool = True
    # Top parameter names to probe (beyond the built-in list)
    extra_params: list[str] = Field(default_factory=list)


class XSSConfig(BaseModel):
    enabled: bool = True
    dalfox_enabled: bool = True
    reflection_scanner_enabled: bool = True
    verify_findings: bool = True
    concurrent: int = 5
    timeout: float = 10.0
    # Blind XSS callback URL (optional – e.g. from XSS Hunter)
    blind_xss_url: str = ""


class ArjunConfig(BaseModel):
    enabled: bool = True
    threads: int = 5
    timeout: int = 30


class OpenRedirectConfig(BaseModel):
    enabled: bool = True
    concurrent: int = 5
    timeout: float = 8.0
    verify_findings: bool = True


class CORSConfig(BaseModel):
    enabled: bool = True
    concurrent: int = 10
    timeout: float = 8.0
    # Test API paths for CORS - more likely to have sensitive data
    api_paths: list[str] = Field(default_factory=lambda: [
        "/", "/api/", "/api/v1/", "/graphql", "/user"
    ])


class TakeoverConfig(BaseModel):
    enabled: bool = True
    concurrent: int = 20
    timeout: float = 10.0


class HeaderInjectionConfig(BaseModel):
    enabled: bool = True
    concurrent: int = 5
    timeout: float = 10.0


class JSScannerConfig(BaseModel):
    enabled: bool = True
    max_js_files: int = 100
    timeout: float = 10.0


class ExposureConfig(BaseModel):
    enabled: bool = True
    concurrent: int = 20
    timeout: float = 8.0
    # Categories to test - comment out any to disable
    categories: list[str] = Field(default_factory=lambda: [
        "git", "env", "api_docs", "graphql",
        "spring_actuator", "debug", "backup", "admin"
    ])
    # Use the LLM to generate additional targeted paths based on tech stack
    # and JS-extracted routes (runs after JS scanning phase)
    ai_path_generation: bool = True


class AnomalyConfig(BaseModel):
    """Configuration for the adaptive anomaly-based vulnerability detector."""

    enabled: bool = True
    concurrent: int = 5
    timeout: float = 10.0
    score_threshold: int = 5
    max_hosts: int = 50          # cost control — cap hosts probed per scan
    min_severity: str = "medium" # never auto-create low/info novel findings
    replay_patterns: bool = True # proactively test confirmed patterns from DB


class VulnToolsConfig(BaseModel):
    """Vulnerability-specific tool configuration."""
    ssrf: SSRFConfig = Field(default_factory=SSRFConfig)
    xss: XSSConfig = Field(default_factory=XSSConfig)
    arjun: ArjunConfig = Field(default_factory=ArjunConfig)
    open_redirect: OpenRedirectConfig = Field(default_factory=OpenRedirectConfig)
    cors: CORSConfig = Field(default_factory=CORSConfig)
    takeover: TakeoverConfig = Field(default_factory=TakeoverConfig)
    header_injection: HeaderInjectionConfig = Field(default_factory=HeaderInjectionConfig)
    js_scanner: JSScannerConfig = Field(default_factory=JSScannerConfig)
    exposure: ExposureConfig = Field(default_factory=ExposureConfig)
    anomaly: AnomalyConfig = Field(default_factory=AnomalyConfig)
    post_ssrf: bool = True  # Enable POST body SSRF testing


class AIConfig(BaseModel):
    # Provider selection: "claude" or "openai"
    provider: str = "claude"
    # Claude settings
    claude_model: str = "claude-opus-4-6"
    # OpenAI settings
    openai_model: str = "gpt-4o"
    # Shared settings
    max_tokens: int = 8192
    temperature: float = 0

    @property
    def model(self) -> str:
        """Convenience: return the active model name."""
        if self.provider == "openai":
            return self.openai_model
        return self.claude_model


class OutputConfig(BaseModel):
    results_dir: str = "./results"
    formats: list[str] = Field(default_factory=lambda: ["html", "markdown", "json"])
    verbose: bool = False


class AppConfig(BaseModel):
    """Top-level application configuration."""

    target: TargetConfig = Field(default_factory=lambda: TargetConfig(domain=""))
    targets: list[TargetConfig] = Field(default_factory=list)
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    rate_limits: RateLimitsConfig = Field(default_factory=RateLimitsConfig)
    tools: ToolsConfig = Field(default_factory=ToolsConfig)
    vuln: VulnToolsConfig = Field(default_factory=VulnToolsConfig)
    ai: AIConfig = Field(default_factory=AIConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    notifications: NotificationsConfig = Field(default_factory=NotificationsConfig)

    # Injected from environment – not from YAML
    anthropic_api_key: str = ""
    openai_api_key: str = ""
    db_dsn: str = ""

    @model_validator(mode="after")
    def inject_api_keys(self) -> "AppConfig":
        if not self.anthropic_api_key:
            self.anthropic_api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not self.openai_api_key:
            self.openai_api_key = os.environ.get("OPENAI_API_KEY", "")
        if not self.db_dsn:
            self.db_dsn = os.environ.get("DATABASE_URL", "")
        # Inject notification credentials from environment if not set in YAML
        if not self.notifications.slack_webhook:
            self.notifications.slack_webhook = os.environ.get("SLACK_WEBHOOK_URL", "")
        if not self.notifications.discord_webhook:
            self.notifications.discord_webhook = os.environ.get("DISCORD_WEBHOOK_URL", "")
        if not self.notifications.smtp_password:
            self.notifications.smtp_password = os.environ.get("SMTP_PASSWORD", "")
        return self


def load_config(path: str, domain_override: Optional[str] = None) -> AppConfig:
    """Load configuration from a YAML file, merging with environment variables.

    Args:
        path: Path to the YAML configuration file.
        domain_override: Optional domain to override the target domain in config.

    Returns:
        Populated AppConfig instance.

    Raises:
        FileNotFoundError: If the config file does not exist.
        ValueError: If the YAML is malformed or required fields are missing.
    """
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {path}")

    with config_path.open("r") as f:
        raw: dict[str, Any] = yaml.safe_load(f) or {}

    # Apply domain override before validation
    if domain_override:
        raw.setdefault("target", {})
        raw["target"]["domain"] = domain_override

    # Ensure target has at least a placeholder domain when only targets list is given
    if "target" not in raw and "targets" in raw and raw["targets"]:
        raw["target"] = {"domain": raw["targets"][0]["domain"]}

    config = AppConfig(**raw)

    # Inject API key from environment
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if api_key:
        config.anthropic_api_key = api_key

    return config
