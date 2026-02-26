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


class VulnToolsConfig(BaseModel):
    """Vulnerability-specific tool configuration."""
    ssrf: SSRFConfig = Field(default_factory=SSRFConfig)
    xss: XSSConfig = Field(default_factory=XSSConfig)
    arjun: ArjunConfig = Field(default_factory=ArjunConfig)


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

    target: TargetConfig
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    rate_limits: RateLimitsConfig = Field(default_factory=RateLimitsConfig)
    tools: ToolsConfig = Field(default_factory=ToolsConfig)
    vuln: VulnToolsConfig = Field(default_factory=VulnToolsConfig)
    ai: AIConfig = Field(default_factory=AIConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)

    # Injected from environment – not from YAML
    anthropic_api_key: str = ""
    openai_api_key: str = ""

    @model_validator(mode="after")
    def inject_api_keys(self) -> "AppConfig":
        if not self.anthropic_api_key:
            self.anthropic_api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not self.openai_api_key:
            self.openai_api_key = os.environ.get("OPENAI_API_KEY", "")
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

    config = AppConfig(**raw)

    # Inject API key from environment
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if api_key:
        config.anthropic_api_key = api_key

    return config
