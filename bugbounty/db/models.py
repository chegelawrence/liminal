"""Pydantic data models for the bug bounty database."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class ScanRun(BaseModel):
    """Represents a single end-to-end scan execution."""

    id: str  # UUID
    target_domain: str
    program_name: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    status: str  # running, completed, failed


class Subdomain(BaseModel):
    """A subdomain discovered during recon."""

    id: str
    scan_run_id: str
    subdomain: str
    source: str  # subfinder, amass, dnsx, etc.
    discovered_at: datetime


class LiveHost(BaseModel):
    """A subdomain confirmed to be a live HTTP/HTTPS host."""

    id: str
    scan_run_id: str
    url: str  # full URL with scheme
    subdomain: str
    status_code: int
    title: Optional[str] = None
    technologies: list[str] = Field(default_factory=list)
    content_length: Optional[int] = None
    server: Optional[str] = None
    probed_at: datetime


class OpenPort(BaseModel):
    """An open port discovered via port scanning."""

    id: str
    scan_run_id: str
    host: str
    port: int
    protocol: str
    service: Optional[str] = None
    discovered_at: datetime


class DiscoveredURL(BaseModel):
    """A URL discovered via crawling or archive sources."""

    id: str
    scan_run_id: str
    url: str
    source: str  # gau, katana, wayback
    status_code: Optional[int] = None
    discovered_at: datetime


class Finding(BaseModel):
    """A security vulnerability finding."""

    id: str
    scan_run_id: str
    template_id: str
    name: str
    severity: str  # critical, high, medium, low, info
    host: str
    matched_at: str
    description: str
    tags: list[str] = Field(default_factory=list)
    cvss_score: Optional[float] = None
    cve_id: Optional[str] = None
    raw_output: dict = Field(default_factory=dict)
    is_false_positive: bool = False
    ai_analysis: Optional[str] = None
    poc_steps: Optional[str] = None
    discovered_at: datetime

    # Report-ready fields populated by the reporter agent
    impact_statement: Optional[str] = None
    remediation: Optional[str] = None
    references: list[str] = Field(default_factory=list)
    report_title: Optional[str] = None
    formatted_description: Optional[str] = None


class AnomalyPattern(BaseModel):
    """A confirmed anomaly detection pattern saved for cross-scan learning."""

    id: str
    created_at: datetime
    tech_stack: list[str] = Field(default_factory=list)
    probe_type: str
    vulnerability_class: str
    severity: str
    confirmation_method: dict = Field(default_factory=dict)
    response_signature: str
    confirmed_count: int = 1
    fp_count: int = 0
    last_seen: datetime


class AnalysisResult(BaseModel):
    """Structured output from the AnalyzerAgent."""

    true_positives: list[Finding] = Field(default_factory=list)
    false_positives: list[Finding] = Field(default_factory=list)
    high_impact_chains: list[dict] = Field(default_factory=list)
    executive_summary: str = ""
    total_critical: int = 0
    total_high: int = 0
    total_medium: int = 0
    total_low: int = 0
    total_info: int = 0
