"""Service exposure checker for open ports.

For each open port that maps to a known service, sends a targeted HTTP(S)
probe and validates the response to detect unauthenticated access.

Also provides helpers to build HTTP target URLs from discovered open ports so
that all other scanners (exposure, XSS, SSRF, CORS, etc.) automatically cover
non-standard ports.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Callable, Optional

import httpx

from bugbounty.core.scope import ScopeValidator
from bugbounty.db.models import OpenPort

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Port → URL scheme mapping
# Ports here will have HTTP or HTTPS target URLs constructed and fed into
# every downstream scanner (exposure, CORS, XSS, SSRF, etc.)
# ---------------------------------------------------------------------------

# Ports that serve plain HTTP
HTTP_TARGET_PORTS: frozenset[int] = frozenset({
    80, 8080, 8000, 8001, 8008, 8009, 8081, 8082, 8083, 8088, 8090, 8091,
    8095, 8096, 8099, 8100, 8180, 8888, 8889,
    3000, 3001, 4000, 4001, 4200, 5000, 5001,
    7000, 7001, 7070, 7071,
    9000, 9001, 9080, 9090, 9091, 9093, 9094, 9099, 9100, 9200, 9300, 10000,
    8086,   # InfluxDB
    8123,   # ClickHouse
    8161,   # ActiveMQ console
    8200,   # Vault
    8300, 8500,  # Consul
    4646,   # Nomad
    5601,   # Kibana
    5984,   # CouchDB
    7474,   # Neo4j
    8222,   # NATS monitoring
    9411,   # Zipkin
    10255,  # Kubelet read-only
    15672,  # RabbitMQ management
    16686,  # Jaeger UI
    4317, 4318,  # OTLP
    4194,   # cAdvisor
    9323,   # Docker metrics
    61616,  # ActiveMQ
})

# Ports that serve HTTPS (TLS)
HTTPS_TARGET_PORTS: frozenset[int] = frozenset({
    443, 8443, 9443, 4443,
    6443,   # Kubernetes API
    2379, 2380,  # etcd
    8201,   # Vault cluster TLS
    10250,  # Kubelet API
    2376,   # Docker daemon TLS
})

# ---------------------------------------------------------------------------
# Service probe definitions
# ---------------------------------------------------------------------------

@dataclass
class ServiceProbe:
    service: str
    scheme: str          # "http" or "https"
    path: str
    validator: Callable[[int, str], bool]
    severity: str
    description: str


def _val_elasticsearch(status: int, body: str) -> bool:
    return status == 200 and "cluster_name" in body and "version" in body

def _val_kibana(status: int, body: str) -> bool:
    body_l = body.lower()
    return status == 200 and ("kibana" in body_l or "elasticsearch" in body_l)

def _val_prometheus(status: int, body: str) -> bool:
    return status == 200 and ("activeTargets" in body or "# HELP" in body or '"status":"success"' in body)

def _val_prometheus_metrics(status: int, body: str) -> bool:
    return status == 200 and "# HELP" in body

def _val_alertmanager(status: int, body: str) -> bool:
    return status == 200 and ("alertmanager" in body.lower() or '"status"' in body)

def _val_grafana(status: int, body: str) -> bool:
    return status == 200 and ("database" in body.lower() or "grafana" in body.lower())

def _val_rabbitmq(status: int, body: str) -> bool:
    return status == 200 and ("rabbitmq" in body.lower() or "cluster_name" in body or "message_stats" in body)

def _val_consul(status: int, body: str) -> bool:
    # /v1/catalog/services returns a JSON object of service names
    return status == 200 and body.strip().startswith("{") and "consul" in body.lower()

def _val_vault(status: int, body: str) -> bool:
    return status in (200, 429, 501, 503) and "initialized" in body

def _val_nomad(status: int, body: str) -> bool:
    # Unauthenticated /v1/jobs returns a JSON array (possibly empty [])
    return status == 200 and (body.strip().startswith("[") or body.strip() == "[]")

def _val_etcd(status: int, body: str) -> bool:
    return status == 200 and ("etcdserver" in body.lower() or '"health"' in body or "etcd" in body.lower())

def _val_kubelet(status: int, body: str) -> bool:
    return status == 200 and ('"items"' in body or "pods" in body.lower())

def _val_docker(status: int, body: str) -> bool:
    return status == 200 and ("DockerRootDir" in body or "ServerVersion" in body or "NCPU" in body)

def _val_docker_metrics(status: int, body: str) -> bool:
    return status == 200 and "# HELP" in body and "container" in body.lower()

def _val_cadvisor(status: int, body: str) -> bool:
    return status == 200 and ("machine" in body.lower() or "container" in body.lower() or "cAdvisor" in body)

def _val_influxdb(status: int, body: str) -> bool:
    return status == 200 and ("results" in body or "databases" in body or "series" in body)

def _val_couchdb(status: int, body: str) -> bool:
    # /_all_dbs returns a JSON array of database names
    return status == 200 and body.strip().startswith("[")

def _val_clickhouse(status: int, body: str) -> bool:
    return status == 200 and body.strip() in ("1", "1\n")

def _val_neo4j(status: int, body: str) -> bool:
    body_l = body.lower()
    return status == 200 and ("neo4j" in body_l or "browser" in body_l or "bolt" in body_l)

def _val_activemq(status: int, body: str) -> bool:
    body_l = body.lower()
    return status == 200 and ("activemq" in body_l or "apache" in body_l)

def _val_jaeger(status: int, body: str) -> bool:
    return status == 200 and ('"data"' in body or "jaeger" in body.lower())

def _val_zipkin(status: int, body: str) -> bool:
    return status == 200 and (body.strip().startswith("[") or "zipkin" in body.lower())

def _val_nats(status: int, body: str) -> bool:
    return status == 200 and ("server_id" in body or "connections" in body or "nats" in body.lower())

def _val_k8s_api(status: int, body: str) -> bool:
    # Unauthenticated request returns 200 /api or 401/403 — 200 with paths is the vuln
    return status == 200 and ("apiVersion" in body or '"paths"' in body)


# port → list[ServiceProbe]  (multiple probes possible per port)
SERVICE_PROBES: dict[int, list[ServiceProbe]] = {
    9200: [ServiceProbe(
        "Elasticsearch", "http", "/",
        _val_elasticsearch, "high",
        "Elasticsearch cluster is accessible without authentication. "
        "Attackers can read, modify, or delete all indexed data.",
    )],
    5601: [ServiceProbe(
        "Kibana", "http", "/api/status",
        _val_kibana, "high",
        "Kibana is accessible without authentication, exposing log data "
        "and potentially Elasticsearch cluster management.",
    )],
    9090: [ServiceProbe(
        "Prometheus", "http", "/api/v1/targets",
        _val_prometheus, "high",
        "Prometheus is accessible without authentication. Internal service "
        "topology, IPs, ports, and metric data are exposed.",
    )],
    9091: [ServiceProbe(
        "Prometheus (push gateway)", "http", "/metrics",
        _val_prometheus_metrics, "medium",
        "Prometheus Pushgateway metrics endpoint is publicly accessible.",
    )],
    9093: [ServiceProbe(
        "Alertmanager", "http", "/api/v2/status",
        _val_alertmanager, "medium",
        "Alertmanager API is accessible without authentication. "
        "Alert routing configuration and receiver details are exposed.",
    )],
    3000: [ServiceProbe(
        "Grafana", "http", "/api/health",
        _val_grafana, "high",
        "Grafana is accessible. Unauthenticated health endpoint may expose "
        "version, database status, and allow further enumeration.",
    )],
    15672: [ServiceProbe(
        "RabbitMQ Management", "http", "/api/overview",
        _val_rabbitmq, "high",
        "RabbitMQ management API is accessible without authentication. "
        "Queue configuration, connections, and message stats are exposed.",
    )],
    8500: [ServiceProbe(
        "Consul", "http", "/v1/catalog/services",
        _val_consul, "high",
        "Consul service catalog is accessible without authentication. "
        "Full service mesh topology and configuration are exposed.",
    )],
    8200: [ServiceProbe(
        "HashiCorp Vault", "http", "/v1/sys/health",
        _val_vault, "medium",
        "Vault health endpoint is accessible. Initialization and seal state "
        "is exposed; further unauthenticated paths may exist.",
    )],
    4646: [ServiceProbe(
        "HashiCorp Nomad", "http", "/v1/jobs",
        _val_nomad, "high",
        "Nomad job API is accessible without authentication (ACLs disabled). "
        "Job definitions, secrets, and task configurations are exposed.",
    )],
    2379: [ServiceProbe(
        "etcd", "http", "/health",
        _val_etcd, "critical",
        "etcd health endpoint is reachable. Unauthenticated etcd exposes all "
        "Kubernetes secrets, configs, and cluster state.",
    )],
    10255: [ServiceProbe(
        "Kubelet (read-only)", "http", "/pods",
        _val_kubelet, "high",
        "Kubelet read-only port is accessible. Running pod specs, environment "
        "variables, and mounted secret names are exposed.",
    )],
    10250: [ServiceProbe(
        "Kubelet API", "https", "/pods",
        _val_kubelet, "critical",
        "Kubelet API is accessible without authentication. Attackers can exec "
        "into containers, read secrets, and compromise the node.",
    )],
    2375: [ServiceProbe(
        "Docker Daemon (unauthenticated)", "http", "/info",
        _val_docker, "critical",
        "Docker daemon is exposed without TLS or authentication. "
        "Full container management including exec and privileged run is possible.",
    )],
    2376: [ServiceProbe(
        "Docker Daemon (TLS)", "https", "/info",
        _val_docker, "critical",
        "Docker daemon TLS port is responding. If client certificate "
        "authentication is not enforced, full daemon access may be possible.",
    )],
    9323: [ServiceProbe(
        "Docker metrics", "http", "/metrics",
        _val_docker_metrics, "medium",
        "Docker daemon Prometheus metrics are publicly accessible, exposing "
        "container counts, image names, and resource usage.",
    )],
    4194: [ServiceProbe(
        "cAdvisor", "http", "/api/v2.0/machine",
        _val_cadvisor, "medium",
        "cAdvisor is accessible without authentication, exposing container "
        "and host resource metrics.",
    )],
    8086: [ServiceProbe(
        "InfluxDB", "http", "/query?q=SHOW+DATABASES&db=_internal",
        _val_influxdb, "high",
        "InfluxDB query endpoint is accessible without authentication. "
        "All time-series databases and their data can be read or modified.",
    )],
    5984: [ServiceProbe(
        "CouchDB", "http", "/_all_dbs",
        _val_couchdb, "critical",
        "CouchDB is accessible without authentication. All database names are "
        "exposed; data may be fully readable and writable.",
    )],
    8123: [ServiceProbe(
        "ClickHouse", "http", "/?query=SELECT+1",
        _val_clickhouse, "high",
        "ClickHouse HTTP interface is accessible without authentication. "
        "All databases and tables may be queryable.",
    )],
    7474: [ServiceProbe(
        "Neo4j Browser", "http", "/browser/",
        _val_neo4j, "high",
        "Neo4j browser is accessible. Unauthenticated graph database access "
        "may allow full data read/write.",
    )],
    8161: [ServiceProbe(
        "ActiveMQ Web Console", "http", "/admin/",
        _val_activemq, "high",
        "ActiveMQ web console is accessible. Default credentials (admin/admin) "
        "may allow full broker management.",
    )],
    16686: [ServiceProbe(
        "Jaeger UI", "http", "/api/services",
        _val_jaeger, "medium",
        "Jaeger distributed tracing UI is accessible without authentication. "
        "Internal service names, trace data, and request patterns are exposed.",
    )],
    9411: [ServiceProbe(
        "Zipkin", "http", "/api/v2/services",
        _val_zipkin, "medium",
        "Zipkin tracing API is accessible without authentication. "
        "Internal service topology and trace data are exposed.",
    )],
    8222: [ServiceProbe(
        "NATS Monitoring", "http", "/varz",
        _val_nats, "medium",
        "NATS monitoring endpoint is accessible without authentication, "
        "exposing server stats, subscriptions, and connection details.",
    )],
    6443: [ServiceProbe(
        "Kubernetes API Server", "https", "/api/v1/namespaces",
        _val_k8s_api, "critical",
        "Kubernetes API server returned data without authentication. "
        "Full cluster access including secrets may be possible.",
    )],
}


# ---------------------------------------------------------------------------
# Finding dataclass
# ---------------------------------------------------------------------------

@dataclass
class ServiceFinding:
    host: str
    port: int
    service: str
    url: str
    severity: str
    description: str
    status_code: int
    content_preview: str
    confidence: str = "confirmed"

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "service": self.service,
            "url": self.url,
            "severity": self.severity,
            "description": self.description,
            "status_code": self.status_code,
            "content_preview": self.content_preview[:200],
            "confidence": self.confidence,
        }


# ---------------------------------------------------------------------------
# Main checker
# ---------------------------------------------------------------------------

class PortServiceChecker:
    """Probes open ports for unauthenticated service access.

    For each open port that maps to a known service in SERVICE_PROBES,
    sends a targeted HTTP(S) request and validates the response to confirm
    genuine exposure rather than a generic error page.
    """

    def __init__(
        self,
        scope_validator: ScopeValidator,
        concurrent: int = 20,
        timeout: float = 8.0,
    ) -> None:
        self.scope = scope_validator
        self.timeout = timeout
        self._semaphore = asyncio.Semaphore(concurrent)

    def build_http_targets(self, open_ports: list[OpenPort]) -> list[str]:
        """Return HTTP/HTTPS target URLs for all open ports that may serve HTTP.

        These URLs are injected into the scan pipeline so that every subsequent
        scanner (exposure, CORS, XSS, SSRF, etc.) covers non-standard ports.
        """
        urls: list[str] = []
        seen: set[str] = set()

        for p in open_ports:
            host = p.host
            port = p.port

            candidates: list[str] = []
            if port in HTTP_TARGET_PORTS:
                candidates.append(
                    f"http://{host}:{port}/" if port != 80 else f"http://{host}/"
                )
            if port in HTTPS_TARGET_PORTS:
                candidates.append(
                    f"https://{host}:{port}/" if port != 443 else f"https://{host}/"
                )

            for url in candidates:
                if url not in seen and self.scope.is_in_scope(url):
                    seen.add(url)
                    urls.append(url)

        return urls

    async def check_services(
        self, open_ports: list[OpenPort]
    ) -> list[ServiceFinding]:
        """Run targeted probes against all open ports with known service mappings.

        Args:
            open_ports: Open ports discovered during recon.

        Returns:
            List of confirmed service exposure findings.
        """
        tasks = []
        for p in open_ports:
            probes = SERVICE_PROBES.get(p.port, [])
            for probe in probes:
                tasks.append(asyncio.create_task(self._probe(p, probe)))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        findings: list[ServiceFinding] = []
        for r in results:
            if isinstance(r, Exception):
                logger.debug("Service probe exception: %s", r)
                continue
            if r is not None:
                findings.append(r)

        logger.info(
            "Port service checker: %d ports checked, %d findings",
            len(tasks), len(findings),
        )
        return findings

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _probe(
        self,
        port_record: OpenPort,
        probe: ServiceProbe,
    ) -> Optional[ServiceFinding]:
        async with self._semaphore:
            host = port_record.host
            port = port_record.port
            url = f"{probe.scheme}://{host}:{port}{probe.path}"

            if not self.scope.is_in_scope(f"{probe.scheme}://{host}/"):
                return None

            try:
                async with httpx.AsyncClient(
                    timeout=self.timeout,
                    follow_redirects=True,
                    verify=False,
                ) as client:
                    resp = await client.get(url)
                    status = resp.status_code
                    body = resp.text[:4096]
            except Exception as exc:
                logger.debug("Service probe failed %s: %s", url, exc)
                return None

            if not probe.validator(status, body):
                return None

            return ServiceFinding(
                host=host,
                port=port,
                service=probe.service,
                url=url,
                severity=probe.severity,
                description=probe.description,
                status_code=status,
                content_preview=body[:200],
            )
