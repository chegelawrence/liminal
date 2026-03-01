# Liminal

> AI-powered vulnerability hunting framework for unauthenticated bug bounty targets.

Automates the full pipeline from subdomain discovery to confirmed vulnerability reporting, using Claude, OpenAI, Groq (free), or Ollama (local) as the reasoning engine. Purpose-built scanners cover ten hardcoded vulnerability classes; an adaptive anomaly-detection layer finds novel vulnerabilities outside that set and learns confirmed patterns across scans.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [How It Works](#how-it-works)
  - [Recon Phase](#recon-phase)
  - [Scan Pipeline (15 Phases)](#scan-pipeline-15-phases)
  - [Port Scanning](#port-scanning)
  - [Service Exposure Detection](#service-exposure-detection)
  - [SSRF Detection (GET + POST + Headers)](#ssrf-detection-get--post--headers)
  - [XSS Detection](#xss-detection)
  - [CORS Misconfiguration](#cors-misconfiguration)
  - [Subdomain Takeover](#subdomain-takeover)
  - [Open Redirect Detection](#open-redirect-detection)
  - [JavaScript Secret Scanning](#javascript-secret-scanning)
  - [Exposed Endpoint Detection](#exposed-endpoint-detection)
  - [AI Path Generation](#ai-path-generation)
  - [Adaptive Novel Vulnerability Detection](#adaptive-novel-vulnerability-detection)
  - [AI Analysis](#ai-analysis)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
  - [AI Provider](#ai-provider)
  - [Scope](#scope)
  - [Multi-Target Batch Scanning](#multi-target-batch-scanning)
  - [Notifications](#notifications)
  - [Port Scanning](#port-scanning-1)
  - [SSRF Settings](#ssrf-settings)
  - [XSS Settings](#xss-settings)
  - [CORS Settings](#cors-settings)
  - [Subdomain Takeover Settings](#subdomain-takeover-settings)
  - [Open Redirect Settings](#open-redirect-settings)
  - [JS Scanner Settings](#js-scanner-settings)
  - [Exposed Endpoint Settings](#exposed-endpoint-settings)
  - [Adaptive Anomaly Detection Settings](#adaptive-anomaly-detection-settings)
- [Usage](#usage)
  - [Full scan](#full-scan)
  - [Multi-target batch scan](#multi-target-batch-scan)
  - [Log to file (background-friendly)](#log-to-file-background-friendly)
  - [Autonomous background operation (systemd)](#autonomous-background-operation-systemd)
- [False Positive Minimisation](#false-positive-minimisation)
- [Output & Reports](#output--reports)
- [Project Structure](#project-structure)

---

## Overview

```
liminal scan --config my-target.yaml
```

```
  ____              ____                  _         _    ___
 | __ ) _   _  __ | __ )  ___  _   _ _ __ | |_ _   _| |  / _ \
 |  _ \| | | |/ _` |  _ \ / _ \| | | | '_ \| __| | | | | | | |
 | |_) | |_| | (_| | |_) | (_) | |_| | | | | |_| |_| | | |_| |
 |____/ \__,_|\__, |____/ \___/ \__,_|_| |_|\__|\__, |_|\___/
              |___/                              |___/

  AI-Powered Security Reconnaissance Framework v0.1.0

┌─ Scan Configuration ──────────────────────────────────┐
│ Target:     api.example.com                            │
│ Programme:  Example Bug Bounty                         │
│ Platform:   HackerOne                                  │
│ Scan ID:    3f2a1b9c-...                               │
│ Model:      claude-opus-4-6  (provider: claude)        │
│ Coverage:   SSRF·XSS·CORS·Takeover·Redirect·JS·Expose │
└────────────────────────────────────────────────────────┘

 Phase 1: Reconnaissance
 ⠸ Reconnaissance  [0:02:14]

 Recon complete: 47 subdomains, 31 live hosts, 284 ports, 1,832 URLs

──────────── Phase 2: Vulnerability Scanning (15 phases) ────────────

 [pre]  port-url-injection   ████████████ done  — 12 new targets from open ports
 [1/15] nuclei               ████████████ done
 [2/15] subdomain-takeover   ████████████ done  — 1 takeover candidate
 [3/15] exposed-endpoints    ████████████ done  — 3 exposures
 [4/15] service-checks       ████████████ done  — 2 unauthenticated services
 [5/15] cors-scan            ████████████ done  — 2 CORS issues
 [6/15] js-scanning          ████████████ done  — 4 secrets, 12 new URLs
 [7/15] ai-path-gen          ████████████ done  — 38 AI-generated paths
 [8/15] ai-exposure          ████████████ done  — 1 hidden endpoint
 [9/15] param-discovery      ████████████ done
 [10/15] ssrf-get            ████████████ done  — 2 SSRF confirmed
 [11/15] ssrf-post           ████████████ done  — 1 SSRF (JSON body)
 [12/15] header-ssrf         ████████████ done
 [13/15] open-redirect       ████████████ done  — 1 redirect (OAuth chain)
 [14/15] xss                 ████████████ done  — 3 XSS confirmed
 [15/15] anomaly-detection   ████████████ done  — 1 novel finding (debug-interface)

 Scan complete: 18 findings
   SSRF: 3 · XSS: 3 · CORS: 2 · Takeover: 1 · Redirect: 1
   Exposure: 3 · Service: 2 · AI-paths: 1 · Nuclei: 1 · Novel: 1

──────────── Phase 3: AI Analysis ────────────
 ⠼ AI Analyzer triaging 17 findings...
```

**What it finds (unauthenticated):**

| Vulnerability | Method | Confirmation |
|---|---|---|
| **SSRF (GET params)** | 40+ URL-like parameters | OOB DNS/HTTP callback |
| **SSRF (POST body)** | 36 JSON/form field names | OOB DNS/HTTP callback |
| **SSRF (HTTP headers)** | 14 headers (X-Forwarded-For, etc.) | OOB or reflection |
| **XSS (reflected)** | Context-aware payloads + dalfox | Unescaped in response |
| **CORS misconfiguration** | 5 bypass techniques | Credentials + origin |
| **Subdomain takeover** | CNAME chain + 20+ service fingerprints | Body fingerprint match |
| **Open redirect** | 52 redirect parameter names | Actual Location header |
| **JS secret scanning** | 16 patterns (API keys, tokens, URLs) | Regex match in .js files |
| **Exposed endpoints (static)** | 70+ paths across 8 categories | Content validation |
| **Exposed endpoints (AI-generated)** | LLM-reasoned paths from tech stack + JS context | HTTP 2xx/403 response |
| **Service exposure** | 22 services probed on open ports | Targeted response validators |
| **Novel/adaptive** | ~20 HTTP behavioural probes per host (method confusion, header injection, path/param variants) | Three-gate LLM confirmation; patterns saved and replayed on future scans |

**What makes it different:**
- OOB (out-of-band) DNS/HTTP callbacks for SSRF — only confirmed findings are reported
- **104 targeted ports** scanned across web, databases, K8s, containers, monitoring, and brokers
- **Open ports feed back into all scanners** — non-standard HTTP ports are automatically included in every subsequent scan phase
- **Service exposure checks** — unauthenticated Elasticsearch, Prometheus, Kubelet, Docker daemon, etcd, Consul, Vault, and more detected via targeted probes
- **AI path generation** — the LLM reasons about the target's tech stack and JS-extracted routes to generate custom paths beyond static lists
- **Adaptive anomaly detection** — finds vulnerabilities outside the hardcoded set; every finding requires HTTP-level behavioural confirmation before being created
- **Cross-scan learning** — confirmed probe patterns are saved to the database and automatically replayed against future targets with the same tech stack
- AI triage removes remaining false positives and detects vulnerability chains
- Reports include CWE IDs, CVSS 3.1 vectors, and ready-to-use `curl` PoC commands

---

## Architecture

```mermaid
flowchart TD
    CLI["CLI liminal scan"] --> ORCH

    subgraph ORCH["Orchestrator"]
        direction TB
        PL["Planner Agent (recon strategy)"]
        RP["Recon Pipeline"]
        SP["Scan Pipeline (15 phases)"]
        AN["Analyzer Agent (triage + FP removal)"]
        RR["Reporter Agent (CWE · CVSS · curl PoC)"]
        PL --> RP --> SP --> AN --> RR
    end

    subgraph RECON["Recon Pipeline"]
        direction LR
        SF["subfinder amass"] --> DNS["dnsx (resolve)"]
        DNS --> HX["httpx (probe)"]
        HX --> NB["naabu (104 ports)"]
        HX --> GA["gau + waybackurls (URLs)"]
        GA --> KT["katana (crawl)"]
    end

    subgraph SCAN["Scan Pipeline — 15 phases"]
        direction TB
        PRE["pre · port URL injection (extend target surface)"]
        NC["1 · nuclei (template scan)"]
        TK["2 · takeover (CNAME + fingerprint)"]
        EX["3 · exposure (static paths)"]
        SVC["4 · service checks (22 services on open ports)"]
        CO["5 · CORS (5 bypass techniques)"]
        JS["6 · JS scanning (secrets + endpoints)"]
        AI_P["7 · AI path gen (LLM-reasoned paths)"]
        AI_E["8 · AI exposure (probe AI paths)"]
        PD["9 · param discovery arjun"]
        S1["10 · SSRF GET (OOB + error-based)"]
        S2["11 · SSRF POST (JSON + form body)"]
        S3["12 · SSRF headers (14 injection headers)"]
        RD["13 · open redirect (52 param names)"]
        XS["14 · XSS reflection + dalfox"]
        AN["15 · anomaly detection (novel vulns + pattern replay)"]
    end

    subgraph AI["AI Layer (Claude · OpenAI · Groq · Ollama)"]
        direction TB
        PLAN["Planner → ReconPlan"]
        PATH["Path Generator → custom paths"]
        ANOMALY["Anomaly Analyzer → novel finding confirmation"]
        ANALYZE["Analyzer → TP/FP/Chains"]
        REPORT["Reporter → CWE·CVSS·PoC"]
    end

    subgraph LEARN["Cross-scan Learning"]
        direction TB
        PAT[("anomaly_patterns DB table")]
        PAT -->|"replay on matching tech stack"| AN
        AN -->|"confirmed pattern → save"| PAT
    end

    subgraph OUT["Output"]
        DB[("PostgreSQL")]
        HTML["report.html"]
        MD["report.md"]
        JSON["report.json"]
    end

    RP <--> RECON
    SP <--> SCAN
    ORCH <--> AI
    ORCH --> OUT
```

---

## How It Works

### Recon Phase

The framework enumerates all subdomains for the target domain, validates which ones are live, and builds a comprehensive URL database before any vulnerability scanning starts.

```mermaid
sequenceDiagram
    participant O as Orchestrator
    participant SF as subfinder/amass
    participant DNS as dnsx
    participant HX as httpx
    participant NB as naabu
    participant GA as gau/katana
    participant DB as PostgreSQL

    O->>SF: enumerate(domain)
    SF-->>O: [sub1.example.com, sub2.example.com, ...]
    O->>DNS: resolve(subdomains)
    DNS-->>O: [valid subdomains with IPs]
    O->>HX: probe(subdomains)
    HX-->>O: [live hosts + status + tech fingerprint]
    O->>NB: port_scan(hosts, 104 targeted ports)
    NB-->>O: [open ports per host]
    O->>GA: fetch_urls(domain) + crawl(live_hosts)
    GA-->>O: [1000s of historical + crawled URLs]
    O->>DB: save all results
```

**What gets discovered:**
- All resolvable subdomains and their IP addresses
- Live HTTP/HTTPS services with status codes, page titles, and detected technologies (React, Spring Boot, nginx, etc.)
- Open ports across 104 targeted ports (see [Port Scanning](#port-scanning))
- Historical URLs from Wayback Machine, Common Crawl, OTX, URLScan
- Crawled application paths and parameters

---

### Scan Pipeline (15 Phases)

The scan pipeline runs in a fixed order. Open port results are processed first to extend the target surface before any phase runs. JS scanning discovers new URLs and tech context that feeds the AI path generator, and AI-generated paths feed back into the exposure scanner. The anomaly detection phase (15) runs after XSS and before persistence.

```mermaid
flowchart LR
    subgraph PRE["Pre-scan"]
        P0["port URL injection (extend target_urls)"]
    end

    subgraph FAST["Discovery"]
        P1["1 · nuclei templates"]
        P2["2 · subdomain takeover"]
        P3["3 · static exposure"]
        P4["4 · service checks"]
        P5["5 · CORS misconfig"]
        P6["6 · JS scanning"]
        P7["7 · AI path generation"]
        P8["8 · AI exposure"]
    end

    subgraph PARAM["Parameter Prep"]
        P9["9 · param discovery"]
    end

    subgraph SSRF_BLOCK["SSRF (three vectors)"]
        P10["10 · SSRF GET URL params"]
        P11["11 · SSRF POST JSON / form body"]
        P12["12 · SSRF headers 14 injection headers"]
    end

    subgraph INJECT["Injection"]
        P13["13 · open redirect"]
        P14["14 · XSS reflection + dalfox"]
    end

    subgraph NOVEL["Novel / Adaptive"]
        P15["15 · anomaly detection pattern replay + fresh probes"]
    end

    PRE --> FAST --> PARAM --> SSRF_BLOCK --> INJECT --> NOVEL

    P6 --"new URLs + tech context"--> P7
    P7 --"AI paths"--> P8
    P0 --"port-derived URLs"--> P10
    P0 --"port-derived URLs"--> P14
    DB[("anomaly_patterns")] --"known patterns"--> P15
    P15 --"confirmed patterns"--> DB
```

---

### Port Scanning

naabu is configured with **104 targeted ports** covering every major service category across on-premises, cloud, and hybrid environments. This replaces the generic top-1000 scan, which misses critical internal ports (etcd, Kubelet, Docker daemon) while wasting time on rarely used ones.

| Category | Ports |
|---|---|
| Standard web | 80, 443 |
| HTTP alternates | 8000–8889 range (18 ports) |
| HTTPS alternates | 4443, 8443, 9443 |
| Dev/framework servers | 3000, 3001, 4000–4001, 4200, 5000–5001, 7000–7071, 9000–10000 range |
| **Kubernetes** | 6443 (API), 2379–2380 (etcd), 10250 (Kubelet), 10255 (Kubelet RO), 10256, 8001 |
| **Container/Docker** | 2375 (daemon unauth), 2376 (daemon TLS), 9323 (metrics), 4194 (cAdvisor) |
| Relational databases | 3306 (MySQL), 5432 (PostgreSQL) |
| Key-value/cache | 6379–6380 (Redis), 11211 (Memcached) |
| Document/search | 27017–27018 (MongoDB), 9200/9300 (Elasticsearch), 5984 (CouchDB), 8123 (ClickHouse) |
| Graph/time-series | 7474/7687 (Neo4j), 8086 (InfluxDB) |
| Wide-column/coordination | 9042 (Cassandra), 2181 (ZooKeeper) |
| Message brokers | 5672/15672 (RabbitMQ), 9092 (Kafka), 61616/8161 (ActiveMQ), 4222/8222 (NATS), 6650 (Pulsar) |
| **Monitoring/observability** | 9090/9091/9093/9094 (Prometheus/Alertmanager), 5601 (Kibana), 16686/14268 (Jaeger), 9411 (Zipkin), 4317/4318 (OTLP) |
| HashiCorp stack | 8200/8201 (Vault), 8300/8500 (Consul), 4646 (Nomad) |
| CI/CD | 9418 (Git daemon), 2222 (Gitea/alt SSH) |
| Standard services | 21 (FTP), 22 (SSH), 23 (Telnet), 25 (SMTP), 53 (DNS), 110/143 (POP3/IMAP), 389 (LDAP), 445 (SMB), 3389 (RDP), 5900 (VNC), 111/2049 (NFS) |

**Open ports feed the entire pipeline.** At scan start, the pipeline loads all discovered open ports and constructs `http://host:port/` or `https://host:port/` URLs for every HTTP-capable port. These are injected into `target_urls` before Phase 1 runs, so the exposure scanner, CORS scanner, XSS, and SSRF phases all automatically cover non-standard ports without any extra configuration.

The custom port list can be overridden or extended in `config.yaml`:

```yaml
tools:
  naabu:
    ports: [80, 443, 8080, 8443, 9200, 10250]  # override with custom list
    top_ports: 1000  # fallback if ports is empty
```

---

### Service Exposure Detection

After the static exposure scan (Phase 3), the pipeline runs targeted probes against every open port that maps to a known service (Phase 4). Unlike the generic exposure scanner which probes URL paths, this checker sends service-specific requests and validates the response content.

**22 services checked:**

| Service | Port | Probe | Severity |
|---|---|---|---|
| Kubernetes API | 6443 | `GET /api/v1/namespaces` (HTTPS) | Critical |
| etcd | 2379 | `GET /health` | Critical |
| Kubelet API | 10250 | `GET /pods` (HTTPS) | Critical |
| Docker daemon (unauth) | 2375 | `GET /info` | Critical |
| Docker daemon (TLS) | 2376 | `GET /info` (HTTPS) | Critical |
| CouchDB | 5984 | `GET /_all_dbs` | Critical |
| Elasticsearch | 9200 | `GET /` | High |
| Kibana | 5601 | `GET /api/status` | High |
| Prometheus | 9090 | `GET /api/v1/targets` | High |
| Grafana | 3000 | `GET /api/health` | High |
| RabbitMQ Management | 15672 | `GET /api/overview` | High |
| Consul | 8500 | `GET /v1/catalog/services` | High |
| HashiCorp Nomad | 4646 | `GET /v1/jobs` | High |
| Kubelet (read-only) | 10255 | `GET /pods` | High |
| InfluxDB | 8086 | `GET /query?q=SHOW+DATABASES` | High |
| ClickHouse | 8123 | `GET /?query=SELECT+1` | High |
| Neo4j Browser | 7474 | `GET /browser/` | High |
| ActiveMQ Web Console | 8161 | `GET /admin/` | High |
| HashiCorp Vault | 8200 | `GET /v1/sys/health` | Medium |
| Alertmanager | 9093 | `GET /api/v2/status` | Medium |
| Jaeger UI | 16686 | `GET /api/services` | Medium |
| Zipkin | 9411 | `GET /api/v2/services` | Medium |
| NATS Monitoring | 8222 | `GET /varz` | Medium |
| Docker metrics | 9323 | `GET /metrics` | Medium |
| cAdvisor | 4194 | `GET /api/v2.0/machine` | Medium |
| Prometheus push gateway | 9091 | `GET /metrics` | Medium |

Every probe uses a content validator — a generic `200 OK` is not enough. Elasticsearch must return `cluster_name` and `version`; Kubelet must return pod specs with `"items"`; Docker must return `DockerRootDir` or `ServerVersion`. This eliminates custom error pages from false-positive findings.

Findings are tagged `CWE-306` (Missing Authentication for Critical Function) with CVSS scores from 5.3 (metrics endpoints) to 9.8 (unauthenticated Docker daemon or Kubernetes API).

---

### AI Path Generation

After JavaScript scanning (Phase 6), the framework calls the configured LLM with context about what was found and asks it to generate additional paths to probe. This goes beyond the static list to discover target-specific hidden endpoints.

```mermaid
flowchart TD
    CONTEXT["Context gathered from recon"] --> LLM

    subgraph CONTEXT["Context inputs"]
        direction LR
        TECH["Tech stack detected per host (React, Spring Boot, nginx ...)"]
        JSROUTES["JS-extracted paths (top 60 by relevance score)"]
        URLPAT["URL patterns (normalised structure: /api/v2/{id}/, /internal/ ...)"]
        CONV["Naming conventions (snake_case / kebab-case / camelCase)"]
    end

    LLM["LLM reasoning (via submit_paths tool call)"] --> PATHS

    subgraph PATHS["Generated paths"]
        direction TB
        TECH_P["Framework-specific paths (Django admin, Spring Actuator ...)"]
        INFRA_P["Internal tool paths (/prometheus/, /grafana/, /consul/ ...)"]
        CONV_P["Naming-convention paths (matches app style)"]
        VAR_P["API version variants (/api/v2/admin/, /api/internal/ ...)"]
    end

    PATHS --> VALIDATE["Path validation (must start with /, no traversal, URL-safe chars, not already known)"]
    VALIDATE --> PROBE["Probe against every live host (any 2xx or 403 → finding)"]
    PROBE --> DB[("Save to DB")]
```

The LLM receives the full tech stack summary, up to 40 normalised URL patterns, and the 60 highest-signal JS paths ranked by keywords (`admin`, `internal`, `dashboard`, `monitor`, etc.). It uses the `submit_paths` tool to return a structured JSON array, avoiding free-text parsing. Already-known paths are excluded from the prompt to prevent duplication.

AI path generation can be disabled:

```yaml
vuln:
  exposure:
    ai_path_generation: false
```

---

### SSRF Detection (GET + POST + Headers)

SSRF is tested across three distinct injection vectors. All three share the same OOB-first confirmation strategy.

```mermaid
flowchart TD
    START["All discovered URLs + parameterised endpoints + port-derived URLs"] --> VECTOR

    VECTOR{"Injection vector"}

    VECTOR -->|"GET params (url=, redirect=, dest= ...)"| GET_SC
    VECTOR -->|"POST JSON/form body (imageUrl, webhookUrl ...)"| POST_SC
    VECTOR -->|"HTTP headers (X-Forwarded-For, X-Host ...)"| HDR_SC

    subgraph OOB_FLOW["OOB Confirmation (all vectors)"]
        direction TB
        INJECT["Inject: http://tag.oast.pro into candidate"]
        WAIT["Wait 15s for DNS/HTTP callback"]
        GOT{{"Callback received?"}}
        INJECT --> WAIT --> GOT
    end

    GET_SC & POST_SC & HDR_SC --> OOB_FLOW

    GOT -->|"Yes ✓"| CONFIRM["CONFIRMED confidence: confirmed severity: high  CVSS: 8.6"]
    GOT -->|"No"| ERR_BASED["Error-Based Fallback Inject: 169.254.169.254 / cloud IMDS Analyse response body"]
    ERR_BASED --> REPRO["Re-verify — repeat injection, confirm reproducible"]
    REPRO -->|"Yes"| MEDIUM["FINDING confidence: medium Needs manual verification"]
    REPRO -->|"No"| SKIP["Skip"]

    CONFIRM --> DB[("Save to DB")]
    MEDIUM --> DB
```

**GET SSRF — tested parameter names (40+ total):**

| Priority | Parameters |
|----------|-----------|
| **Highest** | `url`, `redirect`, `dest`, `callback`, `webhook` |
| **High** | `src`, `href`, `path`, `uri`, `next`, `fetch`, `proxy` |
| **Medium** | `target`, `resource`, `host`, `from`, `to`, `feed`, `load` |
| **Also tested** | `ref`, `location`, `continue`, `goto`, `redir`, `endpoint` |

**POST SSRF — tested field names (36 total):**

| Category | Fields |
|----------|--------|
| **Image/media** | `imageUrl`, `image_url`, `avatarUrl`, `logoUrl`, `thumbnailUrl` |
| **Webhooks** | `webhookUrl`, `webhook_url`, `callbackUrl`, `notifyUrl` |
| **Remote access** | `remoteUrl`, `remote_url`, `fileUrl`, `pdfUrl`, `xmlUrl` |
| **Integration** | `apiEndpoint`, `serviceUrl`, `targetUrl`, `importUrl` |

**Header SSRF — tested headers (14 total):**

```
X-Forwarded-For    X-Forwarded-Host   X-Real-IP
X-Original-URL     X-Rewrite-URL      X-Host
X-Custom-IP-Authorization             Forwarded
True-Client-IP     Client-IP          X-Client-IP
X-Remote-IP        X-Remote-Addr      X-Originating-IP
```

---

### XSS Detection

XSS scanning uses two parallel approaches, both designed to minimise false positives by requiring proof of unescaped execution context.

```mermaid
flowchart TD
    URLS["URLs with query parameters"] --> SPLIT

    SPLIT --> REFL["Reflection Scanner (custom)"]
    SPLIT --> DALF["Dalfox (automated)"]

    subgraph REFLECTION["Reflection Scanner"]
        direction TB
        PROBE["1 · Send unique probe ?param=xss3f9a2b Check if probe appears in response"]
        PROBE --> FOUND_R{{"Probe in response?"}}
        FOUND_R -->|No| SKIP_R["Skip param"]
        FOUND_R -->|Yes| CTX["2 · Detect context where reflection appears"]
        CTX --> CONTEXTS["HTML body · HTML attribute JS string · HTML comment · URL value"]
        CONTEXTS --> PAYLOAD["3 · Send context-aware payload"]
        PAYLOAD --> HTML_P["html_body: <script>alert(1)</script> <img src=x onerror=alert(1)>"]
        PAYLOAD --> ATTR_P["html_attribute: ' onmouseover='alert(1)' x='"]
        PAYLOAD --> JS_P["js_string: ';alert(1)//"]
        HTML_P & ATTR_P & JS_P --> UNESC["4 · Confirm payload is unescaped in response (raw marker must appear literally)"]
        UNESC --> VERIFY_R["5 · Re-test to confirm reproducibility"]
    end

    subgraph DALFOX_FLOW["Dalfox"]
        direction TB
        D1["Feeds up to 200 parameterised URLs"]
        D1 --> D2["dalfox file URLs.txt --format json --delay 100ms"]
        D2 --> D3["dalfox internally verifies execution context before reporting"]
        D3 --> D4["JSON output parsed and scope-validated"]
    end

    REFL --> REFLECTION
    DALF --> DALFOX_FLOW
    REFLECTION --> MERGE["Merge + deduplicate"]
    DALFOX_FLOW --> MERGE
    MERGE --> AI_XSS["AI Analyzer final triage pass"]
```

---

### CORS Misconfiguration

The CORS scanner tests five distinct bypass techniques. Any misconfiguration that returns `Access-Control-Allow-Credentials: true` is elevated to high/critical.

```mermaid
flowchart TD
    HOST["Live HTTPS host"] --> FIVE

    subgraph FIVE["5 bypass techniques"]
        direction LR
        T1["Reflected origin Origin: https://evil.com Expect: ACA-Origin = evil.com"]
        T2["Null origin Origin: null Expect: ACA-Origin = null"]
        T3["Prefix bypass Origin: https://evil.example.com (trusted prefix spoofed)"]
        T4["Suffix bypass Origin: https://evilexample.com (suffix match abuse)"]
        T5["Wildcard Origin: https://anything.com Expect: ACA-Origin = *"]
    end

    FIVE --> CRED{{"ACA-Credentials: true?"}}
    CRED -->|Yes| HIGH["High / Critical Cross-origin credential leak"]
    CRED -->|No| MED["Medium / Low Origin reflection without credentials"]

    HIGH --> REVERIFY["Re-verify critical/high before saving"]
    REVERIFY --> DB[("Save to DB")]
    MED --> DB
```

**Severity matrix:**

| Bypass Type | With Credentials | Without Credentials |
|---|---|---|
| Reflected origin | **Critical** | Medium |
| Null origin | **High** | Low |
| Prefix/Suffix bypass | **High** | Medium |
| Wildcard | Low (by design) | Info |

---

### Subdomain Takeover

The takeover scanner resolves the full CNAME chain for each subdomain and checks whether the final target is an unclaimed service using 20+ provider fingerprints.

```mermaid
flowchart TD
    SUBS["All enumerated subdomains"] --> DNS_RES

    DNS_RES["DNS CNAME resolution (dnspython)"]
    DNS_RES --> HAS_CNAME{{"CNAME chain?"}}
    HAS_CNAME -->|No| SKIP["Skip — A record only"]
    HAS_CNAME -->|Yes| CHAIN["Full chain resolved: sub.example.com → service.s3-website-us-east-1.amazonaws.com → ..."]

    CHAIN --> HTTP["Fetch HTTP body of CNAME target"]
    HTTP --> MATCH{{"Fingerprint match?"}}

    MATCH -->|No| CLEAN["No takeover indicator"]
    MATCH -->|Yes| FINDING["Takeover finding severity: critical cwe: CWE-284"]
    FINDING --> DB[("Save to DB")]
```

**Supported providers (20+ fingerprints):**

| Cloud / CDN | SaaS / Hosting |
|---|---|
| AWS S3, CloudFront | GitHub Pages, Netlify, Vercel |
| Azure Blob / Traffic Manager | Fastly, Heroku, Shopify |
| Pantheon, WP Engine | Zendesk, Freshdesk, HubSpot |
| Tumblr, Ghost, Cargo | Surge.sh, ReadTheDocs, Statuspage |

---

### Open Redirect Detection

The redirect scanner tests 52 parameter names, follows the actual redirect chain, and detects OAuth token-theft chaining potential.

```mermaid
flowchart TD
    URLS["URLs with redirect-like parameter names"] --> INJECT

    subgraph PARAMS["52 tested parameters"]
        direction LR
        P1["redirect · return · next continue · url · goto"]
        P2["dest · destination · target returnTo · returnUrl · back"]
        P3["forward · location · path returnPath · redirectUri · to"]
    end

    INJECT["Inject external domain ?redirect=https://evil.com/ (with / without slash variations)"]
    INJECT --> FOLLOW["Follow redirect chain (httpx aiohttp, max 5 hops)"]
    FOLLOW --> LAND{{"Final host = injected host?"}}

    LAND -->|Yes| HOST_CHECK["Strict host comparison (no partial matches)"]
    HOST_CHECK --> CHAIN_CHECK{{"OAuth / token context?"}}
    CHAIN_CHECK -->|"redirect_uri response_type client_id"| CHAIN_WARN["Chaining potential: HIGH OAuth token theft severity → high"]
    CHAIN_CHECK -->|No| PLAIN["severity: medium"]

    CHAIN_WARN & PLAIN --> VERIFY["Re-verify before saving"]
    VERIFY --> DB[("Save to DB")]

    LAND -->|No| SKIP["No redirect finding"]
```

---

### JavaScript Secret Scanning

Every `.js` file discovered during recon is fetched and scanned for hardcoded secrets and hidden endpoints. Newly discovered endpoints and tech context are fed into the AI path generator.

```mermaid
flowchart LR
    JS_URLS["All .js URLs from recon + crawl"] --> FETCH

    FETCH["Fetch JS content (scope-validated)"] --> SECRETS

    subgraph SECRETS["16 secret patterns"]
        direction TB
        S1["AWS access key · secret key AWS session token"]
        S2["Google API key Service account JSON"]
        S3["GitHub token · GitLab token Slack webhook · Discord token"]
        S4["Stripe key · Twilio SID SendGrid API key"]
        S5["Private RSA/EC key Generic API key · Bearer token"]
    end

    FETCH --> ENDPOINTS

    subgraph ENDPOINTS["Endpoint extraction"]
        direction TB
        E1["Relative paths: /api/v1/users"]
        E2["Absolute URLs: https://..."]
        E3["Fetch/XHR calls axios.get('/endpoint')"]
        E4["GraphQL endpoint hints"]
    end

    SECRETS --> FINDINGS["JS findings (secret truncated: first8chars...)"]
    ENDPOINTS --> NEW_URLS["New URLs + context fed into AI path generator and SSRF + XSS phases"]

    FINDINGS --> DB[("Save to DB")]
```

**What gets redacted in findings:**
Secrets are truncated to the first 8 characters followed by `...` — enough to confirm the finding without storing the full secret in the database.

---

### Exposed Endpoint Detection

Eight categories of common sensitive path exposure are checked with content-based validation, followed by an AI-generated pass for target-specific paths.

| Category | Example paths | Content validation |
|---|---|---|
| **git** | `/.git/config`, `/.git/HEAD` | Must contain `[core]` |
| **env** | `/.env`, `/.env.production` | Must contain `KEY=VALUE` |
| **api_docs** | `/swagger.json`, `/openapi.yaml`, `/graphql` | Must contain OpenAPI markers or GraphQL schema |
| **graphql** | `/graphql`, `/api/graphql` | Sends introspection query, must return `__schema` |
| **spring_actuator** | `/actuator/env`, `/actuator/beans` | Must contain `activeProfiles` or `beans` |
| **debug** | `/debug`, `/phpinfo.php`, `/server-info` | Must contain debug-specific keywords |
| **backup** | `/.DS_Store`, `/backup.zip`, `/db.sql.gz` | File type / size validation |
| **admin** | `/admin`, `/wp-admin`, `/administrator` | Must contain login/credential keywords |
| **ai_generated** | LLM-reasoned paths | Any 2xx or 403 response |

See [AI Path Generation](#ai-path-generation) for how the `ai_generated` category works.

---

### Adaptive Novel Vulnerability Detection

Phase 15 finds vulnerabilities that are **not in the hardcoded scanner set** by probing for behavioural anomalies and using the LLM to hypothesise and confirm them. It also replays confirmed patterns from previous scans against new targets with the same tech stack.

**The non-negotiable FP constraint:** No finding is ever created by the LLM making a judgment call alone. Every finding requires an HTTP-level behavioural confirmation: a specific probe that produces specific, unambiguous content in the response.

```mermaid
flowchart TD
    HOSTS["Live hosts (capped at max_hosts, deduplicated to 1 per eTLD+1)"]

    HOSTS --> REPLAY
    HOSTS --> PROBE

    subgraph REPLAY["Step A — Pattern replay (cross-scan learning)"]
        direction TB
        DB[("anomaly_patterns DB")] -->|"WHERE tech_stack overlaps"| PAT["Matching confirmed patterns"]
        PAT --> EXEC_R["Execute stored confirmation probe against current target"]
        EXEC_R --> EVAL_R["LLM evaluates actual response"]
        EVAL_R -->|confirmed| FINDING_R["Novel finding (source: pattern-replay)"]
        EVAL_R -->|not confirmed| FP["Increment fp_count for pattern"]
    end

    subgraph PROBE["Step B — Fresh anomaly detection"]
        direction TB
        BASE["Baseline GET per host"] --> VARIANTS["~20 HTTP probe variants"]

        subgraph VARIANTS["~20 HTTP probe variants"]
            direction LR
            M["Method confusion × 5 TRACE · PUT · DELETE · PATCH method-override"]
            H["Header injection × 8 X-Forwarded-For · X-Original-URL XXE · Accept variants"]
            P["Parameter/path × 7 ?debug=true · ?format=xml path traversal · null byte overflow"]
        end

        VARIANTS --> SCORE["Divergence scoring (11 signals)"]

        subgraph SCORE["Divergence scoring"]
            direction LR
            S1["Status 2xx↔4xx flip   +5"]
            S2["Other status change    +3"]
            S3["Error keywords         +4"]
            S4["Internal IP in body    +4"]
            S5["Credential pattern     +4"]
            S6["Body delta >50%        +3"]
            S7["Response time >5×      +3"]
            S8["Content-Type changed   +1"]
            S9["Debug headers appeared +2"]
        end

        SCORE -->|"score >= 5"| GATE1["Gate 1 passed — send to LLM"]
        SCORE -->|"score < 5"| DISCARD["Discard"]

        GATE1 --> HYP["LLM: formulate_hypothesis tool
        Must name a class from closed list
        Rejects: 'other' class or confidence='low'"]

        HYP -->|"accepted"| DESIGN["LLM: design_confirmation_probe tool
        confirms_if must be specific content
        Rejects: 'status changes', 'different response'"]

        DESIGN -->|"accepted"| EXEC["Framework executes probe
        LLM cannot hallucinate the response"]

        EXEC --> EVAL["LLM: evaluate_confirmation tool
        confirmed=True with empty/generic evidence
        → forced to False"]

        EVAL -->|"confirmed + severity >= medium"| FINDING["Novel finding (source: anomaly-detection)"]
        EVAL -->|"not confirmed"| DISCARD2["No finding"]

        FINDING --> SAVE[("Save to anomaly_patterns for future scans")]
    end
```

**Probe categories (20 total):**

| Category | Probes | What they detect |
|---|---|---|
| **Method confusion** (5) | `TRACE`, `PUT`, `DELETE`, `PATCH`, `X-HTTP-Method-Override: DELETE` | Unexpected method acceptance, reflected headers in TRACE |
| **Header injection** (8) | `X-Forwarded-For: 127.0.0.1/169.254.169.254`, `X-Forwarded-Host: evil.com`, `X-Original-URL: /admin`, `X-Rewrite-URL: /admin`, XXE Content-Type, `Accept: application/xml`, `Accept: text/html` | Routing bypass, host header injection, XXE, content negotiation issues |
| **Parameter/path** (7) | `?debug=true`, `?format=xml`, `?callback=x` (JSONP), `?admin=true`, URL-encoded path traversal, null byte, 2000-char overflow | Debug interfaces, content format overrides, access control bypass, path traversal, error disclosure |

**Divergence scoring — threshold ≥ 5 to proceed to LLM:**

| Signal | Score |
|---|---|
| Status 4xx/5xx ↔ 2xx flip | +5 |
| Any other status change | +3 |
| Error keywords (`exception`, `traceback`, `SQLSTATE`, `ORA-`, ...) | +4 |
| Internal IP in body (`10.x`, `172.16-31.x`, `192.168.x`, `169.254.169.254`) | +4 |
| Credential pattern (`password=`, `api_key=`, `Bearer `) | +4 |
| Body length delta > 50% of baseline | +3 |
| Body length delta > 20% | +1 |
| Response time > 5× baseline | +3 |
| Response time > 2× baseline | +1 |
| Content-Type changed | +1 |
| Debug/internal header appeared | +2 |

**All seven false-positive gates:**

| Gate | Where | Mechanism |
|---|---|---|
| 1 | `AnomalyProber` | Divergence score ≥ 5 before LLM is contacted |
| 2a | `formulate_hypothesis` tool | LLM must name a class from a closed list of 12 |
| 2b | `formulate_hypothesis` tool | LLM confidence must be "medium" or "high" |
| 3a | `design_confirmation_probe` tool | `confirms_if` must be specific content, not status/length signal |
| 3b | Framework | Probe is actually executed — LLM cannot hallucinate the result |
| 3c | `evaluate_confirmation` tool | `confirmed=True` with empty or generic evidence is blocked |
| 4 | `_run_anomaly_phase` | `min_severity: medium` — low/info novel findings never auto-created |

**Cross-scan learning:** When a novel finding is confirmed, its probe details and expected content pattern are stored in the `anomaly_patterns` table. On the next scan of a host with the same tech stack, those patterns are replayed directly (bypassing Gate 1) — the LLM only needs to evaluate the response, not re-hypothesise from scratch. False-positive replays increment a `fp_count` counter; noisy patterns are deprioritised over time.

**Allowed vulnerability classes (closed list):**

```
path-traversal  |  ssrf  |  xxe  |  method-confusion  |  info-disclosure
injection  |  auth-bypass  |  header-injection  |  content-type-confusion
parameter-pollution  |  idok-exposure  |  debug-interface
```

Novel findings appear in reports with the `ai-detected` and `novel` tags and a `source` field set to either `anomaly-detection` or `pattern-replay`.

---

### AI Analysis

After automated scanning, an AI agent triages all findings, removes false positives, detects vulnerability chains, and formats surviving findings for bug bounty submission.

```mermaid
sequenceDiagram
    participant O as Orchestrator
    participant A as Analyzer Agent
    participant LLM as Claude / OpenAI
    participant DB as Database

    O->>A: analyze_findings(findings, live_hosts)
    A->>LLM: "Triage these N findings..."
    loop For each finding
        LLM->>LLM: tool_use: assess_finding(finding)
        Note over LLM: SSRF OOB confirmed → fp_likelihood: low<br/>SSRF error-based → fp_likelihood: medium<br/>XSS dalfox confirmed → fp_likelihood: low<br/>CORS + credentials → fp_likelihood: low<br/>Takeover + fingerprint → fp_likelihood: low<br/>Service unauthenticated → fp_likelihood: low
        LLM->>LLM: tool_use: suggest_poc(vuln_type, host)
    end
    LLM->>LLM: tool_use: check_vuln_chain(all_findings)
    Note over LLM: XSS + CSRF → Account Takeover<br/>SSRF + IMDS → Credential Theft<br/>Open Redirect + OAuth → Token Theft<br/>CORS + credentials → Cross-origin data access<br/>Kubelet unauth → Container escape
    LLM-->>A: {true_positive_ids, false_positive_ids, chains, summary}
    A->>DB: update findings (is_false_positive flag)
    A-->>O: AnalysisResult

    O->>LLM: Reporter Agent: format findings for submission
    LLM-->>O: CWE · CVSS 3.1 vector · curl PoC · remediation · business impact
```

---

## Requirements

### Python

- Python 3.11+

### PostgreSQL

- PostgreSQL 14+ (any edition — RDS, Azure Database, on-prem, Docker)
- Set `DATABASE_URL` in your `.env` file (see [Installation](#installation))

### External tools (all optional — framework degrades gracefully)

| Tool | Purpose | Install |
|------|---------|---------|
| `subfinder` | Passive subdomain enumeration | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| `amass` | Active/passive subdomain enumeration | `go install github.com/owasp-amass/amass/v4/...@master` |
| `dnsx` | DNS resolution and validation | `go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| `httpx` | HTTP probing and tech detection | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| `naabu` | Port scanning (104 targeted ports) | `go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` |
| `nuclei` | Template-based vulnerability scanning | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| `gau` | Historical URL discovery | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| `katana` | Web crawler | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| `waybackurls` | Wayback Machine URL fetcher | `go install github.com/tomnomnom/waybackurls@latest` |
| **`dalfox`** | **XSS scanner (primary)** | `go install github.com/hahwul/dalfox/v2@latest` |
| **`interactsh-client`** | **SSRF OOB callback server** | `go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest` |
| **`arjun`** | **Hidden parameter discovery** | `pip install arjun` |

> **Minimum for full coverage:** `httpx`, `dalfox`, `interactsh-client`, `gau`/`katana`
>
> **For SSRF only:** `interactsh-client` + Python aiohttp (built-in)

After installing nuclei, update templates:
```bash
nuclei -update-templates
```

---

## Installation

```bash
# Clone or download
cd liminal

# Install all external tools (Go + Python)
./install-tools.sh

# Check what is/isn't installed without making changes
./install-tools.sh --check

# Install Python dependencies for the framework itself
pip install -e .

# Set API keys and database
cp .env.example .env
# Edit .env — only the key for your chosen provider is needed:
#   ANTHROPIC_API_KEY=sk-ant-...   (provider: "claude")
#   OPENAI_API_KEY=sk-...          (provider: "openai")
#   GROQ_API_KEY=gsk_...           (provider: "groq"  — free)
#   No key needed                  (provider: "ollama" — local)
#   DATABASE_URL=postgresql://liminal:password@localhost:5432/liminal

# Verify tools
liminal check-tools
```

### PostgreSQL setup

Create the database before the first scan:

```bash
# Local PostgreSQL
psql -U postgres -c "CREATE USER liminal WITH PASSWORD 'password';"
psql -U postgres -c "CREATE DATABASE liminal OWNER liminal;"

# Docker (quick dev setup)
docker run -d --name bb-db \
  -e POSTGRES_USER=liminal \
  -e POSTGRES_PASSWORD=password \
  -e POSTGRES_DB=liminal \
  -p 5432:5432 postgres:16-alpine
```

The schema (all tables) is created automatically on first run. No migrations needed.

The install script accepts flags to target a subset of tools:

```bash
./install-tools.sh --go      # Go tools only (subfinder, httpx, dalfox, etc.)
./install-tools.sh --python  # Python tools only (arjun)
./install-tools.sh --check   # Print install status, make no changes
```

> **Prerequisites:** [Go 1.21+](https://go.dev/dl/) and Python 3.11+.
> After installing Go tools, ensure `$(go env GOPATH)/bin` is in your `PATH`.

---

## Configuration

Copy and edit the example config:

```bash
cp config/config.yaml my-target.yaml
```

### AI Provider

Four providers are supported. Only the key for the chosen provider is required.

| Provider | `ai.provider` | Cost | Notes |
|---|---|---|---|
| Anthropic Claude | `claude` | Paid | Default; highest quality |
| OpenAI | `openai` | Paid | GPT-4o |
| **Groq** | `groq` | **Free tier** | Llama 3.3 70B, OpenAI-compatible API |
| **Ollama** | `ollama` | **Free (local)** | Any model you pull; no data leaves the machine |

**Claude (default):**

```yaml
ai:
  provider: "claude"
  claude_model: "claude-opus-4-6"   # or claude-sonnet-4-6 for lower cost
```

```bash
ANTHROPIC_API_KEY=sk-ant-...
```

**OpenAI:**

```yaml
ai:
  provider: "openai"
  openai_model: "gpt-4o"
```

```bash
OPENAI_API_KEY=sk-...
```

**Groq (free tier — recommended for cost reduction):**

```yaml
ai:
  provider: "groq"
  groq_model: "llama-3.3-70b-versatile"   # or mixtral-8x7b-32768
```

```bash
# Free key at https://console.groq.com
GROQ_API_KEY=gsk_...
```

**Ollama (fully local, zero API cost):**

```yaml
ai:
  provider: "ollama"
  groq_model: "llama3.3"   # any model you have pulled locally
```

```bash
# No key required — just have ollama running:
#   ollama pull llama3.3
#   ollama serve
```

> Groq and Ollama both use the OpenAI-compatible API under the hood — no extra dependencies required beyond the existing `openai` package.

**Shared settings** (all providers):

```yaml
ai:
  max_tokens: 8192   # max completion tokens per LLM call
  temperature: 0     # 0 = deterministic (recommended for tool use)
```

Set the database URL regardless of provider:

```bash
DATABASE_URL=postgresql://liminal:password@localhost:5432/liminal
```

### Scope

Always define scope before running. The framework scope-validates every target before testing — nothing outside scope is ever touched.

```yaml
scope:
  in_scope:
    - "*.example.com"          # wildcard – matches all subdomains
    - "example.com"            # exact domain
    - "api.example.com"        # explicit subdomain
  out_of_scope:
    - "blog.example.com"       # excluded even if matched by wildcard above
    - "status.example.com"
  ip_ranges:
    - "10.0.0.0/8"             # CIDR ranges (optional)
```

> Out-of-scope rules always take precedence over in-scope wildcards.

### Multi-Target Batch Scanning

Instead of a single `target:` block, define a `targets:` list. The agent scans them sequentially and prints a consolidated summary at the end.

Each target can carry its own scope — handy when managing multiple bug bounty programmes in one config file.

```yaml
# config/targets.yaml

targets:
  - domain: "api.example.com"
    program_name: "Example API Bug Bounty"
    platform: "HackerOne"
    in_scope:
      - "*.api.example.com"
      - "api.example.com"
    out_of_scope:
      - "staging.api.example.com"

  - domain: "app.example.org"
    program_name: "Example App Program"
    platform: "Bugcrowd"
    in_scope:
      - "*.app.example.org"

# All other sections (rate_limits, tools, vuln, ai, output) apply globally
# to every target in the list.
```

When a target defines its own `in_scope`/`out_of_scope`, those values replace the global `scope:` block for that target only. If a target omits them, the global scope is used.

The single-target format (`target:`) remains fully supported for backward compatibility.

---

### Notifications

The agent can push notifications to Slack, Discord, a generic webhook, or email when scans start, complete, or surface a critical finding. Configure in YAML or inject credentials via environment variables.

```yaml
notifications:
  # Slack incoming webhook — set here or via SLACK_WEBHOOK_URL env var
  slack_webhook: ""

  # Discord incoming webhook — set here or via DISCORD_WEBHOOK_URL env var
  discord_webhook: ""

  # Generic HTTP endpoint — receives POST {"message": "...", "source": "liminal"}
  webhook_url: ""

  # Email via SMTP + STARTTLS
  email_to: "team@example.com"
  smtp_host: "smtp.example.com"
  smtp_port: 587
  smtp_user: "alerts@example.com"
  smtp_from: "alerts@example.com"
  # Password: set here or via SMTP_PASSWORD env var

  # Control which events trigger a notification
  notify_on_start: false     # fire when each target scan begins
  notify_on_complete: true   # fire when each target scan finishes
  notify_on_critical: true   # immediate alert per critical finding
```

**Environment variable injection** (preferred for secrets):

```bash
# .env or systemd EnvironmentFile
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T.../B.../...
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
SMTP_PASSWORD=super-secret
```

**Notification events:**

| Event | Triggered by | Content |
|---|---|---|
| Scan started | `notify_on_start: true` | Domain, Run ID |
| Scan complete | `notify_on_complete: true` | Domain, duration, severity counts, report path |
| Critical finding | `notify_on_critical: true` | Domain, vulnerability name, affected host |
| Scan failed | Always | Domain, error message |
| Batch complete | After all targets | Total/succeeded/failed, total findings |

All configured backends (Slack, Discord, webhook, email) fire in parallel. A delivery failure is logged but never interrupts the scan.

### Port Scanning

```yaml
tools:
  naabu:
    enabled: true
    # Custom port list — covers web, databases, K8s, containers, monitoring,
    # message brokers, and standard services (104 ports by default).
    # Set to [] to fall back to top_ports.
    ports:
      - 80
      - 443
      - 8080
      - 9200   # Elasticsearch
      - 10250  # Kubelet
      # ... add more as needed
    top_ports: 1000   # used only when ports is empty
    timeout: 300
```

### SSRF Settings

```yaml
vuln:
  ssrf:
    enabled: true
    interactsh_server: "oast.pro"   # public server; self-host for reliability
    oob_wait_seconds: 15.0          # increase for slow outbound DNS
    concurrent: 5
    timeout: 10.0
    verify_findings: true
    extra_params:
      - "service_url"
      - "integration_endpoint"

  header_injection:
    enabled: true
    concurrent: 3
    timeout: 10.0
```

### XSS Settings

```yaml
vuln:
  xss:
    enabled: true
    dalfox_enabled: true
    reflection_scanner_enabled: true
    verify_findings: true
    concurrent: 5
    timeout: 10.0
    blind_xss_url: "https://your-id.xss.ht"   # optional: https://xsshunter.com
```

### CORS Settings

```yaml
vuln:
  cors:
    enabled: true
    concurrent: 10
    timeout: 10.0
```

### Subdomain Takeover Settings

```yaml
vuln:
  takeover:
    enabled: true
    concurrent: 20
    timeout: 10.0
```

### Open Redirect Settings

```yaml
vuln:
  open_redirect:
    enabled: true
    concurrent: 10
    timeout: 10.0
    verify_findings: true
```

### JS Scanner Settings

```yaml
vuln:
  js_scanner:
    enabled: true
    max_js_files: 100
    timeout: 10.0
```

### Exposed Endpoint Settings

```yaml
vuln:
  exposure:
    enabled: true
    concurrent: 20
    timeout: 8.0
    categories:
      - git
      - env
      - api_docs
      - graphql
      - spring_actuator
      - debug
      - backup
      - admin
    # LLM-generated paths based on tech stack and JS context
    ai_path_generation: true
```

### Adaptive Anomaly Detection Settings

```yaml
vuln:
  anomaly:
    enabled: true
    concurrent: 5          # probe concurrency per host
    timeout: 10.0          # per-request timeout (seconds)
    score_threshold: 5     # minimum divergence score before contacting the LLM
    max_hosts: 50          # cost control — cap hosts probed per scan
    min_severity: "medium" # never auto-create low/info novel findings
    replay_patterns: true  # proactively replay confirmed patterns from DB
```

**Tuning guidance:**

| Setting | Lower | Higher |
|---|---|---|
| `score_threshold` | More LLM calls, broader coverage | Fewer calls, only high-confidence anomalies |
| `max_hosts` | Faster scan, less coverage | Slower scan, more hosts probed |
| `concurrent` | Less load on target | Faster probing |
| `replay_patterns: false` | Skip cross-scan learning (useful for isolated scans) | — |

To disable the phase entirely:

```yaml
vuln:
  anomaly:
    enabled: false
```

---

## Usage

### Full scan

```bash
liminal scan --config my-target.yaml
```

### Override target domain

```bash
liminal scan --config my-target.yaml --domain api.othertarget.com
```

### Recon only (no vulnerability scanning)

```bash
liminal scan --config my-target.yaml --only-recon
```

### Scan only (reuse existing recon)

```bash
# After a prior scan with --only-recon:
liminal scan --config my-target.yaml --only-scan --resume <SCAN_ID>
```

### Resume an interrupted scan

```bash
liminal scan --config my-target.yaml --resume 3f2a1b9c-...
```

### List all previous scans

```bash
liminal list-scans --config my-target.yaml
```

```
Scan Runs
┌──────────────────┬──────────────┬─────────────────────┬───────────┐
│ ID               │ Target       │ Started             │ Status    │
├──────────────────┼──────────────┼─────────────────────┼───────────┤
│ 3f2a1b9c-...     │ example.com  │ 2026-02-26 09:14:32 │ completed │
│ 1a7e4c2d-...     │ example.com  │ 2026-02-25 17:03:11 │ failed    │
└──────────────────┴──────────────┴─────────────────────┴───────────┘
```

### Regenerate a report

```bash
liminal report 3f2a1b9c-... --config my-target.yaml --format html
```

### Verbose mode (show all tool output)

```bash
liminal scan --config my-target.yaml --verbose
```

### Multi-target batch scan

Add a `targets:` list to your config (see [Multi-Target Batch Scanning](#multi-target-batch-scanning)) then run normally — the agent scans each target in sequence and prints a summary table when all are done:

```bash
liminal scan --config config/targets.yaml
```

```
╔══════════════════════╦══════════╦══════════╦══════╦══════╦═════╗
║ Target               ║ Status   ║ Duration ║ Crit ║ High ║ Med ║
╠══════════════════════╬══════════╬══════════╬══════╬══════╬═════╣
║ api.example.com      ║ complete ║ 43m 12s  ║  2   ║  5   ║  8  ║
║ app.example.org      ║ failed   ║  3m 01s  ║  –   ║  –   ║  –  ║
╚══════════════════════╩══════════╩══════════╩══════╩══════╩═════╝
```

Failed targets are retried up to twice with a 60-second delay before being marked failed. The process exits with code 1 if any target failed.

### Log to file (background-friendly)

```bash
liminal scan --config config/targets.yaml \
    --log-file /var/log/liminal/scan.log
```

The file handler always writes at `INFO` level with full timestamps (`YYYY-MM-DD HH:MM:SS`), regardless of `--verbose`. The console handler is unaffected. The directory is created automatically if it does not exist.

### Graceful shutdown (SIGTERM)

The agent respects `SIGTERM` and `SIGINT` (Ctrl-C). On receipt, it sets a shutdown flag and exits cleanly **after the current target finishes** — no mid-scan corruption, no partial reports. Useful when running as a systemd `oneshot` service.

```bash
kill -TERM <pid>      # finishes current target, then exits
kill -INT  <pid>      # same — Ctrl-C in a terminal session
```

---

## Autonomous Background Operation (systemd)

Drop the agent on an EC2 instance, start it once, and come back to findings in Slack.

### 1. Install the agent

```bash
# Create a dedicated user (no login shell)
sudo useradd --system --no-create-home --shell /usr/sbin/nologin liminal

# Install to /opt
sudo mkdir -p /opt/liminal
sudo git clone <repo-url> /opt/liminal
sudo chown -R liminal:liminal /opt/liminal

# Create virtualenv and install dependencies
sudo -u liminal python3 -m venv /opt/liminal/venv
sudo -u liminal /opt/liminal/venv/bin/pip install -e /opt/liminal

# Create log directory
sudo mkdir -p /var/log/liminal
sudo chown liminal:liminal /var/log/liminal
```

### 2. Configure targets and credentials

```bash
# Copy example config and edit
sudo cp /opt/liminal/config/targets-example.yaml \
        /opt/liminal/config/targets.yaml
sudo nano /opt/liminal/config/targets.yaml

# Create .env with secrets (never put API keys in the YAML)
# Only the key for your chosen ai.provider is required.
sudo tee /opt/liminal/.env > /dev/null <<EOF
# Pick one:
ANTHROPIC_API_KEY=sk-ant-...   # provider: "claude"
# OPENAI_API_KEY=sk-...        # provider: "openai"
# GROQ_API_KEY=gsk_...         # provider: "groq"  (free)
# Ollama needs no key          # provider: "ollama" (local)

DATABASE_URL=postgresql://liminal:password@localhost:5432/liminal
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T.../B.../...
SMTP_PASSWORD=your-smtp-password
EOF
sudo chmod 600 /opt/liminal/.env
sudo chown liminal:liminal /opt/liminal/.env
```

### 3. Install the systemd service

```bash
# Copy unit files
sudo cp /opt/liminal/systemd/liminal.service /etc/systemd/system/
sudo cp /opt/liminal/systemd/liminal.timer   /etc/systemd/system/

# Reload and enable
sudo systemctl daemon-reload
sudo systemctl enable liminal.timer   # auto-start on boot
```

### 4. Run it

**One-shot (run now, exit when done):**
```bash
sudo systemctl start liminal.service
```

**Scheduled (daily, every day):**
```bash
sudo systemctl start liminal.timer
sudo systemctl status liminal.timer
```

**Watch live output:**
```bash
# Journal (real-time)
journalctl -u liminal -f

# Log file (same content, persisted)
tail -f /var/log/liminal/scan.log
```

**Check last run status:**
```bash
systemctl status liminal.service
journalctl -u liminal --since "1 hour ago"
```

### 5. Customise the schedule

Edit `/etc/systemd/system/liminal.timer`:

```ini
[Timer]
OnCalendar=daily          # every day at midnight
# OnCalendar=Mon *-*-* 02:00:00   # every Monday at 02:00
# OnCalendar=*-*-* 02:00:00       # every day at 02:00 (same as daily)
Persistent=true           # catch up on missed runs after downtime
```

After editing:
```bash
sudo systemctl daemon-reload
sudo systemctl restart liminal.timer
```

### 6. Stop and disable

```bash
# Stop a running scan (graceful — finishes current target first)
sudo systemctl stop liminal.service

# Disable the timer (no more scheduled runs)
sudo systemctl disable liminal.timer
sudo systemctl stop liminal.timer
```

### Systemd unit summary

| File | Purpose |
|---|---|
| `systemd/liminal.service` | `Type=oneshot` service — runs the scan to completion and exits |
| `systemd/liminal.timer` | Triggers the service on a schedule (`OnCalendar=daily`) |

The service reads credentials from `/opt/liminal/.env` via `EnvironmentFile=`. Logs go to both the systemd journal and `/var/log/liminal/scan.log`. `Restart=on-failure` with a 5-minute back-off guards against transient errors.

---

## False Positive Minimisation

This is a first-class concern. Every layer of the pipeline applies FP reduction.

```mermaid
flowchart LR
    RAW["Raw findings (11 scanner types)"]

    RAW --> L1["Layer 1 Scope validation Every result checked before it's saved"]
    L1 --> L2["Layer 2 In-tool FP filtering SSRF: OOB-only or re-verified XSS: unescaped context check CORS: credentials present Takeover: body fingerprint Exposure: content validation Service: response body validator Redirect: actual Location header Novel: 7-gate behavioural confirmation pipeline"]
    L2 --> L3["Layer 3 Re-verification pass Each finding re-tested before writing to DB"]
    L3 --> L4["Layer 4 AI triage FP likelihood scored per vulnerability class (all findings including novel)"]
    L4 --> OUT["Confirmed findings ready for submission"]
```

**Confidence scoring by signal type:**

| Signal | Confidence adjustment |
|--------|----------------------|
| OOB DNS/HTTP callback received (SSRF) | +3 (definitive) |
| Dalfox confirmed XSS | +2 |
| Unescaped reflection in known HTML context | +2 |
| CORS with `Access-Control-Allow-Credentials: true` | +2 |
| Subdomain takeover fingerprint matched | +2 |
| Open redirect: actual Location header match | +2 |
| Service: content validator passed (e.g. Elasticsearch cluster_name) | +2 |
| Internal IP found in response body | +2 |
| `.git/config` with `[core]` present | +2 |
| `.env` with `KEY=VALUE` present | +2 |
| JS secret pattern matched | +1 |
| AI-generated path: 2xx response | +1 |
| Error-based SSRF (not reproducible) | +1 FP indicator |
| Nuclei XSS without payload confirmation | +1 FP indicator |
| Informational/detection nuclei template | +2 FP indicators |
| CORS without credentials (wildcard) | +1 FP indicator |

Net score ≥ 2 → `fp_likelihood: low` → reported
Net score ≤ 0 → `fp_likelihood: high` → discarded

---

## Output & Reports

Each scan produces three report formats in `./results/<scan-id>/`:

### HTML Report

A self-contained Bootstrap 5 report with:
- Executive summary and statistics cards
- Per-finding cards with colour-coded severity borders
- CWE reference and CVSS 3.1 vector string per finding
- Ready-to-use `curl` PoC command for SSRF, CORS, and redirect findings
- Numbered PoC reproduction steps
- Remediation guidance
- Vulnerability chain highlights (e.g. SSRF → IMDS → credential theft, Kubelet unauth → container exec)
- Filterable findings table by severity

```
results/
└── 3f2a1b9c-4a2b-4c3d-8e5f-6a7b8c9d0e1f/
    ├── report.html     ← main report (open in browser)
    ├── report.md       ← markdown (paste into Jira/Confluence)
    └── report.json     ← machine-readable (integrate with other tools)
```

**CWE and CVSS coverage:**

| Vulnerability | CWE | CVSS Base |
|---|---|---|
| SSRF (OOB confirmed) | CWE-918 | 8.6 |
| SSRF (error-based) | CWE-918 | 6.5 |
| XSS (reflected, confirmed) | CWE-79 | 6.1 |
| CORS (with credentials) | CWE-942 | 8.1 |
| Subdomain takeover | CWE-284 | 8.2 |
| Open redirect (OAuth chain) | CWE-601 | 6.1 |
| Open redirect (plain) | CWE-601 | 4.7 |
| Exposed `.git` / `.env` | CWE-538 / CWE-312 | 7.5 |
| JS secret exposure | CWE-312 | 7.5 |
| Service: Docker daemon unauth | CWE-306 | 9.8 |
| Service: Kubernetes API unauth | CWE-306 | 9.8 |
| Service: etcd unauth | CWE-306 | 9.8 |
| Service: Kubelet API unauth | CWE-306 | 9.8 |
| Service: Elasticsearch unauth | CWE-306 | 8.5 |
| Service: Prometheus / Grafana | CWE-306 | 5.3–8.5 |
| AI-identified exposed path | CWE-200 | 5.3 |
| Novel: path-traversal (AI-detected) | CWE-22 | 7.5 |
| Novel: info-disclosure (AI-detected) | CWE-200 | 5.3 |
| Novel: debug-interface (AI-detected) | CWE-215 | 5.3 |
| Novel: auth-bypass (AI-detected) | CWE-284 | 7.5 |
| Novel: ssrf (AI-detected) | CWE-918 | 7.5 |
| Novel: xxe (AI-detected) | CWE-611 | 7.5 |

---

## Project Structure

```
liminal/
│
├── config/
│   ├── config.yaml              # single-target example configuration
│   └── targets-example.yaml     # multi-target + notifications example
│
├── systemd/
│   ├── liminal.service  # systemd oneshot service unit
│   └── liminal.timer    # systemd daily timer unit
│
├── bugbounty/
│   ├── core/
│   │   ├── config.py            # Pydantic config models + YAML loader
│   │   ├── notifier.py          # Notifier: Slack / Discord / webhook / SMTP delivery
│   │   ├── scope.py             # ScopeValidator (wildcard + CIDR)
│   │   ├── rate_limiter.py      # Semaphore + token-bucket rate limiting
│   │   ├── llm.py               # LLM provider abstraction (Claude, OpenAI, Groq, Ollama)
│   │   └── interactsh.py        # OOB callback client for SSRF confirmation
│   │
│   ├── tools/
│   │   ├── base.py              # BaseTool: subprocess runner, scope check, timing
│   │   ├── recon.py             # subfinder, amass, dnsx, httpx, naabu (104 ports)
│   │   ├── scanner.py           # nuclei (template scan)
│   │   ├── params.py            # ParamExtractor + arjun wrapper
│   │   ├── ssrf.py              # SSRFScanner (GET) + PostSSRFScanner (POST/JSON)
│   │   ├── xss.py               # ReflectionScanner + DalfoxScanner
│   │   ├── cors.py              # CORSScanner (5 bypass techniques)
│   │   ├── takeover.py          # TakeoverScanner (CNAME + 20+ fingerprints)
│   │   ├── redirect.py          # OpenRedirectScanner (52 params, OAuth detection)
│   │   ├── headers.py           # HeaderInjectionScanner (14 SSRF headers)
│   │   ├── js_scanner.py        # JSScanner (16 secret patterns + endpoint extraction)
│   │   ├── exposure.py          # ExposureScanner (8 categories + AI-generated paths)
│   │   ├── port_service_checker.py  # PortServiceChecker (22 services on open ports)
│   │   ├── ai_path_generator.py     # AIPathGenerator (LLM-reasoned path generation)
│   │   ├── anomaly.py               # AnomalyProber: 20 probes, divergence scoring (Phase 15)
│   │   ├── fuzzer.py            # ffuf, dalfox (legacy)
│   │   └── discovery.py         # gau, katana, waybackurls
│   │
│   ├── agents/
│   │   ├── base.py              # BaseAgent: provider-agnostic agentic loop
│   │   ├── planner.py           # PlannerAgent → ReconPlan (7-dimension scoring)
│   │   ├── analyzer.py          # AnalyzerAgent → triage, FP removal, chains
│   │   ├── anomaly_analyzer.py  # AnomalyAnalysisAgent: 3-stage novel finding confirmation
│   │   └── reporter.py          # ReporterAgent → CWE, CVSS, curl PoC, remediation
│   │
│   ├── pipeline/
│   │   ├── recon.py             # ReconPipeline: subdomain → live hosts → ports → URLs
│   │   ├── scan.py              # ScanPipeline: 15-phase vulnerability scan
│   │   └── orchestrator.py      # Orchestrator: end-to-end coordinator
│   │
│   ├── db/
│   │   ├── models.py            # Pydantic models: Finding, LiveHost, OpenPort, AnomalyPattern, ...
│   │   └── store.py             # DataStore: asyncpg PostgreSQL CRUD + deduplication + pattern learning
│   │
│   ├── reporting/
│   │   ├── generator.py         # ReportGenerator: Jinja2 → HTML/MD/JSON
│   │   └── templates/
│   │       ├── report.html.j2   # Bootstrap 5 HTML report
│   │       └── report.md.j2     # GitHub-flavoured Markdown report
│   │
│   └── main.py                  # Click CLI: scan, report, list-scans, check-tools
│
├── results/                     # Scan output (gitignored)
├── pyproject.toml
├── requirements.txt
└── .env.example                 # ANTHROPIC_API_KEY, OPENAI_API_KEY, GROQ_API_KEY,
                                 # DATABASE_URL, SLACK_WEBHOOK_URL, DISCORD_WEBHOOK_URL,
                                 # SMTP_PASSWORD (Ollama needs no key)
```

---

## Safety & Ethics

This framework is designed exclusively for **authorised security testing**:

- **Scope enforcement is mandatory** — every tool call scope-validates its target before execution. The `ScopeValidator` runs on every subdomain, URL, and scan result.
- **Only unauthenticated vectors** — no session tokens, cookies, or credentials are used or tested.
- **Non-destructive** — no DoS templates, no write operations, no data modification.
- **Rate limiting** — all tools run with configurable rate limits to avoid service disruption.
- **Secret redaction** — JS scanner truncates secrets to 8 characters in findings to avoid storing live credentials.

Only run this against targets where you have explicit written authorisation (bug bounty programme scope or signed penetration testing agreement).
