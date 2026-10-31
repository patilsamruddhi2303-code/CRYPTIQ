# GraphOps — Incident-Centered Exposure & Containment Intelligence
## Decision-Support Prototype for Tier-2 SOC Analysts & Incident Responders

> **HackFront India 2026** — Cybersecurity / GraphOps Problem Statement  
> **Repository**: CRYPTIQ04  
> **Core Concept**: `ALERT → CONTEXT → PATH → BLAST RADIUS → CHOKE POINT → WHAT-IF CONTAINMENT → REMAINING EXPOSURE → HUMAN DECISION`

---

## 1. Executive Summary & Problem Framing

When security alerts trigger, modern Security Operations Centers (SOCs) are inundated with isolated event logs from disparate tools: EDR alerts on an endpoint, IAM authentications in Okta, firewall sessions in network logs, and unpatched CVEs in vulnerability scanners.

**The Analyst's Core Dilemma**:
An isolated alert does not reveal multi-hop reachability. An analyst investigating a compromised workstation cannot easily see:
1. What critical database or Active Directory assets could the attacker reach within 1 to 3 hops?
2. Which intermediate jumpboxes or servers act as structural choke points?
3. If we isolate a machine, does that actually eliminate exposure, or does an unmonitored alternate route (e.g., via an external VPN or secondary API gateway) leave the asset exposed?
4. What remains exposed after a proposed containment action?

**GraphOps solves this with decision-support intelligence**:
> Rather than replacing SIEMs or executing autonomous actions, GraphOps normalizes multi-source telemetry into a connected graph model, traces dynamic attack paths, calculates bounded blast radius, identifies structural choke points, and lets the analyst run **what-if containment simulations** to compare options before taking action.

---

## 2. Master Product Workflow

The application guides the Tier-2 analyst through an explainable 8-stage operational flow:

```text
ALERT ───────────► High-priority incident detected with suspected lateral movement
  │
  ▼
CONTEXT ─────────► Correlate IAM, EDR, Network, CMDB, and Vulnerability telemetry
  │
  ▼
PATH ────────────► Trace hop-bounded attack paths to high-value Crown Jewels
  │
  ▼
BLAST RADIUS ────► Traversal reachability dynamically calculated across 1, 2, or 3 hops
  │
  ▼
CHOKE POINT ─────► Structural bottleneck ranked by Critical-Path Interception %
  │
  ▼
WHAT-IF CONTAIN ─► Recompute graph reachability with candidate node isolated
  │
  ▼
REMAINING EXPOSE ─► Detect alternate paths & itemize protected vs exposed assets
  │
  ▼
HUMAN DECISION ──► Decision support record requiring human-in-the-loop review
```

---

## 3. Product Positioning & Anti-Fabrication Principles

To maintain strict technical credibility and alignment with modern industry standards:

- **Decision Support, Not Autonomous SOC**: The system never enacts live firewall rules, IAM modifications, or endpoint quarantines. All containment actions are graph simulations.
- **Explainable Heuristics, Not "AI"**: Numerical risk scores and anomaly detection rules are deterministic heuristics derived from entity privilege, target criticality, and path length. They are explicitly labeled as prototype heuristics.
- **In-Memory Analytics Engine**: The current prototype leverages an optimized, deterministic Python graph analytics engine (BFS bounded reachability, DFS acyclic path solver, and dynamic containment sub-graph reachability recalculation). Neo4j is documented as the natural production database evolution.
- **Deterministic Synthetic Telemetry**: All environments use a deterministic seed (`seed=42`) modeling an interconnected enterprise network (~75 nodes) with realistic timestamps and multi-source telemetry.

---

## 4. Multi-Source Telemetry & Relationship Semantics

GraphOps normalizes heterogeneous enterprise telemetry into explicit relationship semantics:

| Relationship Category | Semantic Meaning | Visual Styling | Example Telemetry Sources |
|---|---|---|---|
| **OBSERVED** | Direct telemetry observed in security event logs | Solid cyan line (`#38bdf8`) | EDR process execution, Okta IAM interactive logon, Zeek/NetFlow sessions |
| **AUTHORIZED** | Permitted access capability, network policy, or role grant | Dashed slate line (`#94a3b8`) | CyberArk PAM vault sessions, Active Directory groups, firewall routes, DB ACLs |
| **INFERRED** | Graph-reasoned traversal potential or vulnerability pivot | Dotted amber line (`#eab308`) | Tenable/Qualys unpatched CVE vulnerability links, exploit reachability |

---

## 5. System Architecture

```text
                     MULTI-SOURCE TELEMETRY
          ┌──────────────┬──────────────┬──────────────┐
          │     IAM      │     EDR      │   NETWORK    │
          └──────┬───────┴──────┬───────┴──────┬───────┘
                 │              │              │
                 └──────────────┼──────────────┘
                                ▼
                    TELEMETRY NORMALIZATION
                                ▼
                     CONNECTED GRAPH MODEL
                 (Nodes: Users, Endpoints, Servers,
                 Applications, Crown Jewels, CVEs)
                                ▼
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
     OBSERVED               AUTHORIZED               INFERRED
  (Direct Events)        (Access Policies)       (Analytic Paths)
        │                       │                       │
        └───────────────────────┼───────────────────────┘
                                ▼
                     GRAPH ANALYTICS ENGINE
       ┌────────────────────────┼────────────────────────┐
       ▼                        ▼                        ▼
  ATTACK PATHS             BLAST RADIUS             CHOKE POINTS
 (Hop-Bounded DFS)       (BFS 1, 2, 3 Hops)      (Path Interception %)
       │                        │                        │
       └────────────────────────┼────────────────────────┘
                                ▼
                      CONTAINMENT ENGINE
                                ▼
                     WHAT-IF SIMULATION
                                ▼
                    BEFORE / AFTER DELTAS
                                ▼
                 ALTERNATE PATH & REMAINING EXPOSURE
                                ▼
                    ANALYST DECISION RECORD
```

---

## 6. Supported Scenarios

| Scenario ID | Name | Focus Root | Primary Target | Expected Choke Point | Key Demonstration Feature |
|---|---|---|---|---|---|
| `scenario_lateral` | **Multi-hop Lateral Movement (Flagship)** | `user.sneha` | `finance-db` | `bastion-mgmt` | **Surprise Alternate Path**: Isolating `bastion-mgmt` severs primary path, but `finance-db` remains exposed via `vpn-gateway`. Isolating `ws-17-ops` severs all paths. |
| `scenario_chokepoint` | Multi-Path Convergence | `user.sneha` | `crown-jewel-db` | `bastion-mgmt` | Multiple independent user sessions funnel through single management jumpbox before reaching core database. |
| `scenario_alternate_path` | Alternate Path & Residual Exposure | `user.sneha` | `finance-db` | `bastion-mgmt` | Explicitly demonstrates incomplete containment alert when dual routes exist. |
| `scenario_blast_radius` | High Connectivity Blast Radius | `user.ananya` | `identity-srv` | `bastion-mgmt` | Exponential reachability fanout from Domain Admin credentials across multiple enclaves. |
| `scenario_benign` | Benign Maintenance Activity | `user.sneha` | *None* | `backup-node` | Off-hours backup snapshot job. Risk score remains Low (24/100) with 0 critical assets exposed. |
| `scenario_normal` | Normal Operations Baseline | `user.vikram` | *None* | `ws-fin-02` | Standard enterprise workday operations without security alert triggers. Risk score: 15/100. |

---

## 7. Quickstart & Run Instructions

### Prerequisites
- Python 3.10+ (tested on Python 3.14)
- Node.js 18+ and npm

### 1. Backend Service
```bash
# Navigate to repository root
cd CRYPTIQ-GraphOPS

# Install backend dependencies
python -m pip install fastapi uvicorn pydantic httpx pytest

# Start FastAPI server
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```
- API Swagger Documentation: `http://localhost:8000/docs`
- Health Endpoint: `http://localhost:8000/health`

### 2. Frontend Application
```bash
# In a separate terminal, navigate to frontend
cd CRYPTIQ-GraphOPS/frontend

# Install dependencies
npm install

# Start development server
npm run dev
```
- Open your browser at: `http://localhost:5173`

### 3. Production Frontend Build
```bash
cd CRYPTIQ-GraphOPS/frontend
npm run build
```

---

## 8. Verification & Test Suite

Run the automated test suite covering graph traversals, choke points, containment simulation, alternate path detection, candidate comparisons, and API endpoints:

```bash
# From repository root
python -m pytest backend/ -v
```

**Test Coverage Summary (24 Tests Passed)**:
- Deterministic synthetic topology consistency (`seed=42`).
- Root differentiation (different roots yield distinct blast radiuses).
- Hop depth bounds strictly enforced (1, 2, 3 hops).
- Attack path discovery and path score ranking.
- Zero critical paths in benign scenario.
- Critical-Path Interception calculation.
- Itemized critical asset exposure status (`PROTECTED` vs `STILL EXPOSED`).
- Partial containment isolation.
- **Alternate path detection on jumpbox isolation**.
- Containment candidate comparison matrix generation.
- Analyst decision record structure and human-in-the-loop requirement.
- Multi-scenario risk score differentiation (benign < 30 vs lateral >= 75).
- Performance latency measurement (`compute_time_ms`).
- API health, scenarios, timeline, entity inspection, and input validation rejection.
- Choke-points endpoint API schema and response verification.
- Anomalies endpoint API schema and response verification.
- Summary statistics endpoint API schema and metric verification.

---

## 9. Limitations & Future Roadmap

### Current Prototype Scope
- In-memory deterministic graph model (optimized for reproducible demo and sub-10ms evaluation).
- Fixed maximum hop boundary of 3 hops to maintain analyst cognitive focus and graph readability.
- Operational business disruption (e.g., uptime impact of isolating a shared host) is not modeled.

### Production Evolution Roadmap
- Integration with graph databases (Neo4j / Amazon Neptune) using parameterized Cypher queries.
- Live telemetry streaming connectors for Snowflake / Datadog / Splunk SIEM.
- EDR API integrations (CrowdStrike Falcon / Microsoft Defender) for analyst-approved containment execution.
- Automated service dependency mapping (CMDB) to evaluate business disruption risk before isolation.

---

## 10. Repository Layout Structure

The codebase is organized into cleanly partitioned, self-contained directories:

```text
CRYPTIQ-GraphOPS/
├── backend/                  # FastAPI graph analytics & containment engine
│   ├── engine.py             # Graph data structures, BFS/DFS, choke points, simulation
│   ├── generator.py          # Deterministic multi-scenario enterprise generator (seed=42)
│   ├── main.py               # REST API endpoints & CORS middleware
│   ├── test_analytics.py     # 24 automated unit and integration tests
│   ├── Dockerfile            # Container definition for backend
│   └── requirements.txt      # Backend Python dependencies
├── frontend/                 # React 18 + TypeScript + Vite + Cytoscape.js UI
│   ├── src/
│   │   ├── App.tsx           # Master investigation workspace & layout
│   │   ├── index.css         # Cyberpunk/enterprise SOC Tailwind styling
│   │   └── main.tsx          # React application entry point
│   ├── package.json          # Node dependencies and scripts
│   ├── tsconfig.json         # TypeScript configuration
│   ├── vite.config.ts        # Vite build tool configuration
│   └── Dockerfile            # Container definition for frontend
├── docs/                     # Architecture, specifications & demo scripts
│   ├── architecture.md       # Graph engine & containment mechanics
│   ├── data_model.md         # Node/edge schemas and relationship semantics
│   └── DEMO_SCRIPT.md        # 5-minute judge demonstration walkthrough
├── PROJECT_SPEC.md           # Engineering specifications & boundaries
├── README.md                 # Primary project documentation & quickstart
├── .gitignore                # Git ignore rules for node_modules, pycache, etc.
├── .env.example              # Sample environment configuration
└── docker-compose.yml        # Multi-container local execution specification
```
