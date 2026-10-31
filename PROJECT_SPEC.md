# PROJECT_SPEC.md — GraphOps Master Specification
## Incident-Centered Exposure & Containment Intelligence

---

## 1. Product Definition & Vision
**GraphOps** is an evidence-backed decision-support system for Security Operations Centers (SOC). It provides deterministic graph analytics for incident investigation, multi-hop blast radius calculation, attack path tracing, choke-point identification, and what-if containment simulation.

The system correlates heterogeneous security telemetry across users, endpoints, servers, applications, vulnerabilities, and critical database assets using explicit graph semantics:
- **OBSERVED**: Telemetry directly observed from simulated security logging (`LOGGED_IN_TO`, `CONNECTED_TO`).
- **AUTHORIZED/CAPABILITY**: Technical access permissions, network policies, or reachability (`CAN_REACH`, `AUTHORIZED_FOR`, `ACCESSES`).
- **INFERRED/PREDICTED**: Graph-derived potential traversal paths or exploitability (`HAS_VULNERABILITY`, `EXPLOITS`).

---

## 2. Target User (Ideal Customer Profile)
- **Primary Persona**: Tier-2 SOC Analyst / Incident Responder.
- **Operational Context**: Investigating high-severity alerts with suspected lateral movement across hybrid enterprise subnets.
- **Core Need**: Rapidly determine what an attacker could reach within 1 to 3 hops, identify exposed high-value crown jewels, identify structural choke points, and test containment actions before committing to operational changes.

---

## 3. Core Operational Capabilities
1. **Dynamic Investigation Focus**: Any entity in the graph can be selected as the root of investigation. Graph traversals, hop distances, and blast radius boundaries are calculated strictly from the selected entity.
2. **Hop-Bounded Blast Radius**: Deterministic BFS traversals strictly bounded to 1, 2, or 3 hops. Returns total reachability counts, categorical entity breakdown (Users, Endpoints, Servers, Applications, CriticalAssets, Vulnerabilities), and exposed critical assets.
3. **Hop-Bounded Attack Paths**: Calculates all acyclic simple directed paths from the focus root to reachable critical assets within the requested hop limit. Enriches each path with step-by-step nodes, relationship categories, CVEs, and heuristic path scores.
4. **Structural Choke-Point Analysis**: Calculates **Critical-Path Interception** (percentage of active critical attack paths that traverse the candidate entity). Identifies downstream critical assets, reachability reduction percentage, and remaining alternate paths.
5. **What-If Containment Simulation**: Simulates isolating candidate entities. Dynamically recomputes post-containment reachability, active paths, severed paths, and remaining alternate paths.
6. **Alternate Path & Residual Exposure Detection**: Explicitly identifies when a primary path is severed but a critical asset remains reachable via an alternate route (e.g., via VPN or secondary jumpbox).
7. **Candidate Comparison Matrix**: Provides a side-by-side comparison matrix evaluating multiple containment candidates before taking action.
8. **Analyst Decision Record**: Generates a structured decision support summary emphasizing that final operational authorization requires human review.
9. **Explainable Heuristics & Timeline**: Provides plain-language explanations for all heuristic risk scores and chronological telemetry timelines. All risk ratings are clearly labeled as prototype heuristics.
10. **Deterministic Scenarios**: Supports 6 deterministic scenarios generated from a fixed seed (`seed=42`).

---

## 4. Product Boundaries & Non-Goals
- **NO Autonomous Containment**: The system never executes active network changes, firewall blocklists, or endpoint quarantines.
- **NO SIEM/EDR Replacement**: GraphOps is a decision-support layer that correlates existing telemetry, not an ingestion or detection pipeline replacement.
- **NO Black-Box Machine Learning**: Deterministic graph algorithms and rule-based heuristics must never be claimed as artificial intelligence or deep learning.
- **NO Arbitrary Cypher Execution**: Traversal depth and query parameters are strictly bounded (1–3 hops) and validated via Pydantic schemas.

---

## 5. System Architecture
```text
┌────────────────────────────────────────────────────────┐
│             React 18 + TypeScript + Vite UI            │
│         Cytoscape.js Topology Canvas + Tailwind        │
└───────────────────────────┬────────────────────────────┘
                            │ REST / JSON (FastAPI)
┌───────────────────────────▼────────────────────────────┐
│                  FastAPI Backend Server                │
│    Pydantic Schemas | Hop Traverser | Path Solver      │
│   Critical-Path Interception | Containment Simulator   │
└───────────────────────────┬────────────────────────────┘
                            │ Parameterized Calls / In-Memory Driver
┌───────────────────────────▼────────────────────────────┐
│         GraphOps Deterministic Graph Analytics         │
│       Synthetic Enterprise Topology (Seed: 42)         │
│          (Production Evolution Target: Neo4j)          │
└────────────────────────────────────────────────────────┘
```

---

## 6. Data Model & Node Schema
### Node Types:
- `User`: Username, department, privilege level (`standard`, `privileged`, `domain_admin`), owner email.
- `Endpoint`: Hostname, IP, OS, zone (`workstation`, `jumpbox`, `bastion`, `dmz`, `iot`), owner pool.
- `Server`: Hostname, IP, role (`application`, `management`, `backup`, `dns`, `monitoring`), zone, criticality.
- `Application`: Name, tier (`Tier-1`, `Tier-2`, `Tier-3`), service port, owner.
- `CriticalAsset`: Name, category (`database`, `idp`, `pki`), criticality (`Critical`, `High`), data classification.
- `Vulnerability`: CVE ID, CVSS score, severity (`Critical`, `High`), description.

### Relationships (Explicit Semantics):
- `LOGGED_IN_TO` (`OBSERVED`): IAM interactive user login.
- `CONNECTED_TO` (`OBSERVED`): EDR or network connection.
- `AUTHORIZED_FOR` (`AUTHORIZED`): Configured privilege or PAM permission.
- `CAN_REACH` (`AUTHORIZED`): Firewall route or network reachability.
- `ACCESSES` (`AUTHORIZED`): Application to database capability.
- `HAS_VULNERABILITY` (`INFERRED`): Host vulnerability scanner finding.
- `EXPLOITS` (`INFERRED`): Potential remote exploitation path.

---

## 7. API Specification
- `GET /health` — Service health, active scenario, node/edge counts, and engine architecture.
- `GET /api/summary` — Active incident metadata, trigger event, heuristic risk score, and graph metrics.
- `GET /api/scenarios` — Available deterministic scenarios with ground-truth definitions.
- `POST /api/scenarios/load?scenario_id={id}` — Switch active scenario topology.
- `GET /api/incidents` — High-level incident registry across scenarios.
- `GET /api/incidents/{incident_id}` — Detailed incident header, MITRE matrix, and risk breakdown.
- `GET /api/timeline` — Chronological simulated telemetry event stream for current incident.
- `GET /api/entities?type={optional}` — List entities with optional type filter.
- `GET /api/entities/{entity_id}` — Entity details, metadata, connected edges, and heuristic risk contributors.
- `GET /api/blast-radius/{entity_id}?hops=1|2|3` — Traversal reachability, distances, and category breakdown.
- `GET /api/paths?source_id={source}&hops=1|2|3` — Hop-bounded attack paths to critical assets with scores.
- `GET /api/choke-points?source_id={source}&hops=1|2|3` — Structural choke points ranked by Critical-Path Interception.
- `POST /api/containment/simulate` — Submit `{ source_id, candidate_node_id, max_hops }` and receive before/after delta, severed paths, alternate path alert, itemized asset statuses, and analyst decision record.
- `GET /api/containment/compare?source_id={source}&hops=1|2|3` — Multi-candidate comparison matrix.
- `GET /api/anomalies` — Rule-based structural anomalies with plain-text explanation.

---

## 8. Definition of Done
1. Deterministic synthetic data generator creates reproducible enterprise topologies (`seed=42`).
2. Backend provides all endpoints with strict Pydantic validation, bounded hops (1–3), and error handling.
3. Choke points and containment simulation dynamically calculate graph metric deltas (before vs. after isolation).
4. Alternate path detection explicitly identifies residual exposure when primary paths are severed.
5. Interactive frontend allows changing focus entity, adjusting hop depth, tracing attack paths, inspecting entities, filtering graph elements, and toggling simulated containment.
6. Automated test suite (Pytest) passes 21 unit, integration, and API tests.
7. Clear documentation distinguishing evidence, hypotheses, and assumptions.
