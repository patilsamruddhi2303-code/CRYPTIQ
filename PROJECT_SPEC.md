# PROJECT_SPEC.md — GraphOps

## 1. What It Is
GraphOps is an evidence-backed prototype decision-support tool for Security Operations Centers (SOC). It provides deterministic graph analytics for threat investigation, multi-hop blast radius containment, attack path tracing, and structural choke point analysis.

The system correlates entities across users, endpoints, servers, applications, vulnerabilities, and critical assets using explicit graph semantics:
- **OBSERVED**: Telemetry observed from simulated security logging (e.g. `LOGGED_IN_TO`, `CONNECTED_TO`).
- **AUTHORIZED/CAPABILITY**: Technical access permissions, network policies, or reachability (e.g. `CAN_REACH`, `AUTHORIZED_FOR`).
- **INFERRED/PREDICTED**: Graph-derived potential traversal paths (e.g. `EXPLOITS`, `ACCESSES`).

## 2. Target User (ICP)
- **Role**: Tier-2 SOC Analyst / Incident Responder.
- **Context**: Investigating security alerts with potential lateral movement across complex enterprise subnets.
- **Goal**: Rapidly determine what an attacker can reach within 1 to 3 hops, identify exposed high-value assets, and determine high-leverage choke points for simulated containment.

## 3. What It Must Do (Core Capabilities)
1. **Dynamic Investigation Focus**: Any entity in the graph can be chosen as the investigation root. Graph traversals, hop distances, and blast radius boundaries are calculated strictly from the selected entity.
2. **Blast Radius Calculation**: Compute deterministic 1-hop, 2-hop, and 3-hop reachability from the focus entity. Return reachable node counts, entity categories, and flag exposed `CriticalAsset` targets.
3. **Graph-Derived Attack Paths**: Calculate shortest and multi-hop paths from a source compromised entity to high-value assets using validated relationship semantics.
4. **Structural Choke-Point Identification**: Compute structural betweenness and path participation to find bottleneck entities whose removal disconnects the greatest volume of attack paths to critical assets.
5. **Dynamic Containment Simulation**: Simulate isolating/quarantining candidate nodes. Recompute reachability and attack paths dynamically across the graph to show exact severed paths and remaining exposed assets.
6. **Explainable Heuristics**: Provide structured, human-readable rationale for risk scores and anomaly indicators. Clearly label all risk scores as prototype heuristics.
7. **Deterministic Scenarios**: Support reproducible scenarios generated with a fixed seed (e.g., Scenario 2: Multi-hop Lateral Movement; Scenario 4: Choke Point Isolation).

## 4. What It Does NOT Do (Product Boundaries)
- **NO Production Detection**: Does not replace SIEM, EDR, or SOAR detection engines.
- **NO Real-World Network Containment**: Does not alter active firewalls, network switches, EDR agents, or Active Directory/IAM credentials.
- **NO Arbitrary Cypher Queries**: Does not expose ad-hoc or arbitrary database query execution to the frontend or user.
- **NO Black-Box Machine Learning**: Deterministic graph algorithms and rule-based heuristics must never be claimed as AI or deep learning.
- **NO Live Enterprise Ingestion**: Operates on curated, deterministic synthetic telemetry designed for testing and reproducible evaluation.

## 5. System Architecture
```
┌────────────────────────────────────────────────────────┐
│             React + TypeScript + Vite UI               │
│          Cytoscape.js Visualization + Tailwind         │
└───────────────────────────┬────────────────────────────┘
                            │ REST / JSON (FastAPI)
┌───────────────────────────▼────────────────────────────┐
│                  FastAPI Backend Server                │
│    Pydantic Schemas | Hop Traverser | Path Solver      │
│     Betweenness Centrality | Containment Simulator     │
└───────────────────────────┬────────────────────────────┘
                            │ Parameterized Cypher / Driver
┌───────────────────────────▼────────────────────────────┐
│            Neo4j Graph Engine / In-Memory Graph        │
│       Deterministic Synthetic Topology (Seed: 42)      │
└────────────────────────────────────────────────────────┘
```

## 6. Data Model & Schema
### Node Labels:
- `User`: Username, department, privilege level (`standard`, `privileged`, `domain_admin`).
- `Endpoint`: Hostname, IP, OS, zone (`workstation`, `jumpbox`, `bastion`).
- `Server`: Hostname, IP, role (`web`, `application`, `management`, `backup`).
- `Application`: App name, tier, service port.
- `CriticalAsset`: Asset name, category (`database`, `identity_provider`, `pki`), criticality (`High`, `Critical`).
- `Vulnerability`: CVE ID, CVSS score, severity (`High`, `Critical`).

### Relationships (with Explicit Semantics):
- `LOGGED_IN_TO` (`OBSERVED`)
- `CONNECTED_TO` (`OBSERVED`)
- `AUTHORIZED_FOR` (`AUTHORIZED/CAPABILITY`)
- `CAN_REACH` (`AUTHORIZED/CAPABILITY`)
- `ACCESSES` (`AUTHORIZED/CAPABILITY`)
- `HAS_VULNERABILITY` (`CAPABILITY`)
- `EXPLOITS` (`INFERRED/PREDICTED`)

## 7. API Specification
- `GET /health` — Service status and graph engine connectivity.
- `GET /api/summary` — Entity counts, relationship counts, active scenarios.
- `GET /api/scenarios` — Available deterministic scenarios with ground-truth definitions.
- `POST /api/scenarios/load` — Load/switch active scenario topology.
- `GET /api/entities` — Query/filter entities for selection.
- `GET /api/entities/{entity_id}` — Entity details, metadata, and connected edges.
- `GET /api/blast-radius/{entity_id}?hops=1|2|3` — Traversal reachability, distances, and exposed critical assets.
- `GET /api/paths?source_id={source}&target_id={target}` — Calculated attack paths between source and destination.
- `GET /api/choke-points?source_id={source}` — Structural betweenness centrality candidates and affected paths.
- `POST /api/containment/simulate` — Submit `{ isolated_node_id, source_id }` and receive recalculated reachability diff.
- `GET /api/anomalies` — Rule-based structural anomalies with plain-text explanation.

## 8. Definition of Done
1. Deterministic synthetic data generator creates reproducible graph topologies matching specified entity counts.
2. Backend provides all required endpoints with strict Pydantic validation, bounded hops (1–3), and error handling.
3. Choke points and containment simulation dynamically calculate graph metric deltas (before vs. after isolation).
4. Interactive frontend allows changing focus entity, adjusting hop depth, tracing attack paths, inspecting entities, and toggling simulated containment.
5. Automated test suite (Pytest) passes all tests for graph traversals, choke points, containment reachability, and API boundaries.
6. Local development and Docker Compose instructions enable zero-friction execution.
7. Clear documentation distinguishing evidence, hypotheses, and assumptions.
