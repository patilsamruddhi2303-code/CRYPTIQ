# Activity 1 – Problem Definition & Initial Direction

## Theme
Cybersecurity – GraphOps for proactive threat hunting and blast‑radius containment.

## Problem V1 (hypothesis)
SOC analysts struggle to reconstruct incident context when users, endpoints, servers, applications, vulnerabilities and network activity are distributed across multiple data sources. Manual, multi‑hop lateral‑movement analysis is time‑consuming and error‑prone.

## Intended Build Direction
Create a prototype that ingests synthetic telemetry into Neo4j, builds a unified graph of entities and relationships, and provides analytics for:
- Alert → Context → Path → Blast radius → Choke point → Action
- 1‑, 2‑, 3‑hop reachability
- Attack‑path enumeration
- Containment simulation

## AI Leverage Map
| AI Task | Leveraged By | Rationale |
|---------|--------------|-----------|
| Synthetic data generation (Python) | Create deterministic seed‑based test data | Guarantees reproducible scenarios |
| Code scaffolding (Antigravity) | Initialise project structure, Docker files, API stubs | Accelerates setup |
| Documentation drafting | Build‑log entries, README, BUILD‑SUMMARY | Ensures consistency |

## Human‑Owned Decisions
- Define core graph model (node/relationship types) – **human**
- Select which MITRE ATT&CK techniques to simulate – **human**
- Determine evaluation metrics for blast‑radius & choke‑point – **human**

## Assumptions (labelled as **Assumption**) 
- Synthetic data accurately reflects common enterprise topology.
- Fixed random seed yields deterministic graph for testing.
- Neo4j Community edition is sufficient for required traversals.

## Initial Success Direction (hypothesis)
If the prototype can generate a graph from synthetic data and correctly compute 1‑3 hop reachability, then it demonstrates the core value of GraphOps for SOC analysts.
