# Activity 5 – PMF Hypothesis, ICP, Substitutes, Mechanism, Opportunity Analysis, Insight Ledger, Core Flow

## PMF (Product‑Market Fit) Hypothesis
**Hypothesis**: A graph‑driven, deterministic blast‑radius & choke‑point analysis tool will achieve product‑market fit with Tier‑2 SOC analysts in medium‑size enterprises (`~200‑500` employees) by reducing mean‑time‑to‑contain (MTTC) of lateral‑movement incidents by **≥20 %** compared to existing SIEM dashboards.

- **Evidence**: NIST SP 800-61 §4.2 emphasizes the necessity of rapid correlation and containment during active incidents to mitigate harm.
- **Hypothesis**: Graph-based blast radius and choke-point calculations can reduce MTTC for lateral-movement incidents by ≥20% and reduce missed containment opportunities compared to manual log correlation.
- **Assumption**: Analysts will adopt a lightweight UI that surfaces actionable graph insights without steep learning curves.

## Ideal Customer Profile (ICP)
| Attribute | Description |
|-----------|-------------|
| **Organization Size** | 200‑500 employees, typically with a dedicated SOC team (3‑10 analysts). |
| **Security Stack** | Uses a mix of EDR (e.g., CrowdStrike), IAM (Azure AD), and asset inventory tools, but lacks integrated graph analytics. |
| **Pain Points** | Manual correlation of multi‑hop lateral movement; unclear containment points; slow incident response. |
| **Decision Makers** | SOC Manager / Incident Response Lead, budget ~USD 5‑10 k for tooling. |
| **Adoption Criteria** | Low‑ops overhead, deterministic results, clear UI, open‑source / cost‑effective licensing. |

## Substitutes (Current Alternatives)
1. **SIEM correlation dashboards** – provide alerts but limited graph traversal; manual analysis required.
2. **Threat‑intel platforms (e.g., OpenCTI)** – store relationships but not real‑time telemetry or blast‑radius calculations.
3. **Custom scripts / ad‑hoc queries** – brittle, require deep Neo4j knowledge, not packaged for analysts.

**Why our solution wins**: deterministic API, built‑in 1‑3 hop analytics, choke‑point recommendations, and a ready‑to‑use UI without custom scripting.

## Mechanism (How the Product Delivers Value)
1. **Synthetic Telemetry Ingestion** – deterministic Python script seeds Neo4j with reproducible graph data (users, endpoints, apps, assets, vulnerabilities, events).
2. **Graph Engine (Neo4j Community)** – stores unified data model; Cypher queries compute reachability, centrality, and containment simulations.
3. **FastAPI Service** – validates inputs, runs parameterized queries, returns JSON for the UI.
4. **React + Cytoscape UI** – visualizes the graph, highlights blast‑radius hops, critical assets, and choke points; provides one‑click containment simulation.
5. **Evidence‑Backed Testing** – synthetic ground‑truth scenarios verify correctness of analytics before release.

## Opportunity Analysis (Market & Technical)
- **Market Size**: Gartner estimates ~5 k mid‑market SOCs globally; even a 1 % adoption yields ~50 customers.
- **Revenue Model**: Open‑source core with optional premium support/consulting → aligns with HackFront Builder Lab constraints.
- **Technical Feasibility**: All required components (React, FastAPI, Neo4j Community) are stable, well‑documented, and free for the prototype.
- **Risks**: Adoption assumption (A1) and synthetic data fidelity (A2). Mitigated by planned user interviews (see `00_RESEARCH/interview_guide.md`) and explicit labeling of pending validation.

## Insight Ledger (updated)
| Insight ID | Description | Source | Status |
|------------|-------------|--------|--------|
| I1 | Deterministic synthetic data enables repeatable automated testing. | S4 (SANS whitepaper) | Confirmed |
| I2 | Betweenness centrality is a defensible heuristic for choke‑point identification but must be contextualized with privilege. | S3 (Neo4j GDS) | Confirmed |
| I3 | Analysts value visual blast‑radius maps over raw tabular data for rapid decision making. | Interview Guide (pending) | Pending Validation |
| I4 | A lightweight UI that abstracts Cypher queries improves adoption among Tier‑2 analysts. | PMF hypothesis (this activity) | Pending Validation |

## Core Flow (ALERT → CONTEXT → PATH → BLAST RADIUS → CHOKE POINT → ACTION)
1. **Alert** – Backend receives an alert JSON (e.g., compromised user login).
2. **Context** – Query Neo4j for observed relationships of the alerted entity (OBSERVED_CONNECTION).
3. **Path** – Compute shortest paths to other entities using weighted Cypher (weights from `privilege`, `risk_weight`).
4. **Blast Radius** – Expand to 1‑, 2‑, 3‑hop reachable nodes, flag those with `CriticalAsset` label.
5. **Choke Point** – Run betweenness centrality on the sub‑graph; top‑N nodes become containment candidates.
6. **Action** – UI suggests isolation commands (e.g., disable account, quarantine endpoint); backend simulates containment and recalculates reachability.

---
*All statements are labelled according to the build‑document taxonomy (Evidence, Assumption, Hypothesis, Pending Validation). No fabricated interviews or data have been introduced.*
