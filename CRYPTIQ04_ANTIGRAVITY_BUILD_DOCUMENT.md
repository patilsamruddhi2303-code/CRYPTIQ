# CRYPTIQ04 --- GraphOps

## Antigravity Complete Build Document

**Project:** HackFront India 2026 / Builder Lab\
**Team:** CRYPTIQ04\
**Theme:** Cybersecurity\
**Problem:** GraphOps --- Graph analytics for proactive threat hunting
and blast radius containment in security operations centers

## 1. Purpose

This is the source-of-truth build document for Antigravity. It is to be
used with the official problem statement, supplied cohort Activities
1--6, and the existing research pack.

Antigravity must autonomously: 1. execute Activities 1--6; 2. create all
required cohort artifacts; 3. perform evidence-backed research; 4.
challenge the product direction; 5. design and build the technical
system; 6. test and security-review it; 7. prepare the demo; 8. prepare
the final submission package.

There are only three mandatory human checkpoints.

## 2. Non-negotiable rules

### No fabrication

Never invent interviews, customer quotes, statistics, market numbers,
benchmarks, competitor capabilities, incidents, adoption, validation or
test results.

Label uncertain material as: - Evidence - Inference - Hypothesis -
Assumption - Pending validation

### Observed vs inferred

**OBSERVED:** represented by simulated telemetry.\
**AUTHORIZED/CAPABILITY:** configured permission or technical
reachability.\
**INFERRED/PREDICTED:** calculated by graph analysis.

Never present an inferred path as confirmed attacker activity.

### No production claims

This is a prototype. Do not claim production-grade detection, guaranteed
attack prediction, complete threat coverage, enterprise SOC readiness,
SIEM/SOAR replacement, or autonomous incident response.

### Explainability first

Use deterministic graph analysis before adding ML. Never call a rule
"AI".

## 3. Stack

Use unless a compelling blocker appears:

-   React + TypeScript + Vite
-   Tailwind CSS
-   Cytoscape.js
-   Lucide React
-   Python + FastAPI + Pydantic
-   Neo4j Community Edition + Cypher
-   Neo4j Graph Data Science Community Edition only where useful
-   deterministic Python synthetic data with fixed seed
-   Pytest + API/integration/end-to-end tests
-   Docker + Docker Compose
-   Git/GitHub

Architecture:

React UI → REST/JSON → FastAPI → GraphOps analysis → Neo4j/Cypher →
graph result → FastAPI JSON → React/Cytoscape.

Do not add Kafka, Spark, Kubernetes, microservices, PostgreSQL,
Elasticsearch or complex ML infrastructure unless a concrete requirement
proves it necessary.

## 4. Research baseline

Prefer: 1. official HackFront/problem statement; 2. supplied cohort
material; 3. official/primary cybersecurity sources; 4. official
technical documentation; 5. reputable secondary research.

Maintain: - `00_RESEARCH/source_register.md` -
`00_RESEARCH/claim_register.md` - `00_RESEARCH/competitor_analysis.md` -
`00_RESEARCH/insight_ledger.md` - `00_RESEARCH/interview_guide.md`

Current primary references to verify and record include NIST SP 800-61
Rev. 3, MITRE ATT&CK TA0008/T1021/T1021.001/T1210, Neo4j documentation,
Cytoscape.js documentation, FastAPI documentation and official
competitor documentation.

## 5. Activities 1--6

### Activity 1

Create `build-log/activity_1.md`.

Document: - Cybersecurity/GraphOps theme; - Problem V1; - intended build
direction; - AI leverage map; - human-owned decisions; - assumptions; -
initial success direction.

Problem V1 should remain a hypothesis: SOC analysts may struggle to
reconstruct connected incident context when users, endpoints, servers,
applications, vulnerabilities and network activity are distributed
across security data. Multi-hop lateral movement may make manual
reconstruction harder. Graph analysis may help connect context, attack
paths, blast radius and containment.

Do not present this as proven.

### Activity 2

Create `build-log/activity_2.md`.

Apply: - Delegation - Description - Discernment - Diligence

For every major AI task specify Context, Objective, Task, Constraints,
Output and Success criteria.

### Activity 3

Create `build-log/activity_3.md`.

Research a decision-critical question such as:

"What evidence supports graph-based connected context, attack-path and
blast-radius analysis for incident investigation/containment, and what
functionality already exists in competitors?"

First identify five questions that must be answered. Use primary
sources. Preserve raw output where technically possible. Never fabricate
it.

### Activity 4

Create `build-log/activity_4.md`.

Perform: - Five Whys; - two reframes; -
user/competitor/technical/operator critiques; - strongest objection; -
top assumptions ranked by project breakage; - 48-hour tests; - Problem
V2.

Problem V2 must specify user, situation, cost/current behavior and why
the current approach may be insufficient.

### Activity 5

Create `build-log/activity_5.md`.

Produce: - PMF hypothesis; - specific ICP; - five real examples if
available; - substitutes; - mechanism; - traceable opportunity
analysis; - Insight Ledger; - one core 3--4 action flow.

Initial ICP hypothesis: Tier-2 SOC analyst / incident responder handling
an alert where lateral movement or connected impact is suspected.
Challenge this hypothesis.

Never fabricate interviews. If field research is unavailable, create an
interview guide and mark validation pending.

### Activity 6

Create `build-log/activity_6.md` and `PROJECT_SPEC.md`.

PROJECT_SPEC must define: 1. what it is; 2. who uses it; 3. what it must
do; 4. what it does not do; 5. data sources; 6. constraints; 7.
definition of done; 8. remaining unknowns.

## 6. Product core

Target the validated version of:

**ALERT → CONTEXT → PATH → BLAST RADIUS → CHOKE POINT → ACTION**

Suggested demo: 1. select/simulate compromised entity; 2. show
incident-centered graph; 3. calculate 1/2/3-hop potential reach; 4.
highlight critical assets; 5. inspect a possible path; 6. explain path
risk; 7. identify a choke point; 8. simulate isolation; 9. recalculate
reachability; 10. show the change.

If Checkpoint 1 produces a better flow, use the validated flow.

## 7. Graph model

Potential nodes: User, IP, Endpoint, Server, Application, Vulnerability,
CriticalAsset, Process, SecurityEvent, Incident.

Potential relationships: LOGGED_IN_TO, CONNECTED_TO, ACCESSES, RUNS,
EXPLOITS, HAS_VULNERABILITY, CAN_REACH, AUTHORIZED_FOR,
OBSERVED_CONNECTION, RELATED_TO, COMPROMISED.

Only implement meaningful relationships.

Useful properties may include: - observed_at - source - confidence -
privilege - protocol - risk_weight - status

Keep observed/capability/inferred semantics explicit.

## 8. Graph analytics

### Blast radius

Support 1, 2 and 3 hop graph-derived reachability. Return hop distance,
entities, relationship semantics and critical assets. Cap
traversal/result size.

### Attack paths

Calculate real paths between selected source and target. Support path
explanation and documented weighted cost if weights are used.

### Choke points

Use path participation/centrality where useful. Betweenness centrality
is a strong candidate because it measures how often nodes lie on
shortest paths. Do not equate highest centrality automatically with the
best security control. Combine path impact with criticality, privilege,
vulnerability and containment impact.

### Containment

Implement simulation only: Before isolation → calculated reachability.
After simulated isolation → recalculated reachability.

### Anomalies

Use explainable structural heuristics first: - rare relationship; -
unexpected privileged relationship; - unusual path; - abnormal multi-hop
sequence.

Every anomaly needs an explanation. Do not call rules ML.

### Risk

If used, make it a reproducible heuristic using factors such as
severity, criticality, privilege, vulnerability, anomaly, recency and
mitigation. Label it: "Prototype heuristic risk score --- not a
production security rating."

## 9. MITRE ATT&CK

Use only when supported by simulated evidence.

Potential concepts: - TA0008 Lateral Movement - T1021 Remote Services -
T1021.001 RDP - T1210 Exploitation of Remote Services - Valid Accounts
where supported

An ATT&CK mapping does not prove that the technique occurred.

## 10. Synthetic data

Use a fixed seed.

Target approximately: - 25--60 users - 30--80 endpoints/servers - 10--25
applications - 5--15 critical assets - 15--40 vulnerabilities - 100--500
relationships/events

Required scenarios: 1. normal; 2. multi-hop lateral movement; 3.
blast-radius expansion; 4. choke point; 5. anomalous relationship; 6.
benign unusual path.

Each scenario must have expected outcomes/ground truth so tests can
verify it.

## 11. API

Use a small explicit REST API. Suggested endpoints:

-   `GET /health`
-   `GET /api/summary`
-   `GET /api/entities`
-   `GET /api/entities/{id}`
-   `GET /api/blast-radius/{entity_id}?hops=1|2|3`
-   `GET /api/paths?source_id=...&target_id=...`
-   `GET /api/choke-points`
-   `GET /api/anomalies`
-   `POST /api/containment/simulate`

Exact design may be improved. Never expose arbitrary Cypher.

Validate IDs, hop counts, limits and request bodies.

## 12. Frontend

Primary UI: - scenario/entity selector; - incident context; - graph; -
hop controls; - selected entity details; - path highlighting; - critical
assets; - choke-point explanation; - containment simulation; - anomaly
explanations; - legend.

The graph is the primary visual. Do not build unnecessary dashboards.

## 13. Project structure

Create a clean structure similar to:

``` text
00_RESEARCH/
build-log/
docs/
backend/
frontend/
data/
neo4j/
demo/
tests/
PROJECT_SPEC.md
README.md
BUILD-SUMMARY.md
ANTIGRAVITY_PROTOCOL.md
docker-compose.yml
.env.example
.gitignore
```

Useful docs: - `docs/architecture.md` - `docs/data_model.md` -
`docs/api.md` - `docs/security.md` - `docs/testing.md` -
`demo/demo_script.md`

## 14. Testing

Use synthetic ground truth to test: - 1/2/3-hop blast radius; - expected
paths; - choke-point candidates; - containment effect; - anomaly
detection; - API validation; - seed consistency.

Also intentionally test: - empty input; - invalid ID; - invalid hop
count; - oversized query; - missing database; - disconnected graph; - no
path; - duplicate data; - malformed request.

Do not fabricate test results.

## 15. Security

Must: - use parameterized Cypher; - validate inputs; - cap traversal; -
cap result size; - avoid arbitrary Cypher; - hide internal stack
traces; - use `.env.example`; - use `.gitignore`; - never commit
credentials; - use only synthetic/private-safe data; - simulate
containment only.

Pin compatible dependency versions. Do not rely on `latest`.

## 16. Docker

Create Docker Compose for: - frontend; - backend; - Neo4j.

Persist Neo4j appropriately. Document startup, shutdown and logs. Do not
use Enterprise-only features without a valid license.

## 17. Documentation

README must let a stranger: - understand the problem; - understand the
architecture; - configure the environment; - start Neo4j; - seed data; -
start backend; - start frontend; - run Docker; - run tests; - run demo.

Create `BUILD-SUMMARY.md` with: - theme; - original problem; - final
problem; - changes; - ICP; - product; - core flow; - built features; -
exclusions; - stack; - architecture; - evidence; - assumptions; -
limitations; - testing; - security; - next step.

## 18. Checkpoint 1 --- Product Direction

After Activities 1--5, STOP.

Report: - final Problem V2; - target user; - evidence; - assumptions; -
contradictions; - competitor findings; - proposed product; - core
flow; - differentiation; - biggest risks; - files to review.

Status: `REVIEW GATE 1 — PRODUCT DIRECTION` `WAITING FOR HUMAN REVIEW`

Do not proceed until `APPROVE`.

`REVISE` means revise, retest affected work and remain at Gate 1.
`REVIEW` means freeze. `STATUS` means report only. `STOP` means stop
safely.

## 19. Checkpoint 2 --- Technical Build

After Activity 6, PROJECT_SPEC, architecture, graph model, API, security
plan, synthetic scenarios and initial vertical slice, STOP.

Report: - GraphOps requirement mapping; - architecture; - graph model; -
blast-radius implementation; - attack-path implementation; - choke-point
implementation; - anomaly implementation; - containment simulation; -
testing plan/results available so far; - security risks; - exclusions; -
known blockers.

Status: `REVIEW GATE 2 — TECHNICAL BUILD` `WAITING FOR HUMAN REVIEW`

Do not proceed until `APPROVE`.

## 20. Checkpoint 3 --- Final Demo/Submission

After full implementation, testing and packaging, STOP.

Report: - working status; - demo status; - important test results; -
known limitations; - evidence status; - claims requiring caution; -
final files; - final ZIP path; - remaining risks.

Status: `REVIEW GATE 3 — FINAL DEMO / SUBMISSION`
`WAITING FOR HUMAN REVIEW`

Do not proceed until `APPROVE`.

## 21. Automatic blockers

Stop outside the three gates only for a genuine blocker: - required
human information is unavailable; - critical dependency cannot be
resolved; - evidence materially contradicts the product; - architecture
cannot satisfy a requirement; - serious security problem; - core
functionality cannot be implemented honestly.

Say: `BLOCKER — HUMAN INPUT REQUIRED`

Never invent a workaround.

## 22. Final quality review

Review as: - product manager; - SOC analyst; - cybersecurity reviewer; -
senior engineer; - security engineer; - hackathon judge; - skeptical
competitor.

Challenge: - unsupported claims; - misleading visuals; - fake AI; -
false precision; - broken paths; - meaningless centrality; - insecure
APIs; - fragile demo; - missing requirements.

Fix what can be fixed. Document what cannot.

## 23. Final package

After final approval create:

`CRYPTIQ04_Cybersecurity_Module1.zip`

Exclude: - `.env`; - secrets; - API keys; - credentials; -
node_modules; - virtual environments; - caches; - private data.

Include: - prototype; - README; - Build Logs; - Build Summary; -
PROJECT_SPEC; - research; - tests; - docs; - demo material.

Run a final secret/repository hygiene check.

## 24. Definition of complete

Do not say "complete" because files exist.

Complete means: - prototype starts; - Neo4j starts; - seed data loads; -
frontend connects; - backend responds; - core GraphOps flow works; -
tests pass or failures are honestly documented; - demo works; - no
secrets are included; - evidence and assumptions are separated; -
submission package is ready.

**Build less. Prove more. Never fake evidence or functionality.**
