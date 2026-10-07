# GraphOps — Decision Support System for Security Operations Centers

> **Theme**: Cybersecurity  
> **Problem**: GraphOps — Graph analytics for proactive threat hunting and blast radius containment in SOCs.  
> **Team**: CRYPTIQ04 (Module 1 Submission)

---

## 1. Executive Summary & Problem Framing
When investigating alerts with potential multi-hop lateral movement, SOC Tier-2 analysts struggle to reconstruct connected context across disparate tools. 

GraphOps delivers an interactive graph analytics experience that transforms:
$$\text{ALERT} \longrightarrow \text{CONTEXT \& PATH} \longrightarrow \text{BLAST RADIUS} \longrightarrow \text{CHOKE POINT} \longrightarrow \text{CONTAINMENT SIMULATION}$$

- **Dynamic Traversal Root**: Any entity can be selected as the root of investigation.
- **Computed Blast Radius**: Hop-bounded traversals (1, 2, and 3 hops) compute reachable attack surfaces and exposed crown jewels.
- **Attack Paths**: Traces shortest and multi-hop paths to sensitive assets across explicit relationship semantics.
- **Structural Choke Points**: Leverages path-participation betweenness centrality to identify critical bottlenecks.
- **Containment Simulation**: Recomputes reachability in real-time when an entity is isolated—demonstrating severed paths without touching live production infrastructure.

---

## 2. Architecture & Tech Stack
- **Frontend**: React 18 + TypeScript + Vite + Tailwind CSS + Cytoscape.js + Lucide React.
- **Backend**: Python 3 + FastAPI + Pydantic + Uvicorn.
- **Graph Analytics**: GraphOps Deterministic In-Memory Graph Engine (BFS bounded reachability, DFS hop-bounded path solver, Critical-Path Interception metric, and dynamic containment sub-graph reachability recalculation). Designed with clean repository abstractions to be graph-database (Neo4j) ready.
- **Synthetic Data**: Seeded deterministic topology generator (`seed=42`).
- **Containerization Scaffolding**: Docker Compose (`docker-compose.yml`) provided as development scaffolding. Primary verified execution path is local development.

---

## 3. Quickstart & Local Setup

### Option A: Local Development (FastAPI + Vite)

#### 1. Backend Service
```bash
# From workspace root
python -m pip install fastapi uvicorn pydantic requests
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```
API Documentation will be available at: `http://localhost:8000/docs`

#### 2. Frontend Application
```bash
cd frontend
npm install
npm run dev
```
Open `http://localhost:5173` in your browser.

---

### Option B: Docker Compose
```bash
docker-compose up --build
```
- Access UI: `http://localhost:5173`
- Access API: `http://localhost:8000`

---

## 4. Verification & Automated Testing
Run the backend test suite:
```bash
python -m unittest backend/test_analytics.py -v
```
All 6 core tests verify:
- Deterministic synthetic topology consistency across runs.
- Dynamic root traversal across 1, 2, and 3-hop blast radius.
- Automated attack path discovery to critical databases.
- Centrality-based choke-point identification.
- Dynamic reachability recalculation after simulated containment.
- Multi-path convergence isolation.

---

## 5. Security & Prototype Boundaries
- **Prototype Heuristic Risk Score**: Numerical risk indicators are deterministic heuristics, not certified production security ratings.
- **Simulation Boundary**: Containment actions are purely simulated models. Zero production network, firewall, or directory changes are enacted.
- **No Arbitrary Cypher**: All traversals are parameterized and bound to a maximum depth of 3 hops.
