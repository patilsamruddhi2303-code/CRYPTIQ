# Architecture Specification

## Overview
GraphOps operates as a decoupled, micro-containerized or locally executable web application. It connects an interactive analyst frontend with a high-performance Python FastAPI graph analysis service and a Neo4j graph database.

```
┌────────────────────────────────────────────────────────┐
│                   Analyst Browser                      │
│        React 19 + TypeScript + Vite + Tailwind         │
│               Cytoscape.js Graph Canvas                │
└───────────────────────────┬────────────────────────────┘
                            │ REST / JSON (HTTP)
                            │ Port 8000
┌───────────────────────────▼────────────────────────────┐
│                 FastAPI Backend Service                │
│    - Endpoint Routers & Pydantic Request Validation   │
│    - Hop-bounded Graph Traversal Engine                │
│    - Shortest & Multi-hop Path Solvers                 │
│    - Structural Betweenness Centrality Engine          │
│    - Dynamic Containment Simulation Engine             │
└───────────────────────────┬────────────────────────────┘
                            │ Bolt / Cypher Protocol
                            │ Port 7687 (or in-memory mock)
┌───────────────────────────▼────────────────────────────┐
│               Neo4j Community Graph Engine             │
│    - Labeled Property Graph Model                      │
│    - Seeded Deterministic Synthetic Telemetry          │
└────────────────────────────────────────────────────────┘
```

## Security & Architectural Boundaries
1. **Query Boundary**: The frontend never communicates directly with Neo4j. All queries are strictly mediated by parameterized FastAPI routes. Raw Cypher strings are prohibited from API parameters.
2. **Depth Boundary**: All traversals are bounded to a maximum depth of 3 hops to prevent traversal explosion and denial-of-service.
3. **Simulation Boundary**: Containment simulations run in non-destructive memory/transaction spaces. No external infrastructure, firewalls, EDR agents, or directories are called.
4. **Environment Isolation**: Database credentials and ports are managed via `.env` configuration with secure defaults.
