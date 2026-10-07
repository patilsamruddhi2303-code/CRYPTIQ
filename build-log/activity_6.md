# Activity 6 – Build & Systemize: Specification, Architecture, and Vertical Slice

## 1. Context & Objective
Activity 6 transforms the validated product direction (Checkpoint 1) into an executable technical system:
- Implements the complete graph data model, deterministic synthetic dataset, FastAPI REST backend, and React/Cytoscape interactive frontend.
- Delivers the minimal vertical slices:
  - **Scenario 2 (Multi-hop Lateral Movement)**: `Compromised User` → `Jumpbox Endpoint` → `App Server` → `Critical Database`.
  - **Scenario 4 (Choke Point Isolation)**: Dynamic betweenness centrality identifying the bottleneck node, simulated isolation, and genuine graph reachability recalculation.

## 2. Specification & Design Deliverables
- [`PROJECT_SPEC.md`](../PROJECT_SPEC.md): Comprehensive functional requirements, data contracts, and definition of done.
- [`docs/architecture.md`](../docs/architecture.md): Component interactions, network boundaries, and query flows.
- [`docs/data_model.md`](../docs/data_model.md): Explicit schema separating `OBSERVED`, `AUTHORIZED/CAPABILITY`, and `INFERRED/PREDICTED` semantics.
- [`data/generator.py`](../backend/generator.py): Deterministic Python synthetic graph generator using fixed seed (`seed=42`).

## 3. Ground Truth Scenarios
| Scenario ID | Name | Focus Entity | Target Critical Asset | Key Choke Point | Expected Reach (3 Hops) | Expected Post-Containment |
|-------------|------|--------------|-----------------------|-----------------|-------------------------|---------------------------|
| `scenario_lateral` | Multi-hop Lateral Movement | `user.sneha` | `finance-db`, `crown-jewel-db` | `ws-17-ops` | 7 reachable nodes | 0 paths to DBs severed |
| `scenario_chokepoint`| Multi-Path Choke Point | `user.sneha` | `crown-jewel-db`, `identity-srv` | `bastion-mgmt` | 8 reachable nodes | Critical assets isolated |
| `scenario_benign` | Benign Maintenance | `user.sneha` | None | `backup-node` | 2 reachable nodes | 0 critical assets exposed |

## 4. Technical Constraints Maintained
- No arbitrary Cypher execution allowed from the frontend or API parameters.
- Bounded traversals: Maximum hop depth capped at 3 hops.
- Containment is strictly simulated: Graph reachability is recomputed in memory or Cypher transaction without altering live infrastructure.
- Zero fabrication: Risk scores are explicitly labeled as prototype heuristics.

## 5. Verification Plan
- Unit and integration tests in `backend/tests/test_analytics.py`:
  - Test deterministic seeding.
  - Test hop-bounded blast radius calculation (1, 2, 3 hops).
  - Test attack path discovery between source and destination.
  - Test betweenness centrality calculation on choke points.
  - Test dynamic containment reachability collapse.
  - Test API input validation (invalid IDs, out-of-bound hops).
