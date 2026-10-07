# Activity 2 – Delegation, Description, Discernment, Diligence

## Delegation Table
| AI Task | Context | Objective | Task | Constraints | Expected Output | Success Criteria |
|---------|---------|-----------|------|-------------|-----------------|------------------|
| **Synthetic Data Generation** | Python module for deterministic data | Produce reproducible graph entities & relationships | Generate users, endpoints, applications, assets, vulnerabilities, events with fixed seed | Fixed random seed (e.g., `SEED=42`), no external dependencies, data size within limits | CSV/JSON files under `data/seed/` and a Neo4j import script | Files created, reproducible across runs, counts within required ranges |
| **Project Scaffolding** | Antigravity code generation | Initialise repo structure, Docker Compose, CI placeholders | Run Antigravity CLI templates for `frontend/`, `backend/`, `docker-compose.yml` | Use only supported stack, no placeholder secrets | Directory tree created, files with TODO markers | Repository contains required top‑level directories and files |
| **Documentation Drafting** | Build‑log creation | Produce clear markdown artifacts for each activity | Write markdown files describing decisions, evidence, assumptions | Follow build‑document guidelines, no fabrication | `activity_*.md` files with required sections | Files pass linting, include labelled evidence/assumptions |
| **Graph Model Design** | Domain knowledge | Define node/relationship schema | Outline node types, properties, relationships in markdown | Align with GraphOps core flow, avoid unnecessary entities | `docs/data_model.md` with diagram and table | Review by SOC analyst (simulated) confirms relevance |
| **API Skeleton** | FastAPI framework | Provide stub endpoints for health, summary, entities, blast radius | Create `backend/app/main.py` with route definitions | Validate input types, no arbitrary Cypher exposure | API starts, returns 200 on health check | 

## Description
We delegate distinct responsibilities to AI‑assisted tasks while retaining critical decisions for human oversight. Each task includes clear constraints to keep the prototype honest and reproducible.

## Discernment
- **Synthetic data**: Human decides the range of entity counts (see Build Document). AI only populates within these bounds.
- **Graph model**: Human validates the relevance of each node/relationship to the core ALERT → CONTEXT → PATH → BLAST‑RADIUS → CHOKE‑POINT → ACTION flow.
- **API design**: Human ensures no exposure of raw Cypher queries; AI provides only endpoint signatures.

## Diligence
- All generated files contain `TODO` comments where human review is required.
- Each AI‑produced artifact is labelled with a timestamp and a provenance note.
- Version control: after each activity we will commit changes with descriptive messages.

---
*This activity documents the delegation framework and sets the foundation for subsequent engineering work.*
