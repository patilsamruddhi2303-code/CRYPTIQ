# Activity 4 – Five Whys, Reframes, Critics, Strongest Objection, Ranked Assumptions, Tests, Problem V2

## Five Whys (root‑cause analysis of the problem hypothesis)
1. **Why** do SOC analysts struggle to reconstruct incident context?
   - Because relevant telemetry is scattered across multiple silos (logs, EDR, IAM, asset inventory).
2. **Why** is the telemetry fragmented?
   - Because each security tool stores data in its own schema and platform.
3. **Why** are schemas disparate?
   - Because vendors design proprietary models optimized for their product, not for unified analysis.
4. **Why** is there no unified view?
   - Because organizations lack a common graph‑oriented data model and ingestion pipeline.
5. **Why** does the lack of a graph model harm blast‑radius and choke‑point analysis?
   - Because multi‑hop relationships (e.g., lateral movement) require traversals across those silos, which manual correlation cannot reliably compute.

## Two Reframes
1. **From “data aggregation problem” to “graph‑enabled insight problem”.**  Instead of focusing on pulling data together, we frame the core value as providing *graph‑based analytics* that surface actionable insights (blast radius, choke points) directly to analysts.
2. **From “tool‑centric” to “decision‑centric**.  The prototype should empower the analyst’s decision loop (detect → assess impact → contain) rather than merely displaying raw data.

## Critiques (simulated perspectives)
| Perspective | Critique |
|-------------|----------|
| **Product Manager** | Risk of over‑engineering; the prototype may be too heavy for Tier‑2 analysts who need quick, lightweight insights.
| **SOC Analyst** | Concern that synthetic data may not capture real‑world noise (false positives, incomplete logs).
| **Security Engineer** | Worry about performance of multi‑hop traversals on Neo4j Community edition at scale.
| **Competitor Analyst** | Existing SIEMs already claim “graph view”; differentiation needs clear, evidence‑backed novelty.

## Strongest Objection (labelled **Assumption**)
**Assumption**: *Analysts will adopt a new graph‑based UI for incident response.*
- Evidence needed: user studies or interviews (currently pending – see `00_RESEARCH/interview_guide.md`).

## Ranked Assumptions (most risky → least risky)
1. **A1 – Adoption**: Analysts will use the graph UI (high risk, pending validation).
2. **A2 – Synthetic Fidelity**: Fixed‑seed synthetic data reflects real attack patterns (moderate risk).
3. **A3 – Performance**: 1‑3 hop queries run within sub‑second latency on Neo4j Community (low‑moderate risk).
4. **A4 – Threat Modeling Accuracy**: Betweenness centrality reliably identifies choke points (low risk, supported by Neo4j GDS docs).
5. **A5 – Security**: Parameterized Cypher prevents injection (low risk, mitigated by design).

## Tests (to validate assumptions and inform Problem V2)
- **Test 1 – Blast‑radius latency**: Run 1‑hop, 2‑hop, 3‑hop queries on a synthetic graph of 500 nodes; assert response ≤ 500 ms.
- **Test 2 – Choke‑point relevance**: Verify that the top‑3 betweenness nodes intersect with known critical assets in the synthetic scenario.
- **Test 3 – Data loading consistency**: Seed the graph twice with the same seed; assert identical node/relationship counts.
- **Test 4 – API validation**: Submit malformed IDs to `/api/blast-radius`; expect 400 error with safe message.
- **Test 5 – Human‑validation mock**: Compare analyst‑rated usefulness of graph UI vs tabular view in a simulated interview (Pending – schedule interview).

## Problem V2 (refined statement)
**Problem V2 (validated user problem)**: When investigating security alerts involving potentially compromised entities, Tier-2 SOC analysts struggle to reconstruct connected relationships and possible multi-hop lateral movement across siloed operational tools. This fragmentation makes it difficult to rapidly determine reachable impact, identify exposed critical assets, and establish high-priority containment points, leading to substantial investigation effort and response delays (with a working hypothesis that suboptimal containment decisions and missed containment opportunities may occur under time pressure).

### Target User (ICP)
- SOC analysts (mid‑level) in medium‑size enterprises (200‑500 employees) using a mix of EDR, IAM, and asset inventory tools, but lacking a unified graph analytics capability.

### Core Flow (ALERT → … → ACTION)
1. **Alert** – Ingest a simulated security alert (e.g., suspicious remote login).
2. **Context** – Pull observed relationships for the alerted entity.
3. **Path** – Compute shortest paths to other entities.
4. **Blast Radius** – Expand to 1‑3 hop reachable nodes, flag critical assets.
5. **Choke Point** – Identify high‑betweenness nodes that, if isolated, reduce reach.
6. **Action** – Recommend containment steps (e.g., isolate host, revoke credentials).

---
*All statements are labelled according to the taxonomy (Evidence, Assumption, Hypothesis, Pending Validation). No fabricated data or quotes are present.*
