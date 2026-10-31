# DEMO_SCRIPT.md — GraphOps Master Demo Script
## HackFront India 2026 — Judge-Ready Presentation Guide

---

## 1. 30-Second Elevator Pitch
> *"Security alerts tell analysts what happened on a single machine, but the true impact depends on the connected graph of relationships between identities, endpoints, servers, and high-value databases. **GraphOps** transforms isolated alerts into an explainable attack path and blast radius analysis, then lets the analyst simulate containment actions in real-time. By testing containment before taking action, analysts discover hidden alternate pathways and make informed, evidence-backed decisions."*

---

## 2. 1-Minute Executive Explanation
> *"In a typical Tier-2 SOC investigation, when an alert flags suspicious lateral movement on a workstation, the analyst has to answer three critical questions:*
> 1. *What critical databases or crown jewels can this compromised identity reach?*
> 2. *Where are the structural choke points where containment would have the highest leverage?*
> 3. *If we isolate a machine, does that actually protect our assets, or is there an unmonitored alternate route?*
>
> *GraphOps answers these questions directly. It correlates IAM, EDR, Network, and Vulnerability data into a graph, traces multi-hop attack paths to high-value assets, identifies choke points using Critical-Path Interception, and runs what-if containment simulations. Crucially, it highlights remaining exposure and alternate paths, ensuring the human analyst has the complete picture before pulling the trigger."*

---

## 3. 3-Minute Fast-Track Demo
1. **0:00 - 0:45: The Alert & Context**:
   - Open `http://localhost:5173`. Show incident `INC-2026-0042` with `user.sneha` as root.
   - Show how the graph distinguishes **Observed telemetry** (solid cyan), **Authorized capability** (dashed slate), and **Inferred paths** (dotted amber).
2. **0:45 - 1:30: Blast Radius & Path Tracing**:
   - Click `1 HOP` → `2 HOPS` → `3 HOPS`. Show dynamic expansion from 3 to 14 entities and 3 exposed critical databases.
   - Click **Attack Path #1**: The graph immediately highlights the path in amber (`user.sneha → ws-17-ops → bastion-mgmt → finance-db`).
3. **1:30 - 2:30: Choke Point & Containment Simulation**:
   - Show the Choke Point panel: `bastion-mgmt` intercepts 67% of critical attack paths.
   - Click **"Simulate Isolating bastion-mgmt"**.
   - Show the Before/After Delta: Reachable entities reduced, Crown jewels protected.
   - **The Aha! Moment**: Point out the amber alert: *"CONTAINMENT INCOMPLETE: Critical asset 'finance-db' remains reachable through alternate route: user.sneha → ws-17-ops → vpn-gateway → finance-db."*
4. **2:30 - 3:00: Candidate Matrix & Decision**:
   - Switch to the **Candidate Matrix** tab: Compare `bastion-mgmt` vs `ws-17-ops`.
   - Show that isolating `ws-17-ops` severs all paths and eliminates exposure.
   - Conclude: GraphOps provides decision support, keeping the human analyst in the loop.

---

## 4. 5-Minute Master Judge Walkthrough (Minute-by-Minute)

### 0:00 — ALERT (The Starting Point)
- **Action**: Point to top header.
- **Narrative**:
  > *"Judges, let's look at this like a Tier-2 SOC analyst starting their shift. We receive alert `INC-2026-0042`: Potential Lateral Movement. Our suspected origin is user `user.sneha` with a Heuristic Risk Score of 82/100. In a traditional SIEM, this is just a single log line. We don't want to investigate it in isolation. We need connected context."*

### 0:30 — CONTEXT & TIMELINE
- **Action**: Click the **Incident Timeline** tab.
- **Narrative**:
  > *"Here is how multi-source telemetry created this graph: At 09:41:12, an Okta interactive login was observed on workstation `ws-17-ops`. Six seconds later, CrowdStrike EDR logged an outbound SSH connection to our core jumpbox `bastion-mgmt`. At 09:41:26, PAM authorized access to application server `app-srv-02`, which Tenable vulnerability scanner flagged with unpatched CVE-2024-21413. Finally, a database connection terminated in `finance-db`."*
- **Action**: Switch back to the **Investigation** workspace. Point out the visual semantics in the graph legend:
  > *"Notice our graph edges: Solid cyan indicates directly observed telemetry. Dashed slate represents authorized access capability. Dotted amber indicates analytical vulnerability reachability."*

### 1:00 — ATTACK PATH EXPLORER
- **Action**: Click **Attack Path #1** in the left panel.
- **Narrative**:
  > *"GraphOps computes all acyclic paths to our Crown Jewels. When I click Attack Path #1, the graph highlights every step in bright amber and de-emphasizes non-path nodes. We can see the complete vector: user.sneha → ws-17-ops → bastion-mgmt → finance-db. Notice how the analyst can instantly trace the path without writing graph queries."*

### 1:45 — BLAST RADIUS (1, 2, 3 HOPS)
- **Action**: Click the `1 HOP`, `2 HOPS`, and `3 HOPS` buttons sequentially.
- **Narrative**:
  > *"How far could an attacker pivot from user.sneha? At 1 hop, reachability is strictly confined to 3 direct entities: her workstation and a network printer, with zero critical assets exposed. At 2 hops, it expands to 7 entities. At 3 hops, reachability reaches 14 entities and exposes 3 high-value databases: finance-db, crown-jewel-db, and identity-srv. Notice that every number is computed dynamically from graph BFS traversal."*

### 2:15 — CHOKE-POINT ANALYSIS
- **Action**: Scroll to the Choke Point card in the right panel.
- **Narrative**:
  > *"Instead of guessing which server to isolate, GraphOps calculates **Critical-Path Interception**. Look at `bastion-mgmt`: It intercepts 67% of all critical attack paths. Downstream, it reaches 2 critical databases. The system gives us an explainable rationale: +67% path interception, +2 assets downstream, +43% reachability reduction."*

### 2:45 — WHAT-IF CONTAINMENT SIMULATION
- **Action**: Click **"Simulate Isolating bastion-mgmt"**.
- **Narrative**:
  > *"The analyst wants to test isolating bastion-mgmt. Watch the graph change: bastion-mgmt turns dashed and translucent. Connected edges are severed. Unreachable downstream nodes fade into the background. And look at the Before/After Delta card: Active paths drop from 4 to 1, and crown jewels exposed drop from 3 to 1."*

### 3:30 — THE SURPRISE: ALTERNATE PATH DETECTION
- **Action**: Point to the prominent amber alert box.
- **Narrative**:
  > *"Here is the most critical feature of GraphOps. In many tools, isolating the primary jumpbox would display 'Attack Contained'. But GraphOps recomputes graph connectivity and discovers a dangerous reality:*
  > **'CONTAINMENT INCOMPLETE: Primary path through bastion-mgmt severed. However, critical asset finance-db remains reachable through alternate route: user.sneha → ws-17-ops → vpn-gateway → finance-db.'**
  > *Because an external SSL-VPN route bypasses the bastion, the database was NOT protected. Without this graph simulation, the SOC team would have believed they were safe while an active vector remained open."*

### 4:00 — CANDIDATE MATRIX COMPARISON
- **Action**: Switch to the **Candidate Matrix** tab.
- **Narrative**:
  > *"So what should the analyst do? We switch to our Containment Candidate Matrix. Here we compare our options side-by-side:*
  > - *Isolating bastion-mgmt: severs 3 paths, protects 2 assets, but leaves 1 alternate path active (Medium residual exposure).*
  > - *Isolating ws-17-ops: severs all 4 paths, protects all 3 assets, with 0 alternate paths remaining (Low residual exposure).*
  > *GraphOps clearly highlights ws-17-ops as the superior candidate."*

### 4:30 — ANALYST DECISION RECORD (HUMAN-IN-THE-LOOP)
- **Action**: Switch back to workspace, click **"Simulate Isolating ws-17-ops"**, and highlight the **Analyst Decision Record**.
- **Narrative**:
  > *"When we simulate isolating ws-17-ops, crown jewels exposed drops to 0, and all assets are marked '✓ PROTECTED'. GraphOps generates an Analyst Decision Record. Notice our positioning: GraphOps does NOT autonomously pull the plug on production machines. It presents evidence quality, modeled impact, and remaining exposure, and leaves the final operational decision to human incident command."*

### 5:00 — CONCLUSION
- **Narrative**:
  > *"In summary, GraphOps takes the SOC from:*
  > **ALERT → CONTEXT → PATH → BLAST RADIUS → CHOKE POINT → WHAT-IF SIMULATION → REMAINING EXPOSURE → INFORMED HUMAN DECISION.**
  > *Thank you, judges. We welcome your questions."*

---

## 5. Technical Questions & Answers for Judges

### Q1: *"Are you using a real graph database like Neo4j?"*
> **Answer**: *"For this prototype, we implemented a deterministic, in-memory Python graph analytics engine running BFS bounded traversals and DFS acyclic path enumeration. This guarantees deterministic reproducibility (`seed=42`) and sub-10 millisecond response times without requiring external database dependencies during evaluation. The architecture has clean repository boundaries, making Neo4j with parameterized Cypher queries our natural production evolution."*

### Q2: *"Is this AI or Machine Learning?"*
> **Answer**: *"No. We explicitly do not claim this is AI or black-box machine learning. The analytics are deterministic graph algorithms: breadth-first search for blast radius, depth-first acyclic search for attack paths, and path participation frequency for Critical-Path Interception. All risk scores are explainable heuristics derived from credential privilege, target criticality, and hop distance."*

### Q3: *"How does alternate path detection work algorithmically?"*
> **Answer**: *"When an entity is isolated, we remove that node and its incident edges from the active adjacency graph. We then re-run our path solver to all pre-containment critical assets. If an asset that was targeted by a severed path is still reached by an active acyclic path through other nodes, the engine tags it as an active alternate path and flags an incomplete containment alert."*

### Q4: *"Can the analyst change the root of the investigation?"*
> **Answer**: *"Yes. Any entity in the graph—whether a workstation, server, database, or identity—can be selected as the root. When selected, all blast radius calculations, hop limits, and attack paths recompute strictly from that entity."*

---

## 6. Backup Demo Plan
If network or port conflicts occur during a live presentation:
1. Verify backend: `curl http://localhost:8000/health` should return `{"status": "healthy"}`.
2. If frontend dev server stops: run `npm run preview` in `frontend/` to serve the pre-compiled production build on `http://localhost:4173`.
3. All data is seeded deterministically (`seed=42`), so hitting **Reset** in the top header always restores the pristine starting state.
