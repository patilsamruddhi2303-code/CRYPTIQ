import time
from collections import deque
from typing import Dict, List, Set, Any, Optional

class GraphAnalyticsEngine:
    """
    GraphOps Deterministic In-Memory Graph Analytics Engine.
    
    Implements explicit relationship semantics:
    - OBSERVED: Direct logged telemetry (e.g., LOGGED_IN_TO, CONNECTED_TO). Always traversable.
    - AUTHORIZED/CAPABILITY: Configured permissions or technical reachability (e.g., CAN_REACH, ACCESSES, AUTHORIZED_FOR).
    - INFERRED/PREDICTED: Structurally inferred potential paths (e.g., HAS_VULNERABILITY, EXPLOITS).
    """
    def __init__(self, nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]]):
        self.raw_nodes = nodes
        self.raw_edges = edges
        self.nodes_by_id = {n["id"]: n for n in nodes}
        self.adj: Dict[str, List[Dict[str, Any]]] = {n["id"]: [] for n in nodes}
        self.rev_adj: Dict[str, List[Dict[str, Any]]] = {n["id"]: [] for n in nodes}

        for e in edges:
            src = e["source"]
            tgt = e["target"]
            if src in self.adj and tgt in self.nodes_by_id:
                self.adj[src].append(e)
            if tgt in self.rev_adj and src in self.nodes_by_id:
                self.rev_adj[tgt].append(e)

    def get_summary(self) -> Dict[str, Any]:
        node_counts = {}
        for n in self.raw_nodes:
            t = n.get("type", "Unknown")
            node_counts[t] = node_counts.get(t, 0) + 1

        edge_counts = {}
        for e in self.raw_edges:
            cat = e.get("category", "UNKNOWN")
            edge_counts[cat] = edge_counts.get(cat, 0) + 1

        return {
            "total_nodes": len(self.raw_nodes),
            "total_edges": len(self.raw_edges),
            "node_types": node_counts,
            "edge_categories": edge_counts
        }

    def compute_blast_radius(self, start_id: str, max_hops: int = 3, blocked_node_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Calculates reachability strictly rooted at start_id bounded by max_hops (1, 2, or 3).
        Excludes blocked_node_id if containment is simulated.
        Tracks entity category breakdown and measures actual computation latency in ms.
        """
        t0 = time.perf_counter()
        if start_id not in self.nodes_by_id:
            return {"error": f"Entity '{start_id}' not found."}

        max_hops = min(max(1, max_hops), 3)

        visited: Dict[str, int] = {start_id: 0}
        queue = deque([start_id])
        reachable_edges: List[Dict[str, Any]] = []

        while queue:
            curr = queue.popleft()
            curr_dist = visited[curr]

            if curr_dist >= max_hops:
                continue

            for edge in self.adj.get(curr, []):
                tgt = edge["target"]
                # In containment simulation, candidate node cannot route traffic
                if blocked_node_id and (tgt == blocked_node_id or curr == blocked_node_id):
                    continue

                reachable_edges.append(edge)

                if tgt not in visited:
                    visited[tgt] = curr_dist + 1
                    queue.append(tgt)

        reached_entities = []
        critical_assets_exposed = []
        type_breakdown: Dict[str, int] = {}

        for nid, dist in visited.items():
            node = self.nodes_by_id[nid]
            ntype = node.get("type", "Unknown")
            type_breakdown[ntype] = type_breakdown.get(ntype, 0) + 1

            entity_data = {
                "id": node["id"],
                "label": node.get("label", node["id"]),
                "type": ntype,
                "hops": dist,
                "is_critical": node.get("isCritical", False),
                "zone": node.get("zone", "default"),
                "role": node.get("role", node.get("privilege", "standard")),
                "criticality": node.get("criticality", "Normal")
            }
            reached_entities.append(entity_data)
            if node.get("isCritical", False) and dist > 0:
                critical_assets_exposed.append(entity_data)

        # Sort entities by hop distance
        reached_entities.sort(key=lambda x: x["hops"])

        latency_ms = round((time.perf_counter() - t0) * 1000, 2)

        return {
            "focus_entity": start_id,
            "max_hops_requested": max_hops,
            "reachable_count": len(reached_entities),
            "critical_asset_count": len(critical_assets_exposed),
            "reachable_entities": reached_entities,
            "critical_assets": critical_assets_exposed,
            "reachable_edges": reachable_edges,
            "entity_type_breakdown": type_breakdown,
            "compute_time_ms": latency_ms
        }

    def find_attack_paths(self, source_id: str, max_hops: int = 3, blocked_node_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Calculates all acyclic simple directed paths from source_id to any reachable CriticalAsset,
        strictly bounded by max_hops (length <= max_hops).
        Excludes paths traversing blocked_node_id if isolated.
        Enriches each path with relationship categories, vulnerabilities, and path score.
        """
        t0 = time.perf_counter()
        if source_id not in self.nodes_by_id:
            return []

        target_set = set(n["id"] for n in self.raw_nodes if n.get("isCritical", False) and n["id"] != source_id)
        all_paths: List[List[str]] = []

        def dfs(curr: str, path: List[str], visited: Set[str]):
            # Path length in hops is len(path) - 1
            if (len(path) - 1) > max_hops:
                return
            if curr in target_set and len(path) > 1:
                all_paths.append(list(path))
                return
            for edge in self.adj.get(curr, []):
                nxt = edge["target"]
                # In containment, blocked node cannot transmit
                if blocked_node_id and (nxt == blocked_node_id or curr == blocked_node_id):
                    continue
                if nxt not in visited:
                    visited.add(nxt)
                    path.append(nxt)
                    dfs(nxt, path, visited)
                    path.pop()
                    visited.remove(nxt)

        dfs(source_id, [source_id], {source_id})

        formatted_paths = []
        for idx, p in enumerate(all_paths):
            dest = p[-1]
            dest_node = self.nodes_by_id[dest]
            
            # Extract relationship types, categories, and vulnerabilities along path
            rel_types = []
            categories = []
            vulns = []
            
            for i in range(len(p) - 1):
                u, v = p[i], p[i+1]
                edge = next((e for e in self.adj.get(u, []) if e["target"] == v), None)
                if edge:
                    rel_types.append(edge.get("type", "CONNECTED_TO"))
                    categories.append(edge.get("category", "OBSERVED"))
                # Check if intermediate node has connected vulnerabilities
                for e_adj in self.adj.get(u, []):
                    if e_adj.get("type") == "HAS_VULNERABILITY":
                        vulns.append(e_adj["target"])

            hop_length = len(p) - 1
            # Explainable path risk score (shorter paths to critical targets = higher path score)
            path_score = max(10, 100 - (hop_length * 15))
            if dest_node.get("criticality") == "Critical":
                path_score = min(100, path_score + 10)

            formatted_paths.append({
                "path_id": f"path-{idx + 1}",
                "nodes": p,
                "length": hop_length,
                "target_id": dest,
                "target_type": dest_node.get("type"),
                "criticality": dest_node.get("criticality", "High"),
                "relationship_types": rel_types,
                "categories": categories,
                "vulnerabilities": list(set(vulns)),
                "path_score": path_score,
                "is_active": True
            })

        # Rank paths: higher path score first, then shorter length
        formatted_paths.sort(key=lambda x: (x["path_score"], -x["length"]), reverse=True)
        return formatted_paths

    def identify_choke_points(self, source_id: str, max_hops: int = 3) -> List[Dict[str, Any]]:
        """
        Calculates Critical-Path Interception (Path Participation Centrality):
        Percentage of currently analyzed critical attack paths that traverse this entity.
        Computes downstream critical assets, reachability reduction %, and alternate paths.
        """
        paths = self.find_attack_paths(source_id=source_id, max_hops=max_hops)
        if not paths:
            return []

        pre_blast = self.compute_blast_radius(start_id=source_id, max_hops=max_hops)
        pre_reachable_count = pre_blast.get("reachable_count", 1)

        total_paths = len(paths)
        participation: Dict[str, List[Dict[str, Any]]] = {}
        for p in paths:
            # Intermediate nodes (exclude source root and final target)
            intermediates = p["nodes"][1:-1]
            for node in intermediates:
                if node not in participation:
                    participation[node] = []
                participation[node].append(p)

        choke_candidates = []
        for node_id, node_paths in participation.items():
            node = self.nodes_by_id[node_id]
            count = len(node_paths)
            pct = round((count / total_paths) * 100, 1)

            # Determine downstream critical assets reached through this intermediate node
            downstream_assets = list(set(p["target_id"] for p in node_paths))

            # Simulate reachability reduction
            sim_blast = self.compute_blast_radius(start_id=source_id, max_hops=max_hops, blocked_node_id=node_id)
            post_count = sim_blast.get("reachable_count", 0)
            reduction_pct = round(((pre_reachable_count - post_count) / max(1, pre_reachable_count)) * 100, 1)

            # Alternate paths remaining if this node is severed
            remaining_paths = [p for p in paths if node_id not in p["nodes"]]
            alt_path_count = len(remaining_paths)

            reasons = [
                f"+{pct}% critical-path interception ({count}/{total_paths} paths)",
                f"+{len(downstream_assets)} critical asset(s) downstream ({', '.join(downstream_assets)})",
                f"+{reduction_pct}% reachable entity reduction"
            ]
            if alt_path_count > 0:
                reasons.append(f"-{alt_path_count} alternate path(s) remain active")
            else:
                reasons.append("✓ 0 alternate paths remain (complete path elimination)")

            choke_candidates.append({
                "node_id": node_id,
                "label": node.get("label", node_id),
                "type": node.get("type"),
                "paths_affected": count,
                "total_critical_paths": total_paths,
                "coverage_pct": pct,
                "critical_assets_downstream": len(downstream_assets),
                "downstream_asset_ids": downstream_assets,
                "reachability_reduction_pct": reduction_pct,
                "alternate_path_count": alt_path_count,
                "centrality_metric": "Critical-Path Interception",
                "interception_rating": "HIGH" if pct >= 60 else ("MEDIUM" if pct >= 30 else "LOW"),
                "ranking_reasons": reasons,
                "suggested_action": f"Quarantine host or isolate credentials for {node_id}"
            })

        choke_candidates.sort(key=lambda x: (x["paths_affected"], x["critical_assets_downstream"]), reverse=True)
        return choke_candidates

    def simulate_containment(self, source_id: str, candidate_node_id: str, max_hops: int = 3) -> Dict[str, Any]:
        """
        Authoritative backend containment simulation:
        1. Evaluates pre-containment reachability and paths.
        2. Recomputes post-containment reachability and paths by masking candidate_node_id.
        3. Identifies severed paths vs active remaining paths.
        4. Detects ALTERNATE PATHS where an asset remains exposed via another route.
        5. Evaluates itemized per-asset exposure status (Protected vs Still Exposed).
        6. Generates an Analyst Decision Record.
        """
        t0 = time.perf_counter()
        pre_blast = self.compute_blast_radius(start_id=source_id, max_hops=max_hops)
        pre_paths = self.find_attack_paths(source_id=source_id, max_hops=max_hops)

        post_blast = self.compute_blast_radius(start_id=source_id, max_hops=max_hops, blocked_node_id=candidate_node_id)
        post_paths = self.find_attack_paths(source_id=source_id, max_hops=max_hops, blocked_node_id=candidate_node_id)

        pre_crit_nodes = {ca["id"] for ca in pre_blast.get("critical_assets", [])}
        post_crit_nodes = {ca["id"] for ca in post_blast.get("critical_assets", [])}

        # Itemized per-asset status
        asset_statuses = []
        for asset_id in pre_crit_nodes:
            node = self.nodes_by_id[asset_id]
            is_still_exposed = asset_id in post_crit_nodes
            # Find remaining hop distance if still exposed
            post_asset_meta = next((ca for ca in post_blast.get("critical_assets", []) if ca["id"] == asset_id), None)
            hops_left = post_asset_meta["hops"] if post_asset_meta else None

            asset_statuses.append({
                "id": asset_id,
                "label": node.get("label", asset_id),
                "criticality": node.get("criticality", "High"),
                "status": "STILL EXPOSED" if is_still_exposed else "PROTECTED",
                "remaining_distance_hops": hops_left
            })

        active_path_ids = {p["path_id"] for p in post_paths}
        severed_paths = [p for p in pre_paths if candidate_node_id in p["nodes"] or p["path_id"] not in active_path_ids]

        # Explicit Alternate Path Detection:
        # If an asset was targeted by a severed path, but still has an active path in post_paths!
        severed_target_ids = set(p["target_id"] for p in severed_paths)
        alternate_paths = []
        for p in post_paths:
            if p["target_id"] in severed_target_ids:
                alternate_paths.append(p)

        alternate_path_alert = None
        if alternate_paths:
            primary_alt = alternate_paths[0]
            alt_path_str = " → ".join(primary_alt["nodes"])
            alternate_path_alert = (
                f"CONTAINMENT INCOMPLETE: Primary path through {candidate_node_id} severed. "
                f"However, critical asset '{primary_alt['target_id']}' remains reachable through alternate route: "
                f"{alt_path_str}."
            )

        protected_count = len(pre_crit_nodes) - len(post_crit_nodes)
        entities_reduced = pre_blast.get("reachable_count", 0) - post_blast.get("reachable_count", 0)
        is_complete = (len(post_crit_nodes) == 0 and len(post_paths) == 0)

        # Remaining Exposure Assessment
        remaining_exposure_rating = "LOW" if len(post_crit_nodes) == 0 else ("MEDIUM" if protected_count > 0 else "HIGH")

        # Analyst Decision Record (Decision Support)
        decision_record = {
            "candidate_id": candidate_node_id,
            "action_proposed": f"Simulated Isolation of {candidate_node_id}",
            "expected_graph_effect": "Complete Exposure Elimination" if is_complete else "Partial Containment (Alternate Paths Remain)",
            "critical_assets_protected_ratio": f"{protected_count} / {len(pre_crit_nodes)} Protected",
            "remaining_exposure_rating": remaining_exposure_rating,
            "evidence_quality": "Observed Telemetry + Authorized Access Policy + Inferred Reachability",
            "operational_impact": "Operational impact on production workflows is not modeled in graph prototype.",
            "recommendation": (
                f"Strong graph-level containment candidate: severs {len(severed_paths)} path(s) and protects {protected_count} critical asset(s)."
                if protected_count > 0 or len(severed_paths) > 0
                else f"Low leverage candidate: isolates {candidate_node_id} without reducing critical path exposure."
            ),
            "final_action": "ANALYST DECISION REQUIRED (Human-in-the-Loop)"
        }

        latency_ms = round((time.perf_counter() - t0) * 1000, 2)

        return {
            "isolated_node": candidate_node_id,
            "source_id": source_id,
            "max_hops": max_hops,
            "pre_containment": {
                "reachable_count": pre_blast.get("reachable_count", 0),
                "critical_assets_exposed": len(pre_crit_nodes),
                "active_paths_count": len(pre_paths),
                "paths": pre_paths,
                "reachable_entities": pre_blast.get("reachable_entities", []),
                "entity_type_breakdown": pre_blast.get("entity_type_breakdown", {})
            },
            "post_containment": {
                "reachable_count": post_blast.get("reachable_count", 0),
                "critical_assets_exposed": len(post_crit_nodes),
                "active_paths_count": len(post_paths),
                "paths": post_paths,
                "reachable_entities": post_blast.get("reachable_entities", []),
                "reachable_edges": post_blast.get("reachable_edges", []),
                "entity_type_breakdown": post_blast.get("entity_type_breakdown", {})
            },
            "delta": {
                "reachable_entities_delta": -entities_reduced,
                "critical_assets_delta": -protected_count,
                "paths_delta": -len(severed_paths)
            },
            "severed_paths": severed_paths,
            "remaining_paths": post_paths,
            "alternate_paths": alternate_paths,
            "alternate_path_alert": alternate_path_alert,
            "asset_statuses": asset_statuses,
            "impact_summary": {
                "entities_reduced": entities_reduced,
                "critical_assets_protected": protected_count,
                "paths_severed": len(severed_paths),
                "remaining_active_paths": len(post_paths),
                "is_effective": protected_count > 0 or len(severed_paths) > 0,
                "containment_rating": "FULL CONTAINMENT" if is_complete else "PARTIAL CONTAINMENT"
            },
            "remaining_exposure": {
                "remaining_entities_count": post_blast.get("reachable_count", 0),
                "remaining_critical_count": len(post_crit_nodes),
                "remaining_paths_count": len(post_paths),
                "alternate_paths_count": len(alternate_paths),
                "exposure_level": remaining_exposure_rating
            },
            "decision_record": decision_record,
            "compute_time_ms": latency_ms,
            "disclaimer": "SIMULATION ONLY — No production network, firewall, or IAM actions were taken."
        }

    def compare_containment_candidates(self, source_id: str, max_hops: int = 3) -> List[Dict[str, Any]]:
        """
        Calculates side-by-side comparison matrix for containment candidates:
        Tests isolating each candidate node and summarizes impact, severed paths, and remaining exposure.
        """
        chokes = self.identify_choke_points(source_id=source_id, max_hops=max_hops)
        candidate_ids = [cp["node_id"] for cp in chokes]

        # Also add direct 1-hop outbound neighbors of source_id if not already included
        for e in self.adj.get(source_id, []):
            tgt = e["target"]
            if tgt not in candidate_ids and not self.nodes_by_id[tgt].get("isCritical", False):
                candidate_ids.append(tgt)

        comparisons = []
        for cid in candidate_ids[:5]: # Top 5 candidates
            sim = self.simulate_containment(source_id=source_id, candidate_node_id=cid, max_hops=max_hops)
            node = self.nodes_by_id[cid]
            comparisons.append({
                "candidate_id": cid,
                "label": node.get("label", cid),
                "type": node.get("type", "Unknown"),
                "paths_severed": sim["impact_summary"]["paths_severed"],
                "critical_assets_protected": sim["impact_summary"]["critical_assets_protected"],
                "entity_reduction": sim["impact_summary"]["entities_reduced"],
                "remaining_alternate_paths": len(sim["alternate_paths"]),
                "remaining_exposure": sim["remaining_exposure"]["exposure_level"],
                "is_recommended": sim["impact_summary"]["critical_assets_protected"] > 0
            })

        # Sort by critical assets protected desc, then paths severed desc
        comparisons.sort(key=lambda x: (x["critical_assets_protected"], x["paths_severed"], x["entity_reduction"]), reverse=True)
        return comparisons
