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
        """
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

        for nid, dist in visited.items():
            node = self.nodes_by_id[nid]
            entity_data = {
                "id": node["id"],
                "label": node.get("label", node["id"]),
                "type": node.get("type", "Unknown"),
                "hops": dist,
                "is_critical": node.get("isCritical", False)
            }
            reached_entities.append(entity_data)
            if node.get("isCritical", False) and dist > 0:
                critical_assets_exposed.append(entity_data)

        # Sort entities by hop distance
        reached_entities.sort(key=lambda x: x["hops"])

        return {
            "focus_entity": start_id,
            "max_hops_requested": max_hops,
            "reachable_count": len(reached_entities),
            "critical_asset_count": len(critical_assets_exposed),
            "reachable_entities": reached_entities,
            "critical_assets": critical_assets_exposed,
            "reachable_edges": reachable_edges
        }

    def find_attack_paths(self, source_id: str, max_hops: int = 3, blocked_node_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Calculates all acyclic simple directed paths from source_id to any reachable CriticalAsset,
        strictly bounded by max_hops (length <= max_hops).
        Excludes paths traversing blocked_node_id if isolated.
        """
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
            formatted_paths.append({
                "path_id": f"path-{idx + 1}",
                "nodes": p,
                "length": len(p) - 1,
                "target_id": dest,
                "target_type": dest_node.get("type"),
                "criticality": dest_node.get("criticality", "High")
            })

        return formatted_paths

    def identify_choke_points(self, source_id: str, max_hops: int = 3) -> List[Dict[str, Any]]:
        """
        Calculates Critical-Path Interception (Path Participation Centrality):
        Percentage of currently analyzed critical attack paths that traverse this entity.
        """
        paths = self.find_attack_paths(source_id=source_id, max_hops=max_hops)
        if not paths:
            return []

        total_paths = len(paths)
        participation: Dict[str, int] = {}
        for p in paths:
            # Intermediate nodes (exclude source root and final target)
            intermediates = p["nodes"][1:-1]
            for node in intermediates:
                participation[node] = participation.get(node, 0) + 1

        choke_candidates = []
        for node_id, count in participation.items():
            node = self.nodes_by_id[node_id]
            pct = round((count / total_paths) * 100, 1)
            choke_candidates.append({
                "node_id": node_id,
                "label": node.get("label", node_id),
                "type": node.get("type"),
                "paths_affected": count,
                "total_critical_paths": total_paths,
                "coverage_pct": pct,
                "centrality_metric": "Critical-Path Interception",
                "interception_rating": "HIGH" if pct >= 60 else ("MEDIUM" if pct >= 30 else "LOW"),
                "suggested_action": f"Quarantine host or isolate credentials for {node_id}"
            })

        choke_candidates.sort(key=lambda x: x["paths_affected"], reverse=True)
        return choke_candidates

    def simulate_containment(self, source_id: str, candidate_node_id: str, max_hops: int = 3) -> Dict[str, Any]:
        """
        Authoritative backend containment simulation:
        1. Evaluates pre-containment reachability and paths.
        2. Recomputes post-containment reachability and paths by masking candidate_node_id.
        3. Evaluates per-asset exposure status (Protected vs Still Exposed).
        """
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
            asset_statuses.append({
                "id": asset_id,
                "label": node.get("label", asset_id),
                "criticality": node.get("criticality", "High"),
                "status": "STILL EXPOSED" if is_still_exposed else "PROTECTED"
            })

        active_path_ids = {p["path_id"] for p in post_paths}
        severed_paths = [p for p in pre_paths if p["path_id"] not in active_path_ids]

        return {
            "isolated_node": candidate_node_id,
            "source_id": source_id,
            "max_hops": max_hops,
            "pre_containment": {
                "reachable_count": pre_blast.get("reachable_count", 0),
                "critical_assets_exposed": len(pre_crit_nodes),
                "active_paths_count": len(pre_paths),
                "paths": pre_paths,
                "reachable_entities": pre_blast.get("reachable_entities", [])
            },
            "post_containment": {
                "reachable_count": post_blast.get("reachable_count", 0),
                "critical_assets_exposed": len(post_crit_nodes),
                "active_paths_count": len(post_paths),
                "paths": post_paths,
                "reachable_entities": post_blast.get("reachable_entities", []),
                "reachable_edges": post_blast.get("reachable_edges", [])
            },
            "severed_paths": severed_paths,
            "asset_statuses": asset_statuses,
            "impact_summary": {
                "entities_reduced": pre_blast.get("reachable_count", 0) - post_blast.get("reachable_count", 0),
                "critical_assets_protected": len(pre_crit_nodes) - len(post_crit_nodes),
                "paths_severed": len(severed_paths),
                "is_effective": (len(pre_crit_nodes) - len(post_crit_nodes)) > 0 or len(severed_paths) > 0
            },
            "disclaimer": "SIMULATION ONLY — No production network, firewall, or IAM actions were taken."
        }
