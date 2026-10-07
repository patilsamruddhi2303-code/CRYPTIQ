import unittest
from backend.generator import SyntheticTopologyGenerator
from backend.engine import GraphAnalyticsEngine

class TestGraphAnalytics(unittest.TestCase):
    def setUp(self):
        self.gen = SyntheticTopologyGenerator(seed=42)
        self.lateral_data = self.gen.generate_scenario_lateral()
        self.lateral_engine = GraphAnalyticsEngine(self.lateral_data["nodes"], self.lateral_data["edges"])
        self.chokepoint_data = self.gen.generate_scenario_chokepoint()
        self.chokepoint_engine = GraphAnalyticsEngine(self.chokepoint_data["nodes"], self.chokepoint_data["edges"])
        self.benign_data = self.gen.generate_scenario_benign()
        self.benign_engine = GraphAnalyticsEngine(self.benign_data["nodes"], self.benign_data["edges"])

    def test_deterministic_seeding(self):
        g1 = SyntheticTopologyGenerator(seed=42).generate_scenario_lateral()
        g2 = SyntheticTopologyGenerator(seed=42).generate_scenario_lateral()
        self.assertEqual(len(g1["nodes"]), len(g2["nodes"]))
        self.assertEqual(len(g1["edges"]), len(g2["edges"]))
        self.assertEqual(g1["nodes"][0]["id"], g2["nodes"][0]["id"])

    def test_different_roots_produce_different_traversals(self):
        # user.sneha vs ws-17-ops produce different reachability sets
        r_user = self.lateral_engine.compute_blast_radius("user.sneha", max_hops=1)
        r_ws = self.lateral_engine.compute_blast_radius("ws-17-ops", max_hops=1)
        
        self.assertNotEqual(r_user["reachable_count"], r_ws["reachable_count"])
        user_entities = {e["id"] for e in r_user["reachable_entities"]}
        ws_entities = {e["id"] for e in r_ws["reachable_entities"]}
        self.assertIn("user.sneha", user_entities)
        self.assertNotIn("user.sneha", ws_entities)

    def test_hop_bounds_strictly_respected(self):
        # 1-hop from user.sneha reaches only direct neighbors (ws-17-ops, printer-corp)
        r1 = self.lateral_engine.compute_blast_radius("user.sneha", max_hops=1)
        self.assertEqual(r1["reachable_count"], 3)  # user.sneha + ws-17-ops + printer-corp
        self.assertEqual(r1["critical_asset_count"], 0)

        # 2-hop reaches intermediate servers
        r2 = self.lateral_engine.compute_blast_radius("user.sneha", max_hops=2)
        self.assertGreater(r2["reachable_count"], r1["reachable_count"])
        self.assertEqual(r2["critical_asset_count"], 0)

        # 3-hop reaches crown jewels
        r3 = self.lateral_engine.compute_blast_radius("user.sneha", max_hops=3)
        self.assertGreater(r3["reachable_count"], r2["reachable_count"])
        self.assertGreaterEqual(r3["critical_asset_count"], 2)

    def test_attack_paths_scope_and_discovery(self):
        # At 1 hop, no critical paths exist from user.sneha
        p1 = self.lateral_engine.find_attack_paths("user.sneha", max_hops=1)
        self.assertEqual(len(p1), 0)

        # At 3 hops, multi-hop paths to critical databases exist
        p3 = self.lateral_engine.find_attack_paths("user.sneha", max_hops=3)
        self.assertGreaterEqual(len(p3), 2)
        targets = [p["target_id"] for p in p3]
        self.assertTrue("finance-db" in targets or "crown-jewel-db" in targets)

    def test_no_critical_paths_in_benign_scenario(self):
        # Benign scenario has zero paths to critical assets
        paths = self.benign_engine.find_attack_paths("user.sneha", max_hops=3)
        self.assertEqual(len(paths), 0)
        chokes = self.benign_engine.identify_choke_points("user.sneha", max_hops=3)
        self.assertEqual(len(chokes), 0)

    def test_choke_point_interception_metric(self):
        choke_candidates = self.lateral_engine.identify_choke_points("user.sneha", max_hops=3)
        self.assertGreater(len(choke_candidates), 0)
        top = choke_candidates[0]
        self.assertEqual(top["node_id"], "ws-17-ops")
        self.assertEqual(top["centrality_metric"], "Critical-Path Interception")
        self.assertGreaterEqual(top["coverage_pct"], 60.0)

    def test_containment_itemized_asset_status(self):
        # Isolating ws-17-ops isolates ALL downstream critical assets
        sim = self.lateral_engine.simulate_containment("user.sneha", candidate_node_id="ws-17-ops", max_hops=3)
        self.assertEqual(sim["post_containment"]["critical_assets_exposed"], 0)
        self.assertEqual(sim["post_containment"]["active_paths_count"], 0)
        for asset in sim["asset_statuses"]:
            self.assertEqual(asset["status"], "PROTECTED")

    def test_partial_containment_scenario(self):
        # Isolating srv-mgmt-01 protects crown-jewel-db, but finance-db and identity-srv remain STILL EXPOSED
        sim = self.lateral_engine.simulate_containment("user.sneha", candidate_node_id="srv-mgmt-01", max_hops=3)
        status_map = {a["id"]: a["status"] for a in sim["asset_statuses"]}
        self.assertEqual(status_map.get("crown-jewel-db"), "PROTECTED")
        self.assertEqual(status_map.get("finance-db"), "STILL EXPOSED")
        self.assertEqual(status_map.get("identity-srv"), "STILL EXPOSED")
        self.assertGreater(sim["post_containment"]["active_paths_count"], 0)

    def test_invalid_node_and_hop_rejection(self):
        res = self.lateral_engine.compute_blast_radius("non_existent_node", max_hops=2)
        self.assertIn("error", res)
        # Bounded hops clamped between 1 and 3
        res_clamp = self.lateral_engine.compute_blast_radius("user.sneha", max_hops=99)
        self.assertEqual(res_clamp["max_hops_requested"], 3)

if __name__ == "__main__":
    unittest.main()
