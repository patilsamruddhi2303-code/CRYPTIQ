import unittest
from fastapi.testclient import TestClient

from backend.generator import SyntheticTopologyGenerator
from backend.engine import GraphAnalyticsEngine
from backend.main import app

class TestGraphAnalytics(unittest.TestCase):
    def setUp(self):
        self.gen = SyntheticTopologyGenerator(seed=42)
        self.all_scenarios = self.gen.get_all_scenarios()
        self.lateral_data = self.all_scenarios["scenario_lateral"]
        self.lateral_engine = GraphAnalyticsEngine(self.lateral_data["nodes"], self.lateral_data["edges"])
        self.chokepoint_data = self.all_scenarios["scenario_chokepoint"]
        self.chokepoint_engine = GraphAnalyticsEngine(self.chokepoint_data["nodes"], self.chokepoint_data["edges"])
        self.benign_data = self.all_scenarios["scenario_benign"]
        self.benign_engine = GraphAnalyticsEngine(self.benign_data["nodes"], self.benign_data["edges"])
        self.client = TestClient(app)

    def test_deterministic_seeding(self):
        g1 = SyntheticTopologyGenerator(seed=42).generate_scenario_lateral()
        g2 = SyntheticTopologyGenerator(seed=42).generate_scenario_lateral()
        self.assertEqual(len(g1["nodes"]), len(g2["nodes"]))
        self.assertEqual(len(g1["edges"]), len(g2["edges"]))
        self.assertEqual(g1["nodes"][0]["id"], g2["nodes"][0]["id"])

    def test_different_roots_produce_different_traversals(self):
        r_user = self.lateral_engine.compute_blast_radius("user.sneha", max_hops=1)
        r_ws = self.lateral_engine.compute_blast_radius("ws-17-ops", max_hops=1)
        
        self.assertNotEqual(r_user["reachable_count"], r_ws["reachable_count"])
        user_entities = {e["id"] for e in r_user["reachable_entities"]}
        ws_entities = {e["id"] for e in r_ws["reachable_entities"]}
        self.assertIn("user.sneha", user_entities)
        self.assertNotIn("user.sneha", ws_entities)

    def test_hop_bounds_strictly_respected(self):
        r1 = self.lateral_engine.compute_blast_radius("user.sneha", max_hops=1)
        self.assertEqual(r1["reachable_count"], 3)  # user.sneha + ws-17-ops + printer-corp
        self.assertEqual(r1["critical_asset_count"], 0)

        r2 = self.lateral_engine.compute_blast_radius("user.sneha", max_hops=2)
        self.assertGreater(r2["reachable_count"], r1["reachable_count"])
        self.assertEqual(r2["critical_asset_count"], 0)

        r3 = self.lateral_engine.compute_blast_radius("user.sneha", max_hops=3)
        self.assertGreater(r3["reachable_count"], r2["reachable_count"])
        self.assertGreaterEqual(r3["critical_asset_count"], 2)

    def test_attack_paths_scope_and_discovery(self):
        p1 = self.lateral_engine.find_attack_paths("user.sneha", max_hops=1)
        self.assertEqual(len(p1), 0)

        p3 = self.lateral_engine.find_attack_paths("user.sneha", max_hops=3)
        self.assertGreaterEqual(len(p3), 2)
        targets = [p["target_id"] for p in p3]
        self.assertTrue("finance-db" in targets or "crown-jewel-db" in targets)

    def test_no_critical_paths_in_benign_scenario(self):
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
        sim = self.lateral_engine.simulate_containment("user.sneha", candidate_node_id="ws-17-ops", max_hops=3)
        self.assertEqual(sim["post_containment"]["critical_assets_exposed"], 0)
        self.assertEqual(sim["post_containment"]["active_paths_count"], 0)
        for asset in sim["asset_statuses"]:
            self.assertEqual(asset["status"], "PROTECTED")

    def test_partial_containment_scenario(self):
        sim = self.lateral_engine.simulate_containment("user.sneha", candidate_node_id="srv-mgmt-01", max_hops=3)
        status_map = {a["id"]: a["status"] for a in sim["asset_statuses"]}
        self.assertEqual(status_map.get("crown-jewel-db"), "PROTECTED")
        self.assertEqual(status_map.get("finance-db"), "STILL EXPOSED")
        self.assertEqual(status_map.get("identity-srv"), "STILL EXPOSED")
        self.assertGreater(sim["post_containment"]["active_paths_count"], 0)

    def test_alternate_path_detected_on_bastion_isolation(self):
        sim = self.lateral_engine.simulate_containment("user.sneha", candidate_node_id="bastion-mgmt", max_hops=3)
        self.assertGreaterEqual(len(sim["alternate_paths"]), 1)
        self.assertIsNotNone(sim["alternate_path_alert"])
        self.assertIn("finance-db", sim["alternate_path_alert"])
        status_map = {a["id"]: a["status"] for a in sim["asset_statuses"]}
        self.assertEqual(status_map.get("finance-db"), "STILL EXPOSED")

    def test_candidate_comparison_matrix(self):
        comparisons = self.lateral_engine.compare_containment_candidates("user.sneha", max_hops=3)
        self.assertGreaterEqual(len(comparisons), 2)
        top = comparisons[0]
        self.assertIn("candidate_id", top)
        self.assertIn("paths_severed", top)
        self.assertIn("critical_assets_protected", top)
        self.assertIn("entity_reduction", top)

    def test_decision_record_structure(self):
        sim = self.lateral_engine.simulate_containment("user.sneha", candidate_node_id="bastion-mgmt", max_hops=3)
        rec = sim["decision_record"]
        self.assertEqual(rec["candidate_id"], "bastion-mgmt")
        self.assertIn("ANALYST DECISION REQUIRED", rec["final_action"])
        self.assertIn("evidence_quality", rec)

    def test_all_six_scenarios_generate_consistently(self):
        expected_scenarios = [
            "scenario_lateral", "scenario_chokepoint", "scenario_alternate_path",
            "scenario_blast_radius", "scenario_benign", "scenario_normal"
        ]
        self.assertEqual(set(self.all_scenarios.keys()), set(expected_scenarios))
        lateral_risk = self.all_scenarios["scenario_lateral"]["base_risk"]
        benign_risk = self.all_scenarios["scenario_benign"]["base_risk"]
        self.assertGreaterEqual(lateral_risk, 75)
        self.assertLessEqual(benign_risk, 30)

    def test_latency_measurement_present(self):
        res = self.lateral_engine.compute_blast_radius("user.sneha", max_hops=2)
        self.assertIn("compute_time_ms", res)
        self.assertGreaterEqual(res["compute_time_ms"], 0.0)

    def test_invalid_node_and_hop_rejection(self):
        res = self.lateral_engine.compute_blast_radius("non_existent_node", max_hops=2)
        self.assertIn("error", res)
        res_clamp = self.lateral_engine.compute_blast_radius("user.sneha", max_hops=99)
        self.assertEqual(res_clamp["max_hops_requested"], 3)

    # FastAPI Endpoint Integration Tests
    def test_api_health(self):
        res = self.client.get("/health")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["status"], "healthy")

    def test_api_scenarios_and_load(self):
        res = self.client.get("/api/scenarios")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(len(res.json()), 6)

        # Load benign scenario
        load_res = self.client.post("/api/scenarios/load?scenario_id=scenario_benign")
        self.assertEqual(load_res.status_code, 200)
        self.assertEqual(load_res.json()["scenario_id"], "scenario_benign")

        # Reload lateral scenario
        load_lat = self.client.post("/api/scenarios/load?scenario_id=scenario_lateral")
        self.assertEqual(load_lat.status_code, 200)

        # 404 for invalid scenario
        err_res = self.client.post("/api/scenarios/load?scenario_id=nonexistent")
        self.assertEqual(err_res.status_code, 404)

    def test_api_incidents_and_timeline(self):
        inc_res = self.client.get("/api/incidents")
        self.assertEqual(inc_res.status_code, 200)
        self.assertGreaterEqual(len(inc_res.json()), 1)

        detail_res = self.client.get("/api/incidents/INC-2026-0042")
        self.assertEqual(detail_res.status_code, 200)
        self.assertEqual(detail_res.json()["scenario_id"], "scenario_lateral")

        timeline_res = self.client.get("/api/timeline")
        self.assertEqual(timeline_res.status_code, 200)
        self.assertIn("timeline", timeline_res.json())

    def test_api_entities_and_inspection(self):
        ents_res = self.client.get("/api/entities")
        self.assertEqual(ents_res.status_code, 200)
        self.assertGreater(len(ents_res.json()), 0)

        ent_detail = self.client.get("/api/entities/user.sneha")
        self.assertEqual(ent_detail.status_code, 200)
        self.assertIn("heuristic_risk_score", ent_detail.json())
        self.assertIn("risk_contributors", ent_detail.json())

        # 404 for nonexistent entity
        err_ent = self.client.get("/api/entities/fake-entity-999")
        self.assertEqual(err_ent.status_code, 404)

    def test_api_blast_radius_and_paths(self):
        blast_res = self.client.get("/api/blast-radius/user.sneha?hops=2")
        self.assertEqual(blast_res.status_code, 200)
        self.assertIn("entity_type_breakdown", blast_res.json())

        paths_res = self.client.get("/api/paths?source_id=user.sneha&hops=3")
        self.assertEqual(paths_res.status_code, 200)
        self.assertGreaterEqual(paths_res.json()["total_paths"], 2)

    def test_api_containment_simulation_and_compare(self):
        sim_res = self.client.post("/api/containment/simulate", json={
            "source_id": "user.sneha",
            "candidate_node_id": "bastion-mgmt",
            "max_hops": 3
        })
        self.assertEqual(sim_res.status_code, 200)
        body = sim_res.json()
        self.assertIn("decision_record", body)
        self.assertIn("alternate_paths", body)

        cmp_res = self.client.get("/api/containment/compare?source_id=user.sneha&hops=3")
        self.assertEqual(cmp_res.status_code, 200)
        self.assertIn("candidate_comparisons", cmp_res.json())

    def test_api_input_validation(self):
        # hops > 3 rejected by Pydantic Query validation
        inv_blast = self.client.get("/api/blast-radius/user.sneha?hops=10")
        self.assertEqual(inv_blast.status_code, 422)

        # hops < 1 rejected
        inv_paths = self.client.get("/api/paths?source_id=user.sneha&hops=0")
        self.assertEqual(inv_paths.status_code, 422)

    def test_api_choke_points(self):
        cp_res = self.client.get("/api/choke-points?source_id=user.sneha&hops=3")
        self.assertEqual(cp_res.status_code, 200)
        body = cp_res.json()
        self.assertIn("choke_points", body)
        self.assertGreater(len(body["choke_points"]), 0)

    def test_api_anomalies(self):
        anom_res = self.client.get("/api/anomalies")
        self.assertEqual(anom_res.status_code, 200)
        body = anom_res.json()
        self.assertIn("anomalies", body)
        self.assertIn("Rule-Based Structural Anomaly Detection", body["engine_label"])

    def test_api_summary(self):
        sum_res = self.client.get("/api/summary")
        self.assertEqual(sum_res.status_code, 200)
        body = sum_res.json()
        self.assertIn("scenario", body)
        self.assertIn("metrics", body)

if __name__ == "__main__":
    unittest.main()
