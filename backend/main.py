from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

from .generator import SyntheticTopologyGenerator
from .engine import GraphAnalyticsEngine

app = FastAPI(
    title="GraphOps Decision Support API",
    description="Deterministic In-Memory Graph Analytics Engine for SOC Blast Radius, Choke Points, and Containment Simulation",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

generator = SyntheticTopologyGenerator(seed=42)
all_scenarios = generator.get_all_scenarios()
current_scenario_id = "scenario_lateral"
current_scenario_data = all_scenarios[current_scenario_id]
engine = GraphAnalyticsEngine(current_scenario_data["nodes"], current_scenario_data["edges"])

class ContainmentSimRequest(BaseModel):
    source_id: str = Field(..., description="Investigation focus / root entity ID")
    candidate_node_id: str = Field(..., description="Choke-point candidate node to isolate")
    max_hops: Optional[int] = Field(3, ge=1, le=3, description="Traversal hop depth (1-3)")


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "GraphOps In-Memory Analytics Engine",
        "version": "2.0.0",
        "active_scenario": current_scenario_id,
        "nodes_loaded": len(current_scenario_data["nodes"]),
        "edges_loaded": len(current_scenario_data["edges"]),
        "engine_type": "Deterministic In-Memory Traversal (Production Evolution: Neo4j)"
    }


@app.get("/api/summary")
def get_graph_summary():
    return {
        "scenario": {
            "id": current_scenario_data["id"],
            "name": current_scenario_data["name"],
            "incident_id": current_scenario_data.get("incident_id", "INC-2026-0042"),
            "severity": current_scenario_data.get("severity", "HIGH"),
            "status": current_scenario_data.get("status", "INVESTIGATING"),
            "description": current_scenario_data["description"],
            "root_entity": current_scenario_data["root_entity"],
            "primary_target": current_scenario_data.get("primary_target", "Critical Asset"),
            "mitre_technique": current_scenario_data.get("mitre_technique"),
            "initial_event": current_scenario_data.get("initial_event"),
            "base_risk": current_scenario_data.get("base_risk", 50),
            "risk_factors": current_scenario_data.get("risk_factors", []),
            "risk_breakdown": current_scenario_data.get("risk_breakdown", [])
        },
        "metrics": engine.get_summary()
    }


@app.get("/api/scenarios")
def list_scenarios():
    return [
        {
            "id": sc["id"],
            "name": sc["name"],
            "incident_id": sc.get("incident_id", "INC-2026-0000"),
            "severity": sc.get("severity", "MEDIUM"),
            "status": sc.get("status", "ACTIVE"),
            "description": sc["description"],
            "root_entity": sc["root_entity"],
            "primary_target": sc.get("primary_target", "N/A"),
            "mitre_technique": sc.get("mitre_technique"),
            "base_risk": sc.get("base_risk", 50)
        }
        for sc in all_scenarios.values()
    ]


@app.post("/api/scenarios/load")
def load_scenario(scenario_id: str = Query(..., description="Scenario ID to load")):
    global current_scenario_id, current_scenario_data, engine
    if scenario_id not in all_scenarios:
        raise HTTPException(status_code=404, detail=f"Scenario '{scenario_id}' not found.")
    current_scenario_id = scenario_id
    current_scenario_data = all_scenarios[scenario_id]
    engine = GraphAnalyticsEngine(current_scenario_data["nodes"], current_scenario_data["edges"])
    return {
        "status": "loaded",
        "scenario_id": current_scenario_id,
        "name": current_scenario_data["name"],
        "incident_id": current_scenario_data.get("incident_id"),
        "node_count": len(current_scenario_data["nodes"]),
        "edge_count": len(current_scenario_data["edges"])
    }


@app.get("/api/incidents")
def get_incidents():
    """Returns overview of all modeled security incidents across scenarios."""
    return [
        {
            "incident_id": sc.get("incident_id", f"INC-2026-{idx:04d}"),
            "scenario_id": sc["id"],
            "name": sc["name"],
            "severity": sc.get("severity", "HIGH"),
            "status": sc.get("status", "INVESTIGATING"),
            "root_entity": sc["root_entity"],
            "primary_target": sc.get("primary_target", "None"),
            "base_risk": sc.get("base_risk", 50),
            "initial_event": sc.get("initial_event", "N/A"),
            "mitre_technique": sc.get("mitre_technique", "N/A")
        }
        for idx, sc in enumerate(all_scenarios.values(), 1)
    ]


@app.get("/api/incidents/{incident_id}")
def get_incident_detail(incident_id: str):
    matched = next((sc for sc in all_scenarios.values() if sc.get("incident_id") == incident_id or sc["id"] == incident_id), None)
    if not matched:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")
    return {
        "incident_id": matched.get("incident_id", "INC-2026-0042"),
        "scenario_id": matched["id"],
        "name": matched["name"],
        "severity": matched.get("severity", "HIGH"),
        "status": matched.get("status", "INVESTIGATING"),
        "description": matched["description"],
        "root_entity": matched["root_entity"],
        "primary_target": matched.get("primary_target"),
        "timeline": matched.get("timeline", []),
        "mitre_context": matched.get("mitre_context", []),
        "risk_breakdown": matched.get("risk_breakdown", []),
        "base_risk": matched.get("base_risk", 50)
    }


@app.get("/api/timeline")
def get_incident_timeline():
    """Returns chronological simulated telemetry timeline for the current active incident."""
    return {
        "incident_id": current_scenario_data.get("incident_id", "INC-2026-0042"),
        "scenario_id": current_scenario_id,
        "timeline": current_scenario_data.get("timeline", [])
    }


@app.get("/api/entities")
def get_entities(type: Optional[str] = Query(None, description="Filter entities by node type")):
    nodes = current_scenario_data["nodes"]
    if type:
        nodes = [n for n in nodes if n.get("type", "").lower() == type.lower()]
    return nodes


@app.get("/api/entities/{entity_id}")
def get_entity_detail(entity_id: str):
    if entity_id not in engine.nodes_by_id:
        raise HTTPException(status_code=404, detail=f"Entity '{entity_id}' not found.")
    node = engine.nodes_by_id[entity_id]
    outbound = engine.adj.get(entity_id, [])
    inbound = engine.rev_adj.get(entity_id, [])

    # Explainable node heuristic risk calculation
    risk_score = 20
    risk_contributors = ["+20 Baseline asset presence"]
    if node.get("isRoot"):
        risk_score += 40
        risk_contributors.append("+40 Suspected incident root")
    if node.get("isCritical"):
        risk_score += 35
        risk_contributors.append("+35 Crown jewel critical asset status")
    if node.get("privilege") in ["privileged", "domain_admin"]:
        risk_score += 25
        risk_contributors.append(f"+25 Elevated credential privilege ({node.get('privilege')})")
    if outbound:
        risk_score += min(15, len(outbound) * 3)
        risk_contributors.append(f"+{min(15, len(outbound)*3)} Outbound reachability fanout ({len(outbound)} links)")

    risk_score = min(100, risk_score)

    return {
        "entity": node,
        "outbound_edges": outbound,
        "inbound_edges": inbound,
        "heuristic_risk_score": risk_score,
        "risk_contributors": risk_contributors,
        "disclaimer": "Prototype heuristic risk score — not a certified production security rating."
    }


@app.get("/api/blast-radius/{entity_id}")
def get_blast_radius(
    entity_id: str,
    hops: int = Query(3, ge=1, le=3, description="Bounded hop depth (1 to 3)")
):
    if entity_id not in engine.nodes_by_id:
        raise HTTPException(status_code=404, detail=f"Entity '{entity_id}' not found.")
    res = engine.compute_blast_radius(start_id=entity_id, max_hops=hops)
    return res


@app.get("/api/paths")
def get_attack_paths(
    source_id: str = Query(..., description="Investigation root or source entity ID"),
    hops: int = Query(3, ge=1, le=3, description="Bounded hop depth for paths (1 to 3)")
):
    if source_id not in engine.nodes_by_id:
        raise HTTPException(status_code=404, detail=f"Source entity '{source_id}' not found.")
    paths = engine.find_attack_paths(source_id=source_id, max_hops=hops)
    return {
        "source_id": source_id,
        "max_hops": hops,
        "total_paths": len(paths),
        "paths": paths
    }


@app.get("/api/choke-points")
def get_choke_points(
    source_id: str = Query(..., description="Source entity ID to trace bottlenecks"),
    hops: int = Query(3, ge=1, le=3, description="Bounded hop depth (1 to 3)")
):
    if source_id not in engine.nodes_by_id:
        raise HTTPException(status_code=404, detail=f"Source entity '{source_id}' not found.")
    choke_points = engine.identify_choke_points(source_id=source_id, max_hops=hops)
    return {
        "source_id": source_id,
        "max_hops": hops,
        "choke_points": choke_points
    }


@app.post("/api/containment/simulate")
def simulate_containment(req: ContainmentSimRequest):
    if req.source_id not in engine.nodes_by_id:
        raise HTTPException(status_code=404, detail=f"Source entity '{req.source_id}' not found.")
    if req.candidate_node_id not in engine.nodes_by_id:
        raise HTTPException(status_code=404, detail=f"Candidate node '{req.candidate_node_id}' not found.")

    res = engine.simulate_containment(
        source_id=req.source_id,
        candidate_node_id=req.candidate_node_id,
        max_hops=req.max_hops or 3
    )
    return res


@app.get("/api/containment/compare")
def compare_containment_candidates(
    source_id: str = Query(..., description="Investigation root / source entity ID"),
    hops: int = Query(3, ge=1, le=3, description="Bounded hop depth (1 to 3)")
):
    if source_id not in engine.nodes_by_id:
        raise HTTPException(status_code=404, detail=f"Source entity '{source_id}' not found.")
    comparisons = engine.compare_containment_candidates(source_id=source_id, max_hops=hops)
    return {
        "source_id": source_id,
        "max_hops": hops,
        "candidate_comparisons": comparisons
    }


@app.get("/api/anomalies")
def get_anomalies():
    """
    Returns explainable structural anomalies defined for the active scenario.
    Rule-based structural heuristic — not AI or machine learning.
    """
    return {
        "scenario_id": current_scenario_id,
        "engine_label": "Rule-Based Structural Anomaly Detection",
        "anomalies": current_scenario_data.get("anomalies", [])
    }
