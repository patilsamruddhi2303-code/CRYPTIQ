from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

from .generator import SyntheticTopologyGenerator
from .engine import GraphAnalyticsEngine

app = FastAPI(
    title="GraphOps Decision Support API",
    description="Deterministic In-Memory Graph Analytics Engine for SOC Blast Radius and Choke Point Containment",
    version="1.0.0"
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
        "active_scenario": current_scenario_id,
        "nodes_loaded": len(current_scenario_data["nodes"]),
        "edges_loaded": len(current_scenario_data["edges"])
    }


@app.get("/api/summary")
def get_graph_summary():
    return {
        "scenario": {
            "id": current_scenario_data["id"],
            "name": current_scenario_data["name"],
            "description": current_scenario_data["description"],
            "root_entity": current_scenario_data["root_entity"],
            "mitre_technique": current_scenario_data.get("mitre_technique"),
            "initial_event": current_scenario_data.get("initial_event"),
            "base_risk": current_scenario_data.get("base_risk", 50),
            "risk_factors": current_scenario_data.get("risk_factors", [])
        },
        "metrics": engine.get_summary()
    }


@app.get("/api/scenarios")
def list_scenarios():
    return [
        {
            "id": sc["id"],
            "name": sc["name"],
            "description": sc["description"],
            "root_entity": sc["root_entity"],
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
        "node_count": len(current_scenario_data["nodes"])
    }


@app.get("/api/entities")
def get_entities():
    return current_scenario_data["nodes"]


@app.get("/api/entities/{entity_id}")
def get_entity_detail(entity_id: str):
    if entity_id not in engine.nodes_by_id:
        raise HTTPException(status_code=404, detail=f"Entity '{entity_id}' not found.")
    node = engine.nodes_by_id[entity_id]
    outbound = engine.adj.get(entity_id, [])
    inbound = engine.rev_adj.get(entity_id, [])
    return {
        "entity": node,
        "outbound_edges": outbound,
        "inbound_edges": inbound
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


@app.get("/api/anomalies")
def get_anomalies():
    """
    Returns explainable structural anomalies defined for the active scenario.
    """
    return {
        "scenario_id": current_scenario_id,
        "anomalies": current_scenario_data.get("anomalies", [])
    }
