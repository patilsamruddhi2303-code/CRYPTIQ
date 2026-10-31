import { useEffect, useState, useRef } from 'react';
import cytoscape, { Core } from 'cytoscape';
import { 
  RotateCcw, ChevronRight, AlertTriangle, 
  Search, Sliders, Clock,
  Database, Filter
} from 'lucide-react';

interface Entity {
  id: string;
  label: string;
  type: string;
  isRoot?: boolean;
  isCritical?: boolean;
  isChoke?: boolean;
  zone?: string;
  role?: string;
  privilege?: string;
  department?: string;
  criticality?: string;
  ip?: string;
  os?: string;
  owner?: string;
}

interface BlastRadiusResponse {
  focus_entity: string;
  max_hops_requested: number;
  reachable_count: number;
  critical_asset_count: number;
  reachable_entities: Array<{ 
    id: string; 
    label: string; 
    type: string; 
    hops: number; 
    is_critical: boolean;
    zone?: string;
    role?: string;
    criticality?: string;
  }>;
  critical_assets: Array<{ 
    id: string; 
    label: string; 
    type: string; 
    hops: number; 
    is_critical: boolean;
    criticality?: string;
  }>;
  reachable_edges: Array<{ 
    source: string; 
    target: string; 
    type: string; 
    category: string;
    port?: number;
    protocol?: string;
    source_telemetry?: string;
  }>;
  entity_type_breakdown?: Record<string, number>;
  compute_time_ms?: number;
}

interface PathItem {
  path_id: string;
  nodes: string[];
  length: number;
  target_id: string;
  target_type: string;
  criticality: string;
  relationship_types?: string[];
  categories?: string[];
  vulnerabilities?: string[];
  path_score?: number;
  is_active?: boolean;
}

interface ChokeCandidate {
  node_id: string;
  label: string;
  type: string;
  paths_affected: number;
  total_critical_paths: number;
  coverage_pct: number;
  critical_assets_downstream: number;
  downstream_asset_ids: string[];
  reachability_reduction_pct: number;
  alternate_path_count: number;
  centrality_metric: string;
  interception_rating: string;
  ranking_reasons?: string[];
  suggested_action: string;
}

interface CandidateComparison {
  candidate_id: string;
  label: string;
  type: string;
  paths_severed: number;
  critical_assets_protected: number;
  entity_reduction: number;
  remaining_alternate_paths: number;
  remaining_exposure: string;
  is_recommended: boolean;
}

interface AssetStatus {
  id: string;
  label: string;
  criticality: string;
  status: 'PROTECTED' | 'STILL EXPOSED';
  remaining_distance_hops?: number | null;
}

interface AuthoritativeGraphData {
  scenarioId: string;
  rootId: string;
  hops: number;
  requestVersion: number;
  reachableEntities: Array<{
    id: string;
    label: string;
    type: string;
    hops: number;
    risk_score?: number;
    is_critical?: boolean;
  }>;
  reachableEdges: Array<{
    source: string;
    target: string;
    type: string;
    category: string;
  }>;
}

export default function App() {
  // Navigation & View Mode
  const [activeTab, setActiveTab] = useState<'workspace' | 'timeline' | 'comparison'>('workspace');

  // Scenarios and Summary
  const [scenarios, setScenarios] = useState<any[]>([]);
  const [currentScenario, setCurrentScenario] = useState<string>('scenario_lateral');
  const [summary, setSummary] = useState<any>(null);
  const [entities, setEntities] = useState<Entity[]>([]);
  const [anomalies, setAnomalies] = useState<any[]>([]);
  const [timeline, setTimeline] = useState<any[]>([]);
  
  // Investigation state
  const [focusEntityId, setFocusEntityId] = useState<string>('user.sneha');
  const [inspectedEntityId, setInspectedEntityId] = useState<string>('user.sneha');
  const [inspectedNodeDetail, setInspectedNodeDetail] = useState<any>(null);
  const [hops, setHops] = useState<number>(3);
  const [traversalTrigger, setTraversalTrigger] = useState<number>(0);
  const [searchQuery, setSearchQuery] = useState<string>('');
  
  // Graph Filtering state
  const [typeFilters, setTypeFilters] = useState<{ [key: string]: boolean }>({
    User: true,
    Endpoint: true,
    Server: true,
    Application: true,
    CriticalAsset: true,
    Vulnerability: true
  });
  const [categoryFilters, setCategoryFilters] = useState<{ [key: string]: boolean }>({
    OBSERVED: true,
    AUTHORIZED: true,
    INFERRED: true
  });

  // Graph Analytics state
  const [blastData, setBlastData] = useState<BlastRadiusResponse | null>(null);
  const [authoritativeGraph, setAuthoritativeGraph] = useState<AuthoritativeGraphData | null>(null);
  const [paths, setPaths] = useState<PathItem[]>([]);
  const [selectedPathId, setSelectedPathId] = useState<string | null>(null);
  const [chokePoints, setChokePoints] = useState<ChokeCandidate[]>([]);
  const [comparisons, setComparisons] = useState<CandidateComparison[]>([]);
  const [measuredLatency, setMeasuredLatency] = useState<number | null>(null);
  
  // Containment Simulation state
  const [simulatedIsolationNode, setSimulatedIsolationNode] = useState<string | null>(null);
  const [containmentResult, setContainmentResult] = useState<any>(null);

  // Graph Canvas Lifecycle & State
  const [isLoadingGraph, setIsLoadingGraph] = useState<boolean>(false);
  const [graphError, setGraphError] = useState<string | null>(null);

  const cyRef = useRef<HTMLDivElement>(null);
  const cyInstance = useRef<Core | null>(null);
  const requestVersionRef = useRef<number>(0);

  // Deterministic Hierarchical Hop-Column Layout with Barycentric Alignment & Collision Resolution
  const computeDeterministicPositions = (
    reachableEntities: Array<{ id: string; hops: number; is_critical?: boolean; type: string }>,
    edges: Array<{ source: string; target: string }>,
    focusId: string
  ): { [nodeId: string]: { x: number; y: number } } => {
    const MIN_Y_GAP = 96; // Minimum 96px vertical spacing between node centers for zero label collision
    const HOP_X_GAP = 220; // 220px horizontal spacing between hop progression columns
    const START_X = 130;
    const CANONICAL_CENTER_Y = 320; // Fixed canonical Y center for 100% invariant geometry

    // Group entities by hop distance from root
    const byHop: { [h: number]: Array<{ id: string; hops: number; is_critical?: boolean; type: string }> } = {};
    reachableEntities.forEach(ent => {
      const h = ent.id === focusId ? 0 : Math.min(3, Math.max(1, ent.hops || 1));
      if (!byHop[h]) byHop[h] = [];
      byHop[h].push(ent);
    });

    const positions: { [nodeId: string]: { x: number; y: number } } = {};

    // Hop 0: Root Entity placed at center of first column
    positions[focusId] = { x: START_X, y: CANONICAL_CENTER_Y };

    const hopLevels = Object.keys(byHop).map(Number).sort((a, b) => a - b);

    hopLevels.forEach(h => {
      if (h === 0) return;
      const currentNodes = byHop[h] || [];
      if (currentNodes.length === 0) return;

      const colX = START_X + h * HOP_X_GAP;

      // Sugiyama barycenter: calculate ideal Y position based on average Y of connected parents in upstream column
      const scoredNodes = currentNodes.map(node => {
        const parentEdges = edges.filter(ed => ed.target === node.id && positions[ed.source]);
        let idealY = CANONICAL_CENTER_Y;
        if (parentEdges.length > 0) {
          const sumY = parentEdges.reduce((acc, ed) => acc + positions[ed.source].y, 0);
          idealY = sumY / parentEdges.length;
        }
        return {
          node,
          idealY,
          isCritical: Boolean(node.is_critical || node.type === 'CriticalAsset'),
          id: node.id
        };
      });

      // Deterministic Sort:
      // 1. Natural parent alignment (idealY difference > 20px)
      // 2. Critical assets prioritization
      // 3. Alphabetical ID for 100% reproducible ordering
      scoredNodes.sort((a, b) => {
        const diffY = a.idealY - b.idealY;
        if (Math.abs(diffY) > 20) return diffY;
        if (a.isCritical && !b.isCritical) return -1;
        if (!a.isCritical && b.isCritical) return 1;
        return a.id.localeCompare(b.id);
      });

      const count = scoredNodes.length;
      const totalSpan = (count - 1) * MIN_Y_GAP;
      const startY = CANONICAL_CENTER_Y - totalSpan / 2;

      scoredNodes.forEach((item, idx) => {
        positions[item.id] = {
          x: colX,
          y: Math.round(startY + idx * MIN_Y_GAP)
        };
      });
    });

    // Verification & Collision Resolution Pass
    const nodeIds = Object.keys(positions);
    const MIN_DIST = 88;

    for (let iter = 0; iter < 5; iter++) {
      let hasCollision = false;
      for (let i = 0; i < nodeIds.length; i++) {
        for (let j = i + 1; j < nodeIds.length; j++) {
          const id1 = nodeIds[i];
          const id2 = nodeIds[j];
          const p1 = positions[id1];
          const p2 = positions[id2];
          const dx = p2.x - p1.x;
          const dy = p2.y - p1.y;
          const dist = Math.sqrt(dx * dx + dy * dy);

          if (dist < MIN_DIST) {
            hasCollision = true;
            // Push vertically apart
            const shift = (MIN_DIST - (Math.abs(dy) || 1)) / 2 + 4;
            if (dy >= 0) {
              positions[id1].y -= shift;
              positions[id2].y += shift;
            } else {
              positions[id1].y += shift;
              positions[id2].y += shift;
            }
          }
        }
      }
      if (!hasCollision) break;
    }

    // Ensure all coordinates are valid finite numbers
    nodeIds.forEach(id => {
      if (!Number.isFinite(positions[id].x)) positions[id].x = START_X;
      if (!Number.isFinite(positions[id].y)) positions[id].y = CANONICAL_CENTER_Y;
      positions[id].x = Math.round(positions[id].x);
      positions[id].y = Math.round(positions[id].y);
    });

    return positions;
  };

  // 1. Initial Load: Scenarios
  useEffect(() => {
    fetch('/api/scenarios')
      .then(res => res.json())
      .then(data => setScenarios(data))
      .catch(err => console.error("Error fetching scenarios:", err));

    loadScenarioDetails(currentScenario);
  }, []);

  // 2. Load Scenario Details
  const loadScenarioDetails = async (scId: string) => {
    try {
      setIsLoadingGraph(true);
      setGraphError(null);
      await fetch(`/api/scenarios/load?scenario_id=${scId}`, { method: 'POST' });
      const sumRes = await fetch('/api/summary');
      const sumData = await sumRes.json();
      setSummary(sumData);

      const entRes = await fetch('/api/entities');
      const entData = await entRes.json();
      setEntities(entData);

      const anomRes = await fetch('/api/anomalies');
      const anomData = await anomRes.json();
      setAnomalies(anomData.anomalies || []);

      const tlRes = await fetch('/api/timeline');
      const tlData = await tlRes.json();
      setTimeline(tlData.timeline || []);

      const root = sumData.scenario.root_entity;
      setCurrentScenario(scId);
      setFocusEntityId(root);
      setInspectedEntityId(root);
      setSimulatedIsolationNode(null);
      setContainmentResult(null);
      setSelectedPathId(null);
      setTraversalTrigger(prev => prev + 1);
    } catch (err: any) {
      console.error("Error loading scenario:", err);
      setGraphError(err.message || "Failed to load scenario details");
    } finally {
      setIsLoadingGraph(false);
    }
  };

  // 3. Dynamic Analytics Traversal with Race-Condition Sequence Protection
  useEffect(() => {
    if (!focusEntityId) return;

    const currentVersion = ++requestVersionRef.current;
    setIsLoadingGraph(true);
    setGraphError(null);
    setSelectedPathId(null);
    setSimulatedIsolationNode(null);
    setContainmentResult(null);

    const t0 = performance.now();

    Promise.all([
      fetch(`/api/blast-radius/${focusEntityId}?hops=${hops}`).then(r => {
        if (!r.ok) throw new Error(`Blast radius traversal failed (${r.status})`);
        return r.json();
      }),
      fetch(`/api/paths?source_id=${focusEntityId}&hops=${hops}`).then(r => {
        if (!r.ok) throw new Error(`Attack paths fetch failed (${r.status})`);
        return r.json();
      }),
      fetch(`/api/choke-points?source_id=${focusEntityId}&hops=${hops}`).then(r => {
        if (!r.ok) throw new Error(`Choke points analysis failed (${r.status})`);
        return r.json();
      }),
      fetch(`/api/containment/compare?source_id=${focusEntityId}&hops=${hops}`).then(r => {
        if (!r.ok) throw new Error(`Containment comparison failed (${r.status})`);
        return r.json();
      })
    ])
    .then(([blast, pData, cpData, compData]) => {
      // Discard stale responses if newer request was dispatched
      if (currentVersion !== requestVersionRef.current) return;

      // Sanity check: Ensure returned data corresponds to currently active focusEntityId and hops
      if (blast.focus_entity !== focusEntityId || blast.max_hops_requested !== hops) {
        return;
      }

      setBlastData(blast);
      setPaths(pData.paths || []);
      setChokePoints(cpData.choke_points || []);
      setComparisons(compData.candidate_comparisons || []);

      if (blast.compute_time_ms !== undefined) {
        setMeasuredLatency(blast.compute_time_ms);
      } else {
        setMeasuredLatency(Math.round((performance.now() - t0) * 10) / 10);
      }

      // Atomically commit Authoritative Graph State
      setAuthoritativeGraph({
        scenarioId: currentScenario,
        rootId: focusEntityId,
        hops: hops,
        requestVersion: currentVersion,
        reachableEntities: blast.reachable_entities || [],
        reachableEdges: blast.reachable_edges || []
      });

      setIsLoadingGraph(false);
    })
    .catch(err => {
      if (currentVersion !== requestVersionRef.current) return;
      console.error("Graph analytics fetch error:", err);
      setGraphError(err.message || "Failed to load incident graph");
      setAuthoritativeGraph(null);
      setIsLoadingGraph(false);
    });

  }, [focusEntityId, hops, currentScenario, traversalTrigger]);

  // 4. Fetch Inspected Node Details
  useEffect(() => {
    if (!inspectedEntityId) {
      setInspectedNodeDetail(null);
      return;
    }
    fetch(`/api/entities/${inspectedEntityId}`)
      .then(res => res.json())
      .then(data => setInspectedNodeDetail(data))
      .catch(err => console.error("Error inspecting node:", err));
  }, [inspectedEntityId, currentScenario]);

  // 5. Initialize Cytoscape Instance
  useEffect(() => {
    if (!cyRef.current) return;

    if (!cyInstance.current) {
      cyInstance.current = cytoscape({
        container: cyRef.current,
        style: [
          {
            selector: 'node',
            style: {
              'label': 'data(label)',
              'color': '#e2e8f0',
              'font-size': '11px',
              'font-family': 'ui-monospace, monospace',
              'font-weight': 600,
              'text-valign': 'bottom',
              'text-margin-y': 7,
              'text-background-color': '#090d16',
              'text-background-opacity': 0.85,
              'text-background-padding': '2px',
              'text-background-shape': 'roundrectangle',
              'background-color': '#1e293b',
              'border-width': 2,
              'border-color': '#475569',
              'width': 36,
              'height': 36,
              'transition-property': 'background-color, border-color, width, height, opacity',
              'transition-duration': 0.2
            }
          },
          {
            selector: 'node[type = "User"]',
            style: {
              'background-color': '#0f766e',
              'border-color': '#14b8a6'
            }
          },
          {
            selector: 'node[type = "Endpoint"]',
            style: {
              'background-color': '#1e293b',
              'border-color': '#38bdf8'
            }
          },
          {
            selector: 'node[type = "Server"]',
            style: {
              'background-color': '#1e1b4b',
              'border-color': '#818cf8'
            }
          },
          {
            selector: 'node[type = "Application"]',
            style: {
              'background-color': '#312e81',
              'border-color': '#a78bfa'
            }
          },
          {
            selector: 'node[type = "Vulnerability"]',
            style: {
              'background-color': '#831843',
              'border-color': '#f43f5e',
              'shape': 'diamond',
              'width': 28,
              'height': 28
            }
          },
          {
            selector: 'node[?isFocusRoot]',
            style: {
              'background-color': '#dc2626',
              'border-color': '#f87171',
              'border-width': 4,
              'color': '#fca5a5',
              'font-weight': 'bold',
              'width': 42,
              'height': 42
            }
          },
          {
            selector: 'node[?isCritical]',
            style: {
              'background-color': '#ea580c',
              'border-color': '#fb923c',
              'border-width': 3.5,
              'color': '#fdba74',
              'font-weight': 'bold',
              'shape': 'hexagon',
              'width': 44,
              'height': 44
            }
          },
          {
            selector: 'node[?isChoke]',
            style: {
              'border-color': '#c084fc',
              'border-width': 3.5
            }
          },
          {
            selector: 'node.inspected-node',
            style: {
              'border-color': '#38bdf8',
              'border-width': 4,
              'underlay-color': '#38bdf8',
              'underlay-padding': '4px',
              'underlay-opacity': 0.35
            }
          },
          {
            selector: 'node.path-node-highlight',
            style: {
              'border-color': '#f59e0b',
              'border-width': 4,
              'background-color': '#78350f',
              'color': '#fef3c7',
              'font-weight': 'bold'
            }
          },
          {
            selector: 'node.path-dimmed',
            style: {
              'opacity': 0.2
            }
          },
          {
            selector: 'node.contained-isolated',
            style: {
              'opacity': 0.35,
              'border-style': 'dashed',
              'border-color': '#ef4444',
              'background-color': '#450a0a'
            }
          },
          {
            selector: 'node.severed-unreachable',
            style: {
              'opacity': 0.2,
              'border-style': 'dashed'
            }
          },
          {
            selector: 'edge',
            style: {
              'width': 2,
              'line-color': '#334155',
              'target-arrow-color': '#334155',
              'target-arrow-shape': 'triangle',
              'arrow-scale': 1.1,
              'curve-style': 'bezier',
              'control-point-step-size': 35,
              'label': 'data(type)',
              'font-size': '8px',
              'color': '#94a3b8',
              'text-rotation': 'autorotate',
              'text-margin-y': -8,
              'text-background-color': '#070a12',
              'text-background-opacity': 0.85,
              'text-background-padding': '2px',
              'text-background-shape': 'roundrectangle'
            }
          },
          {
            selector: 'edge[category = "OBSERVED"]',
            style: {
              'line-color': '#38bdf8',
              'target-arrow-color': '#38bdf8',
              'width': 2.5
            }
          },
          {
            selector: 'edge[category = "AUTHORIZED"]',
            style: {
              'line-color': '#94a3b8',
              'target-arrow-color': '#94a3b8',
              'line-style': 'dashed',
              'width': 1.8
            }
          },
          {
            selector: 'edge[category = "INFERRED"]',
            style: {
              'line-color': '#eab308',
              'target-arrow-color': '#eab308',
              'line-style': 'dotted',
              'width': 2
            }
          },
          {
            selector: 'edge.path-edge-highlight',
            style: {
              'width': 4.5,
              'line-color': '#f59e0b',
              'target-arrow-color': '#f59e0b',
              'z-index': 99
            }
          },
          {
            selector: 'edge.path-dimmed',
            style: {
              'opacity': 0.15
            }
          },
          {
            selector: 'edge.severed-edge',
            style: {
              'line-style': 'dashed',
              'opacity': 0.15,
              'line-color': '#ef4444',
              'target-arrow-color': '#ef4444'
            }
          }
        ],
        layout: { name: 'preset' }
      });

      cyInstance.current.on('tap', 'node', (evt) => {
        const node = evt.target;
        setInspectedEntityId(node.id());
      });
    }

    const ro = new ResizeObserver(() => {
      if (cyInstance.current) {
        cyInstance.current.resize();
      }
    });

    if (cyRef.current) {
      ro.observe(cyRef.current);
    }

    return () => {
      ro.disconnect();
    };
  }, []);

  // 5b. Force Resize and Fit Cytoscape Canvas on Tab Switch
  useEffect(() => {
    if (activeTab === 'workspace' && cyInstance.current) {
      requestAnimationFrame(() => {
        if (cyInstance.current) {
          cyInstance.current.resize();
          cyInstance.current.fit(undefined, 35);
        }
      });
    }
  }, [activeTab]);

  // 6. Update Cytoscape Graph Topology with Incident-Centered Scope & Deterministic Layout
  useEffect(() => {
    const cy = cyInstance.current;
    if (!cy) return;

    if (!authoritativeGraph) {
      cy.elements().remove();
      return;
    }

    const { rootId, reachableEntities, reachableEdges } = authoritativeGraph;

    // Incident-Centered Subgraph: Filter by active hop scope and user type filters
    const activeEntities = reachableEntities.filter(e => {
      if (typeFilters[e.type] !== undefined) {
        return typeFilters[e.type];
      }
      return true;
    });

    const activeNodeIds = new Set(activeEntities.map(e => e.id));

    // Calculate deterministic layered layout positions directly from authoritative graph
    const positions = computeDeterministicPositions(
      reachableEntities,
      reachableEdges,
      rootId
    );

    // Sort nodes deterministically for consistent DOM/SVG z-order and reproducible rendering
    const sortedEntities = [...activeEntities].sort((a, b) => {
      if (a.id === rootId) return -1;
      if (b.id === rootId) return 1;
      if (a.hops !== b.hops) return a.hops - b.hops;
      if (a.is_critical && !b.is_critical) return -1;
      if (!a.is_critical && b.is_critical) return 1;
      const typeCompare = a.type.localeCompare(b.type);
      if (typeCompare !== 0) return typeCompare;
      return a.id.localeCompare(b.id);
    });

    const cyNodes = sortedEntities.map(e => {
      const fullMeta = entities.find(ent => ent.id === e.id);
      const pos = positions[e.id] || { x: 130 + (e.hops || 1) * 220, y: 320 };
      return {
        data: {
          id: e.id,
          label: e.label,
          type: e.type,
          isFocusRoot: e.id === rootId,
          isCritical: e.is_critical,
          isChoke: fullMeta?.isChoke || false
        },
        position: pos
      };
    });

    // Render only edges connecting filtered nodes and matching category filters
    const filteredEdges = reachableEdges
      .filter(edge => activeNodeIds.has(edge.source) && activeNodeIds.has(edge.target))
      .filter(edge => categoryFilters[edge.category] !== false);

    // Sort edges deterministically
    const sortedEdges = [...filteredEdges].sort((a, b) => {
      const sComp = a.source.localeCompare(b.source);
      if (sComp !== 0) return sComp;
      const tComp = a.target.localeCompare(b.target);
      if (tComp !== 0) return tComp;
      return a.type.localeCompare(b.type);
    });

    // Edge deduplication map and canonical IDs
    const seenEdges = new Set<string>();
    const cyEdges: Array<any> = [];

    sortedEdges.forEach(edge => {
      const edgeKey = `edge:${edge.source}->${edge.target}:${edge.type}`;
      if (!seenEdges.has(edgeKey)) {
        seenEdges.add(edgeKey);
        cyEdges.push({
          data: {
            id: edgeKey,
            source: edge.source,
            target: edge.target,
            type: edge.type,
            category: edge.category
          }
        });
      }
    });

    // Atomic Clear and Replace inside Cytoscape batch
    cy.batch(() => {
      cy.elements().remove();
      cy.add([...cyNodes, ...cyEdges]);
    });

    cy.resize();
    cy.fit(undefined, 40);

    requestAnimationFrame(() => {
      if (cyInstance.current) {
        cyInstance.current.resize();
        cyInstance.current.fit(undefined, 40);
      }
    });
  }, [authoritativeGraph, entities, typeFilters, categoryFilters]);

  // 7. Interactive Highlighting (Inspected Node & Clicked Attack Path)
  useEffect(() => {
    const cy = cyInstance.current;
    if (!cy) return;

    // Reset highlight classes
    cy.nodes().removeClass('inspected-node path-node-highlight path-dimmed');
    cy.edges().removeClass('path-edge-highlight path-dimmed');

    // Highlight inspected node safely using getElementById
    if (inspectedEntityId) {
      cy.getElementById(inspectedEntityId).addClass('inspected-node');
    }

    // Highlight active attack path and de-emphasize non-path elements
    if (selectedPathId) {
      const activePath = paths.find(p => p.path_id === selectedPathId);
      if (activePath) {
        const pathNodeSet = new Set(activePath.nodes);
        
        // Dim all nodes and edges not in path
        cy.nodes().forEach(n => {
          if (!pathNodeSet.has(n.id())) {
            n.addClass('path-dimmed');
          }
        });
        cy.edges().addClass('path-dimmed');

        // Highlight path nodes safely using getElementById
        activePath.nodes.forEach(nId => {
          cy.getElementById(nId).addClass('path-node-highlight');
        });

        // Highlight path edges
        for (let i = 0; i < activePath.nodes.length - 1; i++) {
          const s = activePath.nodes[i];
          const t = activePath.nodes[i + 1];
          cy.edges(`[source = "${s}"][target = "${t}"]`)
            .removeClass('path-dimmed')
            .addClass('path-edge-highlight');
        }
      }
    }
  }, [inspectedEntityId, selectedPathId, paths]);

  // 8. Visual Synchronization of Containment Simulation
  useEffect(() => {
    const cy = cyInstance.current;
    if (!cy) return;

    cy.nodes().removeClass('contained-isolated severed-unreachable');
    cy.edges().removeClass('severed-edge');

    if (simulatedIsolationNode && containmentResult) {
      // Mark candidate node as isolated safely using getElementById
      cy.getElementById(simulatedIsolationNode).addClass('contained-isolated');
      
      // Sever edges attached to the candidate
      cy.edges().forEach(edge => {
        if (edge.source().id() === simulatedIsolationNode || edge.target().id() === simulatedIsolationNode) {
          edge.addClass('severed-edge');
        }
      });

      // Mark severed/unreachable nodes
      const postReachableIds = new Set(
        containmentResult.post_containment.reachable_entities.map((e: any) => e.id)
      );
      cy.nodes().forEach(node => {
        if (!postReachableIds.has(node.id()) && node.id() !== simulatedIsolationNode) {
          node.addClass('severed-unreachable');
        }
      });
    }
  }, [simulatedIsolationNode, containmentResult]);

  // 9. Toggle Containment Action
  const handleToggleContainment = async (candidateId: string) => {
    if (simulatedIsolationNode === candidateId) {
      setSimulatedIsolationNode(null);
      setContainmentResult(null);
    } else {
      try {
        const res = await fetch('/api/containment/simulate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            source_id: focusEntityId,
            candidate_node_id: candidateId,
            max_hops: hops
          })
        });
        const data = await res.json();
        setSimulatedIsolationNode(candidateId);
        setContainmentResult(data);
      } catch (err) {
        console.error("Containment simulation failed:", err);
      }
    }
  };

  const inspectedEntity = entities.find(e => e.id === inspectedEntityId);

  // Filtered search results strictly scoped to current incident graph
  const incidentGraphEntities = blastData?.reachable_entities || [];
  const searchResults = searchQuery.trim()
    ? incidentGraphEntities.filter(e => 
        e.id.toLowerCase().includes(searchQuery.toLowerCase()) || 
        (e.label && e.label.toLowerCase().includes(searchQuery.toLowerCase())) ||
        e.type.toLowerCase().includes(searchQuery.toLowerCase())
      ).slice(0, 8)
    : [];

  // Dynamic risk calculation
  const currentRisk = summary?.scenario?.base_risk || 50;
  const riskBadge = currentRisk >= 75 ? 'HIGH' : (currentRisk >= 40 ? 'MEDIUM' : 'LOW');
  const riskColor = currentRisk >= 75 ? 'text-red-400' : (currentRisk >= 40 ? 'text-amber-400' : 'text-emerald-400');
  const riskBg = currentRisk >= 75 ? 'bg-red-950/50 border-red-800/40' : (currentRisk >= 40 ? 'bg-amber-950/50 border-amber-800/40' : 'bg-emerald-950/50 border-emerald-800/40');

  return (
    <div className="flex flex-col h-screen w-screen bg-[#090d16] text-slate-200 select-none font-sans">
      
      {/* Top Application Header */}
      <header className="flex flex-wrap items-center justify-between gap-2 px-4 py-2 bg-[#0e1422] border-b border-[#1f293d] shrink-0">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 font-bold text-white tracking-wider text-sm">
            <span className="w-2.5 h-2.5 rounded-full bg-sky-400 shadow-[0_0_10px_rgba(56,189,248,0.8)]" />
            GRAPHOPS
          </div>
          <span className="text-xs text-slate-400 pl-3 border-l border-[#1f293d] hidden sm:inline">
            Incident-Centered Exposure & Containment Intelligence
          </span>
          <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-blue-950/60 text-sky-400 border border-sky-800/40 font-semibold">
            {summary?.scenario?.incident_id || 'INC-2026-0042'}
          </span>
          <span className={`text-[10px] uppercase font-mono px-2 py-0.5 rounded font-bold border ${riskBg} ${riskColor}`}>
            {riskBadge} SEVERITY
          </span>
        </div>

        {/* Search, Scenario Selector, and Root Controls */}
        <div className="flex flex-wrap items-center gap-3 text-xs">
          
          {/* Incident Graph Entity Search */}
          <div className="relative">
            <div className="flex items-center bg-[#141b2d] border border-[#1f293d] focus-within:border-sky-500 rounded px-2.5 py-1 text-slate-300 transition">
              <Search className="w-3.5 h-3.5 text-slate-400 mr-2 shrink-0" />
              <input
                type="text"
                placeholder="Find entity in graph... (e.g. bastion-mgmt)"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="bg-transparent border-none outline-none text-xs w-48 focus:w-64 transition-all text-white placeholder-slate-500 font-mono"
              />
              {searchQuery && (
                <button
                  onClick={() => setSearchQuery('')}
                  className="text-slate-500 hover:text-slate-300 text-xs ml-1"
                >
                  ✕
                </button>
              )}
            </div>

            {searchQuery.trim().length > 0 && (
              <div className="absolute top-full left-0 mt-1.5 w-72 bg-[#141b2d] border border-[#1f293d] rounded-lg shadow-2xl z-50 overflow-hidden">
                <div className="px-2.5 py-1 bg-[#0e1422] border-b border-[#1f293d] text-[10px] text-slate-400 flex justify-between items-center font-mono uppercase">
                  <span>Incident Entities ({searchResults.length})</span>
                  <span>Select to inspect</span>
                </div>
                {searchResults.length > 0 ? (
                  <div className="max-h-60 overflow-y-auto">
                    {searchResults.map(item => (
                      <div
                        key={item.id}
                        onClick={() => {
                          setInspectedEntityId(item.id);
                          setSearchQuery('');
                          if (cyInstance.current) {
                            const node = cyInstance.current.getElementById(item.id);
                            if (node && node.length > 0) {
                              cyInstance.current.animate({
                                center: { eles: node },
                                zoom: Math.max(cyInstance.current.zoom(), 1.25),
                                duration: 350
                              });
                            }
                          }
                        }}
                        className="px-3 py-2 hover:bg-[#1f293d] cursor-pointer text-xs flex justify-between items-center border-b border-[#1f293d]/40 last:border-none transition group"
                      >
                        <div className="flex flex-col">
                          <span className="font-mono text-white group-hover:text-sky-300 font-medium">{item.id}</span>
                          <span className="text-[10px] text-slate-400">{item.label !== item.id ? item.label : ''}</span>
                        </div>
                        <div className="flex items-center gap-1.5">
                          <span className={`text-[9px] px-1.5 py-0.5 rounded font-mono font-semibold uppercase ${
                            item.is_critical ? 'bg-orange-950 text-orange-400 border border-orange-800/40' :
                            item.type === 'User' ? 'bg-teal-950 text-teal-400 border border-teal-800/40' :
                            item.type === 'Server' ? 'bg-indigo-950 text-indigo-400 border border-indigo-800/40' :
                            item.type === 'Endpoint' ? 'bg-sky-950 text-sky-400 border border-sky-800/40' :
                            item.type === 'Vulnerability' ? 'bg-rose-950 text-rose-400 border border-rose-800/40' :
                            'bg-slate-800 text-slate-300'
                          }`}>
                            {item.type}
                          </span>
                          <span className="text-[10px] text-slate-500 font-mono">
                            {item.id === focusEntityId ? 'Root' : `Hop ${item.hops}`}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="p-3 text-xs text-slate-400 italic text-center font-sans">
                    No matching entities in the current incident graph.
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Scenario Selector */}
          <div className="flex items-center gap-1.5">
            <span className="text-slate-400 text-[11px] uppercase">Scenario:</span>
            <select 
              value={currentScenario}
              onChange={(e) => {
                loadScenarioDetails(e.target.value);
              }}
              className="bg-[#141b2d] border border-[#1f293d] rounded px-2 py-1 text-xs text-slate-200 outline-none hover:border-[#334466] font-medium"
            >
              {scenarios.map(sc => (
                <option key={sc.id} value={sc.id}>{sc.name}</option>
              ))}
            </select>
          </div>

          {/* Root Entity Selector */}
          <div className="flex items-center gap-1.5">
            <span className="text-slate-400 text-[11px] uppercase">Root:</span>
            <select 
              value={focusEntityId}
              onChange={(e) => setFocusEntityId(e.target.value)}
              className="bg-[#141b2d] border border-[#1f293d] rounded px-2 py-1 text-xs text-slate-200 outline-none hover:border-[#334466] font-mono"
            >
              {entities.map(e => (
                <option key={e.id} value={e.id}>{e.label} ({e.type})</option>
              ))}
            </select>
          </div>

          {/* Latency & Reset Button */}
          {measuredLatency !== null && (
            <div className="text-[10px] font-mono text-slate-400 px-2 py-1 bg-[#141b2d] border border-[#1f293d] rounded">
              {measuredLatency} ms
            </div>
          )}

          <button 
            onClick={() => loadScenarioDetails(currentScenario)}
            className="flex items-center gap-1.5 bg-[#141b2d] border border-[#1f293d] px-2.5 py-1 rounded text-xs hover:border-[#334466] text-slate-300 hover:text-white"
            title="Reset simulation and layout"
          >
            <RotateCcw className="w-3.5 h-3.5" /> Reset
          </button>
        </div>
      </header>

      {/* 8-Stage Master Workflow Navigation Ribbon */}
      <div className="flex items-center justify-between gap-3 px-4 py-1.5 bg-[#0b101c] border-b border-[#1f293d] text-[11px] font-mono shrink-0 overflow-x-auto whitespace-nowrap scrollbar-thin">
        <div className="flex items-center gap-1.5 text-slate-400">
          <span className="text-sky-400 font-semibold bg-sky-950/50 border border-sky-800/40 px-2 py-0.5 rounded">01. ALERT</span>
          <span className="text-slate-600">→</span>
          <span className="text-sky-400 font-semibold bg-sky-950/50 border border-sky-800/40 px-2 py-0.5 rounded">02. CONTEXT</span>
          <span className="text-slate-600">→</span>
          <span className={`px-2 py-0.5 rounded font-semibold ${paths.length > 0 ? 'text-amber-400 bg-amber-950/50 border border-amber-800/40' : 'text-slate-500'}`}>
            03. PATH ({paths.length})
          </span>
          <span className="text-slate-600">→</span>
          <span className="text-sky-400 font-semibold bg-sky-950/50 border border-sky-800/40 px-2 py-0.5 rounded">
            04. BLAST RADIUS ({hops} HOPS)
          </span>
          <span className="text-slate-600">→</span>
          <span className={`px-2 py-0.5 rounded font-semibold ${chokePoints.length ? 'text-purple-400 bg-purple-950/50 border border-purple-800/40' : 'text-slate-500'}`}>
            05. CHOKE POINT
          </span>
          <span className="text-slate-600">→</span>
          <span className={`px-2 py-0.5 rounded font-semibold ${simulatedIsolationNode ? 'text-emerald-400 bg-emerald-950/50 border border-emerald-800/40' : 'text-slate-500'}`}>
            06. WHAT-IF CONTAINMENT
          </span>
          <span className="text-slate-600">→</span>
          <span className={`px-2 py-0.5 rounded font-semibold ${containmentResult?.alternate_paths?.length ? 'text-amber-400 bg-amber-950/50 border border-amber-800/40' : 'text-slate-500'}`}>
            07. REMAINING EXPOSURE
          </span>
          <span className="text-slate-600">→</span>
          <span className="text-indigo-400 font-semibold bg-indigo-950/50 border border-indigo-800/40 px-2 py-0.5 rounded">
            08. HUMAN DECISION
          </span>
        </div>

        {/* Active View / Back Control */}
        <div className="flex items-center gap-2">
          {activeTab !== 'workspace' && (
            <button
              onClick={() => setActiveTab('workspace')}
              className="flex items-center gap-1.5 px-2.5 py-0.5 rounded bg-sky-950/80 border border-sky-700/60 text-sky-300 hover:text-white text-[11px] font-sans font-semibold transition"
            >
              ← Back to Investigation Graph
            </button>
          )}
          <div className="text-[10px] text-slate-400 flex items-center gap-1.5 font-sans">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
            <span>SOC Incident Active</span>
          </div>
        </div>
      </div>

      {/* Main Investigation Workspace (Persistently Mounted in DOM) */}
      <div className={`grid grid-cols-1 lg:grid-cols-[300px_1fr_340px] xl:grid-cols-[310px_1fr_360px] flex-1 min-h-0 overflow-y-auto lg:overflow-hidden ${activeTab === 'workspace' ? '' : 'hidden'}`}>
        
        {/* LEFT COLUMN: Telemetry Context, Hops & Attack Paths */}
        <div className="bg-[#0e1422] border-r border-[#1f293d] flex flex-col overflow-hidden">
          <div className="px-3 py-2 bg-white/[0.02] border-b border-[#1f293d] text-xs font-semibold uppercase tracking-wider text-slate-400 flex justify-between items-center">
            <span>Incident Telemetry</span>
            <span className="font-mono text-[10px] text-sky-400 bg-sky-950/60 border border-sky-800/40 px-1.5 py-0.5 rounded">
              {summary?.scenario?.id}
            </span>
          </div>

          <div className="p-3 flex flex-col gap-3 overflow-y-auto flex-1">
            
            {/* Event Detection Context Card */}
            <div className="bg-[#141b2d] border border-[#1f293d] rounded p-2.5 flex flex-col gap-1.5">
              <div className="flex justify-between items-center text-[11px] text-slate-400 font-semibold uppercase">
                <span>Detection Trigger</span>
                <span className={`font-bold ${riskColor}`}>{riskBadge} RISK</span>
              </div>
              <div className="text-xs text-white font-semibold leading-snug">
                {summary?.scenario?.initial_event}
              </div>
              <div className="flex justify-between text-xs pt-1 border-t border-[#1f293d]">
                <span className="text-slate-400">Suspected Origin:</span>
                <span className="font-mono text-red-400 font-semibold">{summary?.scenario?.root_entity}</span>
              </div>
              <div className="flex justify-between text-xs">
                <span className="text-slate-400">Primary Target:</span>
                <span className="font-mono text-orange-400 font-semibold">{summary?.scenario?.primary_target}</span>
              </div>
              <div className="flex justify-between text-xs">
                <span className="text-slate-400">MITRE ATT&CK:</span>
                <span className="font-mono text-sky-400">{summary?.scenario?.mitre_technique || 'N/A'}</span>
              </div>
              <div className="flex justify-between text-xs">
                <span className="text-slate-400">Heuristic Score:</span>
                <span className={`font-mono font-bold ${riskColor}`}>{currentRisk} / 100</span>
              </div>

              {/* Contextual Access: Incident Timeline */}
              <button
                onClick={() => setActiveTab('timeline')}
                className="mt-1 flex items-center justify-between w-full px-2.5 py-1.5 bg-[#0e1422] hover:bg-[#1a233a] border border-[#1f293d] hover:border-sky-600/50 rounded text-xs transition group"
                title="View chronological incident telemetry event sequence"
              >
                <div className="flex items-center gap-1.5 text-sky-400 font-medium text-[11px]">
                  <Clock className="w-3.5 h-3.5" />
                  <span>View Incident Timeline</span>
                </div>
                <span className="font-mono text-[10px] text-slate-400 group-hover:text-white bg-[#141b2d] px-1.5 py-0.5 rounded border border-[#1f293d]">
                  {timeline.length} events
                </span>
              </button>
            </div>

              {/* Hop Depth Scope Controls */}
              <div className="bg-[#141b2d] border border-[#1f293d] rounded p-2.5 flex flex-col gap-2">
                <div className="flex justify-between items-center text-[11px] text-slate-400 font-semibold uppercase">
                  <span>Blast Radius Traversal</span>
                  <span className="font-mono text-sky-400">{hops} Hops Rooted at {focusEntityId}</span>
                </div>
                <div className="grid grid-cols-3 gap-1.5">
                  {[1, 2, 3].map(h => (
                    <button
                      key={h}
                      onClick={() => {
                        if (hops === h) {
                          setTraversalTrigger(prev => prev + 1);
                        } else {
                          setHops(h);
                        }
                      }}
                      className={`py-1 text-xs font-mono rounded font-semibold border transition ${
                        hops === h 
                          ? 'bg-sky-600 border-sky-400 text-white shadow-[0_0_8px_rgba(56,189,248,0.4)]' 
                          : 'bg-[#0e1422] border-[#1f293d] text-slate-300 hover:border-[#334466]'
                      }`}
                    >
                      {h} HOP{h > 1 ? 'S' : ''}
                    </button>
                  ))}
                </div>
                
                {/* Categorized Entity Breakdown */}
                <div className="bg-[#0e1422] p-2 rounded border border-[#1f293d] text-[11px] flex flex-col gap-1">
                  <div className="flex justify-between text-slate-400">
                    <span>Reachable Entities:</span>
                    <strong className="text-white font-mono">{blastData?.reachable_count || 0}</strong>
                  </div>
                  {blastData?.entity_type_breakdown && (
                    <div className="grid grid-cols-2 gap-x-2 gap-y-0.5 text-[10px] text-slate-400 pt-1 border-t border-[#1f293d]">
                      {Object.entries(blastData.entity_type_breakdown).map(([t, cnt]) => (
                        <div key={t} className="flex justify-between">
                          <span>{t}:</span>
                          <span className="font-mono text-slate-200">{cnt}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>

              {/* Hop-Bounded Attack Paths Explorer */}
              <div className="bg-[#141b2d] border border-[#1f293d] rounded p-2.5 flex flex-col gap-1.5 flex-1 min-h-[180px]">
                <div className="flex justify-between items-center text-[11px] text-slate-400 font-semibold uppercase">
                  <span>Attack Paths (≤ {hops} Hops)</span>
                  <span className="text-[10px] text-slate-400 font-mono">
                    {simulatedIsolationNode 
                      ? `${containmentResult?.post_containment?.active_paths_count || 0} Active / ${containmentResult?.severed_paths?.length || 0} Severed`
                      : `${paths.length} Active`
                    }
                  </span>
                </div>
                
                {paths.length === 0 ? (
                  <div className="text-xs text-slate-500 py-4 text-center italic">
                    No active paths to critical assets within {hops} hop(s).
                  </div>
                ) : (
                  <div className="flex flex-col gap-1.5 overflow-y-auto max-h-56 pr-0.5">
                    {paths.map(p => {
                      const isSevered = simulatedIsolationNode && (p.nodes.includes(simulatedIsolationNode) || containmentResult?.severed_paths?.some((sp: any) => sp.path_id === p.path_id));
                      const isSelected = selectedPathId === p.path_id;
                      return (
                        <div
                          key={p.path_id}
                          onClick={() => setSelectedPathId(isSelected ? null : p.path_id)}
                          className={`p-2 rounded border cursor-pointer text-xs flex flex-col gap-1 transition ${
                            isSevered 
                              ? 'opacity-40 line-through border-dashed border-red-900 bg-red-950/20'
                              : isSelected 
                                ? 'border-amber-500 bg-amber-950/40 shadow-[0_0_8px_rgba(245,158,11,0.3)]' 
                                : 'border-[#1f293d] bg-[#0e1422] hover:border-[#334466]'
                          }`}
                        >
                          <div className="flex justify-between items-center font-semibold text-[11px]">
                            <span className="text-white flex items-center gap-1">
                              <ChevronRight className="w-3 h-3 text-amber-400 shrink-0" />
                              Target: {p.target_id}
                            </span>
                            <span className={`px-1.5 py-0.2 rounded text-[10px] font-mono ${isSevered ? 'text-red-400 bg-red-950' : 'text-amber-400 bg-amber-950'}`}>
                              {isSevered ? 'SEVERED' : `${p.length} Hops`}
                            </span>
                          </div>
                          <div className="font-mono text-[10px] text-slate-400 truncate">
                            {p.nodes.join(' → ')}
                          </div>
                          {p.vulnerabilities && p.vulnerabilities.length > 0 && (
                            <div className="text-[9px] text-red-400 font-mono flex items-center gap-1">
                              <span>⚠ Exploit Pivot:</span> {p.vulnerabilities.join(', ')}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>

              {/* Critical Assets List with Itemized Status */}
              <div className="bg-[#141b2d] border border-[#1f293d] rounded p-2.5 flex flex-col gap-1.5">
                <div className="flex justify-between items-center text-[11px] text-slate-400 font-semibold uppercase">
                  <span>Crown Jewels at Risk</span>
                  <span className="text-orange-400 font-bold font-mono">
                    {simulatedIsolationNode 
                      ? `${containmentResult?.post_containment?.critical_assets_exposed || 0} Exposed`
                      : `${blastData?.critical_asset_count || 0} Exposed`
                    }
                  </span>
                </div>
                <div className="flex flex-col gap-1 text-xs">
                  {(blastData?.critical_assets || []).length === 0 ? (
                    <div className="text-[11px] text-slate-500 italic py-1">No critical assets reachable within {hops} hops.</div>
                  ) : (
                    (blastData?.critical_assets || []).map(ca => {
                      let assetStatusLabel = `Exposed (${ca.hops} hops)`;
                      let statusColor = 'text-orange-400';

                      if (simulatedIsolationNode && containmentResult) {
                        const item = containmentResult.asset_statuses?.find((s: AssetStatus) => s.id === ca.id);
                        if (item) {
                          assetStatusLabel = item.status === 'PROTECTED' ? '✓ PROTECTED' : '⚠ STILL EXPOSED';
                          statusColor = item.status === 'PROTECTED' ? 'text-emerald-400 font-bold' : 'text-red-400 font-bold';
                        }
                      }

                      return (
                        <div key={ca.id} className="flex justify-between items-center py-1 border-b border-[#1f293d]/40 last:border-none">
                          <span className="font-mono text-white flex items-center gap-1.5">
                            <Database className="w-3 h-3 text-orange-400" />
                            {ca.label}
                          </span>
                          <span className={`text-[11px] font-mono ${statusColor}`}>
                            {assetStatusLabel}
                          </span>
                        </div>
                      );
                    })
                  )}
                </div>
              </div>

            </div>
          </div>

          {/* CENTER COLUMN: Cytoscape Graph Canvas & Entity Filters */}
          <div className="relative flex flex-col bg-[#070a12] overflow-hidden min-h-[480px] lg:min-h-0">
            
            {/* Top Subgraph Info & Filter Bar */}
            <div className="absolute top-3 left-4 right-4 z-10 flex justify-between items-center pointer-events-none">
              <div className="flex flex-col gap-0.5 bg-[#0e1422]/90 backdrop-blur px-3 py-1.5 rounded border border-[#1f293d] pointer-events-auto">
                <div className="text-xs font-bold text-white tracking-wide flex items-center gap-2">
                  <span>INCIDENT-CENTERED SUBGRAPH</span>
                  <span className="text-[10px] font-mono text-slate-400 font-normal">
                    Root: <strong className="text-red-400">{focusEntityId}</strong> • Scope: {hops} Hops • {blastData?.reachable_count || 0} Entities
                  </span>
                </div>
              </div>

              {/* Entity Type & Category Filters */}
              <div className="flex items-center gap-1.5 bg-[#0e1422]/90 backdrop-blur px-2.5 py-1 rounded border border-[#1f293d] pointer-events-auto text-[11px]">
                <Filter className="w-3 h-3 text-slate-400 mr-1" />
                {Object.keys(typeFilters).map(t => (
                  <button
                    key={t}
                    onClick={() => setTypeFilters(prev => ({ ...prev, [t]: !prev[t] }))}
                    className={`px-1.5 py-0.5 rounded text-[10px] font-mono transition ${
                      typeFilters[t] 
                        ? 'bg-[#1f293d] text-white border border-[#334466]' 
                        : 'bg-transparent text-slate-500 border border-transparent'
                    }`}
                  >
                    {t}
                  </button>
                ))}
                <span className="w-px h-3.5 bg-[#1f293d] mx-0.5" />
                {Object.keys(categoryFilters).map(c => (
                  <button
                    key={c}
                    onClick={() => setCategoryFilters(prev => ({ ...prev, [c]: !prev[c] }))}
                    className={`px-1.5 py-0.5 rounded text-[10px] font-mono transition ${
                      categoryFilters[c] 
                        ? (c === 'OBSERVED' ? 'bg-sky-950/70 text-sky-300 border border-sky-700/50' : c === 'AUTHORIZED' ? 'bg-slate-800 text-slate-200 border border-slate-600' : 'bg-amber-950/70 text-amber-300 border border-amber-700/50')
                        : 'bg-transparent text-slate-500 border border-transparent'
                    }`}
                  >
                    {c}
                  </button>
                ))}
              </div>
            </div>

            {/* Cytoscape Canvas Container */}
            <div ref={cyRef} className="w-full h-full" />

            {/* Canvas State Overlays */}
            {isLoadingGraph && (
              <div className="absolute inset-0 z-20 flex flex-col items-center justify-center bg-[#070a12]/80 backdrop-blur-sm pointer-events-auto">
                <div className="w-8 h-8 rounded-full border-2 border-sky-500 border-t-transparent animate-spin mb-3" />
                <span className="text-xs font-mono font-semibold tracking-wider text-sky-400">LOADING INCIDENT GRAPH...</span>
                <span className="text-[10px] font-mono text-slate-400 mt-1">Scope: {hops} Hops Rooted at {focusEntityId}</span>
              </div>
            )}

            {graphError && !isLoadingGraph && (
              <div className="absolute inset-0 z-20 flex flex-col items-center justify-center bg-[#070a12]/90 backdrop-blur-sm pointer-events-auto p-4 text-center">
                <AlertTriangle className="w-8 h-8 text-red-400 mb-2" />
                <span className="text-xs font-mono font-bold text-red-400 uppercase">UNABLE TO LOAD INCIDENT GRAPH</span>
                <span className="text-[11px] text-slate-400 mt-1 max-w-sm">{graphError}</span>
                <button
                  onClick={() => loadScenarioDetails(currentScenario)}
                  className="mt-3 px-3 py-1.5 rounded bg-red-950/80 border border-red-700/60 hover:bg-red-900 text-red-200 text-xs font-semibold"
                >
                  Retry Graph Traversal
                </button>
              </div>
            )}

            {!isLoadingGraph && !graphError && blastData && (blastData.reachable_entities || []).length === 0 && (
              <div className="absolute inset-0 z-20 flex flex-col items-center justify-center bg-[#070a12]/60 pointer-events-auto text-center p-4">
                <Database className="w-8 h-8 text-slate-600 mb-2" />
                <span className="text-xs font-mono font-semibold text-slate-400">NO CONNECTED ENTITIES IN SCOPE</span>
                <span className="text-[10px] text-slate-500 mt-1">Try expanding hop depth or selecting another entity.</span>
              </div>
            )}

            {/* Semantic Relationship Legend */}
            <div className="absolute bottom-3 left-4 z-10 bg-[#0e1422]/90 backdrop-blur border border-[#1f293d] rounded px-3 py-1.5 flex gap-4 text-[11px] text-slate-400 pointer-events-auto">
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-red-600 border border-red-400" />
                <span>Root</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-orange-600 border border-orange-400" />
                <span>Critical Asset</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-purple-600 border border-purple-400" />
                <span>Choke Point</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-3 h-0.5 bg-sky-400" />
                <span>Observed (Telemetry)</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-3 h-0.5 bg-slate-400 border-b border-dashed" />
                <span>Authorized (Policy)</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-3 h-0.5 bg-amber-400 border-b border-dotted" />
                <span>Inferred (Analytic)</span>
              </div>
            </div>
          </div>

          {/* RIGHT COLUMN: Decision Support, Node Inspector, Choke Points & Simulation */}
          <div className="bg-[#0e1422] border-l border-[#1f293d] flex flex-col overflow-hidden">
            <div className="px-3 py-2 bg-white/[0.02] border-b border-[#1f293d] text-xs font-semibold uppercase tracking-wider text-slate-400 flex justify-between items-center">
              <span>Decision Support</span>
              <span className="text-[10px] text-slate-500 font-mono">Tier-2 Analyst</span>
            </div>

            <div className="p-3 flex flex-col gap-3 overflow-y-auto flex-1">
              
              {/* Inspected Node Detail Card */}
              {inspectedEntity && (
                <div className="bg-[#141b2d] border border-[#1f293d] rounded p-2.5 flex flex-col gap-1.5">
                  <div className="flex justify-between items-center text-[11px] text-slate-400 font-semibold uppercase">
                    <span>Node Inspector</span>
                    <span className="px-1.5 py-0.5 rounded text-[10px] bg-sky-950 text-sky-400 font-mono">
                      {inspectedEntity.type}
                    </span>
                  </div>
                  <div className="font-mono text-sm font-bold text-white flex justify-between items-center">
                    <span>{inspectedEntity.id}</span>
                    {inspectedNodeDetail && (
                      <span className="text-xs font-mono text-amber-400">
                        Risk: {inspectedNodeDetail.heuristic_risk_score}/100
                      </span>
                    )}
                  </div>
                  <div className="flex justify-between text-xs">
                    <span className="text-slate-400">Role / Zone:</span>
                    <span className="text-slate-200">{inspectedEntity.role || inspectedEntity.zone || 'Standard'}</span>
                  </div>
                  <div className="flex justify-between text-xs">
                    <span className="text-slate-400">OS / Environment:</span>
                    <span className="text-slate-200 truncate max-w-[190px]">{inspectedEntity.os || 'Enterprise Asset'}</span>
                  </div>
                  <div className="flex justify-between text-xs">
                    <span className="text-slate-400">Containment Status:</span>
                    <span className={`font-semibold ${simulatedIsolationNode === inspectedEntity.id ? 'text-red-400 font-mono' : 'text-emerald-400 font-mono'}`}>
                      {simulatedIsolationNode === inspectedEntity.id ? 'Simulated Isolation' : 'Online'}
                    </span>
                  </div>

                  {/* Node Risk Contributors */}
                  {inspectedNodeDetail?.risk_contributors && (
                    <div className="pt-1.5 border-t border-[#1f293d] flex flex-col gap-0.5 text-[10px] text-slate-400">
                      <span className="font-semibold text-slate-300">Heuristic Risk Contributors:</span>
                      {inspectedNodeDetail.risk_contributors.map((c: string, idx: number) => (
                        <div key={idx} className="font-mono text-slate-300">{c}</div>
                      ))}
                    </div>
                  )}

                  <div className="grid grid-cols-2 gap-1.5 pt-1.5 border-t border-[#1f293d]">
                    {inspectedEntity.id === focusEntityId ? (
                      <div className="py-1 px-2 text-[11px] bg-red-950/50 border border-red-800/60 rounded text-red-300 font-mono font-semibold text-center flex items-center justify-center">
                        Active Root
                      </div>
                    ) : (
                      <button
                        onClick={() => setFocusEntityId(inspectedEntity.id)}
                        className="py-1 text-xs bg-sky-950/60 border border-sky-600/50 rounded hover:bg-sky-900/60 text-sky-200 font-medium transition"
                        title="Re-calculate attack paths and exposure starting from this node"
                      >
                        Set as Root
                      </button>
                    )}
                    <button
                      onClick={() => handleToggleContainment(inspectedEntity.id)}
                      className={`py-1 text-xs rounded font-medium border transition ${
                        simulatedIsolationNode === inspectedEntity.id
                          ? 'bg-red-950 border-red-700 text-red-300'
                          : 'bg-[#0e1422] border-[#1f293d] hover:border-purple-500 text-purple-300'
                      }`}
                    >
                      {simulatedIsolationNode === inspectedEntity.id ? 'Revert' : 'Simulate Isolation'}
                    </button>
                  </div>
                  <div className="text-[10px] text-slate-500 pt-0.5 italic">
                    {inspectedEntity.id === focusEntityId 
                      ? 'Investigation root: graph reachability originates from here.' 
                      : 'Inspection target. Click "Set as Root" to re-calculate graph traversal.'}
                  </div>
                </div>
              )}

              {/* Choke Point Candidates (Critical-Path Interception) */}
              <div className="bg-purple-950/20 border border-purple-800/40 rounded p-2.5 flex flex-col gap-2">
                <div className="flex justify-between items-center text-[11px] text-purple-300 font-semibold uppercase">
                  <span>Choke Point Candidates</span>
                  <span className="text-[10px] px-1.5 py-0.2 rounded bg-purple-900/50 text-purple-200 font-mono">
                    CRITICAL-PATH INTERCEPTION
                  </span>
                </div>
                
                {chokePoints.length === 0 ? (
                  <div className="text-xs text-slate-500 py-2 text-center italic">
                    No structural choke points within {hops} hops.
                  </div>
                ) : (
                  <div className="flex flex-col gap-2">
                    {chokePoints.map(cp => (
                      <div key={cp.node_id} className="flex flex-col gap-1 bg-[#141b2d] border border-[#1f293d] p-2 rounded">
                        <div className="flex justify-between items-center text-xs">
                          <span className="font-mono font-bold text-white">{cp.node_id}</span>
                          <span className="text-purple-400 font-mono text-[11px] font-bold">{cp.coverage_pct}% Interception</span>
                        </div>
                        <div className="text-[10px] text-slate-400">
                          Intercepts <strong className="text-white">{cp.paths_affected}</strong> of <strong className="text-white">{cp.total_critical_paths}</strong> critical paths • Downstream assets: <strong className="text-white">{cp.critical_assets_downstream}</strong>
                        </div>
                        {cp.ranking_reasons && (
                          <div className="flex flex-col gap-0.5 text-[9px] text-slate-400 bg-[#0e1422] p-1.5 rounded">
                            {cp.ranking_reasons.map((r, i) => (
                              <div key={i} className="font-mono text-purple-200/90">{r}</div>
                            ))}
                          </div>
                        )}
                        <button
                          onClick={() => handleToggleContainment(cp.node_id)}
                          className={`mt-1 py-1 px-2 rounded text-xs font-semibold border transition ${
                            simulatedIsolationNode === cp.node_id
                              ? 'bg-red-950 border-red-700 text-red-300'
                              : 'bg-purple-900/40 border-purple-600/50 text-purple-200 hover:bg-purple-900/60'
                          }`}
                        >
                          {simulatedIsolationNode === cp.node_id ? 'Revert Simulation' : `Simulate Isolating ${cp.node_id}`}
                        </button>
                      </div>
                    ))}
                  </div>
                )}

                {comparisons.length > 0 && (
                  <button
                    onClick={() => setActiveTab('comparison')}
                    className="mt-1 flex items-center justify-between w-full px-2.5 py-1.5 bg-purple-950/40 hover:bg-purple-900/50 border border-purple-800/40 hover:border-purple-600/50 rounded text-xs transition group"
                    title="Compare candidate containment leverage side-by-side"
                  >
                    <div className="flex items-center gap-1.5 text-purple-300 font-medium text-[11px]">
                      <Sliders className="w-3.5 h-3.5" />
                      <span>Compare Containment Candidates</span>
                    </div>
                    <span className="font-mono text-[10px] text-purple-300 group-hover:text-white bg-[#141b2d] px-1.5 py-0.5 rounded border border-purple-800/50">
                      {comparisons.length} options
                    </span>
                  </button>
                )}
              </div>

              {/* SURPRISE / Alternate Path Alert Box */}
              {containmentResult?.alternate_path_alert && (
                <div className="bg-amber-950/40 border border-amber-600/60 rounded p-2.5 flex flex-col gap-1.5 shadow-lg">
                  <div className="flex items-center gap-1.5 text-xs font-bold text-amber-300 uppercase tracking-wide">
                    <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
                    <span>CONTAINMENT INCOMPLETE</span>
                  </div>
                  <div className="text-[11px] text-amber-200 leading-snug">
                    {containmentResult.alternate_path_alert}
                  </div>
                  <div className="text-[10px] text-slate-400 italic pt-1 border-t border-amber-800/40">
                    Primary route severed, but alternate traversal route keeps critical database exposed.
                  </div>
                </div>
              )}

              {/* Containment Simulation Before/After Delta Card */}
              {containmentResult && (
                <div className="bg-emerald-950/20 border border-emerald-800/40 rounded p-2.5 flex flex-col gap-2 text-xs">
                  <div className="flex justify-between items-center text-[11px] font-semibold text-emerald-300 uppercase">
                    <span>Before / After Exposure Delta</span>
                    <span className="text-emerald-400 font-mono font-bold">RECALCULATED</span>
                  </div>
                  
                  <div className="grid grid-cols-3 gap-1 bg-[#141b2d] p-1.5 rounded border border-[#1f293d] text-center">
                    <div>
                      <div className="text-[9px] text-slate-400 uppercase">Reachable</div>
                      <div className="font-mono text-xs font-bold text-white">
                        {containmentResult.pre_containment.reachable_count} → {containmentResult.post_containment.reachable_count}
                      </div>
                      <div className="text-[10px] text-emerald-400 font-mono">
                        Δ {containmentResult.delta.reachable_entities_delta}
                      </div>
                    </div>
                    <div>
                      <div className="text-[9px] text-slate-400 uppercase">Crown Jewels</div>
                      <div className="font-mono text-xs font-bold text-white">
                        {containmentResult.pre_containment.critical_assets_exposed} → {containmentResult.post_containment.critical_assets_exposed}
                      </div>
                      <div className="text-[10px] text-emerald-400 font-mono">
                        Δ {containmentResult.delta.critical_assets_delta}
                      </div>
                    </div>
                    <div>
                      <div className="text-[9px] text-slate-400 uppercase">Active Paths</div>
                      <div className="font-mono text-xs font-bold text-white">
                        {containmentResult.pre_containment.active_paths_count} → {containmentResult.post_containment.active_paths_count}
                      </div>
                      <div className="text-[10px] text-emerald-400 font-mono">
                        Δ {containmentResult.delta.paths_delta}
                      </div>
                    </div>
                  </div>

                  <div className="flex justify-between text-[11px]">
                    <span className="text-slate-400">Paths Severed:</span>
                    <span className="font-mono text-emerald-400 font-bold">{containmentResult.impact_summary.paths_severed}</span>
                  </div>
                  <div className="flex justify-between text-[11px]">
                    <span className="text-slate-400">Remaining Alternate Paths:</span>
                    <span className="font-mono text-amber-400 font-bold">{containmentResult.alternate_paths.length}</span>
                  </div>
                </div>
              )}

              {/* Analyst Decision Record Card */}
              {containmentResult?.decision_record && (
                <div className="bg-[#141b2d] border border-indigo-800/40 rounded p-2.5 flex flex-col gap-1.5 text-xs">
                  <div className="flex justify-between items-center text-[11px] font-semibold text-indigo-300 uppercase">
                    <span>Analyst Decision Record</span>
                    <span className="text-[10px] text-indigo-400 font-mono">DECISION SUPPORT</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Simulated Action:</span>
                    <span className="font-mono text-white font-semibold">{containmentResult.decision_record.action_proposed}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Modeled Effect:</span>
                    <span className="font-mono text-slate-200">{containmentResult.decision_record.expected_graph_effect}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Assets Protected:</span>
                    <span className="font-mono text-emerald-400 font-semibold">{containmentResult.decision_record.critical_assets_protected_ratio}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Residual Exposure:</span>
                    <span className={`font-mono font-bold ${containmentResult.decision_record.remaining_exposure_rating === 'LOW' ? 'text-emerald-400' : 'text-amber-400'}`}>
                      {containmentResult.decision_record.remaining_exposure_rating}
                    </span>
                  </div>
                  <div className="text-[10px] text-slate-400 pt-1 border-t border-[#1f293d]">
                    <span className="font-semibold text-slate-300">Evidence Quality:</span> {containmentResult.decision_record.evidence_quality}
                  </div>
                  <div className="text-[10px] text-slate-500 italic">
                    {containmentResult.decision_record.operational_impact}
                  </div>
                  <div className="mt-1 py-1 px-2 rounded bg-indigo-950/60 border border-indigo-700/50 text-[10px] text-indigo-300 font-semibold text-center uppercase tracking-wider">
                    {containmentResult.decision_record.final_action}
                  </div>
                </div>
              )}

              {/* Prototype Structural Anomalies */}
              {anomalies.length > 0 && (
                <div className="bg-[#141b2d] border border-amber-900/40 rounded p-2.5 flex flex-col gap-1.5">
                  <div className="flex justify-between items-center text-[11px] text-amber-400 font-semibold uppercase">
                    <span>Structural Anomalies</span>
                    <span className="text-[10px] text-amber-500 font-mono">Rule-Based</span>
                  </div>
                  {anomalies.map((anom: any) => (
                    <div key={anom.id} className="text-xs bg-[#0e1422] p-2 rounded border border-[#1f293d] flex flex-col gap-0.5">
                      <div className="font-semibold text-white flex justify-between">
                        <span>{anom.type}</span>
                        <span className="text-amber-400 text-[10px] font-mono">{anom.entity_id}</span>
                      </div>
                      <div className="text-[11px] text-slate-400 leading-tight">{anom.explanation}</div>
                    </div>
                  ))}
                </div>
              )}

            </div>
          </div>

        </div>

      {/* INCIDENT TIMELINE TAB */}
      {activeTab === 'timeline' && (
        <div className="flex-1 p-6 overflow-y-auto bg-[#090d16]">
          <div className="max-w-4xl mx-auto flex flex-col gap-4">
            <div className="flex justify-between items-center pb-3 border-b border-[#1f293d]">
              <div className="flex items-center gap-3">
                <button
                  onClick={() => {
                    setActiveTab('workspace');
                    setTimeout(() => {
                      cyInstance.current?.resize();
                      cyInstance.current?.fit(undefined, 35);
                    }, 50);
                  }}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#141b2d] border border-[#1f293d] hover:border-sky-500 text-sky-400 hover:text-white text-xs font-semibold transition"
                >
                  ← Back to Graph
                </button>
                <div>
                  <h2 className="text-base font-bold text-white flex items-center gap-2">
                    <Clock className="w-4 h-4 text-sky-400" />
                    Simulated Incident Timeline & Telemetry Stream
                  </h2>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Chronological event sequence reconstructing how multi-source telemetry populated the graph model.
                  </p>
                </div>
              </div>
              <span className="text-xs font-mono text-sky-400 bg-sky-950/60 border border-sky-800/40 px-2 py-1 rounded">
                Incident: {summary?.scenario?.incident_id}
              </span>
            </div>

            <div className="flex flex-col gap-3">
              {timeline.map((evt, idx) => (
                <div key={idx} className="flex gap-4 p-3.5 bg-[#0e1422] border border-[#1f293d] rounded-lg">
                  <div className="flex flex-col items-center shrink-0">
                    <span className="font-mono text-xs font-bold text-sky-400">{evt.time}</span>
                    <span className="w-px h-full bg-[#1f293d] my-1" />
                  </div>
                  <div className="flex flex-col gap-1 flex-1">
                    <div className="flex justify-between items-center text-xs">
                      <span className="font-semibold text-white">{evt.source}</span>
                      <span className={`px-1.5 py-0.2 rounded text-[10px] font-mono font-semibold ${
                        evt.severity === 'CRITICAL' ? 'bg-red-950 text-red-400' :
                        evt.severity === 'HIGH' ? 'bg-orange-950 text-orange-400' :
                        evt.severity === 'MEDIUM' ? 'bg-amber-950 text-amber-400' : 'bg-slate-800 text-slate-400'
                      }`}>
                        {evt.severity}
                      </span>
                    </div>
                    <div className="text-xs text-slate-300">{evt.event}</div>
                  </div>
                </div>
              ))}
            </div>

            {/* MITRE ATT&CK Context Matrix */}
            {summary?.scenario?.mitre_context && summary.scenario.mitre_context.length > 0 && (
              <div className="mt-4 p-4 bg-[#0e1422] border border-[#1f293d] rounded-lg flex flex-col gap-2">
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">
                  MITRE ATT&CK Matrix Mapping
                </h3>
                <div className="grid grid-cols-2 gap-2 text-xs">
                  {summary.scenario.mitre_context.map((m: any, i: number) => (
                    <div key={i} className="p-2.5 bg-[#141b2d] border border-[#1f293d] rounded flex flex-col gap-1">
                      <div className="flex justify-between font-mono text-sky-400 font-semibold">
                        <span>{m.technique_id}</span>
                        <span className="text-[10px] text-slate-400">{m.tactic}</span>
                      </div>
                      <div className="text-white font-medium">{m.technique_name}</div>
                      <div className="text-[11px] text-slate-400 italic">{m.evidence}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* CANDIDATE MATRIX TAB */}
      {activeTab === 'comparison' && (
        <div className="flex-1 p-6 overflow-y-auto bg-[#090d16]">
          <div className="max-w-4xl mx-auto flex flex-col gap-4">
            <div className="flex justify-between items-center pb-3 border-b border-[#1f293d]">
              <div className="flex items-center gap-3">
                <button
                  onClick={() => {
                    setActiveTab('workspace');
                    setTimeout(() => {
                      cyInstance.current?.resize();
                      cyInstance.current?.fit(undefined, 35);
                    }, 50);
                  }}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#141b2d] border border-[#1f293d] hover:border-purple-500 text-purple-300 hover:text-white text-xs font-semibold transition"
                >
                  ← Back to Graph
                </button>
                <div>
                  <h2 className="text-base font-bold text-white flex items-center gap-2">
                    <Sliders className="w-4 h-4 text-purple-400" />
                    Containment Candidate Comparison Matrix
                  </h2>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Side-by-side graph simulation metrics comparing candidate containment leverage before action.
                  </p>
                </div>
              </div>
              <span className="text-xs font-mono text-purple-400 bg-purple-950/60 border border-purple-800/40 px-2 py-1 rounded">
                Scope: {hops} Hops Rooted at {focusEntityId}
              </span>
            </div>

            <div className="bg-[#0e1422] border border-[#1f293d] rounded-lg overflow-hidden">
              <table className="w-full text-xs text-left">
                <thead className="bg-[#141b2d] text-slate-400 uppercase text-[10px] font-mono border-b border-[#1f293d]">
                  <tr>
                    <th className="p-3">Candidate Node</th>
                    <th className="p-3">Type</th>
                    <th className="p-3 text-right">Paths Severed</th>
                    <th className="p-3 text-right">Assets Protected</th>
                    <th className="p-3 text-right">Entity Reduction</th>
                    <th className="p-3 text-right">Alternate Paths</th>
                    <th className="p-3 text-center">Remaining Exposure</th>
                    <th className="p-3 text-center">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1f293d]">
                  {comparisons.map((c) => (
                    <tr key={c.candidate_id} className="hover:bg-white/[0.02]">
                      <td className="p-3 font-mono font-bold text-white flex items-center gap-1.5">
                        {c.is_recommended && <span className="w-2 h-2 rounded-full bg-emerald-400" />}
                        {c.candidate_id}
                      </td>
                      <td className="p-3 text-slate-400">{c.type}</td>
                      <td className="p-3 text-right font-mono font-bold text-emerald-400">+{c.paths_severed}</td>
                      <td className="p-3 text-right font-mono font-bold text-emerald-400">+{c.critical_assets_protected}</td>
                      <td className="p-3 text-right font-mono text-slate-300">-{c.entity_reduction}</td>
                      <td className="p-3 text-right font-mono text-amber-400">{c.remaining_alternate_paths}</td>
                      <td className="p-3 text-center">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold ${
                          c.remaining_exposure === 'LOW' ? 'bg-emerald-950 text-emerald-400' :
                          c.remaining_exposure === 'MEDIUM' ? 'bg-amber-950 text-amber-400' : 'bg-red-950 text-red-400'
                        }`}>
                          {c.remaining_exposure}
                        </span>
                      </td>
                      <td className="p-3 text-center">
                        <button
                          onClick={() => {
                            handleToggleContainment(c.candidate_id);
                            setActiveTab('workspace');
                          }}
                          className="px-2.5 py-1 bg-purple-900/40 hover:bg-purple-900/60 border border-purple-600/50 text-purple-200 rounded font-semibold text-[11px]"
                        >
                          Simulate
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="p-3.5 bg-[#0e1422] border border-[#1f293d] rounded-lg text-xs text-slate-400 flex flex-col gap-1">
              <span className="font-semibold text-white">How Candidates are Evaluated:</span>
              <p>
                Candidates are ranked by their ability to disconnect multiple critical attack paths and protect high-value assets while minimizing remaining alternate routes. Operational business impact on live services is not modeled in this prototype simulation.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Application Footer */}
      <footer className="flex items-center justify-between px-4 py-1.5 bg-[#0e1422] border-t border-[#1f293d] text-[11px] font-mono text-slate-500 shrink-0">
        <div>Engine: GraphOps Deterministic In-Memory Graph Analytics • Bounded Hop Depth ≤ 3</div>
        <div className="text-amber-500/90 font-medium">Prototype Decision Support — Not Certified Production Security Rating</div>
      </footer>

    </div>
  );
}
