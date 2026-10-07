import { useEffect, useState, useRef } from 'react';
import cytoscape, { Core } from 'cytoscape';
import { RotateCcw, ChevronRight } from 'lucide-react';

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
}

interface BlastRadiusResponse {
  focus_entity: string;
  max_hops_requested: number;
  reachable_count: number;
  critical_asset_count: number;
  reachable_entities: Array<{ id: string; label: string; type: string; hops: number; is_critical: boolean }>;
  critical_assets: Array<{ id: string; label: string; type: string; hops: number; is_critical: boolean }>;
  reachable_edges: Array<{ source: string; target: string; type: string; category: string }>;
}

interface PathItem {
  path_id: string;
  nodes: string[];
  length: number;
  target_id: string;
  target_type: string;
  criticality: string;
}

interface ChokeCandidate {
  node_id: string;
  label: string;
  type: string;
  paths_affected: number;
  total_critical_paths: number;
  coverage_pct: number;
  centrality_metric: string;
  interception_rating: string;
  suggested_action: string;
}

interface AssetStatus {
  id: string;
  label: string;
  criticality: string;
  status: 'PROTECTED' | 'STILL EXPOSED';
}

export default function App() {
  const [scenarios, setScenarios] = useState<any[]>([]);
  const [currentScenario, setCurrentScenario] = useState<string>('scenario_lateral');
  const [summary, setSummary] = useState<any>(null);
  const [entities, setEntities] = useState<Entity[]>([]);
  const [anomalies, setAnomalies] = useState<any[]>([]);
  
  // Investigation state
  const [focusEntityId, setFocusEntityId] = useState<string>('user.sneha');
  const [inspectedEntityId, setInspectedEntityId] = useState<string>('user.sneha');
  const [hops, setHops] = useState<number>(3);
  
  // Graph Analytics state
  const [blastData, setBlastData] = useState<BlastRadiusResponse | null>(null);
  const [paths, setPaths] = useState<PathItem[]>([]);
  const [selectedPathId, setSelectedPathId] = useState<string | null>(null);
  const [chokePoints, setChokePoints] = useState<ChokeCandidate[]>([]);
  
  // Containment Simulation state
  const [simulatedIsolationNode, setSimulatedIsolationNode] = useState<string | null>(null);
  const [containmentResult, setContainmentResult] = useState<any>(null);

  const cyRef = useRef<HTMLDivElement>(null);
  const cyInstance = useRef<Core | null>(null);
  // Persistent layout cache to maintain stable positions across hop expansions
  const nodePositionsCache = useRef<{ [key: string]: { x: number; y: number } }>({});

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

      const root = sumData.scenario.root_entity;
      setFocusEntityId(root);
      setInspectedEntityId(root);
      setSimulatedIsolationNode(null);
      setContainmentResult(null);
      setSelectedPathId(null);
      nodePositionsCache.current = {};
    } catch (err) {
      console.error("Error loading scenario:", err);
    }
  };

  // 3. Dynamic Analytics Traversal whenever Focus, Hops, or Scenario changes
  useEffect(() => {
    if (!focusEntityId) return;

    setSelectedPathId(null);
    setSimulatedIsolationNode(null);
    setContainmentResult(null);

    // Fetch Blast Radius
    fetch(`/api/blast-radius/${focusEntityId}?hops=${hops}`)
      .then(res => res.json())
      .then(data => setBlastData(data))
      .catch(err => console.error("Blast radius error:", err));

    // Fetch Hop-bounded Attack Paths
    fetch(`/api/paths?source_id=${focusEntityId}&hops=${hops}`)
      .then(res => res.json())
      .then(data => setPaths(data.paths || []))
      .catch(err => console.error("Paths error:", err));

    // Fetch Choke Points
    fetch(`/api/choke-points?source_id=${focusEntityId}&hops=${hops}`)
      .then(res => res.json())
      .then(data => setChokePoints(data.choke_points || []))
      .catch(err => console.error("Choke points error:", err));

  }, [focusEntityId, hops, currentScenario]);

  // 4. Initialize Cytoscape Instance
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
              'color': '#94a3b8',
              'font-size': '10px',
              'font-family': 'ui-monospace, monospace',
              'text-valign': 'bottom',
              'text-margin-y': 5,
              'background-color': '#1e293b',
              'border-width': 2,
              'border-color': '#475569',
              'width': 34,
              'height': 34
            }
          },
          {
            selector: 'node[?isFocusRoot]',
            style: {
              'background-color': '#dc2626',
              'border-color': '#f87171',
              'border-width': 4,
              'color': '#fca5a5',
              'font-weight': 'bold'
            }
          },
          {
            selector: 'node[?isCritical]',
            style: {
              'background-color': '#ea580c',
              'border-color': '#fb923c',
              'border-width': 3,
              'color': '#fdba74'
            }
          },
          {
            selector: 'node[?isChoke]',
            style: {
              'background-color': '#7e22ce',
              'border-color': '#c084fc',
              'border-width': 3
            }
          },
          {
            selector: 'node.inspected-node',
            style: {
              'border-color': '#38bdf8',
              'border-width': 4
            }
          },
          {
            selector: 'node.path-node-highlight',
            style: {
              'border-color': '#f59e0b',
              'border-width': 4,
              'background-color': '#78350f'
            }
          },
          {
            selector: 'node.contained-isolated',
            style: {
              'opacity': 0.35,
              'border-style': 'dashed',
              'border-color': '#ef4444',
              'background-color': '#1e1b4b'
            }
          },
          {
            selector: 'node.severed-unreachable',
            style: {
              'opacity': 0.25,
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
              'curve-style': 'bezier',
              'label': 'data(type)',
              'font-size': '8px',
              'color': '#64748b',
              'text-rotation': 'autorotate',
              'text-margin-y': -8
            }
          },
          {
            selector: 'edge[category = "OBSERVED"]',
            style: {
              'line-color': '#38bdf8',
              'target-arrow-color': '#38bdf8'
            }
          },
          {
            selector: 'edge[category = "AUTHORIZED"]',
            style: {
              'line-color': '#94a3b8',
              'target-arrow-color': '#94a3b8',
              'line-style': 'dashed'
            }
          },
          {
            selector: 'edge[category = "INFERRED"]',
            style: {
              'line-color': '#eab308',
              'target-arrow-color': '#eab308',
              'line-style': 'dotted'
            }
          },
          {
            selector: 'edge.path-edge-highlight',
            style: {
              'width': 4,
              'line-color': '#f59e0b',
              'target-arrow-color': '#f59e0b'
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
  }, []);

  // 5. Update Cytoscape Graph Topology with Incident-Centered Scope & Stable Positioning
  useEffect(() => {
    const cy = cyInstance.current;
    if (!cy || !blastData) return;

    // Save existing node positions to preserve layout stability across hop expansions
    cy.nodes().forEach(node => {
      nodePositionsCache.current[node.id()] = node.position();
    });

    cy.elements().remove();

    // Incident-Centered Subgraph: Render ONLY reachable entities within current hop scope
    const activeEntities = blastData.reachable_entities || [];
    const activeNodeIds = new Set(activeEntities.map(e => e.id));

    const cyNodes = activeEntities.map(e => {
      const fullMeta = entities.find(ent => ent.id === e.id);
      return {
        data: {
          id: e.id,
          label: e.label,
          type: e.type,
          isFocusRoot: e.id === focusEntityId,
          isCritical: e.is_critical,
          isChoke: fullMeta?.isChoke || false
        }
      };
    });

    // Render only edges connecting nodes within the incident subgraph
    const cyEdges = (blastData.reachable_edges || [])
      .filter(edge => activeNodeIds.has(edge.source) && activeNodeIds.has(edge.target))
      .map((edge, idx) => ({
        data: {
          id: `edge-${idx}-${edge.source}-${edge.target}`,
          source: edge.source,
          target: edge.target,
          type: edge.type,
          category: edge.category
        }
      }));

    cy.add([...cyNodes, ...cyEdges]);

    // Restore positions for cached nodes; assign concentric circular offset for newly expanded nodes
    let hasUnpositioned = false;
    cy.nodes().forEach((node, i) => {
      const cached = nodePositionsCache.current[node.id()];
      if (cached) {
        node.position(cached);
      } else {
        hasUnpositioned = true;
        const angle = (i / Math.max(1, cyNodes.length)) * 2 * Math.PI;
        node.position({
          x: 280 + Math.cos(angle) * 160,
          y: 240 + Math.sin(angle) * 160
        });
      }
    });

    if (hasUnpositioned && Object.keys(nodePositionsCache.current).length === 0) {
      cy.layout({ name: 'breadthfirst', directed: true, spacingFactor: 1.25, animate: false }).run();
      cy.nodes().forEach(node => {
        nodePositionsCache.current[node.id()] = node.position();
      });
    }

    cy.fit(undefined, 35);
  }, [blastData, entities, focusEntityId]);

  // 6. Interactive Highlighting (Inspected Node & Clicked Attack Path)
  useEffect(() => {
    const cy = cyInstance.current;
    if (!cy) return;

    // Reset temporary highlight classes
    cy.nodes().removeClass('inspected-node path-node-highlight');
    cy.edges().removeClass('path-edge-highlight');

    // Highlight inspected node
    if (inspectedEntityId) {
      cy.$(`#${inspectedEntityId}`).addClass('inspected-node');
    }

    // Highlight active attack path
    if (selectedPathId) {
      const activePath = paths.find(p => p.path_id === selectedPathId);
      if (activePath) {
        activePath.nodes.forEach(nId => {
          cy.$(`#${nId}`).addClass('path-node-highlight');
        });
        for (let i = 0; i < activePath.nodes.length - 1; i++) {
          const s = activePath.nodes[i];
          const t = activePath.nodes[i + 1];
          cy.edges(`[source = "${s}"][target = "${t}"]`).addClass('path-edge-highlight');
        }
      }
    }
  }, [inspectedEntityId, selectedPathId, paths]);

  // 7. Visual Synchronization of Containment Simulation
  useEffect(() => {
    const cy = cyInstance.current;
    if (!cy) return;

    cy.nodes().removeClass('contained-isolated severed-unreachable');
    cy.edges().removeClass('severed-edge');

    if (simulatedIsolationNode && containmentResult) {
      // Mark candidate node as isolated
      cy.$(`#${simulatedIsolationNode}`).addClass('contained-isolated');
      
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

  // 8. Toggle Containment Action
  const handleToggleContainment = async (candidateId: string) => {
    if (simulatedIsolationNode === candidateId) {
      // Revert simulation
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

  // Dynamic risk calculation
  const currentRisk = summary?.scenario?.base_risk || 50;
  const riskBadge = currentRisk >= 75 ? 'HIGH' : (currentRisk >= 40 ? 'MEDIUM' : 'LOW');
  const riskColor = currentRisk >= 75 ? 'text-red-400' : (currentRisk >= 40 ? 'text-amber-400' : 'text-emerald-400');

  return (
    <div className="flex flex-col h-screen w-screen bg-[#0a0d14] text-slate-200">
      {/* Top Header */}
      <header className="flex items-center justify-between px-4 py-2 bg-[#111622] border-b border-[#222d42] shrink-0">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 font-bold text-white tracking-wide text-sm">
            <span className="w-2.5 h-2.5 rounded-full bg-sky-400 shadow-[0_0_8px_rgba(56,189,248,0.7)]" />
            GRAPHOPS
          </div>
          <span className="text-xs text-slate-400 pl-3 border-l border-[#222d42]">
            SOC Decision Support & Blast Radius Containment
          </span>
          <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-orange-950/40 text-orange-400 border border-orange-800/40 font-semibold">
            Prototype Heuristic Evaluation
          </span>
        </div>

        <div className="flex items-center gap-4 text-xs">
          <div className="flex items-center gap-2">
            <span className="text-slate-400 text-[11px] uppercase">Scenario:</span>
            <select 
              value={currentScenario}
              onChange={(e) => {
                setCurrentScenario(e.target.value);
                loadScenarioDetails(e.target.value);
              }}
              className="bg-[#161d2d] border border-[#222d42] rounded px-2 py-1 text-xs text-slate-200 outline-none hover:border-[#334466]"
            >
              {scenarios.map(sc => (
                <option key={sc.id} value={sc.id}>{sc.name}</option>
              ))}
            </select>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-slate-400 text-[11px] uppercase">Investigation Root:</span>
            <select 
              value={focusEntityId}
              onChange={(e) => setFocusEntityId(e.target.value)}
              className="bg-[#161d2d] border border-[#222d42] rounded px-2 py-1 text-xs text-slate-200 outline-none hover:border-[#334466] font-mono"
            >
              {entities.map(e => (
                <option key={e.id} value={e.id}>{e.label} ({e.type})</option>
              ))}
            </select>
          </div>

          <button 
            onClick={() => loadScenarioDetails(currentScenario)}
            className="flex items-center gap-1.5 bg-[#161d2d] border border-[#222d42] px-2.5 py-1 rounded text-xs hover:border-[#334466] text-slate-300"
          >
            <RotateCcw className="w-3.5 h-3.5" /> Reset State
          </button>
        </div>
      </header>

      {/* 5-Stage Core Operational Workflow Ribbon */}
      <div className="flex items-center gap-2 px-4 py-1.5 bg-[#0d111a] border-b border-[#222d42] text-[11px] font-mono text-slate-400 shrink-0">
        <span className="text-sky-400 font-semibold bg-sky-950/40 border border-sky-800/40 px-2 py-0.5 rounded">01. ALERT</span>
        <span className="text-slate-600">→</span>
        <span className="text-sky-400 font-semibold bg-sky-950/40 border border-sky-800/40 px-2 py-0.5 rounded">02. CONTEXT</span>
        <span className="text-slate-600">→</span>
        <span className="text-amber-400 font-semibold bg-amber-950/40 border border-amber-800/40 px-2 py-0.5 rounded">03. ATTACK PATH</span>
        <span className="text-slate-600">→</span>
        <span className="text-sky-400 font-semibold bg-sky-950/40 border border-sky-800/40 px-2 py-0.5 rounded">04. BLAST RADIUS ({hops} HOPS)</span>
        <span className="text-slate-600">→</span>
        <span className={`px-2 py-0.5 rounded ${chokePoints.length ? 'text-purple-400 bg-purple-950/40 border border-purple-800/40 font-semibold' : ''}`}>
          05. CHOKE POINT
        </span>
        <span className="text-slate-600">→</span>
        <span className={`px-2 py-0.5 rounded ${simulatedIsolationNode ? 'text-emerald-400 bg-emerald-950/40 border border-emerald-800/40 font-semibold' : ''}`}>
          CONTAINMENT SIMULATION
        </span>
      </div>

      {/* Main 3-Column Operations Layout */}
      <div className="grid grid-cols-[300px_1fr_350px] flex-1 min-h-0 overflow-hidden">
        
        {/* Left Column: Telemetry Context, Hops & Attack Paths */}
        <div className="bg-[#111622] border-r border-[#222d42] flex flex-col overflow-hidden">
          <div className="px-3 py-2 bg-white/[0.02] border-b border-[#222d42] text-xs font-semibold uppercase tracking-wider text-slate-400 flex justify-between items-center">
            <span>Incident Telemetry</span>
            <span className="font-mono text-[10px] text-red-400 bg-red-950/50 border border-red-800/40 px-1.5 py-0.5 rounded">
              {summary?.scenario?.id}
            </span>
          </div>

          <div className="p-3 flex flex-col gap-3 overflow-y-auto flex-1">
            {/* Detection Context Card */}
            <div className="bg-[#161d2d] border border-[#222d42] rounded p-2.5 flex flex-col gap-1.5">
              <div className="flex justify-between items-center text-[11px] text-slate-400 font-semibold uppercase">
                <span>Event Detection</span>
                <span className={`font-bold ${riskColor}`}>{riskBadge} RISK</span>
              </div>
              <div className="flex justify-between text-xs">
                <span className="text-slate-400">Trigger Event:</span>
                <span className="font-mono text-white truncate max-w-[170px]" title={summary?.scenario?.initial_event}>
                  {summary?.scenario?.initial_event}
                </span>
              </div>
              <div className="flex justify-between text-xs">
                <span className="text-slate-400">ATT&CK Map:</span>
                <span className="font-mono text-sky-400">{summary?.scenario?.mitre_technique || 'N/A'}</span>
              </div>
              <div className="flex justify-between text-xs">
                <span className="text-slate-400">Heuristic Score:</span>
                <span className={`font-mono font-bold ${riskColor}`}>{currentRisk} / 100</span>
              </div>
            </div>

            {/* Hop Depth Scope Controls */}
            <div className="bg-[#161d2d] border border-[#222d42] rounded p-2.5 flex flex-col gap-2">
              <div className="flex justify-between items-center text-[11px] text-slate-400 font-semibold uppercase">
                <span>Blast Radius Scope</span>
                <span className="font-mono text-sky-400">{hops} Hops Active</span>
              </div>
              <div className="grid grid-cols-3 gap-1">
                {[1, 2, 3].map(h => (
                  <button
                    key={h}
                    onClick={() => setHops(h)}
                    className={`py-1 text-xs font-mono rounded font-semibold border transition ${
                      hops === h 
                        ? 'bg-sky-600 border-sky-400 text-white' 
                        : 'bg-[#111622] border-[#222d42] text-slate-300 hover:border-[#334466]'
                    }`}
                  >
                    {h} HOP{h > 1 ? 'S' : ''}
                  </button>
                ))}
              </div>
              <div className="text-[11px] text-slate-400">
                Reachable entities: <strong className="text-white">{blastData?.reachable_count || 0}</strong>
              </div>
            </div>

            {/* Hop-Bounded Attack Paths */}
            <div className="bg-[#161d2d] border border-[#222d42] rounded p-2.5 flex flex-col gap-1.5 flex-1 min-h-[160px]">
              <div className="flex justify-between items-center text-[11px] text-slate-400 font-semibold uppercase">
                <span>Attack Paths (≤ {hops} Hops)</span>
                <span className="text-[10px] text-slate-400">
                  {simulatedIsolationNode 
                    ? `${containmentResult?.post_containment?.active_paths_count || 0} Active / ${containmentResult?.severed_paths?.length || 0} Severed`
                    : `${paths.length} Active`
                  }
                </span>
              </div>
              
              {paths.length === 0 ? (
                <div className="text-xs text-slate-500 py-3 text-center italic">
                  No attack paths to critical assets within {hops} hop(s).
                </div>
              ) : (
                <div className="flex flex-col gap-1.5 overflow-y-auto">
                  {paths.map(p => {
                    const isSevered = simulatedIsolationNode && p.nodes.includes(simulatedIsolationNode);
                    const isSelected = selectedPathId === p.path_id;
                    return (
                      <div
                        key={p.path_id}
                        onClick={() => setSelectedPathId(isSelected ? null : p.path_id)}
                        className={`p-2 rounded border cursor-pointer text-xs flex flex-col gap-1 transition ${
                          isSevered 
                            ? 'opacity-40 line-through border-dashed border-red-900 bg-red-950/10'
                            : isSelected 
                              ? 'border-amber-500 bg-amber-950/30' 
                              : 'border-[#222d42] bg-[#111622] hover:border-[#334466]'
                        }`}
                      >
                        <div className="flex justify-between items-center font-semibold text-[11px]">
                          <span className="text-white flex items-center gap-1">
                            <ChevronRight className="w-3 h-3 text-amber-400" />
                            Target: {p.target_id}
                          </span>
                          <span className={`px-1 py-0.2 rounded text-[10px] ${isSevered ? 'text-red-400 bg-red-950' : 'text-amber-400 bg-amber-950'}`}>
                            {isSevered ? 'SEVERED' : `${p.length} Hops`}
                          </span>
                        </div>
                        <div className="font-mono text-[10px] text-slate-400 truncate">
                          {p.nodes.join(' → ')}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {/* Critical Assets List with Itemized Status */}
            <div className="bg-[#161d2d] border border-[#222d42] rounded p-2.5 flex flex-col gap-1.5">
              <div className="flex justify-between items-center text-[11px] text-slate-400 font-semibold uppercase">
                <span>Critical Assets at Risk</span>
                <span className="text-orange-400 font-bold">
                  {simulatedIsolationNode 
                    ? `${containmentResult?.post_containment?.critical_assets_exposed || 0} Exposed`
                    : `${blastData?.critical_asset_count || 0} Exposed`
                  }
                </span>
              </div>
              <div className="flex flex-col gap-1 text-xs">
                {(blastData?.critical_assets || []).length === 0 ? (
                  <div className="text-[11px] text-slate-500 italic">No critical assets reachable within {hops} hops.</div>
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
                      <div key={ca.id} className="flex justify-between items-center py-0.5">
                        <span className="font-mono text-white">{ca.label}</span>
                        <span className={`text-[11px] ${statusColor}`}>
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

        {/* Center Column: Cytoscape Graph Viewport */}
        <div className="relative flex flex-col bg-[#090c12] overflow-hidden">
          <div className="absolute top-3 left-4 z-10 pointer-events-none flex flex-col gap-0.5">
            <div className="text-sm font-bold text-white tracking-wide">INCIDENT-CENTERED TOPOLOGY</div>
            <div className="text-xs font-mono text-slate-400">
              Root: <span className="text-red-400 font-bold">{focusEntityId}</span> • Scope: {hops} Hops • {blastData?.reachable_count || 0} Subgraph Entities
            </div>
          </div>

          <div ref={cyRef} className="w-full h-full" />

          {/* Graph Legend */}
          <div className="absolute bottom-3 left-4 z-10 bg-[#111622]/90 backdrop-blur border border-[#222d42] rounded px-3 py-1.5 flex gap-4 text-[11px] text-slate-400 pointer-events-auto">
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-red-600 border border-red-400" />
              <span>Root Entity</span>
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
              <span>Observed</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-3 h-0.5 bg-slate-400 border-b border-dashed" />
              <span>Authorized</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-3 h-0.5 bg-amber-400 border-b border-dotted" />
              <span>Inferred</span>
            </div>
          </div>
        </div>

        {/* Right Column: Decision Support, Choke Points & Simulation */}
        <div className="bg-[#111622] border-l border-[#222d42] flex flex-col overflow-hidden">
          <div className="px-3 py-2 bg-white/[0.02] border-b border-[#222d42] text-xs font-semibold uppercase tracking-wider text-slate-400 flex justify-between items-center">
            <span>Decision Support</span>
            <span className="text-[10px] text-slate-500">Heuristics</span>
          </div>

          <div className="p-3 flex flex-col gap-3 overflow-y-auto flex-1">
            {/* Inspected Node Detail */}
            {inspectedEntity && (
              <div className="bg-[#161d2d] border border-[#222d42] rounded p-2.5 flex flex-col gap-1.5">
                <div className="flex justify-between items-center text-[11px] text-slate-400 font-semibold uppercase">
                  <span>Inspected Entity</span>
                  <span className="px-1.5 py-0.5 rounded text-[10px] bg-sky-950 text-sky-400 font-mono">
                    {inspectedEntity.type}
                  </span>
                </div>
                <div className="font-mono text-sm font-bold text-white">{inspectedEntity.id}</div>
                <div className="flex justify-between text-xs">
                  <span className="text-slate-400">Role / Zone:</span>
                  <span className="text-slate-200">{inspectedEntity.role || inspectedEntity.zone || 'Standard'}</span>
                </div>
                <div className="flex justify-between text-xs">
                  <span className="text-slate-400">Containment:</span>
                  <span className={`font-semibold ${simulatedIsolationNode === inspectedEntity.id ? 'text-red-400' : 'text-emerald-400'}`}>
                    {simulatedIsolationNode === inspectedEntity.id ? 'Simulated Isolation' : 'Online'}
                  </span>
                </div>
                <button
                  onClick={() => setFocusEntityId(inspectedEntity.id)}
                  className="mt-1 w-full py-1 text-xs bg-[#111622] border border-[#222d42] rounded hover:border-sky-500 text-sky-300 font-semibold"
                >
                  Set as Investigation Root
                </button>
              </div>
            )}

            {/* Explainable Risk Contributors */}
            <div className="bg-[#161d2d] border border-[#222d42] rounded p-2.5 flex flex-col gap-1.5">
              <div className="flex justify-between items-center text-[11px] text-slate-400 font-semibold uppercase">
                <span>Risk Contributors</span>
                <span className="text-[10px] text-slate-400">Heuristic Rationale</span>
              </div>
              <div className="flex flex-wrap gap-1 text-[11px]">
                {(summary?.scenario?.risk_factors || []).map((factor: string, idx: number) => (
                  <span key={idx} className="bg-slate-800/80 border border-slate-700 text-slate-300 px-2 py-0.5 rounded">
                    + {factor}
                  </span>
                ))}
              </div>
            </div>

            {/* Prototype Structural Anomalies */}
            {anomalies.length > 0 && (
              <div className="bg-[#161d2d] border border-amber-900/40 rounded p-2.5 flex flex-col gap-1.5">
                <div className="flex justify-between items-center text-[11px] text-amber-400 font-semibold uppercase">
                  <span>Structural Anomalies</span>
                  <span className="text-[10px] text-amber-500">Heuristic Rule</span>
                </div>
                {anomalies.map((anom: any) => (
                  <div key={anom.id} className="text-xs bg-[#111622] p-2 rounded border border-[#222d42] flex flex-col gap-0.5">
                    <div className="font-semibold text-white flex justify-between">
                      <span>{anom.type}</span>
                      <span className="text-amber-400 text-[10px] font-mono">{anom.entity_id}</span>
                    </div>
                    <div className="text-[11px] text-slate-400 leading-tight">{anom.explanation}</div>
                  </div>
                ))}
              </div>
            )}

            {/* Choke Point Candidates */}
            <div className="bg-purple-950/20 border border-purple-800/40 rounded p-2.5 flex flex-col gap-2">
              <div className="flex justify-between items-center text-[11px] text-purple-300 font-semibold uppercase">
                <span>Choke Point Candidates</span>
                <span className="text-[10px] px-1.5 py-0.2 rounded bg-purple-900/50 text-purple-200">
                  CRITICAL-PATH INTERCEPTION
                </span>
              </div>
              
              {chokePoints.length === 0 ? (
                <div className="text-xs text-slate-500 py-2 text-center italic">
                  No structural choke points within {hops} hops.
                </div>
              ) : (
                <div className="flex flex-col gap-1.5">
                  {chokePoints.map(cp => (
                    <div key={cp.node_id} className="flex flex-col gap-1 bg-[#161d2d] border border-[#222d42] p-2 rounded">
                      <div className="flex justify-between items-center text-xs">
                        <span className="font-mono font-bold text-white">{cp.node_id}</span>
                        <span className="text-purple-400 font-mono text-[11px]">{cp.coverage_pct}% Interception</span>
                      </div>
                      <div className="text-[10px] text-slate-400">
                        Intercepts {cp.paths_affected} of {cp.total_critical_paths} active critical attack paths.
                      </div>
                      <button
                        onClick={() => handleToggleContainment(cp.node_id)}
                        className={`mt-1 py-1 px-2 rounded text-xs font-semibold border transition ${
                          simulatedIsolationNode === cp.node_id
                            ? 'bg-red-950 border-red-700 text-red-300'
                            : 'bg-purple-900/40 border-purple-600/50 text-purple-200 hover:bg-purple-900/60'
                        }`}
                      >
                        {simulatedIsolationNode === cp.node_id ? 'Revert Simulation' : 'Simulate Isolation'}
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Containment Simulation Impact Card */}
            {containmentResult && (
              <div className="bg-emerald-950/20 border border-emerald-800/40 rounded p-2.5 flex flex-col gap-1.5 text-xs">
                <div className="flex justify-between items-center text-[11px] font-semibold text-emerald-300 uppercase">
                  <span>Containment Impact</span>
                  <span className="text-emerald-400 font-bold">RECALCULATED</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Attack Paths Severed:</span>
                  <span className="font-mono text-emerald-400 font-bold">
                    {containmentResult.impact_summary.paths_severed}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Crown Jewels Protected:</span>
                  <span className="font-mono text-emerald-400 font-bold">
                    {containmentResult.impact_summary.critical_assets_protected}
                  </span>
                </div>
                <div className="text-[10px] text-slate-400 italic mt-1">
                  {containmentResult.disclaimer}
                </div>
              </div>
            )}
          </div>
        </div>

      </div>

      {/* Footer */}
      <footer className="flex items-center justify-between px-4 py-1.5 bg-[#111622] border-t border-[#222d42] text-[11px] font-mono text-slate-500 shrink-0">
        <div>Engine: GraphOps Deterministic In-Memory Graph Analytics • Bounded Hop Depth ≤ 3</div>
        <div className="text-amber-500">Prototype Heuristic Risk Score — Not a Certified Production Security Rating</div>
      </footer>
    </div>
  );
}
