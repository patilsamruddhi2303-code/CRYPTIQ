import random
from typing import Dict, List, Any

class SyntheticTopologyGenerator:
    """
    Deterministic synthetic enterprise topology generator.
    Produces repeatable graph entities and relationships using a fixed seed (default=42).
    """
    def __init__(self, seed: int = 42):
        self.seed = seed
        self.rng = random.Random(seed)

    def generate_scenario_lateral(self) -> Dict[str, Any]:
        """
        Scenario 1: Multi-hop Lateral Movement
        Compromised User -> Workstation -> App Server / Mgmt Server -> Critical Assets
        Contains dual pathways: isolating ws-17-ops severs all paths; isolating srv-mgmt-01
        protects crown-jewel-db while finance-db and identity-srv remain exposed.
        """
        nodes = [
            {"id": "user.sneha", "label": "user.sneha", "type": "User", "privilege": "privileged", "department": "IT Support", "isRoot": True},
            {"id": "ws-17-ops", "label": "ws-17-ops", "type": "Endpoint", "zone": "workstation", "ip": "10.0.1.17", "isChoke": True},
            {"id": "app-srv-02", "label": "app-srv-02", "type": "Server", "role": "application", "ip": "10.0.3.22"},
            {"id": "srv-mgmt-01", "label": "srv-mgmt-01", "type": "Server", "role": "management", "ip": "10.0.3.50", "isChoke": True},
            {"id": "backup-node", "label": "backup-node", "type": "Server", "role": "backup", "ip": "10.0.4.15"},
            {"id": "finance-db", "label": "finance-db", "type": "CriticalAsset", "category": "database", "criticality": "Critical", "isCritical": True},
            {"id": "crown-jewel-db", "label": "crown-jewel-db", "type": "CriticalAsset", "category": "database", "criticality": "Critical", "isCritical": True},
            {"id": "identity-srv", "label": "identity-srv", "type": "CriticalAsset", "category": "idp", "criticality": "Critical", "isCritical": True},
            # Additional contextual entities in the enterprise subnet
            {"id": "printer-corp", "label": "printer-corp", "type": "Endpoint", "zone": "iot", "ip": "10.0.1.99"},
            {"id": "cve-2024-21413", "label": "CVE-2024-21413", "type": "Vulnerability", "cvss": 9.8, "severity": "Critical"}
        ]

        edges = [
            # Root compromise observed telemetry
            {"source": "user.sneha", "target": "ws-17-ops", "type": "LOGGED_IN_TO", "category": "OBSERVED"},
            {"source": "user.sneha", "target": "printer-corp", "type": "CONNECTED_TO", "category": "OBSERVED"},
            # Lateral movement & authorized capabilities from workstation
            {"source": "ws-17-ops", "target": "app-srv-02", "type": "CONNECTED_TO", "category": "OBSERVED"},
            {"source": "ws-17-ops", "target": "srv-mgmt-01", "type": "AUTHORIZED_FOR", "category": "AUTHORIZED"},
            {"source": "ws-17-ops", "target": "backup-node", "type": "CAN_REACH", "category": "AUTHORIZED"},
            {"source": "app-srv-02", "target": "cve-2024-21413", "type": "HAS_VULNERABILITY", "category": "INFERRED"},
            # Target access to critical assets
            {"source": "app-srv-02", "target": "finance-db", "type": "ACCESSES", "category": "AUTHORIZED"},
            {"source": "srv-mgmt-01", "target": "crown-jewel-db", "type": "ACCESSES", "category": "AUTHORIZED"},
            {"source": "backup-node", "target": "identity-srv", "type": "CAN_REACH", "category": "AUTHORIZED"}
        ]

        anomalies = [
            {
                "id": "anom-01",
                "entity_id": "ws-17-ops",
                "type": "Unusual Lateral Pivot",
                "severity": "HIGH",
                "explanation": "Workstation ws-17-ops established uncharacteristic outbound connection to core management server srv-mgmt-01 outside normal operational hours."
            },
            {
                "id": "anom-02",
                "entity_id": "app-srv-02",
                "type": "Vulnerable Path Pivot",
                "severity": "HIGH",
                "explanation": "Application server app-srv-02 exposes unpatched CVE-2024-21413 with direct capability access to Finance Database."
            }
        ]

        return {
            "id": "scenario_lateral",
            "name": "Multi-hop Lateral Movement",
            "description": "Compromised administrative credentials traversing via intermediate endpoints to high-value database tiers.",
            "initial_event": "Suspicious RDP Login from unapproved subnet",
            "mitre_technique": "T1021.001 (Remote Desktop Protocol)",
            "root_entity": "user.sneha",
            "base_risk": 82,
            "risk_factors": ["privileged identity", "multi-hop reachability", "critical asset reachable", "remote-service activity"],
            "expected_choke": "ws-17-ops",
            "nodes": nodes,
            "edges": edges,
            "anomalies": anomalies
        }

    def generate_scenario_chokepoint(self) -> Dict[str, Any]:
        """
        Scenario 2: Multi-Path Choke Point
        Multiple independent pathways funneling through a central management bastion to reach directory services and core databases.
        """
        nodes = [
            {"id": "user.sneha", "label": "user.sneha", "type": "User", "privilege": "standard", "department": "Operations", "isRoot": True},
            {"id": "endpoint-alpha", "label": "endpoint-alpha", "type": "Endpoint", "zone": "workstation", "ip": "10.1.1.5"},
            {"id": "endpoint-beta", "label": "endpoint-beta", "type": "Endpoint", "zone": "workstation", "ip": "10.1.1.6"},
            {"id": "bastion-mgmt", "label": "bastion-mgmt", "type": "Endpoint", "zone": "bastion", "ip": "10.1.2.1", "isChoke": True},
            {"id": "crown-jewel-db", "label": "crown-jewel-db", "type": "CriticalAsset", "category": "database", "criticality": "Critical", "isCritical": True},
            {"id": "identity-srv", "label": "identity-srv", "type": "CriticalAsset", "category": "idp", "criticality": "Critical", "isCritical": True},
            {"id": "monitor-srv", "label": "monitor-srv", "type": "Server", "role": "monitoring", "ip": "10.1.3.10"}
        ]

        edges = [
            {"source": "user.sneha", "target": "endpoint-alpha", "type": "LOGGED_IN_TO", "category": "OBSERVED"},
            {"source": "user.sneha", "target": "endpoint-beta", "type": "LOGGED_IN_TO", "category": "OBSERVED"},
            {"source": "endpoint-alpha", "target": "bastion-mgmt", "type": "CAN_REACH", "category": "AUTHORIZED"},
            {"source": "endpoint-beta", "target": "bastion-mgmt", "type": "CAN_REACH", "category": "AUTHORIZED"},
            {"source": "bastion-mgmt", "target": "crown-jewel-db", "type": "ACCESSES", "category": "AUTHORIZED"},
            {"source": "bastion-mgmt", "target": "identity-srv", "type": "ACCESSES", "category": "AUTHORIZED"},
            {"source": "endpoint-alpha", "target": "monitor-srv", "type": "CONNECTED_TO", "category": "OBSERVED"}
        ]

        anomalies = [
            {
                "id": "anom-03",
                "entity_id": "bastion-mgmt",
                "type": "Convergent Path Funnel",
                "severity": "HIGH",
                "explanation": "Multiple concurrent user sessions converge onto single administrative bastion host with privileged access to Active Directory and Core DB."
            }
        ]

        return {
            "id": "scenario_chokepoint",
            "name": "Multi-Path Choke Point Isolation",
            "description": "Redundant paths converge on a single management bastion before reaching critical crown jewels.",
            "initial_event": "Dual Concurrent Session Anomalies",
            "mitre_technique": "T1078 (Valid Accounts)",
            "root_entity": "user.sneha",
            "base_risk": 78,
            "risk_factors": ["multi-path convergence", "identity provider exposure", "critical asset reachable"],
            "expected_choke": "bastion-mgmt",
            "nodes": nodes,
            "edges": edges,
            "anomalies": anomalies
        }

    def generate_scenario_benign(self) -> Dict[str, Any]:
        """
        Scenario 3: Benign Maintenance Activity
        Routine off-hours snapshot backup job without critical asset exposure.
        """
        nodes = [
            {"id": "user.sneha", "label": "user.sneha", "type": "User", "privilege": "standard", "department": "DevOps", "isRoot": True},
            {"id": "ws-ops-01", "label": "ws-ops-01", "type": "Endpoint", "zone": "workstation", "ip": "10.2.1.8"},
            {"id": "backup-node", "label": "backup-node", "type": "Server", "role": "backup", "ip": "10.2.2.15", "isChoke": True},
            {"id": "log-archive-99", "label": "log-archive-99", "type": "Server", "role": "archive", "ip": "10.2.3.99"}
        ]

        edges = [
            {"source": "user.sneha", "target": "ws-ops-01", "type": "LOGGED_IN_TO", "category": "OBSERVED"},
            {"source": "ws-ops-01", "target": "backup-node", "type": "CONNECTED_TO", "category": "OBSERVED"},
            {"source": "backup-node", "target": "log-archive-99", "type": "CAN_REACH", "category": "AUTHORIZED"}
        ]

        anomalies = [
            {
                "id": "anom-04",
                "entity_id": "backup-node",
                "type": "Off-Hours Archival",
                "severity": "LOW",
                "explanation": "Off-hours snapshot execution matches approved weekly maintenance schedule. No critical assets reachable."
            }
        ]

        return {
            "id": "scenario_benign",
            "name": "Benign Maintenance Activity",
            "description": "Routine scheduled off-hours snapshot archival job without exposure to critical assets.",
            "initial_event": "Scheduled Maintenance Script Execution",
            "mitre_technique": "T1059 (Command & Scripting Interpreter)",
            "root_entity": "user.sneha",
            "base_risk": 24,
            "risk_factors": ["off-hours activity", "scheduled maintenance window", "zero critical assets exposed"],
            "expected_choke": "backup-node",
            "nodes": nodes,
            "edges": edges,
            "anomalies": anomalies
        }

    def get_all_scenarios(self) -> Dict[str, Any]:
        return {
            "scenario_lateral": self.generate_scenario_lateral(),
            "scenario_chokepoint": self.generate_scenario_chokepoint(),
            "scenario_benign": self.generate_scenario_benign()
        }
