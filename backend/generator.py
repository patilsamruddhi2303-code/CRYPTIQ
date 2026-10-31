import random
import time
from typing import Dict, List, Any, Optional

class SyntheticTopologyGenerator:
    """
    Deterministic synthetic enterprise topology generator.
    Produces repeatable graph entities and relationships using a fixed seed (default=42).
    
    Generates a realistic connected enterprise environment (~60-100 nodes across enterprise subnets)
    modeling IAM/Identity, EDR endpoints, Network flows, CMDB assets, and Vulnerability telemetry.
    """
    def __init__(self, seed: int = 42):
        self.seed = seed
        self.rng = random.Random(seed)

    def _generate_enterprise_baseline(self) -> Dict[str, Any]:
        """
        Generates realistic enterprise background entities and baseline network relationships
        to create an interconnected enterprise graph.
        """
        nodes = []
        edges = []

        # 1. Identity & Users
        users = [
            {"id": "user.sneha", "label": "user.sneha", "type": "User", "privilege": "privileged", "department": "IT Support", "owner": "Sneha Rao", "email": "sneha.rao@corp.internal"},
            {"id": "user.aarav", "label": "user.aarav", "type": "User", "privilege": "standard", "department": "Engineering", "owner": "Aarav Patel", "email": "aarav.p@corp.internal"},
            {"id": "user.priya", "label": "user.priya", "type": "User", "privilege": "privileged", "department": "SecOps", "owner": "Priya Sharma", "email": "priya.s@corp.internal"},
            {"id": "user.vikram", "label": "user.vikram", "type": "User", "privilege": "standard", "department": "Finance", "owner": "Vikram Mehta", "email": "vikram.m@corp.internal"},
            {"id": "user.ananya", "label": "user.ananya", "type": "User", "privilege": "domain_admin", "department": "Infrastructure", "owner": "Ananya Iyer", "email": "ananya.i@corp.internal"},
            {"id": "user.rohit", "label": "user.rohit", "type": "User", "privilege": "standard", "department": "HR", "owner": "Rohit Verma", "email": "rohit.v@corp.internal"},
            {"id": "user.kavita", "label": "user.kavita", "type": "User", "privilege": "standard", "department": "Marketing", "owner": "Kavita Nair", "email": "kavita.n@corp.internal"},
            {"id": "user.arjun", "label": "user.arjun", "type": "User", "privilege": "privileged", "department": "DevOps", "owner": "Arjun Das", "email": "arjun.d@corp.internal"},
            {"id": "user.neha", "label": "user.neha", "type": "User", "privilege": "standard", "department": "Sales", "owner": "Neha Joshi", "email": "neha.j@corp.internal"},
            {"id": "user.rahul", "label": "user.rahul", "type": "User", "privilege": "standard", "department": "Legal", "owner": "Rahul Sen", "email": "rahul.s@corp.internal"},
            {"id": "user.deepa", "label": "user.deepa", "type": "User", "privilege": "standard", "department": "Operations", "owner": "Deepa Menon", "email": "deepa.m@corp.internal"},
            {"id": "user.tanya", "label": "user.tanya", "type": "User", "privilege": "standard", "department": "Customer Support", "owner": "Tanya Kapoor", "email": "tanya.k@corp.internal"}
        ]
        nodes.extend(users)

        # 2. Endpoints & Workstations
        endpoints = [
            {"id": "ws-17-ops", "label": "ws-17-ops", "type": "Endpoint", "zone": "workstation", "ip": "10.0.1.17", "os": "Windows 11 Enterprise", "owner": "IT Support Pool"},
            {"id": "ws-eng-04", "label": "ws-eng-04", "type": "Endpoint", "zone": "workstation", "ip": "10.0.1.24", "os": "Ubuntu 24.04 LTS", "owner": "Engineering"},
            {"id": "ws-sec-01", "label": "ws-sec-01", "type": "Endpoint", "zone": "workstation", "ip": "10.0.1.10", "os": "macOS Sonoma", "owner": "SecOps"},
            {"id": "ws-fin-02", "label": "ws-fin-02", "type": "Endpoint", "zone": "workstation", "ip": "10.0.1.32", "os": "Windows 11 Enterprise", "owner": "Finance"},
            {"id": "ws-hr-01", "label": "ws-hr-01", "type": "Endpoint", "zone": "workstation", "ip": "10.0.1.45", "os": "Windows 11 Enterprise", "owner": "HR"},
            {"id": "ws-ops-01", "label": "ws-ops-01", "type": "Endpoint", "zone": "workstation", "ip": "10.0.1.51", "os": "RHEL 9.2", "owner": "Operations"},
            {"id": "bastion-mgmt", "label": "bastion-mgmt", "type": "Endpoint", "zone": "bastion", "ip": "10.0.2.1", "os": "Hardened Linux Jumpbox", "owner": "Core Infrastructure"},
            {"id": "vpn-gateway", "label": "vpn-gateway", "type": "Endpoint", "zone": "dmz", "ip": "10.0.0.5", "os": "Palo Alto GlobalProtect", "owner": "Network Engineering"},
            {"id": "printer-corp", "label": "printer-corp", "type": "Endpoint", "zone": "iot", "ip": "10.0.1.99", "os": "HP Embedded OS", "owner": "Facilities"},
            {"id": "dev-jumpbox-01", "label": "dev-jumpbox-01", "type": "Endpoint", "zone": "bastion", "ip": "10.0.2.10", "os": "Debian 12", "owner": "DevOps"},
            {"id": "endpoint-alpha", "label": "endpoint-alpha", "type": "Endpoint", "zone": "workstation", "ip": "10.1.1.5", "os": "Windows 11", "owner": "Ops Pool Alpha"},
            {"id": "endpoint-beta", "label": "endpoint-beta", "type": "Endpoint", "zone": "workstation", "ip": "10.1.1.6", "os": "Windows 11", "owner": "Ops Pool Beta"}
        ]
        nodes.extend(endpoints)

        # 3. Servers & Infrastructure
        servers = [
            {"id": "app-srv-02", "label": "app-srv-02", "type": "Server", "role": "application", "ip": "10.0.3.22", "zone": "app_tier", "os": "Debian 12 / Node.js API", "criticality": "Medium"},
            {"id": "app-srv-03", "label": "app-srv-03", "type": "Server", "role": "application", "ip": "10.0.3.23", "zone": "app_tier", "os": "Ubuntu 22.04 / FastAPI", "criticality": "Medium"},
            {"id": "srv-mgmt-01", "label": "srv-mgmt-01", "type": "Server", "role": "management", "ip": "10.0.3.50", "zone": "mgmt_tier", "os": "Windows Server 2022", "criticality": "High"},
            {"id": "backup-node", "label": "backup-node", "type": "Server", "role": "backup", "ip": "10.0.4.15", "zone": "backup_tier", "os": "FreeBSD ZFS Storage", "criticality": "Medium"},
            {"id": "core-dns-01", "label": "core-dns-01", "type": "Server", "role": "dns", "ip": "10.0.0.2", "zone": "core_services", "os": "BIND9 Linux", "criticality": "High"},
            {"id": "internal-mail-01", "label": "internal-mail-01", "type": "Server", "role": "email", "ip": "10.0.3.11", "zone": "app_tier", "os": "Postfix Linux", "criticality": "Low"},
            {"id": "log-archive-99", "label": "log-archive-99", "type": "Server", "role": "archive", "ip": "10.2.3.99", "zone": "archive_tier", "os": "S3 Storage Gateway", "criticality": "Low"},
            {"id": "monitor-srv", "label": "monitor-srv", "type": "Server", "role": "monitoring", "ip": "10.1.3.10", "zone": "mgmt_tier", "os": "Prometheus/Grafana", "criticality": "Medium"},
            {"id": "ci-runner-01", "label": "ci-runner-01", "type": "Server", "role": "build", "ip": "10.0.5.12", "zone": "dev_tier", "os": "Ubuntu Docker Runner", "criticality": "Low"},
            {"id": "file-share-01", "label": "file-share-01", "type": "Server", "role": "storage", "ip": "10.0.4.50", "zone": "storage_tier", "os": "Windows Storage Server", "criticality": "Medium"}
        ]
        nodes.extend(servers)

        # 4. Applications
        applications = [
            {"id": "app-billing-api", "label": "Billing API Gateway", "type": "Application", "tier": "Tier-1", "port": 8443, "owner": "Finance Tech"},
            {"id": "app-hr-portal", "label": "Workforce HR Portal", "type": "Application", "tier": "Tier-3", "port": 443, "owner": "People Team"},
            {"id": "app-crm-core", "label": "CRM Customer Hub", "type": "Application", "tier": "Tier-2", "port": 8080, "owner": "Sales Ops"},
            {"id": "app-it-service-desk", "label": "ITSM Service Portal", "type": "Application", "tier": "Tier-2", "port": 8081, "owner": "IT Support"}
        ]
        nodes.extend(applications)

        # 5. Critical Assets (Crown Jewels)
        critical_assets = [
            {"id": "finance-db", "label": "finance-db", "type": "CriticalAsset", "category": "database", "criticality": "Critical", "isCritical": True, "ip": "10.0.6.10", "zone": "db_secure_tier", "data_classification": "PCI-DSS / Confidential"},
            {"id": "crown-jewel-db", "label": "crown-jewel-db", "type": "CriticalAsset", "category": "database", "criticality": "Critical", "isCritical": True, "ip": "10.0.6.15", "zone": "db_secure_tier", "data_classification": "PII / High Integrity"},
            {"id": "identity-srv", "label": "identity-srv", "type": "CriticalAsset", "category": "idp", "criticality": "Critical", "isCritical": True, "ip": "10.0.0.1", "zone": "core_identity", "data_classification": "Active Directory / Kerberos KDC"},
            {"id": "customer-db", "label": "customer-db", "type": "CriticalAsset", "category": "database", "criticality": "Critical", "isCritical": True, "ip": "10.0.6.20", "zone": "db_secure_tier", "data_classification": "Customer Secrets"}
        ]
        nodes.extend(critical_assets)

        # 6. Vulnerabilities
        vulnerabilities = [
            {"id": "cve-2024-21413", "label": "CVE-2024-21413", "type": "Vulnerability", "cvss": 9.8, "severity": "Critical", "description": "Microsoft Outlook Remote Code Execution Flaw (Moniker Link)"},
            {"id": "cve-2023-38606", "label": "CVE-2023-38606", "type": "Vulnerability", "cvss": 8.1, "severity": "High", "description": "Kernel Memory State Modification Vulnerability"},
            {"id": "cve-2024-3400", "label": "CVE-2024-3400", "type": "Vulnerability", "cvss": 10.0, "severity": "Critical", "description": "Palo Alto PAN-OS Command Injection in GlobalProtect Gateway"}
        ]
        nodes.extend(vulnerabilities)

        # Baseline legitimate connections across enterprise
        baseline_edges = [
            {"source": "user.aarav", "target": "ws-eng-04", "type": "LOGGED_IN_TO", "category": "OBSERVED", "source_telemetry": "IAM", "timestamp": "2026-10-27T08:30:10Z"},
            {"source": "user.priya", "target": "ws-sec-01", "type": "LOGGED_IN_TO", "category": "OBSERVED", "source_telemetry": "IAM", "timestamp": "2026-10-27T08:45:00Z"},
            {"source": "user.vikram", "target": "ws-fin-02", "type": "LOGGED_IN_TO", "category": "OBSERVED", "source_telemetry": "IAM", "timestamp": "2026-10-27T09:00:15Z"},
            {"source": "user.rohit", "target": "ws-hr-01", "type": "LOGGED_IN_TO", "category": "OBSERVED", "source_telemetry": "IAM", "timestamp": "2026-10-27T09:05:22Z"},
            {"source": "ws-fin-02", "target": "app-billing-api", "type": "ACCESSES", "category": "AUTHORIZED", "source_telemetry": "CMDB", "timestamp": "2026-10-27T09:10:00Z"},
            {"source": "ws-hr-01", "target": "app-hr-portal", "type": "ACCESSES", "category": "AUTHORIZED", "source_telemetry": "CMDB", "timestamp": "2026-10-27T09:12:00Z"},
            {"source": "ws-sec-01", "target": "bastion-mgmt", "type": "AUTHORIZED_FOR", "category": "AUTHORIZED", "source_telemetry": "IAM Policy", "timestamp": "2026-10-27T08:50:00Z"},
            {"source": "ws-eng-04", "target": "ci-runner-01", "type": "CONNECTED_TO", "category": "OBSERVED", "source_telemetry": "Network Flow", "timestamp": "2026-10-27T09:20:11Z"}
        ]
        edges.extend(baseline_edges)

        return {"nodes": nodes, "edges": edges}

    def generate_scenario_lateral(self) -> Dict[str, Any]:
        """
        Scenario 1 / Flagship: Multi-hop Lateral Movement
        Compromised User (user.sneha) -> Workstation (ws-17-ops) -> Jumpbox (bastion-mgmt) -> App Server (app-srv-02) -> Finance DB.
        
        Demonstrates the SURPRISE alternate path:
        Even if bastion-mgmt is isolated, an alternate route exists via:
        ws-17-ops -> vpn-gateway -> app-srv-03 -> finance-db.
        When ws-17-ops is isolated, ALL attack paths are severed.
        """
        base = self._generate_enterprise_baseline()
        nodes = list(base["nodes"])
        edges = list(base["edges"])

        for n in nodes:
            if n["id"] == "user.sneha":
                n["isRoot"] = True
            elif n["id"] in ["ws-17-ops", "bastion-mgmt", "srv-mgmt-01"]:
                n["isChoke"] = True

        incident_edges = [
            # Root Observed Telemetry (IAM & EDR): exactly 2 neighbors from user.sneha
            {"source": "user.sneha", "target": "ws-17-ops", "type": "LOGGED_IN_TO", "category": "OBSERVED", "source_telemetry": "IAM Logon", "timestamp": "2026-10-27T09:41:12Z", "port": 3389, "protocol": "RDP"},
            {"source": "user.sneha", "target": "printer-corp", "type": "CONNECTED_TO", "category": "OBSERVED", "source_telemetry": "Network Flow", "timestamp": "2026-10-27T09:41:16Z", "port": 9100, "protocol": "RAW"},

            # Lateral movement & authorized capabilities from workstation ws-17-ops:
            # 1. Primary path through bastion-mgmt: ws-17-ops -> bastion-mgmt -> app-srv-02 -> finance-db
            {"source": "ws-17-ops", "target": "bastion-mgmt", "type": "CONNECTED_TO", "category": "OBSERVED", "source_telemetry": "EDR Process", "timestamp": "2026-10-27T09:41:18Z", "port": 22, "protocol": "SSH"},
            {"source": "bastion-mgmt", "target": "app-srv-02", "type": "AUTHORIZED_FOR", "category": "AUTHORIZED", "source_telemetry": "PAM Vault", "timestamp": "2026-10-27T09:41:26Z", "port": 443, "protocol": "HTTPS"},
            {"source": "bastion-mgmt", "target": "finance-db", "type": "ACCESSES", "category": "AUTHORIZED", "source_telemetry": "PAM Vault Session", "timestamp": "2026-10-27T09:41:28Z", "port": 5432, "protocol": "PostgreSQL"},
            {"source": "app-srv-02", "target": "cve-2024-21413", "type": "HAS_VULNERABILITY", "category": "INFERRED", "source_telemetry": "Tenable Vuln Scan", "timestamp": "2026-10-27T09:41:34Z"},
            {"source": "app-srv-02", "target": "finance-db", "type": "ACCESSES", "category": "AUTHORIZED", "source_telemetry": "Network ACL", "timestamp": "2026-10-27T09:41:42Z", "port": 5432, "protocol": "PostgreSQL"},

            # 2. Alternate path: ws-17-ops -> vpn-gateway -> app-srv-03 -> finance-db
            {"source": "ws-17-ops", "target": "vpn-gateway", "type": "CAN_REACH", "category": "AUTHORIZED", "source_telemetry": "VPN Concentrator", "timestamp": "2026-10-27T09:41:15Z", "port": 443, "protocol": "HTTPS"},
            {"source": "vpn-gateway", "target": "app-srv-03", "type": "CAN_REACH", "category": "AUTHORIZED", "source_telemetry": "Firewall Route", "timestamp": "2026-10-27T09:41:20Z", "port": 8080, "protocol": "HTTP"},
            {"source": "vpn-gateway", "target": "finance-db", "type": "ACCESSES", "category": "AUTHORIZED", "source_telemetry": "VPN Enclave Route", "timestamp": "2026-10-27T09:41:22Z", "port": 5432, "protocol": "PostgreSQL"},
            {"source": "app-srv-03", "target": "finance-db", "type": "ACCESSES", "category": "AUTHORIZED", "source_telemetry": "DB Auth Role", "timestamp": "2026-10-27T09:41:45Z", "port": 5432, "protocol": "PostgreSQL"},

            # 3. Direct connection ws-17-ops -> app-srv-02 (Observed telemetry)
            {"source": "ws-17-ops", "target": "app-srv-02", "type": "CONNECTED_TO", "category": "OBSERVED", "source_telemetry": "EDR Sensor", "timestamp": "2026-10-27T09:41:19Z"},

            # 4. Management path: ws-17-ops -> srv-mgmt-01 -> crown-jewel-db
            {"source": "ws-17-ops", "target": "srv-mgmt-01", "type": "AUTHORIZED_FOR", "category": "AUTHORIZED", "source_telemetry": "Active Directory Group", "timestamp": "2026-10-27T09:41:22Z", "port": 445, "protocol": "SMB"},
            {"source": "srv-mgmt-01", "target": "crown-jewel-db", "type": "ACCESSES", "category": "AUTHORIZED", "source_telemetry": "Service Account", "timestamp": "2026-10-27T09:41:30Z", "port": 1433, "protocol": "MSSQL"},

            # 5. Backup path: ws-17-ops -> backup-node -> identity-srv
            {"source": "ws-17-ops", "target": "backup-node", "type": "CAN_REACH", "category": "AUTHORIZED", "source_telemetry": "VLAN Trunk", "timestamp": "2026-10-27T09:41:25Z", "port": 873, "protocol": "RSYNC"},
            {"source": "backup-node", "target": "identity-srv", "type": "CAN_REACH", "category": "AUTHORIZED", "source_telemetry": "Replication Agent", "timestamp": "2026-10-27T09:41:38Z", "port": 389, "protocol": "LDAP"}
        ]
        edges.extend(incident_edges)

        timeline = [
            {"time": "09:41:12", "timestamp": "2026-10-27T09:41:12Z", "source": "IAM / Okta", "event": "Interactive logon detected for user.sneha on workstation ws-17-ops from external ISP ASN.", "severity": "MEDIUM"},
            {"time": "09:41:18", "timestamp": "2026-10-27T09:41:18Z", "source": "CrowdStrike EDR", "event": "Outbound lateral network pivot: ws-17-ops initiated SSH session to core bastion-mgmt.", "severity": "HIGH"},
            {"time": "09:41:26", "timestamp": "2026-10-27T09:41:26Z", "source": "CyberArk PAM", "event": "Administrative session authorized from bastion-mgmt to application server app-srv-02.", "severity": "MEDIUM"},
            {"time": "09:41:34", "timestamp": "2026-10-27T09:41:34Z", "source": "Vulnerability Scanner", "event": "Target app-srv-02 flagged with known unpatched CVE-2024-21413 (CVSS 9.8).", "severity": "HIGH"},
            {"time": "09:41:42", "timestamp": "2026-10-27T09:41:42Z", "source": "Network Flow / Zeek", "event": "Database connection established from app-srv-02 to finance-db (Port 5432).", "severity": "CRITICAL"}
        ]

        anomalies = [
            {
                "id": "anom-01",
                "entity_id": "ws-17-ops",
                "type": "Unusual Lateral Pivot",
                "severity": "HIGH",
                "explanation": "Workstation ws-17-ops established uncharacteristic outbound connection to core management jumpbox bastion-mgmt outside normal operational baseline."
            },
            {
                "id": "anom-02",
                "entity_id": "app-srv-02",
                "type": "Vulnerable Path Pivot",
                "severity": "HIGH",
                "explanation": "Application server app-srv-02 exposes unpatched CVE-2024-21413 with direct authorized access to Finance Database."
            },
            {
                "id": "anom-03",
                "entity_id": "vpn-gateway",
                "type": "Redundant Ingress Path",
                "severity": "MEDIUM",
                "explanation": "Active concurrent remote access session via vpn-gateway creates an unmonitored alternate traversal vector directly into app tier."
            }
        ]

        risk_breakdown = [
            {"factor": "Privileged Identity", "delta": 18, "reason": "user.sneha belongs to IT Support with elevated system access."},
            {"factor": "Active Observed Lateral Movement", "delta": 22, "reason": "Confirmed telemetry link from ws-17-ops to administrative bastion-mgmt."},
            {"factor": "Direct Critical Asset Reachability", "delta": 24, "reason": "Paths terminate at high-value finance-db and crown-jewel-db."},
            {"factor": "Exploitable Vulnerability Pivot", "delta": 12, "reason": "CVE-2024-21413 present along intermediate server app-srv-02."},
            {"factor": "Alternate Traversal Pathway", "delta": 6, "reason": "Concurrent VPN pathway bypasses primary bastion boundary."}
        ]

        mitre_context = [
            {"technique_id": "T1078.002", "technique_name": "Valid Accounts: Domain Accounts", "tactic": "Defense Evasion", "evidence": "Simulated credential compromise of user.sneha"},
            {"technique_id": "T1021.004", "technique_name": "Remote Services: SSH", "tactic": "Lateral Movement", "evidence": "ws-17-ops connecting to bastion-mgmt"},
            {"technique_id": "T1210", "technique_name": "Exploitation of Remote Services", "tactic": "Lateral Movement", "evidence": "CVE-2024-21413 on app-srv-02"},
            {"technique_id": "T1005", "technique_name": "Data from Local System", "tactic": "Collection", "evidence": "Traversing to finance-db and crown-jewel-db"}
        ]

        return {
            "id": "scenario_lateral",
            "name": "Multi-hop Lateral Movement (Flagship)",
            "incident_id": "INC-2026-0042",
            "severity": "HIGH",
            "status": "INVESTIGATING",
            "description": "Compromised administrative credentials traversing via intermediate endpoints and jumpboxes to high-value database tiers.",
            "initial_event": "Suspicious RDP / SSH Pivot to Bastion Jumpbox",
            "mitre_technique": "T1021.004 (Remote Services: SSH)",
            "mitre_context": mitre_context,
            "root_entity": "user.sneha",
            "primary_target": "finance-db",
            "base_risk": 82,
            "risk_factors": ["privileged identity", "multi-hop reachability", "critical asset reachable", "unpatched CVE pivot", "alternate VPN path"],
            "risk_breakdown": risk_breakdown,
            "expected_choke": "bastion-mgmt",
            "timeline": timeline,
            "nodes": nodes,
            "edges": edges,
            "anomalies": anomalies
        }

    def generate_scenario_chokepoint(self) -> Dict[str, Any]:
        """
        Scenario 2: Multi-Path Choke Point Isolation
        Multiple independent pathways funneling through a central management bastion to reach directory services and core databases.
        """
        base = self._generate_enterprise_baseline()
        nodes = list(base["nodes"])
        edges = list(base["edges"])

        for n in nodes:
            if n["id"] == "user.sneha":
                n["isRoot"] = True
            elif n["id"] == "bastion-mgmt":
                n["isChoke"] = True

        incident_edges = [
            {"source": "user.sneha", "target": "endpoint-alpha", "type": "LOGGED_IN_TO", "category": "OBSERVED", "source_telemetry": "IAM", "timestamp": "2026-10-27T10:14:02Z"},
            {"source": "user.sneha", "target": "endpoint-beta", "type": "LOGGED_IN_TO", "category": "OBSERVED", "source_telemetry": "IAM", "timestamp": "2026-10-27T10:14:05Z"},
            {"source": "endpoint-alpha", "target": "bastion-mgmt", "type": "CAN_REACH", "category": "AUTHORIZED", "source_telemetry": "Firewall Rule", "timestamp": "2026-10-27T10:14:10Z"},
            {"source": "endpoint-beta", "target": "bastion-mgmt", "type": "CAN_REACH", "category": "AUTHORIZED", "source_telemetry": "Firewall Rule", "timestamp": "2026-10-27T10:14:12Z"},
            {"source": "bastion-mgmt", "target": "crown-jewel-db", "type": "ACCESSES", "category": "AUTHORIZED", "source_telemetry": "DB Client", "timestamp": "2026-10-27T10:14:20Z"},
            {"source": "bastion-mgmt", "target": "identity-srv", "type": "ACCESSES", "category": "AUTHORIZED", "source_telemetry": "AD Admin", "timestamp": "2026-10-27T10:14:22Z"},
            {"source": "endpoint-alpha", "target": "monitor-srv", "type": "CONNECTED_TO", "category": "OBSERVED", "source_telemetry": "Network Flow", "timestamp": "2026-10-27T10:14:30Z"}
        ]
        edges.extend(incident_edges)

        timeline = [
            {"time": "10:14:02", "timestamp": "2026-10-27T10:14:02Z", "source": "IAM / Active Directory", "event": "Simultaneous logins detected for user.sneha across endpoint-alpha and endpoint-beta.", "severity": "HIGH"},
            {"time": "10:14:10", "timestamp": "2026-10-27T10:14:10Z", "source": "Network Firewall", "event": "Concurrent administrative sessions initiated toward bastion-mgmt.", "severity": "MEDIUM"},
            {"time": "10:14:20", "timestamp": "2026-10-27T10:14:20Z", "source": "PAM Monitor", "event": "High-privilege database session request to crown-jewel-db.", "severity": "HIGH"}
        ]

        anomalies = [
            {
                "id": "anom-choke-01",
                "entity_id": "bastion-mgmt",
                "type": "Convergent Path Funnel",
                "severity": "HIGH",
                "explanation": "Multiple concurrent user sessions converge onto single administrative bastion host with privileged access to Active Directory and Core DB."
            }
        ]

        risk_breakdown = [
            {"factor": "Concurrent Ingress Sessions", "delta": 22, "reason": "Simultaneous user logon events on separate endpoints."},
            {"factor": "Choke Point Convergence", "delta": 28, "reason": "All attack vectors route through single administrative bastion."},
            {"factor": "Core Identity Exposure", "delta": 28, "reason": "Target access terminates directly in identity-srv and crown-jewel-db."}
        ]

        mitre_context = [
            {"technique_id": "T1078.003", "technique_name": "Valid Accounts: Local Accounts", "tactic": "Persistence", "evidence": "Concurrent login activity on endpoint pool"},
            {"technique_id": "T1021.001", "technique_name": "Remote Desktop Protocol", "tactic": "Lateral Movement", "evidence": "Convergent traffic to bastion-mgmt"}
        ]

        return {
            "id": "scenario_chokepoint",
            "name": "Multi-Path Choke Point Convergence",
            "incident_id": "INC-2026-0043",
            "severity": "HIGH",
            "status": "INVESTIGATING",
            "description": "Redundant paths converge on a single management bastion before reaching critical crown jewels.",
            "initial_event": "Dual Concurrent Session Anomalies",
            "mitre_technique": "T1078 (Valid Accounts)",
            "mitre_context": mitre_context,
            "root_entity": "user.sneha",
            "primary_target": "crown-jewel-db",
            "base_risk": 78,
            "risk_factors": ["multi-path convergence", "identity provider exposure", "critical asset reachable"],
            "risk_breakdown": risk_breakdown,
            "expected_choke": "bastion-mgmt",
            "timeline": timeline,
            "nodes": nodes,
            "edges": edges,
            "anomalies": anomalies
        }

    def generate_scenario_alternate_path(self) -> Dict[str, Any]:
        """
        Scenario 3: Explicit Alternate Path Detection
        Demonstrates why isolating the primary bastion leaves finance-db exposed via vpn-gateway.
        """
        base = self._generate_enterprise_baseline()
        nodes = list(base["nodes"])
        edges = list(base["edges"])

        for n in nodes:
            if n["id"] == "user.sneha":
                n["isRoot"] = True
            elif n["id"] in ["bastion-mgmt", "vpn-gateway"]:
                n["isChoke"] = True

        incident_edges = [
            # Path 1: Primary path through bastion-mgmt
            {"source": "user.sneha", "target": "ws-17-ops", "type": "LOGGED_IN_TO", "category": "OBSERVED", "source_telemetry": "IAM", "timestamp": "2026-10-27T11:00:01Z"},
            {"source": "ws-17-ops", "target": "bastion-mgmt", "type": "CONNECTED_TO", "category": "OBSERVED", "source_telemetry": "EDR", "timestamp": "2026-10-27T11:00:10Z"},
            {"source": "bastion-mgmt", "target": "app-srv-02", "type": "AUTHORIZED_FOR", "category": "AUTHORIZED", "source_telemetry": "PAM", "timestamp": "2026-10-27T11:00:20Z"},
            {"source": "app-srv-02", "target": "finance-db", "type": "ACCESSES", "category": "AUTHORIZED", "source_telemetry": "DB Grant", "timestamp": "2026-10-27T11:00:30Z"},

            # Path 2: Alternate path through vpn-gateway
            {"source": "user.sneha", "target": "vpn-gateway", "type": "LOGGED_IN_TO", "category": "OBSERVED", "source_telemetry": "VPN Log", "timestamp": "2026-10-27T11:00:05Z"},
            {"source": "vpn-gateway", "target": "app-srv-03", "type": "CAN_REACH", "category": "AUTHORIZED", "source_telemetry": "Firewall Route", "timestamp": "2026-10-27T11:00:15Z"},
            {"source": "app-srv-03", "target": "finance-db", "type": "ACCESSES", "category": "AUTHORIZED", "source_telemetry": "DB Grant", "timestamp": "2026-10-27T11:00:35Z"}
        ]
        edges.extend(incident_edges)

        timeline = [
            {"time": "11:00:01", "timestamp": "2026-10-27T11:00:01Z", "source": "IAM", "event": "user.sneha logged into workstation ws-17-ops.", "severity": "LOW"},
            {"time": "11:00:05", "timestamp": "2026-10-27T11:00:05Z", "source": "VPN", "event": "Simultaneous secondary session observed via vpn-gateway.", "severity": "MEDIUM"},
            {"time": "11:00:10", "timestamp": "2026-10-27T11:00:10Z", "source": "EDR", "event": "Workstation connects to bastion-mgmt.", "severity": "MEDIUM"},
            {"time": "11:00:30", "timestamp": "2026-10-27T11:00:30Z", "source": "Database Guard", "event": "Both app-srv-02 and app-srv-03 query finance-db.", "severity": "HIGH"}
        ]

        anomalies = [
            {
                "id": "anom-alt-01",
                "entity_id": "vpn-gateway",
                "type": "Dual-Path Bypass",
                "severity": "HIGH",
                "explanation": "Simultaneous external VPN pathway bypasses the internal bastion management perimeter, maintaining redundant reachability to Finance Database."
            }
        ]

        risk_breakdown = [
            {"factor": "Redundant Traversal Paths", "delta": 25, "reason": "Dual independent pathways reach the same critical asset."},
            {"factor": "Bypass of Bastion Control", "delta": 25, "reason": "VPN ingress circumventing normal privileged bastion inspection."},
            {"factor": "Target Criticality", "delta": 25, "reason": "High-value Finance Database exposed to unauthorized queries."}
        ]

        mitre_context = [
            {"technique_id": "T1133", "technique_name": "External Remote Services", "tactic": "Initial Access", "evidence": "vpn-gateway ingress pathway"},
            {"technique_id": "T1078", "technique_name": "Valid Accounts", "tactic": "Defense Evasion", "evidence": "Dual session authentication for user.sneha"}
        ]

        return {
            "id": "scenario_alternate_path",
            "name": "Alternate Path & Residual Exposure",
            "incident_id": "INC-2026-0044",
            "severity": "HIGH",
            "status": "INVESTIGATING",
            "description": "Demonstrates incomplete containment: isolating the primary bastion leaves the finance database reachable via an alternate VPN gateway route.",
            "initial_event": "Dual Pathway Ingress Anomaly",
            "mitre_technique": "T1133 (External Remote Services)",
            "mitre_context": mitre_context,
            "root_entity": "user.sneha",
            "primary_target": "finance-db",
            "base_risk": 75,
            "risk_factors": ["redundant paths", "bastion bypass", "critical asset reachable"],
            "risk_breakdown": risk_breakdown,
            "expected_choke": "bastion-mgmt",
            "timeline": timeline,
            "nodes": nodes,
            "edges": edges,
            "anomalies": anomalies
        }

    def generate_scenario_blast_radius(self) -> Dict[str, Any]:
        """
        Scenario 4: Expanded Blast Radius (High Connectivity)
        A highly connected node in the enterprise network exhibiting multi-hop exponential reachability.
        """
        base = self._generate_enterprise_baseline()
        nodes = list(base["nodes"])
        edges = list(base["edges"])

        for n in nodes:
            if n["id"] == "user.ananya":
                n["isRoot"] = True

        incident_edges = [
            {"source": "user.ananya", "target": "bastion-mgmt", "type": "LOGGED_IN_TO", "category": "OBSERVED", "source_telemetry": "IAM", "timestamp": "2026-10-27T08:00:00Z"},
            {"source": "bastion-mgmt", "target": "srv-mgmt-01", "type": "AUTHORIZED_FOR", "category": "AUTHORIZED", "source_telemetry": "Domain Admin Group", "timestamp": "2026-10-27T08:00:05Z"},
            {"source": "bastion-mgmt", "target": "app-srv-02", "type": "AUTHORIZED_FOR", "category": "AUTHORIZED", "source_telemetry": "Domain Admin Group", "timestamp": "2026-10-27T08:00:10Z"},
            {"source": "bastion-mgmt", "target": "app-srv-03", "type": "AUTHORIZED_FOR", "category": "AUTHORIZED", "source_telemetry": "Domain Admin Group", "timestamp": "2026-10-27T08:00:15Z"},
            {"source": "bastion-mgmt", "target": "backup-node", "type": "AUTHORIZED_FOR", "category": "AUTHORIZED", "source_telemetry": "Domain Admin Group", "timestamp": "2026-10-27T08:00:20Z"},
            {"source": "srv-mgmt-01", "target": "crown-jewel-db", "type": "ACCESSES", "category": "AUTHORIZED", "source_telemetry": "SQL Admin", "timestamp": "2026-10-27T08:00:25Z"},
            {"source": "app-srv-02", "target": "finance-db", "type": "ACCESSES", "category": "AUTHORIZED", "source_telemetry": "App DB User", "timestamp": "2026-10-27T08:00:30Z"},
            {"source": "backup-node", "target": "identity-srv", "type": "CAN_REACH", "category": "AUTHORIZED", "source_telemetry": "Active Directory", "timestamp": "2026-10-27T08:00:35Z"},
            {"source": "app-srv-03", "target": "customer-db", "type": "ACCESSES", "category": "AUTHORIZED", "source_telemetry": "CRM DB Pool", "timestamp": "2026-10-27T08:00:40Z"}
        ]
        edges.extend(incident_edges)

        timeline = [
            {"time": "08:00:00", "timestamp": "2026-10-27T08:00:00Z", "source": "IAM / Kerberos", "event": "Domain Admin logon observed for user.ananya on bastion-mgmt.", "severity": "HIGH"},
            {"time": "08:00:20", "timestamp": "2026-10-27T08:00:20Z", "source": "Network Flow", "event": "Simultaneous reachability fanout across app tier and database secure enclave.", "severity": "HIGH"}
        ]

        anomalies = [
            {
                "id": "anom-blast-01",
                "entity_id": "user.ananya",
                "type": "High Blast Radius Exposure",
                "severity": "HIGH",
                "explanation": "Identity user.ananya possesses broad domain administration privileges spanning 4 critical enterprise databases within 3 hops."
            }
        ]

        risk_breakdown = [
            {"factor": "Domain Admin Identity", "delta": 30, "reason": "Full administrative delegation across core enterprise infrastructure."},
            {"factor": "Broad Reachability Scope", "delta": 30, "reason": "Reaches 4 distinct Crown Jewel databases within 2-3 hops."},
            {"factor": "Unrestricted Jumpbox Pivot", "delta": 25, "reason": "Direct management capabilities into all production server enclaves."}
        ]

        mitre_context = [
            {"technique_id": "T1078.002", "technique_name": "Valid Accounts: Domain Accounts", "tactic": "Initial Access", "evidence": "Domain Admin credentials for user.ananya"},
            {"technique_id": "T1018", "technique_name": "Remote System Discovery", "tactic": "Discovery", "evidence": "Broad reachability across multiple subnets"}
        ]

        return {
            "id": "scenario_blast_radius",
            "name": "High Connectivity & Expanded Blast Radius",
            "incident_id": "INC-2026-0045",
            "severity": "HIGH",
            "status": "INVESTIGATING",
            "description": "Compromised Domain Admin credentials demonstrating wide multi-hop reachability across all database tiers.",
            "initial_event": "Domain Admin Ingress & Multi-Tier Reachability",
            "mitre_technique": "T1078 (Valid Accounts)",
            "mitre_context": mitre_context,
            "root_entity": "user.ananya",
            "primary_target": "identity-srv",
            "base_risk": 85,
            "risk_factors": ["domain admin identity", "4 critical assets reachable", "multi-tier blast radius"],
            "risk_breakdown": risk_breakdown,
            "expected_choke": "bastion-mgmt",
            "timeline": timeline,
            "nodes": nodes,
            "edges": edges,
            "anomalies": anomalies
        }

    def generate_scenario_benign(self) -> Dict[str, Any]:
        """
        Scenario 5: Benign Maintenance Activity
        Routine off-hours snapshot backup job without critical asset exposure.
        Risk score must remain LOW (24/100).
        """
        nodes = [
            {"id": "user.sneha", "label": "user.sneha", "type": "User", "privilege": "standard", "department": "DevOps", "isRoot": True},
            {"id": "ws-ops-01", "label": "ws-ops-01", "type": "Endpoint", "zone": "workstation", "ip": "10.2.1.8"},
            {"id": "backup-node", "label": "backup-node", "type": "Server", "role": "backup", "ip": "10.2.2.15", "isChoke": True},
            {"id": "log-archive-99", "label": "log-archive-99", "type": "Server", "role": "archive", "ip": "10.2.3.99"}
        ]

        edges = [
            {"source": "user.sneha", "target": "ws-ops-01", "type": "LOGGED_IN_TO", "category": "OBSERVED", "source_telemetry": "IAM", "timestamp": "2026-10-27T03:00:10Z"},
            {"source": "ws-ops-01", "target": "backup-node", "type": "CONNECTED_TO", "category": "OBSERVED", "source_telemetry": "EDR", "timestamp": "2026-10-27T03:01:00Z"},
            {"source": "backup-node", "target": "log-archive-99", "type": "CAN_REACH", "category": "AUTHORIZED", "source_telemetry": "Cron Job", "timestamp": "2026-10-27T03:02:00Z"}
        ]

        timeline = [
            {"time": "03:00:10", "timestamp": "2026-10-27T03:00:10Z", "source": "IAM / Automation", "event": "Approved scheduled service account login for weekly snapshot job.", "severity": "LOW"},
            {"time": "03:01:00", "timestamp": "2026-10-27T03:01:00Z", "source": "EDR", "event": "Backup agent triggered archival sync to log-archive-99.", "severity": "LOW"}
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

        risk_breakdown = [
            {"factor": "Off-Hours Activity", "delta": 10, "reason": "Activity executed outside standard business hours (03:00 AM)."},
            {"factor": "Approved Maintenance Window", "delta": 8, "reason": "Correlates with registered ITSM change ticket CHG-8821."},
            {"factor": "Zero Critical Assets Exposed", "delta": 6, "reason": "No paths to databases, IdP, or Crown Jewels."}
        ]

        mitre_context = [
            {"technique_id": "T1059", "technique_name": "Command and Scripting Interpreter", "tactic": "Execution", "evidence": "Automated maintenance cron execution"}
        ]

        return {
            "id": "scenario_benign",
            "name": "Benign Maintenance Activity",
            "incident_id": "INC-2026-0046",
            "severity": "LOW",
            "status": "CLOSED_BENIGN",
            "description": "Routine scheduled off-hours snapshot archival job without exposure to critical assets.",
            "initial_event": "Scheduled Maintenance Script Execution",
            "mitre_technique": "T1059 (Command & Scripting Interpreter)",
            "mitre_context": mitre_context,
            "root_entity": "user.sneha",
            "primary_target": "None (Protected)",
            "base_risk": 24,
            "risk_factors": ["off-hours activity", "scheduled maintenance window", "zero critical assets exposed"],
            "risk_breakdown": risk_breakdown,
            "expected_choke": "backup-node",
            "timeline": timeline,
            "nodes": nodes,
            "edges": edges,
            "anomalies": anomalies
        }

    def generate_scenario_normal(self) -> Dict[str, Any]:
        """
        Scenario 6: Normal Daytime Enterprise Operations
        Standard business activities across endpoints and applications with zero security alert triggers.
        """
        base = self._generate_enterprise_baseline()
        nodes = list(base["nodes"])
        edges = list(base["edges"])

        for n in nodes:
            if n["id"] == "user.vikram":
                n["isRoot"] = True

        timeline = [
            {"time": "09:00:15", "timestamp": "2026-10-27T09:00:15Z", "source": "IAM", "event": "Finance user logged into authorized desktop ws-fin-02.", "severity": "LOW"},
            {"time": "09:10:00", "timestamp": "2026-10-27T09:10:00Z", "source": "Network Flow", "event": "Regular HTTPS traffic to app-billing-api gateway.", "severity": "LOW"}
        ]

        return {
            "id": "scenario_normal",
            "name": "Normal Operations Baseline",
            "incident_id": "INC-2026-0047",
            "severity": "LOW",
            "status": "NORMAL",
            "description": "Legitimate enterprise workday baseline traffic with standard IAM permissions and zero anomalous paths.",
            "initial_event": "Standard Enterprise User Activity",
            "mitre_technique": "None",
            "mitre_context": [],
            "root_entity": "user.vikram",
            "primary_target": "None",
            "base_risk": 15,
            "risk_factors": ["normal business hours", "standard privileges", "authorized policy reachability"],
            "risk_breakdown": [
                {"factor": "Standard User Privilege", "delta": 5, "reason": "Standard non-administrative corporate identity."},
                {"factor": "Authorized Application Tier Access", "delta": 10, "reason": "Standard policy-approved portal access."}
            ],
            "expected_choke": "ws-fin-02",
            "timeline": timeline,
            "nodes": nodes,
            "edges": edges,
            "anomalies": []
        }

    def get_all_scenarios(self) -> Dict[str, Any]:
        return {
            "scenario_lateral": self.generate_scenario_lateral(),
            "scenario_chokepoint": self.generate_scenario_chokepoint(),
            "scenario_alternate_path": self.generate_scenario_alternate_path(),
            "scenario_blast_radius": self.generate_scenario_blast_radius(),
            "scenario_benign": self.generate_scenario_benign(),
            "scenario_normal": self.generate_scenario_normal()
        }
