# Data Model & Graph Semantics

## 1. Graph Model Principles
The GraphOps graph uses an explicit Labeled Property Graph (LPG) representation. Every edge maintains a strict semantic classification:
1. `OBSERVED`: Actual logged telemetry from synthetic sensor logs (e.g. user authentication, network connection).
2. `AUTHORIZED/CAPABILITY`: Permitted network reachability, ACL rules, or administrative role assignment.
3. `INFERRED/PREDICTED`: Analyst- or graph-derived reachability based on vulnerabilities or access paths.

## 2. Node Schema
| Label | Primary Key | Key Properties | Description |
|-------|-------------|----------------|-------------|
| `User` | `id` | `name`, `department`, `privilege` (`standard`, `privileged`, `admin`) | Corporate identity / account |
| `Endpoint` | `id` | `hostname`, `ip`, `zone` (`workstation`, `jumpbox`, `bastion`) | Host computer or intermediate workstation |
| `Server` | `id` | `hostname`, `ip`, `role` (`web`, `application`, `mgmt`, `backup`) | Enterprise server |
| `Application` | `id` | `name`, `tier`, `port` | Software system or service |
| `CriticalAsset`| `id` | `name`, `category` (`database`, `idp`, `pki`), `criticality` (`High`, `Critical`) | High-value crown jewel |
| `Vulnerability`| `id` | `cve_id`, `cvss`, `severity` | Published vulnerability |

## 3. Relationship Schema
| Type | Semantic Category | Source Node | Target Node | Meaning |
|------|-------------------|-------------|-------------|---------|
| `LOGGED_IN_TO` | `OBSERVED` | `User` | `Endpoint` | User authentication session logged |
| `CONNECTED_TO` | `OBSERVED` | `Endpoint` | `Server` / `Endpoint` | Network communication session established |
| `AUTHORIZED_FOR` | `AUTHORIZED` | `User` / `Endpoint` | `Server` / `Application` | Configured permission or credential access |
| `CAN_REACH` | `AUTHORIZED` | `Endpoint` | `Server` / `Endpoint` | Network route/firewall rule open |
| `ACCESSES` | `AUTHORIZED` | `Server` / `Application`| `CriticalAsset` | Service accesses high-value asset |
| `HAS_VULNERABILITY` | `CAPABILITY` | `Endpoint` / `Server` | `Vulnerability` | Host is affected by known CVE |
| `EXPLOITS` | `INFERRED` | `User` / `Endpoint` | `Vulnerability` | Exploit payload delivered |
