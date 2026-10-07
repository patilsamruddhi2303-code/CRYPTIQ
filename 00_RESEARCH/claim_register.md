# Claim Register

| Claim ID | Claim Text | Evidence Source | Status |
|----------|------------|-----------------|--------|
| C1 | [Hypothesis] Graph analytics can reduce incident investigation time by ≥30 % compared to manual methods. | S1 (NIST SP 800-61 §4.2 notes correlation effort; percentage is hypothesis) | Pending Validation |
| C2 | [Inference] Existing tools (e.g., Splunk, Elastic) focus primarily on search/alert correlation rather than deterministic 1-3-hop blast radius with choke-point analysis. | S5 (Gartner Magic Quadrant 2024; secondary review) | Pending Validation |
| C3 | [Hypothesis] Synthetic telemetry generated with fixed seed can faithfully reproduce typical lateral-movement patterns for testing. | S4 (SANS whitepaper 2023) | Pending Validation |
| C4 | [Evidence] MITRE ATT&CK techniques T1021 and T1210 represent remote service exploitation and lateral movement. | S2 (MITRE ATT&CK) | Confirmed |
| C5 | [Hypothesis] Automated choke-point detection based on betweenness centrality can improve mean-time-to-contain and prevent missed containment opportunities. | S3 (Neo4j GDS docs describe centrality; containment impact is hypothesis) | Pending Validation |

