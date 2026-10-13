"""
Incident Response Recommendation Engine
Generates defensive posture remediation tasks based on identified vulnerabilities.
"""

from typing import List, Dict

class RecommendationEngine:
    """Compiles technical, structural checklists for defensive network manipulation."""
    def __init__(self) -> None:
        self._remediation_matrix: Dict[str, List[str]] = {
            "normal traffic": [
                "Maintain baseline continuous passive network sniffing operations.",
                "Verify integrity schedules of automated sensor deployment arrays.",
                "Ensure routine ML log parsing microservices remain active."
            ],
            "port scan": [
                "Isolate or drop offending traffic blocks via active stateful firewall configurations.",
                "Restrict exposed or unneeded perimeter listening sockets.",
                "Audit system architecture profiles for unexpected external telemetry exposures.",
                "Cross-reference source infrastructure with global blacklists."
            ],
            "ddos": [
                "Trigger automated upstream rate-limiting policies at edge routers.",
                "Divert core public services through cloud scrubbing environments.",
                "Deploy challenge-response validation filters across edge reverse proxies.",
                "Monitor load balancer queue utilization metrics."
            ],
            "brute_force": [
                "Enforce immediate temporary connection locks on high-frequency authentication faults.",
                "Validate deployment and integrity of adaptive Multi-Factor Authentication (MFA) parameters.",
                "Analyze authentication audit trails for lateral movement markers.",
                "Rotate service account infrastructure keys if flags point to endpoint compromises."
            ],
            "botnet activity": [
                "Implement strict egress firewalls on the compromised asset to drop known C2 IPs.",
                "Isolate affected internal compute nodes into quarantine VLAN structures.",
                "Execute memory and file system volatile preservation scripts for analysis.",
                "Inspect local persistence vectors (cron entries, registry modifications)."
            ],
            "data exfiltration": [
                "Terminate active stateful socket connections associated with the data path immediately.",
                "Revoke session tokens linked with target storage or directory systems.",
                "Analyze network payload flow captures to calculate loss volumes.",
                "Isolate affected data processing pipelines from wide-area access."
            ]
        }

    def generate_remediation_steps(self, threat_name: str) -> List[str]:
        """Fetches discrete remediation procedures mapped to the active threat profile."""
        normalized = threat_name.lower().strip()
        return self._remediation_matrix.get(
            normalized, 
            ["Initiate standard incident triage playbook protocols.", "Review full packet capture history logs manually."]
        )