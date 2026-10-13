"""
Threat Intelligence Knowledge Base
Contains detailed metadata regarding known network attacks based on framework standards.
"""

from typing import Dict, Any, Optional

class ThreatMetadata:
    """Represents standardized cybersecurity intelligence for a specific network threat."""
    def __init__(self, threat_name: str, base_severity: str, description: str, impact: str):
        self.threat_name: str = threat_name
        self.base_severity: str = base_severity.upper()
        self.description: str = description
        self.impact: str = impact

    def to_dict(self) -> Dict[str, str]:
        """Serializes object data into a standard dictionary format."""
        return {
            "threat_name": self.threat_name,
            "base_severity": self.base_severity,
            "description": self.description,
            "impact": self.impact
        }


class ThreatIntelligenceDB:
    """Manages the lifecycle and queries of the local threat intelligence data storage."""
    def __init__(self) -> None:
        self._db: Dict[str, ThreatMetadata] = {}
        self._initialize_database()

    def _initialize_database(self) -> None:
        """Populates the database with default signatures for NSL-KDD and CICIDS2017 profiles."""
        threats = [
            ThreatMetadata(
                threat_name="Normal Traffic",
                base_severity="LOW",
                description="Network traffic patterns conform to baseline behavior. No structural anomalies detected.",
                impact="Zero operational impact. Continuous baseline monitoring active."
            ),
            ThreatMetadata(
                threat_name="Port Scan",
                base_severity="MEDIUM",
                description="Sequential or parallel probing of communication ports to discover active services and vulnerabilities.",
                impact="Pre-attack reconnaissance. Potential disclosure of open ports, OS versions, and network topology."
            ),
            ThreatMetadata(
                threat_name="DDoS",
                base_severity="CRITICAL",
                description="Distributed Denial of Service aiming to overwhelm targeted network infrastructure or services with excessive traffic volume.",
                impact="Severe service degradation or complete system outage, rendering infrastructure unavailable to legitimate users."
            ),
            ThreatMetadata(
                threat_name="Brute Force",
                base_severity="HIGH",
                description="Systematic, automated attempts to guess cryptographic keys, passwords, or active session tokens on exposed network services.",
                impact="High risk of unauthorized credential harvesting, system compromise, and initial access vectors."
            ),
            ThreatMetadata(
                threat_name="Botnet Activity",
                base_severity="CRITICAL",
                description="Network traffic indicating active Command and Control (C2) communications or malicious distributed agent behavior.",
                impact="Compromised internal host orchestration, unauthorized data exfiltration channels, or participation in external attacks."
            ),
            ThreatMetadata(
                threat_name="Data Exfiltration",
                base_severity="HIGH",
                description="Unauthorized transmission or copying of sensitive data from internal network segments to external, untrusted zones.",
                impact="Direct loss of intellectual property, regulatory compliance violations, and data confidentiality breaches."
            )
        ]
        
        for threat in threats:
            self._db[threat.threat_name.lower().replace(" ", "_")] = threat

    def get_threat_details(self, lookup_name: str) -> Optional[ThreatMetadata]:
        """
        Queries the database for specific threat profiles using a normalized key string.
        """
        normalized_key = lookup_name.lower().strip().replace(" ", "_")
        return self._db.get(normalized_key, None)