"""
Attack Mapping Engine
Translates machine learning model outputs into standardized cybersecurity attack categories.
"""

from typing import Dict


class AttackMappingEngine:
    """Maps custom ML predictions to high-level cybersecurity threat names and taxonomy classification."""

    def __init__(self) -> None:
        # Extensible map: Keys represent potential raw ML model string outputs
        self._mapping_table: Dict[str, str] = {
            "normal": "Normal Traffic",
            "benign": "Normal Traffic",

            # Current CICIDS model output
            "attack": "Suspicious Traffic",

            "port_scan": "Port Scan",
            "satan": "Port Scan",
            "ipsweep": "Port Scan",
            "nmap": "Port Scan",

            "ddos": "DDoS",
            "dos": "DDoS",
            "neptune": "DDoS",
            "smurf": "DDoS",
            "back": "DDoS",

            "brute_force": "Brute Force",
            "ftp_patator": "Brute Force",
            "ssh_patator": "Brute Force",
            "guess_passwd": "Brute Force",

            "botnet": "Botnet Activity",
            "bot": "Botnet Activity",

            "exfiltration": "Data Exfiltration",
            "data_leak": "Data Exfiltration",
        }

    def resolve_prediction(self, raw_prediction: str) -> str:
        """
        Resolves raw text classification from an ML pipeline
        to a standard Threat DB name.

        The current CICIDS model produces BENIGN or ATTACK.
        ATTACK is therefore mapped to Suspicious Traffic rather
        than being incorrectly classified as Normal Traffic.
        """
        normalized = (
            str(raw_prediction)
            .lower()
            .strip()
            .replace("-", "_")
            .replace(" ", "_")
        )

        return self._mapping_table.get(normalized, "Normal Traffic")

    def get_tactical_category(self, standard_name: str) -> str:
        """
        Maps standard threat profiles to tactical cybersecurity
        paradigms (similar to MITRE ATT&CK Matrix).
        """
        categories = {
            "Normal Traffic": "Operations Baseline",
            "Suspicious Traffic": "Unclassified Malicious Activity",
            "Port Scan": "Reconnaissance (TA0043)",
            "DDoS": "Impact / Denial of Service (TA0040)",
            "Brute Force": "Credential Access (TA0006)",
            "Botnet Activity": "Command and Control (TA0011)",
            "Data Exfiltration": "Exfiltration (TA0010)",
        }

        return categories.get(standard_name, "Unclassified Activity")