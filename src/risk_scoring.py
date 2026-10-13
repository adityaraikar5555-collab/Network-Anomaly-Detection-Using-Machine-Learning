"""
Risk Scoring Engine
Calculates security and risk indices based on classified threat states and confidence intervals.
"""

from typing import Dict, Any


class RiskScoringEngine:
    """Computes security scores and determines operational risk tiers."""

    def __init__(self) -> None:
        # Base security scores:
        # 100 = perfectly safe, 0 = entirely compromised
        self._base_scores: Dict[str, int] = {
            "normal traffic": 100,
            "suspicious traffic": 45,
            "port scan": 78,
            "brute force": 55,
            "data exfiltration": 32,
            "botnet activity": 20,
            "ddos": 15,
        }

    def compute_risk(
        self,
        threat_name: str,
        model_confidence: float = 1.0
    ) -> Dict[str, Any]:
        """
        Calculates security score and assigns a severity band.

        The current CICIDS model produces BENIGN or ATTACK.
        ATTACK is mapped to Suspicious Traffic and receives
        an elevated risk score based on model confidence.
        """
        normalized_name = threat_name.lower().strip()

        base_score = self._base_scores.get(
            normalized_name,
            50
        )

        # Adjust score based on ML confidence.
        if normalized_name != "normal traffic":
            # Higher confidence in an attack lowers the
            # security score.
            adjusted_score = int(
                base_score * (1.0 - (model_confidence * 0.15))
            )
        else:
            # Normal traffic remains close to 100.
            adjusted_score = int(
                base_score * (0.9 + (model_confidence * 0.1))
            )

        # Keep score within 0–100.
        final_score = max(0, min(100, adjusted_score))

        risk_level = self._determine_tier(final_score)

        return {
            "security_score": final_score,
            "risk_level": risk_level
        }

    def _determine_tier(self, score: int) -> str:
        """Maps security score to an operational risk level."""

        if 95 <= score <= 100:
            return "LOW"
        elif 70 <= score <= 94:
            return "MEDIUM"
        elif 40 <= score <= 69:
            return "HIGH"
        else:
            return "CRITICAL"