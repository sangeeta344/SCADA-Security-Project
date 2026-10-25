"""Quantum Bit Error Rate (QBER) calculator and statistical verifier."""

from typing import List, Dict, Any


class QBERCalculator:
    """Calculates QBER from disclosed test bits and evaluates threshold compliance."""

    @staticmethod
    def calculate_qber(
        alice_disclosed: List[int],
        bob_disclosed: List[int],
        threshold: float = 0.11,
    ) -> Dict[str, Any]:
        """
        Calculate QBER:
            QBER = (number of mismatched bits) / (total sample bits)
        
        Args:
            alice_disclosed: Bits disclosed by Alice for verification
            bob_disclosed: Corresponding bits measured by Bob
            threshold: Maximum tolerable QBER (typically 11% for BB84)
            
        Returns:
            Dictionary with error metrics and acceptance status
        """
        sample_size = min(len(alice_disclosed), len(bob_disclosed))
        if sample_size == 0:
            return {
                "qber": 1.0,
                "qber_percentage": 100.0,
                "errors": 0,
                "sample_size": 0,
                "threshold": threshold,
                "passed": False,
                "reason": "Empty disclosed sample",
            }

        errors = sum(1 for a, b in zip(alice_disclosed[:sample_size], bob_disclosed[:sample_size]) if a != b)
        qber = errors / sample_size
        passed = qber <= threshold

        return {
            "qber": round(qber, 4),
            "qber_percentage": round(qber * 100.0, 2),
            "errors": errors,
            "sample_size": sample_size,
            "threshold": threshold,
            "passed": passed,
            "reason": "QBER within security threshold" if passed else f"QBER ({qber:.2%}) exceeds threshold ({threshold:.2%})",
        }
