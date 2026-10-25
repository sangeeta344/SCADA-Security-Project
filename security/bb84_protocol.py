"""Educational simulation of the BB84 Quantum Key Distribution protocol.

DISCLAIMER & LIMITATION OF SIMULATION:
This module provides a classical, mathematical simulation of the BB84 QKD protocol
for educational and demonstration purposes. It does NOT implement physical quantum
hardware, single-photon sources, quantum channels, or physical detectors.
In a real-world quantum network, BB84 also requires an authenticated classical channel,
error correction (e.g., Cascade protocol), and privacy amplification (universal hashing).
Simulated QKD does NOT provide real-world quantum physical protection on standard networks.
"""

import random
import uuid
from typing import List, Tuple, Dict, Any, Optional
from datetime import datetime

from config.settings import settings
from security.key_sifting import KeySifter
from security.qber_calculator import QBERCalculator
from config.logging_config import logger


class BB84Simulation:
    """Simulates the BB84 Quantum Key Distribution protocol between Alice (MTU) and Bob (RTU)."""

    BASIS_RECTILINEAR = "+"  # Horizontal / Vertical (0° / 90°)
    BASIS_DIAGONAL = "x"     # 45° / 135°

    def __init__(
        self,
        raw_bits_count: int = 256,
        qber_threshold: float = 0.11,
        sample_ratio: float = 0.33,
        seed: Optional[int] = None,
    ):
        self.raw_bits_count = raw_bits_count
        self.qber_threshold = qber_threshold
        self.sample_ratio = sample_ratio
        self.seed = seed

    def generate_random_bits(self, count: int, rng: random.Random) -> List[int]:
        """Generate random binary bits (0 or 1)."""
        return [rng.randint(0, 1) for _ in range(count)]

    def generate_random_bases(self, count: int, rng: random.Random) -> List[str]:
        """Generate random polarization bases: '+' (Rectilinear) or 'x' (Diagonal)."""
        return [rng.choice([self.BASIS_RECTILINEAR, self.BASIS_DIAGONAL]) for _ in range(count)]

    def simulate_quantum_transmission(
        self,
        alice_bits: List[int],
        alice_bases: List[str],
        noise_level: float = 0.0,
        eavesdropper_present: bool = False,
        rng: Optional[random.Random] = None,
    ) -> List[Dict[str, Any]]:
        """
        Simulate transmission of quantum states from Alice through a quantum channel.
        
        If an eavesdropper (Eve) intercepts:
            Eve measures in a random basis ('+' or 'x'). If Eve's basis matches Alice's,
            Eve receives the correct bit. If Eve's basis differs, Eve measures a random bit (50/50).
            Eve then re-prepares and forwards this state to Bob, introducing error into ~25% of sifted bits.
        
        If channel noise is present:
            Photons experience polarization drift / bit flip with probability `noise_level`.
        """
        rng = rng or random.Random(self.seed)
        transmitted_states = []

        for i in range(len(alice_bits)):
            bit = alice_bits[i]
            basis = alice_bases[i]

            # Intercept-resend attack by Eve
            if eavesdropper_present:
                eve_basis = rng.choice([self.BASIS_RECTILINEAR, self.BASIS_DIAGONAL])
                if eve_basis == basis:
                    eve_measured_bit = bit
                else:
                    eve_measured_bit = rng.randint(0, 1)
                # Eve forwards state prepared in her measurement basis
                bit = eve_measured_bit
                basis = eve_basis

            # Channel noise / environmental interference
            if noise_level > 0.0 and rng.random() < noise_level:
                bit = 1 - bit  # Bit flip caused by noise

            transmitted_states.append({"bit": bit, "basis": basis})

        return transmitted_states

    def measure_quantum_states(
        self,
        transmitted_states: List[Dict[str, Any]],
        bob_bases: List[str],
        rng: Optional[random.Random] = None,
    ) -> List[int]:
        """
        Bob measures incoming quantum states using his chosen measurement bases.
        
        If Bob's basis matches the state basis:
            Bob measures the state bit deterministically.
        If Bob's basis does not match:
            Quantum collapse yields a random bit (0 or 1 with 50% probability).
        """
        rng = rng or random.Random(self.seed)
        bob_bits = []

        for i, state in enumerate(transmitted_states):
            bob_basis = bob_bases[i]
            state_basis = state["basis"]
            state_bit = state["bit"]

            if bob_basis == state_basis:
                bob_bits.append(state_bit)
            else:
                bob_bits.append(rng.randint(0, 1))

        return bob_bits

    def run_key_exchange(
        self,
        noise_level: float = 0.0,
        eavesdropper_present: bool = False,
        seed: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Execute full educational BB84 quantum key exchange sequence.
        
        Returns:
            Dictionary containing public metadata, transmission stats, QBER,
            acceptance status, and the candidate key material (if accepted).
        """
        session_id = f"bb84_{uuid.uuid4().hex[:12]}"
        run_seed = seed if seed is not None else self.seed
        alice_rng = random.Random(run_seed if run_seed is not None else random.randint(0, 100000))
        bob_rng = random.Random((run_seed + 101) if run_seed is not None else random.randint(0, 100000))

        # 1. Alice generates random bits and basis choices
        alice_bits = self.generate_random_bits(self.raw_bits_count, alice_rng)
        alice_bases = self.generate_random_bases(self.raw_bits_count, alice_rng)

        # 2. Transmission through quantum channel (with optional Eve or noise)
        transmitted = self.simulate_quantum_transmission(
            alice_bits,
            alice_bases,
            noise_level=noise_level,
            eavesdropper_present=eavesdropper_present,
            rng=alice_rng,
        )

        # 3. Bob chooses random measurement bases and measures states
        bob_bases = self.generate_random_bases(self.raw_bits_count, bob_rng)
        bob_bits = self.measure_quantum_states(transmitted, bob_bases, rng=bob_rng)

        # 4. Sifting: Alice and Bob compare bases over classical public channel
        alice_sifted, bob_sifted, matched_idx = KeySifter.sift_keys(
            alice_bits, alice_bases, bob_bases, bob_bits
        )

        # 5. Parameter Estimation: Disclose sample to calculate QBER
        alice_disclosed, bob_disclosed, alice_key_bits, bob_key_bits = (
            KeySifter.sample_for_error_estimation(
                alice_sifted, bob_sifted, sample_ratio=self.sample_ratio, seed=run_seed
            )
        )

        # 6. QBER Calculation on disclosed sample
        qber_result = QBERCalculator.calculate_qber(
            alice_disclosed, bob_disclosed, threshold=self.qber_threshold
        )

        # 7. Key Acceptance Decision
        # Key is accepted only if QBER <= threshold AND sufficient remaining key bits exist
        is_accepted = qber_result["passed"] and len(alice_key_bits) >= 32
        rejection_reason = None

        if not qber_result["passed"]:
            rejection_reason = qber_result["reason"]
        elif len(alice_key_bits) < 32:
            is_accepted = False
            rejection_reason = f"Insufficient remaining key material ({len(alice_key_bits)} bits < 32 minimum)"

        status_str = "ACCEPTED" if is_accepted else "REJECTED"

        # Safe key representation (never expose raw key bits in full logs)
        key_material = alice_key_bits if is_accepted else None

        logger.info(
            "BB84 Session %s: %s | QBER=%.2f%% (threshold=%.2f%%) | Sifted=%d | Final Key Bits=%d | Eve=%s | Noise=%.2f",
            session_id,
            status_str,
            qber_result["qber_percentage"],
            self.qber_threshold * 100.0,
            len(alice_sifted),
            len(alice_key_bits) if is_accepted else 0,
            eavesdropper_present,
            noise_level,
        )

        return {
            "session_id": session_id,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "alice_id": "MTU_01",
            "bob_id": "RTU_01",
            "raw_bits_count": self.raw_bits_count,
            "sifted_bits_count": len(alice_sifted),
            "basis_match_percentage": round((len(alice_sifted) / self.raw_bits_count) * 100.0, 1),
            "disclosed_sample_count": len(alice_disclosed),
            "final_key_bits_count": len(alice_key_bits) if is_accepted else 0,
            "qber": qber_result["qber"],
            "qber_percentage": qber_result["qber_percentage"],
            "qber_threshold": self.qber_threshold,
            "errors_detected": qber_result["errors"],
            "status": status_str,
            "passed": is_accepted,
            "eavesdropper_present": eavesdropper_present,
            "noise_level": noise_level,
            "rejection_reason": rejection_reason,
            "key_material_bits": key_material,  # Internal only; not logged or shown directly in UI
            "simulation_notice": "Simulated BB84 protocol for demonstration. Not physical quantum communication.",
        }
