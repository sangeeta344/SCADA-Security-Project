"""Key sifting and basis matching for BB84 QKD simulation."""

from typing import List, Tuple, Dict, Any
import random


class KeySifter:
    """Handles classical basis comparison and bit sifting."""

    @staticmethod
    def sift_keys(
        alice_bits: List[int],
        alice_bases: List[str],
        bob_bases: List[str],
        bob_measured_bits: List[int],
    ) -> Tuple[List[int], List[int], List[int]]:
        """
        Filter bits where Alice and Bob selected the same measurement basis.
        
        Returns:
            (alice_sifted_bits, bob_sifted_bits, matched_indices)
        """
        alice_sifted = []
        bob_sifted = []
        matched_indices = []

        min_len = min(len(alice_bits), len(alice_bases), len(bob_bases), len(bob_measured_bits))
        for i in range(min_len):
            if alice_bases[i] == bob_bases[i]:
                alice_sifted.append(alice_bits[i])
                bob_sifted.append(bob_measured_bits[i])
                matched_indices.append(i)

        return alice_sifted, bob_sifted, matched_indices

    @staticmethod
    def sample_for_error_estimation(
        alice_sifted: List[int],
        bob_sifted: List[int],
        sample_ratio: float = 0.33,
        seed: int = None,
    ) -> Tuple[List[int], List[int], List[int], List[int]]:
        """
        Disclose a pseudo-random sample of sifted bits to estimate QBER.
        
        IMPORTANT: Disclosed bits are discarded and MUST NOT be included in the final secret key.
        
        Returns:
            (alice_disclosed, bob_disclosed, alice_remaining_key, bob_remaining_key)
        """
        n = len(alice_sifted)
        if n == 0:
            return [], [], [], []

        sample_size = max(1, int(n * sample_ratio))
        rng = random.Random(seed)
        all_indices = list(range(n))
        sample_indices = set(rng.sample(all_indices, min(sample_size, n)))

        alice_disclosed = []
        bob_disclosed = []
        alice_remaining = []
        bob_remaining = []

        for i in range(n):
            if i in sample_indices:
                alice_disclosed.append(alice_sifted[i])
                bob_disclosed.append(bob_sifted[i])
            else:
                alice_remaining.append(alice_sifted[i])
                bob_remaining.append(bob_sifted[i])

        return alice_disclosed, bob_disclosed, alice_remaining, bob_remaining
