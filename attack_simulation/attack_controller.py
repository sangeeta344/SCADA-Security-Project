"""Attack simulation controller managing execution, safety bounds, and event logging."""

import threading
import time
from typing import Dict, Any, Optional, List
from datetime import datetime

from attack_simulation.normal_traffic import NormalTrafficGenerator
from attack_simulation.replay_attack import ReplayAttackSimulator
from attack_simulation.data_injection import DataInjectionSimulator
from attack_simulation.mitm_simulation import MITMSimulator
from attack_simulation.dos_simulation import DoSSimulator
from database.repository import Repository, repo as default_repo
from database.models import NetworkTrafficEvent, AttackAlert
from config.logging_config import logger


class AttackController:
    """Manages harmless, local attack simulations and produces labeled traffic events."""

    ALLOWED_ATTACKS = ["replay", "injection", "mitm", "dos"]

    def __init__(self, repository: Optional[Repository] = None, seed: Optional[int] = None):
        self.repo = repository or default_repo
        self.normal_gen = NormalTrafficGenerator(seed=seed)
        self.replay_sim = ReplayAttackSimulator(seed=seed)
        self.injection_sim = DataInjectionSimulator(seed=seed)
        self.mitm_sim = MITMSimulator(seed=seed)
        self.dos_sim = DoSSimulator(seed=seed)

        self.active_attacks: Dict[str, bool] = {
            "replay": False,
            "injection": False,
            "mitm": False,
            "dos": False,
        }
        self.lock = threading.Lock()

    def start_attack(self, attack_name: str) -> Dict[str, Any]:
        """Activate a safe local attack scenario."""
        attack_clean = attack_name.lower().strip()
        if attack_clean not in self.ALLOWED_ATTACKS:
            return {
                "success": False,
                "error": f"Unknown attack '{attack_name}'. Allowed: {self.ALLOWED_ATTACKS}",
            }

        with self.lock:
            self.active_attacks[attack_clean] = True

        logger.info("Attack simulation activated: %s", attack_clean.upper())
        return {
            "success": True,
            "attack": attack_clean,
            "active_attacks": self.get_active_attacks(),
            "message": f"Simulation of {attack_clean.upper()} started safely.",
        }

    def stop_attack(self, attack_name: str) -> Dict[str, Any]:
        """Deactivate a running attack scenario."""
        attack_clean = attack_name.lower().strip()
        if attack_clean not in self.ALLOWED_ATTACKS:
            return {
                "success": False,
                "error": f"Unknown attack '{attack_name}'. Allowed: {self.ALLOWED_ATTACKS}",
            }

        with self.lock:
            self.active_attacks[attack_clean] = False

        logger.info("Attack simulation stopped: %s", attack_clean.upper())
        return {
            "success": True,
            "attack": attack_clean,
            "active_attacks": self.get_active_attacks(),
            "message": f"Simulation of {attack_clean.upper()} stopped.",
        }

    def stop_all(self) -> None:
        """Stop all active attacks immediately."""
        with self.lock:
            for k in self.active_attacks:
                self.active_attacks[k] = False

    def get_active_attacks(self) -> List[str]:
        """Return list of currently active attack types."""
        with self.lock:
            return [k for k, v in self.active_attacks.items() if v]

    def produce_next_event(self) -> Dict[str, Any]:
        """Produce the next network event according to active attack states or baseline normal."""
        active = self.get_active_attacks()

        if "dos" in active:
            event = self.dos_sim.generate_dos_event()
        elif "injection" in active:
            event = self.injection_sim.generate_injection_event()
        elif "replay" in active:
            event = self.replay_sim.generate_replay_event()
        elif "mitm" in active:
            event = self.mitm_sim.generate_mitm_event()
        else:
            event = self.normal_gen.generate_event()
            # Buffer normal events for replay simulator
            self.replay_sim.record_normal_event(event)

        return event


attack_controller = AttackController()
