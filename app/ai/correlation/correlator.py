"""
Correlator – Stateful Memory Layer for Correlation Engine
==========================================================

This component keeps short-term memory of recent AISignals and Events
to allow multi-step correlation rules:

Examples:
    - Multiple failed logins → brute force pattern
    - File written → process spawned → suspicious network → malware chain
    - Abnormal CPU spike + unknown binary → behavioral anomaly
    - Lateral movement detection
"""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional


class Correlator:
    """
    Maintains short-term memory for correlation rules.
    """

    MEMORY_WINDOW_SEC = 60 * 5  # 5-minute sliding window
    MAX_ITEMS_PER_DEVICE = 200  # Bound memory size for safety

    def __init__(self):
        # Structure:
        #   memory[org_id][device_id] = deque([ {signal/event dict}, ... ])
        self.memory = defaultdict(lambda: defaultdict(deque))

    # --------------------------------------------------------
    # Store new item (AISignal or synthetic event dict)
    # --------------------------------------------------------
    def push(self, org_id: int, device_id: Optional[int], item: Dict[str, Any]):
        if device_id is None:
            return

        q = self.memory[org_id][device_id]

        item["ts"] = item.get("ts") or datetime.now(timezone.utc)
        q.append(item)

        # Bound queue length
        while len(q) > self.MAX_ITEMS_PER_DEVICE:
            q.popleft()

        # Prune old timestamps
        self._prune(q)

    # --------------------------------------------------------
    # Retrieve last N items
    # --------------------------------------------------------
    def tail(self, org_id: int, device_id: Optional[int], n: int = 10) -> List[Dict]:
        if device_id is None:
            return []
        q = self.memory[org_id][device_id]
        return list(q)[-n:]

    # --------------------------------------------------------
    # Retrieve all recent signals/events within window
    # --------------------------------------------------------
    def recent(self, org_id: int, device_id: Optional[int]) -> List[Dict]:
        if device_id is None:
            return []

        q = self.memory[org_id][device_id]
        self._prune(q)
        return list(q)

    # --------------------------------------------------------
    # Pruning helper
    # --------------------------------------------------------
    def _prune(self, q: deque):
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=self.MEMORY_WINDOW_SEC)
        while q and q[0]["ts"] < cutoff:
            q.popleft()

    # --------------------------------------------------------
    # Evaluate timeline sequences
    # --------------------------------------------------------
    def evaluate_sequence(
        self,
        org_id: int,
        device_id: Optional[int],
        pattern: List[str],
        window_sec: int = 300,
    ) -> bool:
        """
        Return True if events occurred in the given sequential pattern within the time window.

        Example:
            pattern = ["auth_failed", "auth_failed", "auth_failed", "auth_success"]

        Used in:
            - Bruteforce sequences
            - Lateral movement steps
            - Malware kill-chains
        """
        if device_id is None:
            return False

        seq = []
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=window_sec)
        q = self.memory[org_id][device_id]

        for item in q:
            ts = item.get("ts") or datetime.now(timezone.utc)
            if ts < cutoff:
                continue
            seq.append(item.get("marker"))

        # If marker sequence contains ordered pattern
        pi = 0
        for m in seq:
            if m == pattern[pi]:
                pi += 1
                if pi == len(pattern):
                    return True
        return False
