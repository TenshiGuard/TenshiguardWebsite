# app/ai/correlation/base_rule.py

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from app.extensions import db
from app.models.event import Event
from app.models.ai_signal import AISignal


class CorrelationRule:
    """
    Base class for all correlation rules.

    Subclasses override:
      - name (str)
      - window_minutes (int)
      - process(org, device, aisignal, raw) -> List[Dict]
    """

    name: str = "BaseRule"
    window_minutes: int = 15  # default correlation window

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def process(
        self,
        org,
        device,
        aisignal: AISignal,
        raw: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @property
    def _now(self) -> datetime:
        return datetime.utcnow()

    def _cutoff(self, minutes: Optional[int] = None) -> datetime:
        return self._now - timedelta(minutes=minutes or self.window_minutes)

    def _recent_signals_for_device(
        self,
        device_id: Optional[int],
        org_id: int,
        minutes: Optional[int] = None,
    ):
        if not device_id:
            return []

        cutoff = self._cutoff(minutes)
        return (
            AISignal.query.filter(
                AISignal.organization_id == org_id,
                AISignal.device_id == device_id,
                AISignal.ts >= cutoff,
            )
            .order_by(AISignal.ts.desc())
            .all()
        )

    def _recent_events_for_device(
        self,
        device_id: Optional[int],
        org_id: int,
        minutes: Optional[int] = None,
    ):
        if not device_id:
            return []

        cutoff = self._cutoff(minutes)
        return (
            Event.query.filter(
                Event.organization_id == org_id,
                Event.device_id == device_id,
                Event.ts >= cutoff,
            )
            .order_by(Event.ts.desc())
            .all()
        )

    def _dedup_correlation(
        self,
        org_id: int,
        device_id: Optional[int],
        rule_name: str,
        minutes: Optional[int] = None,
    ) -> bool:
        """
        Check if a correlation event for the same rule/device already exists
        within the given time window. Returns True if we should SKIP.
        """
        cutoff = self._cutoff(minutes)
        q = Event.query.filter(
            Event.organization_id == org_id,
            Event.ts >= cutoff,
            Event.message.like(f"[Correlation] {rule_name}%"),
        )
        if device_id:
            q = q.filter(Event.device_id == device_id)
        return q.first() is not None

    def _build_corr_event(
        self,
        category: str,
        severity: str,
        rule_name: str,
        detail: str,
        risk_score: int,
        mitigation: str = "",
    ) -> Dict[str, Any]:
        return {
            "category": category,
            "severity": severity,
            "rule_name": rule_name,
            "detail": detail,
            "risk_score": risk_score,
            "mitigation": mitigation,
        }
