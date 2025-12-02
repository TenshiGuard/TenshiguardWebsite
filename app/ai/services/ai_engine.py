# app/ai/services/ai_engine.py
"""
TenshiGuard Rule-Based AI Engine (Phase 2)

This engine analyzes normalized events from the agent and returns
AI signals (AISignal-ready). Extended to support robust malware
file detection (hash, filename, path, extensions).
"""

from __future__ import annotations

import logging
import json
from pathlib import Path
from typing import Any, Dict, Optional, List


# ===================================================================
# AI Engine
# ===================================================================
class AIEngine:
    def __init__(self, app: Any = None) -> None:
        self.app = app
        self.logger = getattr(app, "logger", None) or logging.getLogger(__name__)

        # Path: app/ai/rules/
        base = Path(__file__).resolve()
        self.rules_dir = base.parent.parent / "rules"

        # Load JSON rules (best-effort)
        self.malware_signatures = self._load_json_safe("malware_signatures.json")
        self.malware_rules = self._load_json_safe("malware_rules.json")
        self.process_rules = self._load_json_safe("process_rules.json")
        self.network_rules = self._load_json_safe("network_rules.json")

        self.logger.info(
            "[AIEngine] initialized | malware_signatures=%d malware_rules=%d",
            len(self.malware_signatures),
            len(self.malware_rules),
        )

    # ===================================================================
    # MAIN ENTRY POINT
    # ===================================================================
    def analyze(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        etype = (event.get("type") or "").lower().strip()

        if etype == "file":
            sig = self._analyze_file(event)
        elif etype == "process":
            sig = self._analyze_process(event)
        elif etype == "network":
            sig = self._analyze_network(event)
        elif etype in ("auth", "login"):
            sig = self._analyze_auth(event)
        else:
            sig = self._analyze_behavior(event)

        if not sig:
            return None

        sig["raw"] = event
        return sig

    # ===================================================================
    # FILE ANALYSIS  (updated for malware detection)
    # ===================================================================
    def _analyze_file(self, ev: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        filename = (ev.get("file_name") or "").lower()
        fhash = (ev.get("file_hash") or "").lower()
        path = (ev.get("path") or "").lower()

        # ---------------------------------------------------------
        # 1) HASH-BASED SIGNATURE MATCH
        # ---------------------------------------------------------
        for sig in self.malware_signatures:
            sig_hash = (sig.get("hash") or "").lower()
            if fhash and sig_hash and fhash == sig_hash:
                family = sig.get("family", "malware")
                return self._signal(
                    category="malware",
                    severity="critical",
                    rule_name=f"Known malware (hash match)",
                    detail=f"File {filename} matched known malware hash ({family}).",
                    risk_score=95,
                )

        # ---------------------------------------------------------
        # 2) JSON RULESET (malware_rules.json)
        # ---------------------------------------------------------
        for rule in self.malware_rules:
            # hash rule
            hashes = [h.lower() for h in rule.get("hashes", [])]
            if fhash and hashes and fhash in hashes:
                return self._format_rule(rule, filename)

            # filename rule
            for name in rule.get("file_names", []):
                if name.lower() in filename:
                    return self._format_rule(rule, filename)

            # path rule
            for p in rule.get("paths", []):
                if path.startswith(p.lower()):
                    # optional extension check
                    exts = rule.get("extensions", [])
                    if not exts or any(filename.endswith(ext) for ext in exts):
                        return self._format_rule(rule, filename)

        # ---------------------------------------------------------
        # 3) Heuristic rules (existing engine logic)
        # ---------------------------------------------------------
        if any(x in filename for x in ("mimikatz", "rclone", "cobaltstrike", "csagent")):
            return self._signal(
                category="malware",
                severity="high",
                rule_name="Suspicious tool name",
                detail=f"File appears to be a known offensive tool: {filename}",
                risk_score=85,
            )

        if filename.endswith((".exe", ".dll", ".ps1", ".sh", ".bin")) and (
            "/tmp" in path or "/var/tmp" in path or "/dev/shm" in path
        ):
            return self._signal(
                category="malware",
                severity="medium",
                rule_name="Executable in temporary directory",
                detail=f"Executable file dropped in temp directory: {path}",
                risk_score=60,
            )

        # 4) Advanced Heuristics (Double Extension, Ransomware Ext)
        heuristic_sig = self._analyze_file_heuristics(filename, path)
        if heuristic_sig:
            return heuristic_sig

        return None

    def _format_rule(self, rule: Dict[str, Any], filename: str) -> Dict[str, Any]:
        return self._signal(
            category=rule.get("category", "malware"),
            severity=rule.get("severity", "high"),
            rule_name=rule.get("name", "Unknown malware rule"),
            detail=f"{rule.get('detail', '')} File: {filename}. Mitigation: {rule.get('mitigation', '')}",
            risk_score=90 if rule.get("severity") == "critical" else 70,
        )

    # ===================================================================
    # PROCESS ANALYSIS
    # ===================================================================
    def _analyze_process(self, ev: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        pname = (ev.get("process_name") or "").lower()
        cmd = (ev.get("cmdline") or "").lower()

        if "powershell" in cmd and ("-enc" in cmd or "-encodedcommand" in cmd):
            return self._signal(
                category="process",
                severity="high",
                rule_name="Suspicious PowerShell",
                detail=f"Encoded PowerShell detected: {cmd[:200]}",
                risk_score=80,
            )

        if "mimikatz" in pname or "mimikatz" in cmd:
            return self._signal(
                category="process",
                severity="critical",
                rule_name="Mimikatz process detected",
                detail=f"Process: {pname} {cmd}",
                risk_score=95,
            )

        if len(cmd) > 200 and any(x in cmd for x in ("-enc", "frombase64string")):
            return self._signal(
                category="process",
                severity="high",
                rule_name="Obfuscated command line",
                detail=f"Suspicious long command line: {cmd[:200]}",
                risk_score=75,
            )

        return None

    # ===================================================================
    # NETWORK ANALYSIS
    # ===================================================================
    def _analyze_network(self, ev: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        dst_ip = (ev.get("dest_ip") or "").strip()
        dst_port = ev.get("dest_port") or ev.get("port")
        domain = (ev.get("domain") or "").lower()

        high_risk_ports = {4444, 3389, 5900, 8080}

        if dst_port in high_risk_ports:
            return self._signal(
                category="network",
                severity="high",
                rule_name="High-risk outbound port",
                detail=f"Outbound connection detected: {dst_ip}:{dst_port}",
                risk_score=80,
            )

        if any(x in domain for x in (".onion", "tor", "darkweb")):
            return self._signal(
                category="network",
                severity="high",
                rule_name="Suspicious domain",
                detail=f"Connection to suspicious domain: {domain}",
                risk_score=78,
            )

        return None

    # ===================================================================
    # AUTH / LOGIN ANALYSIS
    # ===================================================================
    def _analyze_auth(self, ev: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        action = (ev.get("action") or "").lower()
        if action != "failed_login":
            return None

        username = ev.get("username") or "unknown"
        src_ip = ev.get("source_ip") or "unknown"
        raw_line = ev.get("raw_line") or ""

        detail = f"Failed login for user '{username}' from {src_ip}."
        if raw_line:
            detail += f" Raw: {raw_line[:200]}"

        return self._signal(
            category="auth",
            severity="medium",
            rule_name="Failed login attempt",
            detail=detail + " Mitigation: enable Fail2Ban / lock account.",
            risk_score=55,
        )

    # ===================================================================
    # BEHAVIORAL / FALLBACK RULES
    # ===================================================================
    def _analyze_behavior(self, ev: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        btype = (ev.get("behavior_type") or "").lower()
        desc = ev.get("description") or ""

        if "privilege_escalation" in btype:
            return self._signal(
                category="behavior",
                severity="high",
                rule_name="Privilege escalation",
                detail=desc,
                risk_score=82,
            )

        if "ransomware" in btype:
            return self._signal(
                category="behavior",
                severity="critical",
                rule_name="Ransomware-like activity",
                detail=desc,
                risk_score=95,
            )
            
        # Check for rapid file modification (ransomware behavior)
        if "rapid_file_mod" in btype or "mass_delete" in btype:
             return self._signal(
                category="ransomware",
                severity="critical",
                rule_name="Potential Ransomware Behavior",
                detail=f"Detected rapid file modification/deletion: {desc}",
                risk_score=98,
            )

        return None

    # ===================================================================
    # RANSOMWARE SPECIFIC ANALYSIS
    # ===================================================================
    def _analyze_ransomware(self, ev: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        # Placeholder for specific ransomware logic if separate event type exists
        # Currently handled in behavior, but can be expanded here.
        return None

    def _analyze_file_heuristics(self, filename: str, path: str) -> Optional[Dict[str, Any]]:
        # Double extension check
        if filename.count('.') >= 2:
            if filename.endswith(".exe") or filename.endswith(".scr"):
                return self._signal(
                    category="malware",
                    severity="high",
                    rule_name="Double Extension",
                    detail=f"Suspicious double extension detected: {filename}",
                    risk_score=85
                )
        
        # Ransomware extensions
        ransom_exts = (".lock", ".enc", ".cry", ".crypto", ".wannacry")
        if filename.endswith(ransom_exts):
             return self._signal(
                category="ransomware",
                severity="critical",
                rule_name="Ransomware Extension",
                detail=f"File with known ransomware extension detected: {filename}",
                risk_score=99
            )
            
        return None

    # ===================================================================
    # HELPERS
    # ===================================================================
    def _get_learned_weight(self, rule_name: str) -> float:
        try:
            from app.models.ai_learned_rule import AILearnedRule
            # We need to be inside app context, which we usually are during request
            # But if running standalone, might need care.
            rule = AILearnedRule.query.filter_by(rule_name=rule_name).first()
            return rule.weight_modifier if rule else 0.0
        except Exception:
            return 0.0

    def _get_mitigation_advice(self, category: str, severity: str, rule_name: str) -> str:
        """
        Generates actionable mitigation advice based on the event category, severity, and specific rule.
        """
        category = (category or "").lower()
        severity = (severity or "").lower()
        rule_name = (rule_name or "").lower()
        advice = []

        # High-level severity based advice
        if severity in ["critical", "high"]:
            advice.append("IMMEDIATE ACTION REQUIRED.")
            if category == "network":
                advice.append("Block source/destination IP at firewall.")
                advice.append("Isolate the affected device from the network.")
            elif category == "process":
                advice.append("Terminate the suspicious process immediately.")
                advice.append("Scan the device for persistence mechanisms.")
            elif category == "file":
                advice.append("Quarantine or delete the malicious file.")
                advice.append("Run a full system scan.")
            elif category in ["auth", "failed_login"]:
                advice.append("Lock the compromised user account.")
                advice.append("Force a password reset and enable MFA.")

        # Specific rule-based advice
        if "bruteforce" in rule_name:
            advice.append("Check for botnet activity originating from the source IP.")
        if "ransomware" in rule_name:
            advice.append("Disconnect from backups immediately to prevent encryption spread.")
        if "privilege" in rule_name:
            advice.append("Audit recent permission changes and revert unauthorized admin promotions.")
        if "mimikatz" in rule_name:
            advice.append("Reset all admin credentials immediately. Check for Golden Ticket attacks.")
        if "powershell" in rule_name:
            advice.append("Review PowerShell logs for executed scripts.")

        # Fallback / General advice
        if not advice:
            if severity == "medium":
                advice.append("Investigate the event context. Monitor for escalation.")
            else:
                advice.append("No immediate action required. Continue monitoring.")

        return " ".join(list(set(advice)))

    def _signal(self, category, severity, rule_name, detail, risk_score):
        # Apply learned weight
        modifier = self._get_learned_weight(rule_name)
        adjusted_score = int(risk_score) + modifier
        adjusted_score = max(0, min(100, adjusted_score))

        mitigation = self._get_mitigation_advice(category, severity, rule_name)

        return {
            "category": category,
            "severity": severity,
            "rule_name": rule_name,
            "detail": detail,
            "risk_score": adjusted_score,
            "mitigation": mitigation,
            "rule_hits": [rule_name] # Added for compatibility with some consumers
        }

    def _load_json_safe(self, filename: str) -> List[Dict[str, Any]]:
        path = self.rules_dir / filename
        if not path.exists():
            return []
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, list) else []
        except Exception as e:
            self.logger.warning("[AIEngine] failed to load %s: %s", filename, e)
            return []
