# app/ai/services/ai_manager.py
# ============================================================
# 🧠 TenshiGuard Hybrid AI Engine
#  - Rule-based + lightweight behavioural anomaly scoring
#  - No heavy ML, safe for MVP, realistic for SOC workflows
# ============================================================

import json
import os
from datetime import datetime, timedelta

from app.extensions import db
from app.models.device import Device
from app.models.telemetry import DeviceTelemetry
from app.models.ai_event import AIEvent
from app.models.ai_process import AIProcessEvent
from app.models.ai_file import AIFileEvent
from app.models.ai_network import AINetworkEvent
from app.models.ai_anomaly import AIAnomaly


class AIEngine:
    """
    Hybrid AI engine:
      - Signature / rule-based checks for file, process, network, events
      - Behavioural anomaly scoring using recent telemetry (CPU/MEM trends)
      - Produces a normalized risk score and severity band
    """

    def __init__(self):
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        # e.g. /mnt/f/tenshiguard_ai/app

        self.signatures_path = os.path.join(base_dir, "ai", "signatures")

        self.malware_signatures = self._load_json("malware_signatures.json")
        self.process_rules = self._load_json("process_rules.json")
        self.network_rules = self._load_json("network_rules.json")

        # Fallback if signatures are empty
        if not isinstance(self.malware_signatures, list):
            self.malware_signatures = []
        if not isinstance(self.process_rules, list):
            self.process_rules = []
        if not isinstance(self.network_rules, list):
            self.network_rules = []

        print(
            f"[AIEngine] initialized. "
            f"{len(self.malware_signatures)} malware sigs, "
            f"{len(self.process_rules)} process rules, "
            f"{len(self.network_rules)} network rules."
        )

    # --------------------------------------------------------
    # Internal helpers – load JSON and safe defaults
    # --------------------------------------------------------
    def _load_json(self, filename):
        try:
            full_path = os.path.join(self.signatures_path, filename)
            if not os.path.exists(full_path):
                print(f"[AIEngine] signature file missing: {full_path}")
                return []
            with open(full_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"[AIEngine] failed to load {filename}: {e}")
            return []

    # --------------------------------------------------------
    # Public API – used by /api/ai endpoints
    # --------------------------------------------------------

    def analyze_event(self, payload: dict) -> dict:
        """
        Generic event analysis (e.g. auth failures, privilege changes, etc.).
        Uses:
          - simple rule heuristics
          - behavioural anomaly from telemetry if device known
        """
        org_id = payload.get("org_id")
        device_id = payload.get("device_id")
        event_type = payload.get("event_type", "generic")
        meta = payload.get("metadata", {})

        rule_score, rule_hits = self._score_event_rules(event_type, meta)
        beh_score, beh_details = self._compute_behavior_anomaly(device_id)

        total_score = min(rule_score + beh_score, 100)
        severity = self._score_to_severity(total_score)

        # Persist as AIEvent for history
        ai_event = AIEvent(
            org_id=org_id,
            device_id=device_id,
            source="event",
            category=event_type,
            severity=severity,
            title=f"AI Analysis: {event_type}",
            description="Hybrid AI engine evaluation of event.",
            score=total_score,
            rule_hits=",".join(rule_hits) if rule_hits else "",
            metadata=json.dumps({"meta": meta, "behaviour": beh_details}),
        )
        db.session.add(ai_event)
        db.session.commit()

        return {
            "status": "ok",
            "kind": "event",
            "risk_score": total_score,
            "severity": severity,
            "rule_hits": rule_hits,
            "behaviour": beh_details,
        }

    def analyze_process(self, payload: dict) -> dict:
        """
        Process-level analysis.
        Expected keys:
          - org_id, device_id
          - process_name, path, pid, ppid, user, cpu_percent, mem_percent
        """
        org_id = payload.get("org_id")
        device_id = payload.get("device_id")
        process_name = (payload.get("process_name") or "").lower()
        path = (payload.get("path") or "").lower()

        rule_score, rule_hits = self._score_process_rules(process_name, path)
        beh_score, beh_details = self._compute_behavior_anomaly(device_id, payload)

        total_score = min(rule_score + beh_score, 100)
        severity = self._score_to_severity(total_score)

        ai_proc = AIProcessEvent(
            org_id=org_id,
            device_id=device_id,
            process_name=process_name,
            path=path,
            user=payload.get("user"),
            pid=payload.get("pid"),
            ppid=payload.get("ppid"),
            severity=severity,
            score=total_score,
            rule_hits=",".join(rule_hits) if rule_hits else "",
            metadata=json.dumps({"raw": payload, "behaviour": beh_details}),
        )
        db.session.add(ai_proc)
        db.session.commit()

        # Also store anomaly row if high
        self._maybe_store_anomaly(
            org_id,
            device_id,
            "process",
            total_score,
            {"process_name": process_name, "path": path},
        )

        return {
            "status": "ok",
            "kind": "process",
            "risk_score": total_score,
            "severity": severity,
            "rule_hits": rule_hits,
            "behaviour": beh_details,
        }

    def analyze_file(self, payload: dict) -> dict:
        """
        File-level analysis.
        Expected keys:
          - org_id, device_id
          - file_path, sha256, size, signer, extension
        """
        org_id = payload.get("org_id")
        device_id = payload.get("device_id")
        file_path = (payload.get("file_path") or "").lower()
        sha256 = (payload.get("sha256") or "").lower()

        rule_score, rule_hits = self._score_file_signatures(file_path, sha256)
        beh_score, beh_details = self._compute_behavior_anomaly(device_id)

        total_score = min(rule_score + beh_score, 100)
        severity = self._score_to_severity(total_score)

        ai_file = AIFileEvent(
            org_id=org_id,
            device_id=device_id,
            file_path=file_path,
            sha256=sha256,
            size_bytes=payload.get("size_bytes"),
            signer=payload.get("signer"),
            severity=severity,
            score=total_score,
            rule_hits=",".join(rule_hits) if rule_hits else "",
            metadata=json.dumps({"raw": payload, "behaviour": beh_details}),
        )
        db.session.add(ai_file)
        db.session.commit()

        self._maybe_store_anomaly(
            org_id,
            device_id,
            "file",
            total_score,
            {"file_path": file_path, "sha256": sha256},
        )

        return {
            "status": "ok",
            "kind": "file",
            "risk_score": total_score,
            "severity": severity,
            "rule_hits": rule_hits,
            "behaviour": beh_details,
        }

    def analyze_network(self, payload: dict) -> dict:
        """
        Network-level analysis.
        Expected keys:
          - org_id, device_id
          - src_ip, dst_ip, dst_port, protocol, bytes_sent, bytes_recv, domain
        """
        org_id = payload.get("org_id")
        device_id = payload.get("device_id")
        dst_ip = (payload.get("dst_ip") or "").lower()
        domain = (payload.get("domain") or "").lower()

        rule_score, rule_hits = self._score_network_rules(dst_ip, domain)
        beh_score, beh_details = self._compute_behavior_anomaly(device_id)

        total_score = min(rule_score + beh_score, 100)
        severity = self._score_to_severity(total_score)

        ai_net = AINetworkEvent(
            org_id=org_id,
            device_id=device_id,
            src_ip=payload.get("src_ip"),
            dst_ip=dst_ip,
            dst_port=payload.get("dst_port"),
            protocol=payload.get("protocol"),
            domain=domain,
            severity=severity,
            score=total_score,
            rule_hits=",".join(rule_hits) if rule_hits else "",
            metadata=json.dumps({"raw": payload, "behaviour": beh_details}),
        )
        db.session.add(ai_net)
        db.session.commit()

        self._maybe_store_anomaly(
            org_id,
            device_id,
            "network",
            total_score,
            {"dst_ip": dst_ip, "domain": domain},
        )

        return {
            "status": "ok",
            "kind": "network",
            "risk_score": total_score,
            "severity": severity,
            "rule_hits": rule_hits,
            "behaviour": beh_details,
        }

    # --------------------------------------------------------
    # Rule engines (signatures + heuristics)
    # --------------------------------------------------------

    def _get_learned_weight(self, rule_identifier: str) -> float:
        """
        Fetch the learned weight modifier for a specific rule.
        """
        try:
            from app.models.ai_learned_rule import AILearnedRule
            rule = AILearnedRule.query.filter_by(rule_name=rule_identifier).first()
            return rule.weight_modifier if rule else 0.0
        except Exception:
            return 0.0

    def _score_file_signatures(self, file_path: str, sha256: str):
        score = 0
        hits = []

        for sig in self.malware_signatures:
            try:
                match_hash = sig.get("sha256")
                pattern = (sig.get("path_pattern") or "").lower()
                sig_id = sig.get("id") or "sig"

                hit_name = None
                base_score = 0

                if match_hash and sha256 and match_hash.lower() == sha256:
                    base_score = sig.get("score", 40)
                    hit_name = f"{sig_id}:hash"
                elif pattern and pattern in file_path:
                    base_score = sig.get("score", 25)
                    hit_name = f"{sig_id}:path"
                
                if hit_name:
                    # Apply learned weight
                    modifier = self._get_learned_weight(hit_name)
                    score += (base_score + modifier)
                    hits.append(hit_name)

            except Exception:
                continue

        # Simple heuristic: executables in temp/ or downloads
        if file_path.endswith((".exe", ".dll", ".bat", ".ps1", ".sh")):
            if any(x in file_path for x in ["/tmp", "\\temp", "downloads"]):
                hit_name = "heuristic:suspicious_location"
                modifier = self._get_learned_weight(hit_name)
                score += (15 + modifier)
                hits.append(hit_name)

        return min(max(score, 0), 100), hits

    def _score_process_rules(self, process_name: str, path: str):
        score = 0
        hits = []

        for rule in self.process_rules:
            try:
                name = (rule.get("name") or "").lower()
                pattern = (rule.get("path_pattern") or "").lower()
                sig_id = rule.get("id") or "proc_rule"

                hit_name = None
                base_score = 0

                if name and name in process_name:
                    base_score = rule.get("score", 20)
                    hit_name = f"{sig_id}:name"
                elif pattern and pattern in path:
                    base_score = rule.get("score", 15)
                    hit_name = f"{sig_id}:path"
                
                if hit_name:
                    modifier = self._get_learned_weight(hit_name)
                    score += (base_score + modifier)
                    hits.append(hit_name)

            except Exception:
                continue

        # Heuristic: random-looking names in AppData/tmp, etc.
        if any(x in path for x in ["appdata", "temp", "/tmp"]):
            if len(process_name) > 10 and any(ch.isdigit() for ch in process_name):
                hit_name = "heuristic:suspicious_proc_name"
                modifier = self._get_learned_weight(hit_name)
                score += (10 + modifier)
                hits.append(hit_name)

        return min(max(score, 0), 100), hits

    def _score_network_rules(self, dst_ip: str, domain: str):
        score = 0
        hits = []

        for rule in self.network_rules:
            try:
                ip_pattern = (rule.get("ip_pattern") or "").lower()
                domain_pattern = (rule.get("domain_pattern") or "").lower()
                sig_id = rule.get("id") or "net_rule"

                hit_name = None
                base_score = 0

                if ip_pattern and ip_pattern in dst_ip:
                    base_score = rule.get("score", 30)
                    hit_name = f"{sig_id}:ip"
                elif domain_pattern and domain_pattern in domain:
                    base_score = rule.get("score", 25)
                    hit_name = f"{sig_id}:domain"
                
                if hit_name:
                    modifier = self._get_learned_weight(hit_name)
                    score += (base_score + modifier)
                    hits.append(hit_name)

            except Exception:
                continue

        # Heuristic: high-risk ports (not full list, just basic)
        risky_ports = {22, 23, 445, 3389}
        if dst_ip and "dst_port" in domain:
            # ignore malformed
            pass

        return min(max(score, 0), 100), hits

    def _score_event_rules(self, event_type: str, meta: dict):
        score = 0
        hits = []

        event_type = (event_type or "").lower()
        if event_type in {"auth_failure", "failed_login"}:
            hit_name = "event:failed_login"
            modifier = self._get_learned_weight(hit_name)
            score += (15 + modifier)
            hits.append(hit_name)

            # Bruteforce heuristic: many failures
            failures = meta.get("failure_count")
            if isinstance(failures, int) and failures >= 5:
                hit_name = "event:bruteforce_suspected"
                modifier = self._get_learned_weight(hit_name)
                score += (25 + modifier)
                hits.append(hit_name)

        if event_type in {"privilege_change", "sudo_escalation", "admin_added"}:
            hit_name = "event:privilege_escalation"
            modifier = self._get_learned_weight(hit_name)
            score += (30 + modifier)
            hits.append(hit_name)

        return min(max(score, 0), 100), hits

    # --------------------------------------------------------
    # Behavioural anomaly – lightweight, telemetry-based
    # --------------------------------------------------------

    def _compute_behavior_anomaly(self, device_id, context: dict | None = None):
        """
        Looks at recent telemetry for the device and compares last reading
        vs historical mean to imitate anomaly detection.
        Returns:
            (score, details_dict)
        """
        if not device_id:
            return 0, {"reason": "no_device"}

        try:
            now = datetime.utcnow()
            window_start = now - timedelta(minutes=60)

            telemetry_q = (
                DeviceTelemetry.query
                .filter(DeviceTelemetry.device_id == device_id)
                .filter(DeviceTelemetry.created_at >= window_start)
                .order_by(DeviceTelemetry.created_at.asc())
            )
            rows = telemetry_q.all()

            if len(rows) < 5:
                # not enough history for real behaviour
                return 0, {"reason": "insufficient_history", "samples": len(rows)}

            cpu_values = [r.cpu_percent or 0 for r in rows]
            mem_values = [r.mem_percent or 0 for r in rows]

            last = rows[-1]
            last_cpu = last.cpu_percent or 0
            last_mem = last.mem_percent or 0

            mean_cpu = sum(cpu_values) / len(cpu_values)
            mean_mem = sum(mem_values) / len(mem_values)

            # crude std dev (safe, no numpy)
            cpu_var = sum((c - mean_cpu) ** 2 for c in cpu_values) / len(cpu_values)
            mem_var = sum((m - mean_mem) ** 2 for m in mem_values) / len(mem_values)
            cpu_std = cpu_var ** 0.5
            mem_std = mem_var ** 0.5

            # z-score style anomaly factor
            cpu_z = (last_cpu - mean_cpu) / cpu_std if cpu_std > 1 else 0
            mem_z = (last_mem - mean_mem) / mem_std if mem_std > 1 else 0

            anomaly_factor = max(abs(cpu_z), abs(mem_z))

            # scale anomaly_factor into 0–30 range
            beh_score = max(0, min(int(anomaly_factor * 6), 30))

            details = {
                "reason": "behavioural_anomaly",
                "last_cpu": last_cpu,
                "last_mem": last_mem,
                "mean_cpu": round(mean_cpu, 1),
                "mean_mem": round(mean_mem, 1),
                "cpu_z": round(cpu_z, 2),
                "mem_z": round(mem_z, 2),
                "beh_score": beh_score,
            }

            # If context gives current cpu/mem, merge
            if context:
                details["context_cpu"] = context.get("cpu_percent")
                details["context_mem"] = context.get("mem_percent")

            return beh_score, details

        except Exception as e:
            return 0, {"reason": "behaviour_error", "error": str(e)}

    # --------------------------------------------------------
    # Common scoring helpers
    # --------------------------------------------------------

    @staticmethod
    def _score_to_severity(score: int) -> str:
        if score >= 80:
            return "critical"
        if score >= 60:
            return "high"
        if score >= 40:
            return "medium"
        if score >= 20:
            return "low"
        return "info"

    def _maybe_store_anomaly(self, org_id, device_id, category, score, context: dict):
        """Persist into AIAnomaly if score is high enough."""
        if score < 60:
            return

        anomaly = AIAnomaly(
            org_id=org_id,
            device_id=device_id,
            category=category,
            severity=self._score_to_severity(score),
            score=score,
            metadata=json.dumps(context or {}),
        )
        db.session.add(anomaly)
        db.session.commit()

    # --------------------------------------------------------
    # Mitigation Advice Generator
    # --------------------------------------------------------
    def _get_mitigation_advice(self, category: str, severity: str, rule_hits: list) -> str:
        """
        Generates actionable mitigation advice based on the event category, severity, and specific rules hit.
        """
        category = (category or "").lower()
        severity = (severity or "").lower()
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
        for hit in rule_hits:
            if "bruteforce" in hit:
                advice.append("Check for botnet activity originating from the source IP.")
            if "ransomware" in hit:
                advice.append("Disconnect from backups immediately to prevent encryption spread.")
            if "privilege_escalation" in hit:
                advice.append("Audit recent permission changes and revert unauthorized admin promotions.")
            if "suspicious_location" in hit:
                advice.append("Investigate the directory for other hidden artifacts.")
            if "domain" in hit:
                advice.append("Blacklist the malicious domain in the DNS filter.")

        # Fallback / General advice
        if not advice:
            if severity == "medium":
                advice.append("Investigate the event context. Monitor for escalation.")
            else:
                advice.append("No immediate action required. Continue monitoring.")

        return " ".join(list(set(advice)))  # Deduplicate and join

    def analyze_event(self, payload: dict) -> dict:
        """
        Generic event analysis (e.g. auth failures, privilege changes, etc.).
        Uses:
          - simple rule heuristics
          - behavioural anomaly from telemetry if device known
        """
        org_id = payload.get("org_id")
        device_id = payload.get("device_id")
        event_type = payload.get("event_type", "generic")
        meta = payload.get("metadata", {})

        rule_score, rule_hits = self._score_event_rules(event_type, meta)
        beh_score, beh_details = self._compute_behavior_anomaly(device_id)

        total_score = min(rule_score + beh_score, 100)
        severity = self._score_to_severity(total_score)
        mitigation = self._get_mitigation_advice(event_type, severity, rule_hits)

        # Persist as AIEvent for history
        ai_event = AIEvent(
            org_id=org_id,
            device_id=device_id,
            source="event",
            category=event_type,
            severity=severity,
            title=f"AI Analysis: {event_type}",
            description="Hybrid AI engine evaluation of event.",
            score=total_score,
            rule_hits=",".join(rule_hits) if rule_hits else "",
            metadata=json.dumps({"meta": meta, "behaviour": beh_details}),
        )
        db.session.add(ai_event)
        db.session.commit()

        return {
            "status": "ok",
            "kind": "event",
            "risk_score": total_score,
            "severity": severity,
            "rule_hits": rule_hits,
            "behaviour": beh_details,
            "mitigation": mitigation,
        }

    def analyze_process(self, payload: dict) -> dict:
        """
        Process-level analysis.
        Expected keys:
          - org_id, device_id
          - process_name, path, pid, ppid, user, cpu_percent, mem_percent
        """
        org_id = payload.get("org_id")
        device_id = payload.get("device_id")
        process_name = (payload.get("process_name") or "").lower()
        path = (payload.get("path") or "").lower()

        rule_score, rule_hits = self._score_process_rules(process_name, path)
        beh_score, beh_details = self._compute_behavior_anomaly(device_id, payload)

        total_score = min(rule_score + beh_score, 100)
        severity = self._score_to_severity(total_score)
        mitigation = self._get_mitigation_advice("process", severity, rule_hits)

        ai_proc = AIProcessEvent(
            org_id=org_id,
            device_id=device_id,
            process_name=process_name,
            path=path,
            user=payload.get("user"),
            pid=payload.get("pid"),
            ppid=payload.get("ppid"),
            severity=severity,
            score=total_score,
            rule_hits=",".join(rule_hits) if rule_hits else "",
            metadata=json.dumps({"raw": payload, "behaviour": beh_details}),
        )
        db.session.add(ai_proc)
        db.session.commit()

        # Also store anomaly row if high
        self._maybe_store_anomaly(
            org_id,
            device_id,
            "process",
            total_score,
            {"process_name": process_name, "path": path},
        )

        return {
            "status": "ok",
            "kind": "process",
            "risk_score": total_score,
            "severity": severity,
            "rule_hits": rule_hits,
            "behaviour": beh_details,
            "mitigation": mitigation,
        }

    def analyze_file(self, payload: dict) -> dict:
        """
        File-level analysis.
        Expected keys:
          - org_id, device_id
          - file_path, sha256, size, signer, extension
        """
        org_id = payload.get("org_id")
        device_id = payload.get("device_id")
        file_path = (payload.get("file_path") or "").lower()
        sha256 = (payload.get("sha256") or "").lower()

        rule_score, rule_hits = self._score_file_signatures(file_path, sha256)
        beh_score, beh_details = self._compute_behavior_anomaly(device_id)

        total_score = min(rule_score + beh_score, 100)
        severity = self._score_to_severity(total_score)
        mitigation = self._get_mitigation_advice("file", severity, rule_hits)

        ai_file = AIFileEvent(
            org_id=org_id,
            device_id=device_id,
            file_path=file_path,
            sha256=sha256,
            size_bytes=payload.get("size_bytes"),
            signer=payload.get("signer"),
            severity=severity,
            score=total_score,
            rule_hits=",".join(rule_hits) if rule_hits else "",
            metadata=json.dumps({"raw": payload, "behaviour": beh_details}),
        )
        db.session.add(ai_file)
        db.session.commit()

        self._maybe_store_anomaly(
            org_id,
            device_id,
            "file",
            total_score,
            {"file_path": file_path, "sha256": sha256},
        )

        return {
            "status": "ok",
            "kind": "file",
            "risk_score": total_score,
            "severity": severity,
            "rule_hits": rule_hits,
            "behaviour": beh_details,
            "mitigation": mitigation,
        }

    def analyze_network(self, payload: dict) -> dict:
        """
        Network-level analysis.
        Expected keys:
          - org_id, device_id
          - src_ip, dst_ip, dst_port, protocol, bytes_sent, bytes_recv, domain
        """
        org_id = payload.get("org_id")
        device_id = payload.get("device_id")
        dst_ip = (payload.get("dst_ip") or "").lower()
        domain = (payload.get("domain") or "").lower()

        rule_score, rule_hits = self._score_network_rules(dst_ip, domain)
        beh_score, beh_details = self._compute_behavior_anomaly(device_id)

        total_score = min(rule_score + beh_score, 100)
        severity = self._score_to_severity(total_score)
        mitigation = self._get_mitigation_advice("network", severity, rule_hits)

        ai_net = AINetworkEvent(
            org_id=org_id,
            device_id=device_id,
            src_ip=payload.get("src_ip"),
            dst_ip=dst_ip,
            dst_port=payload.get("dst_port"),
            protocol=payload.get("protocol"),
            domain=domain,
            severity=severity,
            score=total_score,
            rule_hits=",".join(rule_hits) if rule_hits else "",
            metadata=json.dumps({"raw": payload, "behaviour": beh_details}),
        )
        db.session.add(ai_net)
        db.session.commit()

        self._maybe_store_anomaly(
            org_id,
            device_id,
            "network",
            total_score,
            {"dst_ip": dst_ip, "domain": domain},
        )

        return {
            "status": "ok",
            "kind": "network",
            "risk_score": total_score,
            "severity": severity,
            "rule_hits": rule_hits,
            "behaviour": beh_details,
            "mitigation": mitigation,
        }
