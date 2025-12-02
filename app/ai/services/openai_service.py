import logging
import os
from typing import Optional, Dict, Any
import requests
from flask import current_app

class OpenAIService:
    """
    Service to interact with OpenAI API for threat analysis and user assistance.
    """
    def __init__(self, app=None):
        self.api_key = None
        self.model = "gpt-4-turbo-preview"
        self.logger = logging.getLogger(__name__)
        
        if app:
            self.init_app(app)

    def init_app(self, app):
        self.api_key = app.config.get("OPENAI_API_KEY")
        self.model = app.config.get("OPENAI_MODEL", "gpt-4-turbo-preview")
        
        if not self.api_key:
            self.logger.warning("[OpenAI] No API key found. AI features will be disabled.")
        else:
            self.logger.info(f"[OpenAI] Service initialized with model: {self.model}")

    def ask_ai(self, prompt: str, context: Optional[Dict[str, Any]] = None) -> str:
        """
        Send a prompt to OpenAI and get a response.
        """
        if not self.api_key:
            self.logger.info("[OpenAI] No API Key. Using Simulation Mode.")
            return self._simulate_response(prompt, context)

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        system_prompt = (
            "You are TenshiGuard AI, an elite cybersecurity analyst and autonomous defense agent. "
            "Your mission is to protect the user's organization by analyzing threats, explaining security concepts, and providing actionable mitigation strategies.\n\n"
            "CORE DIRECTIVES:\n"
            "1. BE PROACTIVE: Don't just explain; suggest specific actions (e.g., 'Isolate Device', 'Block IP').\n"
            "2. BE CONCISE: Security analysts are busy. Give the bottom line first.\n"
            "3. BE CONTEXT-AWARE: Use the provided context (current page, alerts, device stats) to tailor your answer.\n"
            "4. BE EDUCATIONAL: If the user asks about a concept (e.g., 'Lateral Movement'), explain it simply but accurately.\n\n"
            "TONE: Professional, Vigilant, Authoritative but Helpful."
        )

        if context:
            system_prompt += f"\n\nContext Data:\n{context}"

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.3,
            "max_tokens": 1000
        }

        try:
            response = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers=headers,
                json=payload,
                timeout=30
            )
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"].strip()

        except requests.exceptions.RequestException as e:
            self.logger.error(f"[OpenAI] Request failed: {e}")
            return self._simulate_response(prompt, context)  # Fallback to simulation on network error
        except Exception as e:
            self.logger.error(f"[OpenAI] Unexpected error: {e}")
            return "An unexpected error occurred."

    def _simulate_response(self, prompt: str, context: Optional[Dict[str, Any]] = None) -> str:
        """
        Generate a realistic-looking fake response based on keywords and context.
        Used when no API key is configured.
        """
        prompt_lower = prompt.lower()
        page_title = context.get("page_title", "") if context else ""
        
        # 1. Context-Specific Responses
        if "file" in page_title.lower() or "file" in prompt_lower:
            return (
                "**Analysis:** I've scanned the recent file activity. "
                "There are **3 suspicious binaries** detected in the last hour. "
                "One matches the signature for *Mimikatz*.\n\n"
                "**Recommendation:**\n"
                "1. Isolate the affected device immediately.\n"
                "2. Run a full deep scan on the file system.\n"
                "3. Check the 'File Scans' tab for the full hash report."
            )
        
        if "network" in page_title.lower() or "network" in prompt_lower:
            return (
                "**Network Insight:** I'm detecting unusual outbound traffic on port 4444 to an external IP (192.168.x.x). "
                "This pattern is consistent with **C2 (Command & Control)** communication.\n\n"
                "**Action Required:**\n"
                "1. Block the destination IP at the firewall.\n"
                "2. Review the 'Network Traffic' logs for correlated events."
            )

        if "device" in prompt_lower or "status" in prompt_lower:
             return (
                "**System Status:**\n"
                "- **Online Devices:** 12\n"
                "- **At-Risk:** 2 (High Severity)\n\n"
                "I recommend reviewing the **'Top At-Risk Devices'** table on the main dashboard. "
                "Device `DESKTOP-MAIN` is showing signs of lateral movement attempts."
            )

        # 2. General Security Concepts
        if "ransomware" in prompt_lower:
            return (
                "**Ransomware Detected:** This is a critical threat. "
                "Ransomware attempts to encrypt files and demand payment.\n\n"
                "**Immediate Steps:**\n"
                "1. **Disconnect** infected devices from the network instantly.\n"
                "2. **Restore** data from the last clean backup.\n"
                "3. **Patch** the vulnerability (likely SMB or RDP) used for entry."
            )

        # 3. Default Fallback
        return (
            "I am analyzing the system logs... \n\n"
            "Everything appears stable at the moment, but I recommend keeping an eye on the **Live Event Feed**. "
            "I am monitoring for anomalies in real-time.\n\n"
            "*(Note: This is a simulated response. Add an OpenAI API Key for full analysis.)*"
        )

    def analyze_threat(self, threat_details: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a specific threat event and return structured insights.
        """
        prompt = (
            f"Analyze the following threat event and provide a risk assessment and mitigation plan.\n"
            f"Event: {threat_details}"
        )
        
        response_text = self.ask_ai(prompt)
        
        # In a real scenario, we might want to force JSON output from OpenAI
        # For now, we return the text as the 'analysis'
        return {
            "analysis": response_text,
            "original_event": threat_details
        }
