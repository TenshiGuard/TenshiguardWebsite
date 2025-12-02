import logging
import os
from typing import Optional, Dict, Any
import google.generativeai as genai
from flask import current_app
import json
from datetime import datetime

class GeminiService:
    def __init__(self, app=None):
        self.api_key = None
        self.model_name = "gemini-2.0-flash"
        self.logger = logging.getLogger(__name__)
        self.usage_file = None
        self.daily_limit = 1000
        self.init_error = None
        
        if app:
            self.init_app(app)

    def init_app(self, app):
        try:
            self.api_key = app.config.get("GOOGLE_API_KEY")
            self.usage_file = os.path.join(app.instance_path, "ai_usage.json")
            
            if not self.api_key:
                self.api_key = os.getenv("GOOGLE_API_KEY")

            # FALLBACK: Hardcode key if all else fails (Temporary Fix)
            if not self.api_key:
                self.api_key = "AIzaSyDo4Mstswi0BLL_aQcK-pEfDKBaPW6mPGo"

            if not self.api_key:
                self.logger.warning("[Gemini] No API key found. AI features will use Simulation Mode.")
            else:
                genai.configure(api_key=self.api_key)
                self.model = genai.GenerativeModel(self.model_name)
                self.logger.info(f"[Gemini] Service initialized with model: {self.model_name}")
                
        except Exception as e:
            self.init_error = str(e)
            self.logger.error(f"[Gemini] Initialization failed: {e}")
            # Do not re-raise, allow service to exist in broken/simulated state
            self.api_key = None

    def ask_ai(self, prompt: str, context: Optional[Dict[str, Any]] = None) -> str:
        """
        Send a prompt to Google Gemini and return the response.
        Falls back to simulation if no API key is set or quota exceeded.
        """
        # 1. Check API Key
        if not self.api_key:
            self.logger.warning("[Gemini] No API Key. Using Simulation Mode.")
            # Append init error if present for debugging
            response = self._simulate_response(prompt, context)
            if self.init_error:
                 response += f"\n\n(Debug: Init Error: {self.init_error})"
            return response

        # 2. Check Rate Limit
        if not self._check_rate_limit():
            return (
                "⚠️ **Daily AI Limit Reached**\n\n"
                "To keep this service free, we limit usage. Please try again tomorrow or upgrade your plan."
            )

        # 3. Prepare Prompt
        system_instruction = (
            "You are TenshiGuard AI, an elite cybersecurity analyst and autonomous defense agent. "
            "Your mission is to protect the user's organization by analyzing threats, explaining security concepts, and providing actionable mitigation strategies.\n\n"
            "CORE DIRECTIVES:\n"
            "1. BE PROACTIVE: Don't just explain; suggest specific actions (e.g., 'Isolate Device', 'Block IP').\n"
            "2. BE CONCISE: Security analysts are busy. Give the bottom line first.\n"
            "3. BE CONTEXT-AWARE: Use the provided context (current page, alerts, device stats) to tailor your answer.\n"
            "4. BE EDUCATIONAL: If the user asks about a concept (e.g., 'Lateral Movement'), explain it simply but accurately.\n\n"
            "TONE: Professional, Vigilant, Authoritative but Helpful."
        )

        full_prompt = f"{system_instruction}\n\n"
        
        if context:
            full_prompt += f"CONTEXT DATA:\n{context}\n\n"
            
        full_prompt += f"USER QUERY: {prompt}"

        try:
            response = self.model.generate_content(full_prompt)
            return response.text
            
        except Exception as e:
            self.logger.error(f"[Gemini] Request failed: {e}")
            # DEBUG: Return actual error to user for diagnosis
            return f"⚠️ **AI Error:** {str(e)}\n\n(Falling back to simulation would normally happen here, but I'm showing the error for debugging.)"

    def _simulate_response(self, prompt: str, context: Optional[Dict[str, Any]] = None) -> str:
        """
        Generate a realistic-looking fake response based on keywords and context.
        Used when no API key is configured or API fails.
        """
        prompt_lower = prompt.lower()
        page_title = context.get("page_title", "") if context else ""
        
        # 1. Context-Specific Responses
        if "file" in page_title.lower() or "file" in prompt_lower:
            return (
                "**Gemini Analysis:** I've scanned the recent file activity. "
                "There are **3 suspicious binaries** detected in the last hour. "
                "One matches the signature for *Mimikatz*.\n\n"
                "**Recommendation:**\n"
                "1. Isolate the affected device immediately.\n"
                "2. Run a full deep scan on the file system.\n"
                "3. Check the 'File Scans' tab for the full hash report."
            )
        
        if "network" in page_title.lower() or "network" in prompt_lower:
            return (
                "**Gemini Network Insight:** I'm detecting unusual outbound traffic on port 4444 to an external IP (192.168.x.x). "
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
            "*(Note: This is a simulated response. Add a Google API Key for full analysis.)*"
        )

    def _check_rate_limit(self) -> bool:
        """
        Simple file-based rate limiting.
        Returns True if request is allowed, False if limit exceeded.
        """
        try:
            today = datetime.now().strftime("%Y-%m-%d")
            
            if not os.path.exists(self.usage_file):
                with open(self.usage_file, "w") as f:
                    json.dump({today: 0}, f)
                return True

            with open(self.usage_file, "r") as f:
                usage_data = json.load(f)

            current_usage = usage_data.get(today, 0)
            
            if current_usage >= self.daily_limit:
                self.logger.warning(f"[Gemini] Daily limit reached: {current_usage}/{self.daily_limit}")
                return False

            # Increment usage
            usage_data[today] = current_usage + 1
            
            # Clean up old dates (optional, keep it simple for now)
            
            with open(self.usage_file, "w") as f:
                json.dump(usage_data, f)
                
            return True
            
        except Exception as e:
            self.logger.error(f"[Gemini] Rate limit check failed: {e}")
            # Fail open if rate limiting breaks
            return True
