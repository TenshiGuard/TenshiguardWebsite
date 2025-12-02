import json
import logging
import os
from typing import Any, List, Dict

logger = logging.getLogger(__name__)

# Base directory where all AI rule JSON files live
_RULES_DIR = os.path.join(
    os.path.dirname(__file__),  # .../app/ai/utils
    "..",                       # .../app/ai
    "rules"                     # .../app/ai/rules
)


def _normalize_rules(payload: Any) -> List[Dict[str, Any]]:
    """
    Accepts:
      - a list of rules, or
      - {"rules": [...]} wrapper
    Returns a clean list of dicts.
    """
    if isinstance(payload, list):
        return [r for r in payload if isinstance(r, dict)]
    if isinstance(payload, dict) and isinstance(payload.get("rules"), list):
        return [r for r in payload["rules"] if isinstance(r, dict)]
    return []


def load_rules(filename: str) -> List[Dict[str, Any]]:
    """
    Load rule definitions from JSON file in app/ai/rules.

    Returns an empty list if:
      - file is missing
      - JSON is invalid
      - schema is unexpected
    """
    path = os.path.join(_RULES_DIR, filename)

    if not os.path.exists(path):
        logger.warning(f"[ai.rules] file not found: {path}")
        return []

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        logger.error(f"[ai.rules] failed to load {path}: {e}")
        return []

    rules = _normalize_rules(data)
    logger.info(f"[ai.rules] loaded {len(rules)} rule(s) from {filename}")
    return rules
