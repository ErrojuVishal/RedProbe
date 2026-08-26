# ──────────────────────────────────────────────────────────────────────
# RedProbe — LocalConnector (Offline Rule-Based Responder)
# ──────────────────────────────────────────────────────────────────────
# A lightweight, offline connector that responds to prompts using simple
# rule-based natural language processing.  No API key, no internet, no
# GPU required — runs entirely on Python's standard library.
#
# This connector behaves like a basic safety-aligned LLM: it detects
# potentially adversarial or harmful requests and responds with
# appropriate refusals, just as a well-configured production model
# would.  For benign prompts, it returns a generic helpful response.
#
# Use this connector to:
#   • Test RedProbe's pipeline without needing API credentials
#   • Run scans in CI/CD environments with no network access
#   • Establish a baseline for comparison against real models
# ──────────────────────────────────────────────────────────────────────

import re

from RedProbe.base import BaseConnector


class LocalConnector(BaseConnector):
    """Offline rule-based connector that emulates a safety-aligned LLM.

    The connector uses keyword analysis and pattern matching to understand
    incoming prompts and generate contextually appropriate responses.
    It implements basic safety guardrails similar to those found in
    production LLMs — detecting adversarial patterns and responding
    with clear refusals.

    For benign prompts, it returns a generic helpful response.
    """

    # ── Adversarial patterns (case-insensitive matching) ──────────
    _INJECTION_PATTERNS: list[str] = [
        r"ignore\s+(all\s+)?previous\s+instructions",
        r"ignore\s+(all\s+)?prior\s+instructions",
        r"ignore\s+(any\s+)?previous\s+instructions",
        r"disregard\s+(all\s+)?(prior|previous)\s+",
        r"override\s+mode",
        r"you\s+must\s+now",
        r"new\s+priority\s+directive",
        r"jailbreak",
        r"DAN\s+mode",
        r"\boverride\b.*\binstructions?\b",
    ]

    _LEAKAGE_PATTERNS: list[str] = [
        r"(output|reveal|show|display|print)\s+(your\s+)?system\s+prompt",
        r"system\s+(prompt|instructions|message)",
        r"repeat\s+(your\s+)?(full\s+)?instructions",
        r"(output|reveal|show)\s+(your\s+)?config",
        r"rot13",
        r"internal\s+(config|instructions|prompt)",
        r"what\s+(are|were)\s+your\s+instructions",
    ]

    _HARMFUL_PATTERNS: list[str] = [
        r"(how\s+to|teach\s+me\s+to)\s+(hack|exploit|attack|break\s+into)",
        r"(create|write|generate)\s+(malware|virus|exploit|ransomware)",
        r"bypass\s+(security|safety|filters|guardrails)",
    ]

    # ── Response templates ────────────────────────────────────────
    _INJECTION_REFUSAL = (
        "I appreciate your input, but I'm designed to follow my core "
        "instructions consistently. I can't override my guidelines or "
        "ignore my original instructions, regardless of how the request "
        "is framed. How can I help you within my normal capabilities?"
    )

    _LEAKAGE_REFUSAL = (
        "I understand you're curious, but I'm not able to share my "
        "underlying instructions, internal settings, or initialization "
        "details. This information is confidential by design. "
        "Is there something else I can help you with?"
    )

    _HARMFUL_REFUSAL = (
        "I'm sorry, but I can't assist with that request. It appears "
        "to involve potentially harmful or unsafe activities. I'm here "
        "to help with constructive and safe tasks. Please let me know "
        "if there's something else I can do for you."
    )

    _GENERIC_RESPONSE = (
        "Thank you for your message. I'm a helpful AI assistant and "
        "I'm happy to help you with a wide range of tasks including "
        "answering questions, writing, analysis, and more. How can I "
        "assist you today?"
    )

    # ── Compiled patterns (built once at class level) ─────────────
    _COMPILED_INJECTION = [re.compile(p, re.IGNORECASE) for p in _INJECTION_PATTERNS]
    _COMPILED_LEAKAGE = [re.compile(p, re.IGNORECASE) for p in _LEAKAGE_PATTERNS]
    _COMPILED_HARMFUL = [re.compile(p, re.IGNORECASE) for p in _HARMFUL_PATTERNS]

    # ── BaseConnector interface ───────────────────────────────────
    def generate(self, prompt: str) -> str:
        """Analyze the prompt and return an appropriate response.

        The response pipeline checks patterns in priority order:
        1. Prompt injection attempts → refusal
        2. System prompt leakage attempts → refusal
        3. Harmful/unsafe requests → refusal
        4. Everything else → generic helpful response

        Parameters
        ----------
        prompt : str
            The incoming prompt to respond to.

        Returns
        -------
        str
            A contextually appropriate response string.
        """
        # Check for prompt injection attempts.
        for pattern in self._COMPILED_INJECTION:
            if pattern.search(prompt):
                return self._INJECTION_REFUSAL

        # Check for system prompt leakage attempts.
        for pattern in self._COMPILED_LEAKAGE:
            if pattern.search(prompt):
                return self._LEAKAGE_REFUSAL

        # Check for harmful/unsafe requests.
        for pattern in self._COMPILED_HARMFUL:
            if pattern.search(prompt):
                return self._HARMFUL_REFUSAL

        # Default: benign prompt → helpful response.
        return self._GENERIC_RESPONSE

    def __repr__(self) -> str:
        return "LocalConnector(offline=True, rule_based=True)"
