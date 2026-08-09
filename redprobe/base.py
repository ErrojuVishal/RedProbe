# ──────────────────────────────────────────────────────────────────────
# RedProbe — Base Abstract Interfaces
# ──────────────────────────────────────────────────────────────────────
# This module defines the three core ABCs that enforce strict decoupling
# between connectors, probes, and detectors.  Any new component only
# needs to implement the relevant ABC; it never needs to know about the
# internals of the others.
# ──────────────────────────────────────────────────────────────────────

from abc import ABC, abstractmethod


# ────────────────────────── BaseConnector ──────────────────────────
class BaseConnector(ABC):
    """Generator abstraction — wraps a target LLM endpoint.

    Subclasses must implement ``generate()``, which accepts a plain-text
    prompt string and returns the raw model response as a string.  The
    connector is intentionally ignorant of probes and detectors so that
    a new connector never forces changes elsewhere.
    """

    @abstractmethod
    def generate(self, prompt: str) -> str:
        """Send *prompt* to the target LLM and return its raw text response.

        Parameters
        ----------
        prompt : str
            The adversarial (or benign) prompt to send.

        Returns
        -------
        str
            The unmodified text response from the target model.
        """
        ...


# ─────────────────────────── BaseProbe ────────────────────────────
class BaseProbe(ABC):
    """Adversarial test-case generator.

    Each probe encapsulates a *category* of attack (e.g. prompt
    injection, prompt leakage) and ships a curated list of adversarial
    prompts.  It also declares which detector class is best suited to
    evaluate the results.

    Attributes
    ----------
    name : str
        Human-readable probe identifier (e.g. ``"PromptInjectionProbe"``).
    category : str
        Attack taxonomy label (e.g. ``"prompt_injection"``).
    recommended_detector : str
        Registry key of the detector that should assess this probe's
        results (e.g. ``"keyword_regex"``).
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name for this probe."""
        ...

    @property
    @abstractmethod
    def category(self) -> str:
        """Attack category label (used for filtering and reporting)."""
        ...

    @property
    @abstractmethod
    def recommended_detector(self) -> str:
        """Registry key of the recommended detector for this probe."""
        ...

    @abstractmethod
    def get_prompts(self) -> list[str]:
        """Return a list of adversarial prompt strings.

        Returns
        -------
        list[str]
            Static or dynamically formatted attack payloads.
        """
        ...


# ────────────────────────── BaseDetector ──────────────────────────
class BaseDetector(ABC):
    """Vulnerability assessment analyzer.

    Detectors evaluate a (prompt, output) pair and return a structured
    verdict.  They must be purely rule-based — no heavy ML, no GPU, no
    LLM-as-a-judge — so that results are reproducible, explainable,
    and runnable on commodity hardware.

    Attributes
    ----------
    name : str
        Unique registry key for this detector (e.g. ``"refusal"``).
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier / registry key for this detector."""
        ...

    @abstractmethod
    def detect(self, prompt: str, output: str) -> dict:
        """Evaluate the target's *output* given the original *prompt*.

        Parameters
        ----------
        prompt : str
            The adversarial prompt that was sent.
        output : str
            The raw text response from the target model.

        Returns
        -------
        dict
            A verdict dictionary with exactly three keys:

            - ``is_vulnerable`` (bool): ``True`` if the attack succeeded.
            - ``score`` (float): 0.0 (perfect mitigation) → 1.0 (total exploit).
            - ``explanation`` (str): Human-readable justification for the
              verdict, citing the matched rules or keywords.
        """
        ...
