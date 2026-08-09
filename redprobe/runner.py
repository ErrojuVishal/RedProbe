# ──────────────────────────────────────────────────────────────────────
# RedProbe — RedProbeRunner (Scan Orchestrator)
# ──────────────────────────────────────────────────────────────────────
# The central orchestrator that coordinates the entire red-teaming
# scan lifecycle:
#
#   1. Initialize with a connector and a list of probes.
#   2. Build a detector registry from all available detectors.
#   3. For each probe:
#      a. Resolve its recommended detector.
#      b. Retrieve adversarial prompts.
#      c. Send each prompt through the connector.
#      d. Run the detector on each (prompt, response) pair.
#      e. Collect structured results.
#   4. Return aggregated results for reporting.
# ──────────────────────────────────────────────────────────────────────

from __future__ import annotations

import time

from redprobe.base import BaseConnector, BaseProbe, BaseDetector
from redprobe.detectors import RefusalDetector, KeywordAndRegexDetector


class RedProbeRunner:
    """Central scan orchestrator for RedProbe assessments.

    Parameters
    ----------
    connector : BaseConnector
        The target LLM connector to probe.
    probes : list[BaseProbe]
        The adversarial probes to execute against the target.
    verbose : bool
        If ``True``, print progress messages during the scan.
    """

    def __init__(
        self,
        connector: BaseConnector,
        probes: list[BaseProbe],
        verbose: bool = False,
    ) -> None:
        self._connector = connector
        self._probes = probes
        self._verbose = verbose

        # Build the detector registry — maps detector name → instance.
        # This decouples probes from detectors: a probe only needs to
        # declare a string key, not import a specific detector class.
        self._detector_registry: dict[str, BaseDetector] = {}
        self._register_detectors()

    def _register_detectors(self) -> None:
        """Populate the detector registry with all available detectors."""
        available_detectors: list[BaseDetector] = [
            RefusalDetector(),
            KeywordAndRegexDetector(),
        ]
        for detector in available_detectors:
            self._detector_registry[detector.name] = detector

    def _resolve_detector(self, probe: BaseProbe) -> BaseDetector:
        """Look up the detector recommended by the given probe.

        Falls back to ``KeywordAndRegexDetector`` if the recommended
        detector is not found in the registry.
        """
        detector = self._detector_registry.get(probe.recommended_detector)
        if detector is None:
            if self._verbose:
                print(
                    f"  [!] Detector '{probe.recommended_detector}' not "
                    f"found. Falling back to 'keyword_regex'."
                )
            detector = self._detector_registry["keyword_regex"]
        return detector

    def _log(self, message: str) -> None:
        """Print a progress message if verbose mode is enabled."""
        if self._verbose:
            print(f"  {message}")

    # ── Public API ────────────────────────────────────────────────
    def run(self) -> dict:
        """Execute the full scan lifecycle.

        Returns
        -------
        dict
            A structured results dictionary containing:

            - ``metadata``: Scan metadata (timestamp, connector, probes,
              aggregate counters).
            - ``results``: List of per-prompt result dictionaries.
        """
        scan_start = time.time()
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%S%z")

        results: list[dict] = []
        total = 0
        passed = 0   # Not vulnerable.
        failed = 0   # Vulnerable (exploit succeeded).
        mitigated = 0  # Refusal detected (model defended itself).

        print("\n" + "=" * 70)
        print("  RedProbe — LLM Security Assessment Scan")
        print("=" * 70)
        print(f"  Connector : {self._connector!r}")
        print(f"  Probes    : {len(self._probes)}")
        print(f"  Timestamp : {timestamp}")
        print("=" * 70 + "\n")

        for probe in self._probes:
            detector = self._resolve_detector(probe)
            prompts = probe.get_prompts()

            print(f"── Probe: {probe.name} ({probe.category}) "
                  f"[{len(prompts)} prompts] ──")
            self._log(f"Using detector: {detector.name}")

            for i, prompt in enumerate(prompts, 1):
                total += 1
                self._log(f"  [{i}/{len(prompts)}] Sending prompt...")

                # ── Send prompt to target ─────────────────────────
                output = self._connector.generate(prompt)
                self._log(f"  Response: {output[:80]}...")

                # ── Run detector ──────────────────────────────────
                verdict = detector.detect(prompt, output)

                # ── Classify result ───────────────────────────────
                if verdict["is_vulnerable"]:
                    failed += 1
                    status = "FAIL"
                elif verdict["score"] == 0.0:
                    mitigated += 1
                    passed += 1
                    status = "PASS"
                else:
                    passed += 1
                    status = "PASS"

                # ── Collect result ────────────────────────────────
                result = {
                    "probe": probe.name,
                    "category": probe.category,
                    "prompt": prompt,
                    "output": output,
                    "detector": detector.name,
                    "status": status,
                    "is_vulnerable": verdict["is_vulnerable"],
                    "score": verdict["score"],
                    "explanation": verdict["explanation"],
                }
                results.append(result)

            print()  # Blank line between probes.

        scan_duration = round(time.time() - scan_start, 2)

        # ── Aggregate metadata ────────────────────────────────────
        metadata = {
            "timestamp": timestamp,
            "connector": repr(self._connector),
            "probes_run": [p.name for p in self._probes],
            "total": total,
            "passed": passed,
            "failed": failed,
            "mitigated": mitigated,
            "duration_seconds": scan_duration,
        }

        return {"metadata": metadata, "results": results}
