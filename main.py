#!/usr/bin/env python3
# ──────────────────────────────────────────────────────────────────────
# RedProbe — CLI Entry Point
# ──────────────────────────────────────────────────────────────────────
# Usage examples:
#
#   # Run all probes against the local offline connector:
#   python main.py --connector local --probes all
#
#   # Run only prompt-injection probes with verbose output:
#   python main.py -c local -p prompt_injection -v
#
#   # Run against a real OpenAI-compatible endpoint:
#   export OPENAI_API_KEY="sk-..."
#   python main.py -c openai -m gpt-4 -o reports/
#
#   # Run against a local Ollama instance:
#   export OPENAI_API_BASE="http://localhost:11434/v1"
#   export MODEL_NAME="llama3"
#   python main.py -c openai
# ──────────────────────────────────────────────────────────────────────

from __future__ import annotations

import argparse
import sys

from RedProbe.connectors import LocalConnector, OpenAICompatibleConnector
from RedProbe.probes import PromptInjectionProbe, PromptLeakageProbe
from RedProbe.runner import RedProbeRunner
from RedProbe.report import print_terminal_report, write_json_report


# ── Probe registry ────────────────────────────────────────────────
# Maps CLI category names → probe class constructors.
PROBE_REGISTRY: dict[str, type] = {
    "prompt_injection": PromptInjectionProbe,
    "prompt_leakage": PromptLeakageProbe,
}


def _build_connector(args: argparse.Namespace):
    """Instantiate the appropriate connector based on CLI arguments."""
    if args.connector == "local":
        return LocalConnector()
    elif args.connector == "openai":
        return OpenAICompatibleConnector(model=args.model)
    else:
        print(f"[RedProbe] ERROR: Unknown connector '{args.connector}'",
              file=sys.stderr)
        raise SystemExit(1)


def _build_probes(args: argparse.Namespace) -> list:
    """Instantiate the probe objects selected by the user."""
    requested = [p.strip() for p in args.probes.split(",")]

    if "all" in requested:
        return [cls() for cls in PROBE_REGISTRY.values()]

    probes = []
    for name in requested:
        if name not in PROBE_REGISTRY:
            print(
                f"[RedProbe] WARNING: Unknown probe category '{name}'. "
                f"Available: {', '.join(PROBE_REGISTRY.keys())}",
                file=sys.stderr,
            )
            continue
        probes.append(PROBE_REGISTRY[name]())

    if not probes:
        print("[RedProbe] ERROR: No valid probes selected.", file=sys.stderr)
        raise SystemExit(1)

    return probes


def main() -> None:
    """Parse CLI arguments and execute the RedProbe scan pipeline."""
    parser = argparse.ArgumentParser(
        prog="RedProbe",
        description=(
            "RedProbe — A modular LLM security red-teaming framework.\n"
            "Assess LLM vulnerabilities through adversarial probing, "
            "heuristic detection, and structured reporting."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py --connector local --probes all\n"
            "  python main.py -c openai -m gpt-4 -p prompt_injection -v\n"
            "  python main.py -c local -o reports/ -v\n"
        ),
    )

    parser.add_argument(
        "-c", "--connector",
        choices=["local", "openai"],
        default="local",
        help="Target connector: 'local' (offline) or 'openai' (real API). "
             "Default: local.",
    )
    parser.add_argument(
        "-p", "--probes",
        default="all",
        help="Comma-separated probe categories to run: "
             f"{', '.join(PROBE_REGISTRY.keys())}, all. Default: all.",
    )
    parser.add_argument(
        "-o", "--output",
        default="output",
        help="Directory for the JSON report file. Default: output/.",
    )
    parser.add_argument(
        "-m", "--model",
        default=None,
        help="Model name override for the OpenAI connector "
             "(e.g., gpt-4, llama3). Overrides MODEL_NAME env var.",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose progress output during the scan.",
    )

    args = parser.parse_args()

    # ── Build pipeline ────────────────────────────────────────────
    connector = _build_connector(args)
    probes = _build_probes(args)

    # ── Execute scan ──────────────────────────────────────────────
    runner = RedProbeRunner(
        connector=connector,
        probes=probes,
        verbose=args.verbose,
    )
    scan_results = runner.run()

    # ── Generate reports ──────────────────────────────────────────
    print_terminal_report(scan_results)
    report_path = write_json_report(scan_results, args.output)

    print(f"  Scan complete. Report: {report_path}\n")


if __name__ == "__main__":
    main()
