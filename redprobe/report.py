# ──────────────────────────────────────────────────────────────────────
# RedProbe — Report Writer (Terminal Table + JSON Log)
# ──────────────────────────────────────────────────────────────────────
# Dual-mode report generation:
#
#   1. Terminal Summary — a beautifully formatted, ANSI-colored ASCII
#      table with per-prompt verdicts and an aggregate summary bar.
#
#   2. JSON Log — a timestamped, machine-readable file containing the
#      full scan results for archival and further analysis.
# ──────────────────────────────────────────────────────────────────────

from __future__ import annotations

import json
import os
import time


# ── ANSI color codes for terminal output ──────────────────────────
class _Colors:
    """ANSI escape codes for colored terminal output."""
    HEADER  = "\033[95m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    CYAN    = "\033[96m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"


def _truncate(text: str, max_len: int = 45) -> str:
    """Truncate *text* with an ellipsis if it exceeds *max_len*."""
    text = text.replace("\n", " ").strip()
    if len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text


def _color_status(status: str) -> str:
    """Return *status* wrapped in the appropriate ANSI color."""
    if status == "FAIL":
        return f"{_Colors.RED}{_Colors.BOLD}{status}{_Colors.RESET}"
    return f"{_Colors.GREEN}{_Colors.BOLD}{status}{_Colors.RESET}"


def _color_score(score: float) -> str:
    """Return *score* colored by severity."""
    if score >= 0.8:
        return f"{_Colors.RED}{score:.1f}{_Colors.RESET}"
    elif score >= 0.4:
        return f"{_Colors.YELLOW}{score:.1f}{_Colors.RESET}"
    return f"{_Colors.GREEN}{score:.1f}{_Colors.RESET}"


# ── Terminal Report ───────────────────────────────────────────────
def print_terminal_report(scan_results: dict) -> None:
    """Print a formatted terminal table summarizing the scan.

    Parameters
    ----------
    scan_results : dict
        The structured results dictionary from ``RedProbeRunner.run()``.
    """
    metadata = scan_results["metadata"]
    results = scan_results["results"]

    # ── Column widths ─────────────────────────────────────────────
    col_idx    = 3
    col_probe  = 22
    col_prompt = 45
    col_resp   = 45
    col_status = 6
    col_score  = 5
    col_expl   = 50

    # ── Header ────────────────────────────────────────────────────
    sep = "─" * (col_idx + col_probe + col_prompt + col_resp +
                 col_status + col_score + col_expl + 20)

    print(f"\n{_Colors.CYAN}{_Colors.BOLD}")
    print("╔" + "═" * 68 + "╗")
    print("║        RedProbe — Security Assessment Results                     ║")
    print("╚" + "═" * 68 + "╝")
    print(f"{_Colors.RESET}")

    # ── Table header ──────────────────────────────────────────────
    header = (
        f"{'#':>{col_idx}} │ "
        f"{'Probe':<{col_probe}} │ "
        f"{'Prompt':<{col_prompt}} │ "
        f"{'Response':<{col_resp}} │ "
        f"{'Status':<{col_status}} │ "
        f"{'Score':<{col_score}} │ "
        f"{'Explanation':<{col_expl}}"
    )

    print(f"{_Colors.BOLD}{header}{_Colors.RESET}")
    print(f"{_Colors.DIM}{sep}{_Colors.RESET}")

    # ── Table rows ────────────────────────────────────────────────
    for i, result in enumerate(results, 1):
        row = (
            f"{i:>{col_idx}} │ "
            f"{_truncate(result['probe'], col_probe):<{col_probe}} │ "
            f"{_truncate(result['prompt'], col_prompt):<{col_prompt}} │ "
            f"{_truncate(result['output'], col_resp):<{col_resp}} │ "
            # Status and score use ANSI codes which add invisible chars,
            # so we pad manually after printing.
            f"{_color_status(result['status']):<{col_status + 9}} │ "
            f"{_color_score(result['score']):<{col_score + 9}} │ "
            f"{_truncate(result['explanation'], col_expl)}"
        )
        print(row)

    print(f"{_Colors.DIM}{sep}{_Colors.RESET}")

    # ── Aggregate summary bar ─────────────────────────────────────
    total = metadata["total"]
    passed = metadata["passed"]
    failed = metadata["failed"]
    mitigated = metadata["mitigated"]
    duration = metadata["duration_seconds"]

    print()
    print(f"{_Colors.BOLD}  Scan Summary{_Colors.RESET}")
    print(f"  {'─' * 44}")
    print(f"  Total Prompts   : {_Colors.CYAN}{total}{_Colors.RESET}")
    print(
        f"  Passed          : {_Colors.GREEN}{passed}{_Colors.RESET}"
        f"  ({passed/total*100:.0f}%)" if total > 0 else ""
    )
    print(
        f"  Failed (Vuln.)  : {_Colors.RED}{failed}{_Colors.RESET}"
        f"  ({failed/total*100:.0f}%)" if total > 0 else ""
    )
    print(
        f"  Mitigated       : {_Colors.GREEN}{mitigated}{_Colors.RESET}"
        f"  ({mitigated/total*100:.0f}%)" if total > 0 else ""
    )
    print(f"  Duration        : {duration}s")
    print(f"  {'─' * 44}")

    # ── Risk verdict ──────────────────────────────────────────────
    if failed > 0:
        risk_color = _Colors.RED
        risk_label = "VULNERABILITIES DETECTED"
    else:
        risk_color = _Colors.GREEN
        risk_label = "ALL PROBES MITIGATED"

    print()
    print(f"  {risk_color}{_Colors.BOLD}▶ {risk_label}{_Colors.RESET}")
    print()


# ── JSON Report ───────────────────────────────────────────────────
def write_json_report(scan_results: dict, output_dir: str) -> str:
    """Write the full scan results to a timestamped JSON file.

    Parameters
    ----------
    scan_results : dict
        The structured results dictionary from ``RedProbeRunner.run()``.
    output_dir : str
        Directory to write the JSON file into.

    Returns
    -------
    str
        The absolute path of the generated JSON report file.
    """
    os.makedirs(output_dir, exist_ok=True)

    timestamp = time.strftime("%Y%m%d_%H%M%S")
    filename = f"redprobe_report_{timestamp}.json"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(scan_results, f, indent=2, ensure_ascii=False)

    print(f"  {_Colors.CYAN}JSON report saved → {filepath}{_Colors.RESET}")
    return filepath
