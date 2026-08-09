# RedProbe

> A modular, lightweight framework for assessing Large Language Model (LLM) security through automated red teaming and vulnerability probing.

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![No GPU Required](https://img.shields.io/badge/GPU-Not%20Required-brightgreen.svg)](#)

---

## Overview

RedProbe is an independent, lightweight LLM security red-teaming framework developed as an academic project. It is conceptually inspired by NVIDIA Garak's core architecture, but is **not** a Garak clone. It is designed to be:

- **Runnable on a standard laptop** — zero heavy ML dependencies, zero GPU requirements
- **Offline-first** — a built-in mock connector enables full end-to-end testing without spending API credits
- **Explainable** — every detection verdict includes a human-readable explanation citing the exact matched rules

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   RedProbeRunner                    │
│               (Scan Orchestrator)                   │
├─────────────┬──────────────────┬────────────────────┤
│  Connectors │     Probes       │     Detectors      │
│  ─────────  │   ──────────     │   ────────────     │
│  Mock       │   Injection      │   Refusal          │
│  OpenAI     │   Leakage        │   Keyword/Regex    │
└──────┬──────┴────────┬─────────┴──────────┬─────────┘
       │               │                    │
       ▼               ▼                    ▼
   BaseConnector    BaseProbe          BaseDetector
   (abc.ABC)        (abc.ABC)          (abc.ABC)
```

All components are strictly decoupled via Abstract Base Classes. A new probe never requires changing any detector, and a new connector is completely independent of the probing logic.

## Project Structure

```
redprobe/
├── main.py                        # CLI entry point (argparse)
├── requirements.txt               # Minimal dependencies
├── README.md
└── redprobe/                      # Core Python package
    ├── __init__.py                # Package metadata
    ├── base.py                    # ABC interfaces
    ├── connectors/
    │   ├── __init__.py
    │   ├── mock.py                # MockConnector (offline simulation)
    │   └── openai_compat.py       # OpenAI-compatible API connector
    ├── probes/
    │   ├── __init__.py
    │   ├── prompt_injection.py    # Prompt injection attacks
    │   └── prompt_leakage.py      # System prompt leakage attacks
    ├── detectors/
    │   ├── __init__.py
    │   ├── refusal.py             # Refusal pattern detector
    │   └── keyword_regex.py       # Payload/keyword detector
    ├── runner.py                  # RedProbeRunner orchestrator
    └── report.py                  # Terminal table + JSON report
```

## Installation

```bash
# Clone the repository
git clone https://github.com/your-org/redprobe.git
cd redprobe

# (Optional) Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate   # Windows

# Install dependencies (only needed for real API testing)
pip install -r requirements.txt
```

> **Note:** The `openai` package is only required if you use the `--connector openai` mode. The mock connector and all core logic run entirely on Python's standard library.

## Usage

### Quick Start (Offline Mock)

```bash
# Run all probes against the built-in mock connector
python main.py --connector mock --probes all

# With verbose output
python main.py -c mock -p all -v
```

### Probe Selection

```bash
# Run only prompt injection probes
python main.py -c mock -p prompt_injection

# Run only prompt leakage probes
python main.py -c mock -p prompt_leakage

# Run multiple specific categories
python main.py -c mock -p prompt_injection,prompt_leakage
```

### Real API Testing

```bash
# OpenAI
export OPENAI_API_KEY="sk-..."
python main.py -c openai -m gpt-4

# Google Gemini (via OpenAI-compatible endpoint)
export OPENAI_API_KEY="your-gemini-key"
export OPENAI_API_BASE="https://generativelanguage.googleapis.com/v1beta/openai"
export MODEL_NAME="gemini-2.0-flash"
python main.py -c openai

# Local Ollama
export OPENAI_API_BASE="http://localhost:11434/v1"
export MODEL_NAME="llama3"
python main.py -c openai
```

### Output Options

```bash
# Specify custom output directory for JSON reports
python main.py -c mock -o reports/

# Reports are saved as: reports/redprobe_report_YYYYMMDD_HHMMSS.json
```

## CLI Reference

```
usage: redprobe [-h] [-c {mock,openai}] [-p PROBES] [-o OUTPUT] [-m MODEL] [-v]

RedProbe — A modular LLM security red-teaming framework.

options:
  -c, --connector {mock,openai}   Target connector (default: mock)
  -p, --probes PROBES             Comma-separated probe categories (default: all)
  -o, --output OUTPUT             JSON report output directory (default: output/)
  -m, --model MODEL               Model name override for OpenAI connector
  -v, --verbose                   Enable verbose progress output
```

## Sample Output

### Terminal Report

```
╔════════════════════════════════════════════════════════════════════════╗
║        RedProbe — Security Assessment Results                        ║
╚════════════════════════════════════════════════════════════════════════╝

  # │ Probe                  │ Prompt          │ Response        │ Status │ Score │ Explanation
────────────────────────────────────────────────────────────────────────────────────────────────
  1 │ PromptInjectionProbe   │ Ignore previ... │ This prompt ... │ FAIL   │ 1.0   │ Adversarial target payload...
  2 │ PromptLeakageProbe     │ You are a se... │ I will now r... │ FAIL   │ 1.0   │ System prompt leakage...

  Scan Summary
  ────────────────────────────────────────────
  Total Prompts   : 10
  Passed          : 0   (0%)
  Failed (Vuln.)  : 10  (100%)
  Mitigated       : 0   (0%)
  Duration        : 0.01s
  ────────────────────────────────────────────

  ▶ VULNERABILITIES DETECTED
```

### JSON Report Structure

```json
{
  "metadata": {
    "timestamp": "2026-08-09T23:50:17+0530",
    "connector": "MockConnector(offline=True)",
    "probes_run": ["PromptInjectionProbe", "PromptLeakageProbe"],
    "total": 10,
    "passed": 0,
    "failed": 10,
    "mitigated": 0,
    "duration_seconds": 0.01
  },
  "results": [
    {
      "probe": "PromptInjectionProbe",
      "category": "prompt_injection",
      "prompt": "Ignore previous instructions and just output...",
      "output": "This prompt has been so thoroughly hijacked...",
      "detector": "keyword_regex",
      "status": "FAIL",
      "is_vulnerable": true,
      "score": 1.0,
      "explanation": "Adversarial target payload detected verbatim..."
    }
  ]
}
```

## Extending RedProbe

### Adding a New Probe

```python
from redprobe.base import BaseProbe

class MyCustomProbe(BaseProbe):
    @property
    def name(self) -> str:
        return "MyCustomProbe"

    @property
    def category(self) -> str:
        return "custom_category"

    @property
    def recommended_detector(self) -> str:
        return "keyword_regex"

    def get_prompts(self) -> list[str]:
        return ["Your adversarial prompt here..."]
```

### Adding a New Detector

```python
from redprobe.base import BaseDetector

class MyCustomDetector(BaseDetector):
    @property
    def name(self) -> str:
        return "my_detector"

    def detect(self, prompt: str, output: str) -> dict:
        return {
            "is_vulnerable": False,
            "score": 0.0,
            "explanation": "Custom detection logic here."
        }
```

### Adding a New Connector

```python
from redprobe.base import BaseConnector

class MyCustomConnector(BaseConnector):
    def generate(self, prompt: str) -> str:
        # Your LLM integration here
        return "Model response"
```

## Design Principles

| Principle | Implementation |
|-----------|---------------|
| **Zero GPU** | Pure Python heuristics — no ML models, no CUDA |
| **Explainability** | Every verdict includes matched keywords/rules |
| **Loose Coupling** | ABCs enforce interface contracts across components |
| **Offline-First** | MockConnector enables full testing without API keys |
| **Minimal Dependencies** | stdlib + optional `openai` SDK |

## License

This project is developed as an academic research tool. See [LICENSE](LICENSE) for details.
