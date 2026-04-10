# CyberBurgs Basic Scanner

A terminal-based, strictly non-intrusive website security posture scanner built in Python. Emphasizes determining an initial security baseline using purely observable parameters with deterministic point allocations and localized outputs.

## Features
- **Strictly Passive Scanning:** Limited strictly to HTTP availability checks, TLS certificate telemetry gathering, basic A/AAAA DNS lookups, and response headers checking. No fuzzing, exploiting, port harvesting, or sub-domain harvesting.
- **Deterministic Scorer:** Uses an explicitly clamped (0-100) deductive heuristic point model based off widely agreed best practices (CSP, HSTS).
- **Hardened Reporting Bounds:** Extends into AI-capabilities exclusively using Google's Gemini LLMs for final report consolidation, constrained precisely to summarizing locally collected static JSON variables. 
- **Modular Extension Ready:** Designed systematically so individual `.py` checkers can be ported into Web Backend environments if needed.

## Setup Requirements

Requires **Python 3.10+**.

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Enable exact environments:
   ```bash
   cp .env.example .env
   ```
   Provide your specific `GEMINI_API_KEY` sequentially.

## How to Run

Standard operation (outputs JSON, Plaintext summary, invokes Gemini if key is present):
```bash
python main.py example.com
```

Bypass AI processing reliably:
```bash
python main.py example.com --no-ai
```

Strict JSON output mapping standard:
```bash
python main.py example.com --json-only
```

## Architectural Limits
It operates conservatively via a strict 5-second `requests` and socket `timeout` restriction. It guarantees no intentional brute-force load is impacted onto web-services.
