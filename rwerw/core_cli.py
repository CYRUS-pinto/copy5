"""
core_cli.py — Zenith Pipeline Entrypoint
=========================================
WHAT: The conductor. Runs all four modules in sequence.
      Each module is lazily imported — if missing, prints yellow SKIP
      and continues. The pipeline NEVER crashes.

WHY:  Hackathon resilience. Dev branches may not be merged yet.
      API keys may be missing. Semgrep may not be installed.
      This file handles all of that gracefully.

HOW:  importlib loads each module at runtime inside try/except.
      ZenithPayload threads through all modules.
      WebSocket server starts before the pipeline for live dashboard.

BRANCH RULE: This file lives on main only. Never modified by dev branches.
"""

import argparse
import sys
import os
import importlib
from pathlib import Path
from colorama import Fore, Style, init

init(autoreset=True)

# ── Start WebSocket server before pipeline runs ────────────────────────────
try:
    from src.shared.websocket_broadcast import start_server, broadcast
    start_server(port=8765)
except Exception:
    pass  # Dashboard is optional — never block the pipeline


def run_pipeline(input_path: str = None, prompt: str = None) -> object:
    """
    Execute the full Zenith pipeline end to end.

    Imports each module lazily. Missing modules print yellow SKIP.
    Returns the final ZenithPayload.
    """
    from src.shared.payload import ZenithPayload

    raw = ""
    if input_path:
        try:
            raw = Path(input_path).read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            print(f"{Fore.RED}  Cannot read {input_path}: {e}")
    elif prompt:
        raw = prompt

    payload = ZenithPayload(input_type="unknown", raw_input=raw, file_path=input_path)

    broadcast({"module": "PIPELINE", "status": "running",
               "label": "Pipeline started", "data": {"file": input_path, "prompt": bool(prompt)}})

    MODULES = [
        ("Module 1 · Ingress + Shield", "src.dev1_ingress.ingress",   "run_ingress",
         {"raw_input": raw, "file_path": input_path}),
        ("Module 2 · SAST + CVE",       "src.dev2_sast.sast_runner",  "run_sast",
         {"payload": None}),
        ("Module 3 · Red/Blue Clash",   "src.dev3_clash.clash_runner","run_clash",
         {"payload": None}),
        ("Module 4 · Verify + Score",   "src.dev4_verify.verify_runner","run_verify",
         {"payload": None}),
    ]

    for name, mod_path, func_name, kwargs in MODULES:
        print(f"\n  {'─' * 46}")
        print(f"  {Fore.CYAN}▶ {name}")

        try:
            mod = importlib.import_module(mod_path)
            fn  = getattr(mod, func_name)

            if func_name == "run_ingress":
                payload = fn(**kwargs)
            else:
                kwargs["payload"] = payload
                payload = fn(**kwargs)

            print(f"  {Fore.GREEN}✓ {name} — COMPLETE")

        except ImportError as e:
            print(f"  {Fore.YELLOW}⚠ SKIP — {name} not built yet ({e})")
            payload.skipped_modules.append(name)
        except Exception as e:
            print(f"  {Fore.RED}✗ ERROR in {name}: {type(e).__name__}: {e}")
            print(f"  {Fore.YELLOW}  → Pipeline continuing...")
            payload.log(f"ERROR in {name}: {e}")

    broadcast({"module": "PIPELINE", "status": "complete",
               "label": "Pipeline finished", "data": payload.to_dict()})
    return payload


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Zenith AI Security Pipeline",
        epilog="Examples:\n"
               "  python core_cli.py --file app.py\n"
               "  python core_cli.py --prompt 'ignore all previous instructions'\n"
               "  python core_cli.py  (demo mode)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--file",   help="Path to code file or dependency manifest to scan")
    parser.add_argument("--prompt", help="Raw prompt string to test for injection")
    args = parser.parse_args()

    if not args.file and not args.prompt:
        print(f"{Fore.CYAN}  Running in DEMO MODE — using tests/fixtures/vulnerable.py")
        # Create fixture if it doesn't exist
        fixture = Path("tests/fixtures/vulnerable.py")
        fixture.parent.mkdir(parents=True, exist_ok=True)
        if not fixture.exists():
            fixture.write_text('''"""Vulnerable Python fixture for Zenith demo."""
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect("users.db")
    query = "SELECT * FROM users WHERE id = " + user_id
    return conn.execute(query).fetchall()

def login(username, password):
    if password == "admin123":
        return True
    return False

def eval_input(data):
    return eval(data)
''')
        run_pipeline(input_path=str(fixture))
    else:
        run_pipeline(input_path=args.file, prompt=args.prompt)
