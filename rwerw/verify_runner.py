"""
src/dev4_verify/verify_runner.py — Module 4: Verify + Score + Dashboard
=======================================================================
WHAT: Calculates the final Confidence, Robustness, and Integrity scores.
      Writes results/report.json. Starts the WebSocket server.
      Auto-opens the live dashboard in the browser.

WHY:  Judges need a single, clear signal. Three scores (0-100) replace
      a wall of text. The auto-opening browser is the demo climax —
      it shows everything that just happened in a visual, colour-coded
      flowchart in real time.

HOW:  Score engine uses a deterministic formula — no AI needed.
      WebSocket server is started here (or by core_cli.py).
      dashboard/index.html is the live visualization.

CONNECTS TO: Final module. Receives complete ZenithPayload.
             Writes results/report.json.
             Broadcasts final scores to dashboard.
             Returns final payload to core_cli.py.
"""

import os
import sys
import json
import webbrowser
import dataclasses
import logging
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.shared.payload import ZenithPayload
from src.shared.websocket_broadcast import emit_module_start, emit_module_pass, emit_scores

logger = logging.getLogger(__name__)


class ScoreEngine:
    """
    Deterministic scoring engine. Zero AI calls.

    Calculates three dimensions of security posture:
    - Confidence: how certain are we the threat is real?
    - Robustness: how well does the patch hold under attack?
    - Integrity: is the input clean and the output trustworthy?
    """

    def calculate(self, payload: ZenithPayload) -> dict:
        """
        Calculate Confidence, Robustness, and Integrity scores (0–100).

        Returns dict with "confidence", "robustness", "integrity".
        """
        # ── CONFIDENCE: certainty that threats are real ─────────────────────
        confidence = 100.0
        confidence -= len(payload.injections_detected) * 20     # -20 per injection
        confidence -= sum(15 if f.get("severity") == "CRITICAL" else
                          10 if f.get("severity") == "HIGH" else
                          5 for f in payload.sast_findings)     # findings deduct
        confidence -= len(payload.cve_findings) * 5             # -5 per CVE
        if payload.clash_verdict == "PATCHED":
            confidence += 10                                      # +10 if verified
        confidence = max(0.0, min(100.0, confidence))

        # ── ROBUSTNESS: patch survival under attack ──────────────────────────
        robustness = 50.0
        if payload.clash_verdict == "PATCHED":
            robustness += 25
        if payload.clash_rounds >= 2:
            robustness += 15                                      # Survived 2+ rounds
        if not payload.sast_findings:
            robustness += 10                                      # No SAST findings
        if payload.clash_verdict == "UNRESOLVED":
            robustness -= 20
        robustness -= len(payload.injections_detected) * 10
        robustness = max(0.0, min(100.0, robustness))

        # ── INTEGRITY: input cleanliness ────────────────────────────────────
        if payload.injections_detected:
            integrity = 0.0                                       # Binary: any injection = 0
        else:
            integrity = 100.0
            integrity -= len(payload.sast_findings) * 5
            integrity -= len(payload.cve_findings) * 3
            if payload.clash_verdict == "PATCHED":
                integrity += 5
            integrity = max(0.0, min(100.0, integrity))

        return {
            "confidence": round(confidence, 1),
            "robustness": round(robustness, 1),
            "integrity": round(integrity, 1),
        }


def write_report(payload: ZenithPayload) -> Path:
    """
    Write full pipeline results to results/report.json.

    Returns path to the written file.
    """
    results_dir = Path("results")
    results_dir.mkdir(exist_ok=True)
    report_path = results_dir / "report.json"

    report = dataclasses.asdict(payload)
    report_path.write_text(json.dumps(report, indent=2, default=str))
    return report_path


def run_verify(payload: ZenithPayload) -> ZenithPayload:
    """
    Main entry point for Module 4.

    Calculates scores, writes report, starts WebSocket server,
    and auto-opens the live dashboard.
    """
    from colorama import Fore, Style, init
    init(autoreset=True)

    emit_module_start("M4", "Scoring + dashboard generation...")

    # ── Calculate scores ──────────────────────────────────────────────────────
    engine = ScoreEngine()
    scores = engine.calculate(payload)
    payload.confidence = scores["confidence"]
    payload.robustness = scores["robustness"]
    payload.integrity  = scores["integrity"]

    # ── Set patch status ──────────────────────────────────────────────────────
    if payload.clash_verdict == "PATCHED":
        payload.patch_status = "VERIFIED"
    elif payload.clash_verdict == "UNRESOLVED":
        payload.patch_status = "PENDING_REVIEW"
    elif payload.clash_verdict == "SKIPPED":
        payload.patch_status = "PENDING"
    else:
        payload.patch_status = "PENDING"

    payload.log(f"M4: Scores — C:{payload.confidence} R:{payload.robustness} I:{payload.integrity}")

    # ── Write report ──────────────────────────────────────────────────────────
    report_path = write_report(payload)
    payload.log(f"M4: Report written to {report_path}")

    # ── Broadcast final scores to live dashboard ──────────────────────────────
    emit_scores(payload.confidence, payload.robustness, payload.integrity, payload.patch_status)

    # ── Auto-open dashboard in browser ───────────────────────────────────────
    dashboard = Path("dashboard") / "index.html"
    if dashboard.exists():
        url = f"file://{dashboard.resolve()}"
        try:
            webbrowser.open(url)
            payload.log(f"M4: Dashboard opened → {url}")
        except Exception as e:
            logger.debug(f"Browser open failed: {e}")

    # ── Terminal banner ───────────────────────────────────────────────────────
    print(f"\n  {'═' * 44}")
    print(f"  {Fore.CYAN}  ZENITH PIPELINE COMPLETE")
    print(f"  {'─' * 44}")
    print(f"  {Fore.WHITE}  Confidence:  {_score_color(payload.confidence)}{payload.confidence:.0f}%{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}  Robustness:  {_score_color(payload.robustness)}{payload.robustness:.0f}%{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}  Integrity:   {_score_color(payload.integrity)}{payload.integrity:.0f}%{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}  Threat:      {payload.threat_level}")
    print(f"  {Fore.WHITE}  Patch:       {Fore.GREEN if payload.patch_status == 'VERIFIED' else Fore.YELLOW}{payload.patch_status}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}  → Dashboard opened in browser")
    print(f"  {'═' * 44}\n")

    emit_module_pass("M4", "Pipeline complete", scores)

    return payload


def _score_color(score: float) -> str:
    """Return colorama color string based on score value."""
    from colorama import Fore
    if score >= 75:
        return Fore.GREEN
    elif score >= 50:
        return Fore.YELLOW
    return Fore.RED


# ---------------------------------------------------------------------------
# Smoke tests
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    test_payload = ZenithPayload(
        input_type="source_code",
        raw_input="def safe(): pass",
        sast_findings=[{"rule_id": "SQL-INJ", "severity": "HIGH", "message": "test", "line": 1, "column": 0}],
        cve_findings=[],
        red_team_attacks=["# exploit"],
        blue_team_patches=["# patch"],
        clash_rounds=1,
        clash_verdict="PATCHED",
        threat_level="HIGH",
    )

    result = run_verify(test_payload)
    assert result.confidence > 0
    assert result.patch_status == "VERIFIED"
    assert Path("results/report.json").exists()
    print("📊  Module 4 smoke tests: ALL PASS")
