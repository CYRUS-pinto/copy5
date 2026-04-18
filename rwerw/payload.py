"""
src/shared/payload.py — ZenithPayload dataclass
================================================
WHAT: The shared data contract that flows through all four pipeline modules.
      Every module receives a ZenithPayload and returns a ZenithPayload.

WHY:  Decoupled architecture. Each module only knows about this dataclass,
      never about other modules. This means any module can be swapped,
      skipped, or upgraded independently.

HOW:  Import at the top of every module file:
      from src.shared.payload import ZenithPayload
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any


@dataclass
class ZenithPayload:
    """
    The single source of truth flowing through the Zenith pipeline.

    Created by Module 1, enriched by each subsequent module,
    and consumed by Module 4 to produce the final dashboard report.
    """

    # ── Input metadata ──────────────────────────────────────────────────────
    input_type: str = "unknown"
    # "source_code" | "manifest" | "prompt_string" | "config" | "unknown"

    raw_input: str = ""
    # Original file contents or prompt string

    file_path: Optional[str] = None
    # Absolute path to the scanned file, or None for raw prompt input

    # ── Module 1 outputs ────────────────────────────────────────────────────
    injections_detected: List[str] = field(default_factory=list)
    # List of matched injection pattern strings

    shield_score: float = 0.0
    # ShieldGemma P(violation) — 0.0 to 1.0

    # ── Module 2 outputs ────────────────────────────────────────────────────
    sast_findings: List[Dict[str, Any]] = field(default_factory=list)
    # Each finding: {"rule_id", "severity", "message", "line", "column"}

    cve_findings: List[Dict[str, Any]] = field(default_factory=list)
    # Each CVE: {"package", "version", "cve_ids", "severity", "summary"}

    # ── Module 3 outputs ────────────────────────────────────────────────────
    red_team_attacks: List[str] = field(default_factory=list)
    # List of exploit scripts written by Red Team

    blue_team_patches: List[str] = field(default_factory=list)
    # List of patch attempts written by Blue Team

    clash_rounds: int = 0
    # Number of Red/Blue rounds completed

    clash_verdict: str = ""
    # "PATCHED" | "UNRESOLVED" | "SKIPPED"

    # ── Module 4 outputs ────────────────────────────────────────────────────
    test_results: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0      # 0–100
    robustness: float = 0.0      # 0–100
    integrity: float = 0.0       # 0–100

    # ── Pipeline-wide fields ────────────────────────────────────────────────
    threat_level: str = "LOW"
    # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"

    patch_status: str = "PENDING"
    # "PENDING" | "VERIFIED" | "PENDING_REVIEW" | "FAILED"

    pipeline_log: List[str] = field(default_factory=list)
    # Human-readable log of each module's action — shown in dashboard timeline

    skipped_modules: List[str] = field(default_factory=list)
    # Which modules were skipped (missing key / import error)

    def log(self, message: str):
        """Append a timestamped entry to the pipeline log."""
        import datetime
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.pipeline_log.append(f"[{ts}] {message}")

    def to_dict(self) -> dict:
        """Serialize to plain dict for JSON export and WebSocket broadcast."""
        import dataclasses
        return dataclasses.asdict(self)
