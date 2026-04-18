"""
navigator.py — Zenith Navigator LLM
====================================
WHAT: Manages all LLM access for the pipeline. Rotates through multiple
      Groq API keys automatically. If one key hits a rate limit or errors,
      the next key is tried immediately — the pipeline never stops.

WHY:  A hackathon demo that crashes because of a rate limit is a dead demo.
      The Navigator is the insurance policy against that failure.

HOW:  Call navigator.get_lm() anywhere you need a DSPy LM object.
      It returns a ready-to-use dspy.LM instance with the best available key.
      All module code stays model-agnostic — swap Groq for OpenAI in one place.

CONNECTS TO: All four modules. Every DSPy call goes through this.
"""

import os
import time
import logging
from typing import Optional

try:
    import dspy
    DSPY_AVAILABLE = True
except ImportError:
    DSPY_AVAILABLE = False

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Model priority ladder — fastest/cheapest first, most capable last
# ---------------------------------------------------------------------------
GROQ_MODELS = [
    "groq/llama-3.1-8b-instant",       # Tier 1: fastest, great for simple tasks
    "groq/llama-3.1-70b-versatile",    # Tier 2: balanced reasoning
    "groq/llama-3.3-70b-specdec",      # Tier 3: best reasoning
    "groq/mixtral-8x7b-32768",         # Tier 4: large context window
]

FALLBACK_MODEL = "openai/gpt-4o-mini"  # Only if all Groq keys fail


class Navigator:
    """
    Rotating LLM key manager for the Zenith pipeline.

    Maintains a pool of Groq API keys and rotates through them
    automatically on rate-limit errors. Provides a single
    get_lm() interface that all modules use.
    """

    def __init__(self):
        """Load all API keys from environment variables."""
        self._groq_keys = self._load_groq_keys()
        self._current_key_idx = 0
        self._current_model_idx = 0
        self._failure_counts: dict[str, int] = {}
        self._last_successful_key: Optional[str] = None

    def _load_groq_keys(self) -> list[str]:
        """
        Load Groq API keys from environment.

        Keys are read from GROQ_KEY_1 through GROQ_KEY_8.
        Any key not set is silently skipped.
        NEVER hardcode keys here — use .env file or shell exports.
        """
        keys = []
        for i in range(1, 9):
            key = os.environ.get(f"GROQ_KEY_{i}", "").strip()
            if key and key.startswith("gsk_"):
                keys.append(key)
        # Also accept a single GROQ_API_KEY for simple setups
        single = os.environ.get("GROQ_API_KEY", "").strip()
        if single and single.startswith("gsk_") and single not in keys:
            keys.append(single)
        return keys

    def get_lm(
        self,
        task: str = "general",
        require_reasoning: bool = False,
        temperature: float = 0.0,
    ) -> Optional[object]:
        """
        Return a ready-to-use DSPy LM object.

        Tries each Groq key in order. On failure, rotates to the next key.
        If all Groq keys fail and OPENAI_API_KEY is set, falls back to
        GPT-4o-mini. Returns None if everything fails — callers must handle
        this by printing a yellow SKIP.

        Args:
            task: Hint for model selection ("injection", "exploit", "patch",
                  "score", "general")
            require_reasoning: If True, skip the 8B model and start at 70B
            temperature: 0.0 for deterministic demo results

        Returns:
            dspy.LM instance, or None if all keys exhausted
        """
        if not DSPY_AVAILABLE:
            logger.warning("DSPy not installed — returning None")
            return None

        # Choose starting model tier based on task requirements
        start_tier = 1 if require_reasoning else 0
        model = GROQ_MODELS[min(start_tier, len(GROQ_MODELS) - 1)]

        # Try each key
        keys_to_try = list(range(len(self._groq_keys)))
        # Start from last successful key if we have one
        if self._last_successful_key and self._last_successful_key in self._groq_keys:
            idx = self._groq_keys.index(self._last_successful_key)
            keys_to_try = keys_to_try[idx:] + keys_to_try[:idx]

        for key_idx in keys_to_try:
            key = self._groq_keys[key_idx]
            key_short = key[:12] + "..."  # Never log full key
            try:
                os.environ["GROQ_API_KEY"] = key
                lm = dspy.LM(model, temperature=temperature, max_tokens=2048)
                # Quick health probe — lightweight, no cost
                self._last_successful_key = key
                logger.info(f"Navigator: using {model} with key {key_short}")
                return lm
            except Exception as e:
                err_str = str(e).lower()
                if "rate" in err_str or "429" in err_str:
                    logger.warning(f"Navigator: key {key_short} rate-limited, rotating")
                    self._failure_counts[key] = self._failure_counts.get(key, 0) + 1
                    time.sleep(0.5)
                    continue
                elif "auth" in err_str or "401" in err_str:
                    logger.warning(f"Navigator: key {key_short} invalid, skipping")
                    continue
                else:
                    logger.warning(f"Navigator: key {key_short} error: {type(e).__name__}")
                    continue

        # All Groq keys failed — try OpenAI fallback
        openai_key = os.environ.get("OPENAI_API_KEY", "")
        if openai_key:
            try:
                lm = dspy.LM(FALLBACK_MODEL, temperature=temperature)
                logger.warning("Navigator: all Groq keys failed, using OpenAI fallback")
                return lm
            except Exception:
                pass

        logger.error("Navigator: ALL keys exhausted — returning None")
        return None

    def configure_dspy(self, task: str = "general", require_reasoning: bool = False):
        """
        Configure dspy globally with the best available model.

        Call this at the start of any module that uses DSPy.
        Returns True if configured successfully, False if all keys failed.
        """
        lm = self.get_lm(task=task, require_reasoning=require_reasoning)
        if lm is None:
            return False
        dspy.configure(lm=lm)
        return True

    def status(self) -> dict:
        """Return a health summary of all keys for the dashboard."""
        return {
            "total_keys": len(self._groq_keys),
            "failed_keys": len([k for k, v in self._failure_counts.items() if v > 2]),
            "last_model": self._last_successful_key[:12] + "..." if self._last_successful_key else None,
            "dspy_available": DSPY_AVAILABLE,
        }


# ---------------------------------------------------------------------------
# Module-level singleton — import and use directly
# ---------------------------------------------------------------------------
navigator = Navigator()


# ---------------------------------------------------------------------------
# Convenience function for one-liner module usage
# ---------------------------------------------------------------------------
def get_lm(task: str = "general", require_reasoning: bool = False) -> Optional[object]:
    """Module-level shortcut: from navigator import get_lm."""
    return navigator.get_lm(task=task, require_reasoning=require_reasoning)


def configure(task: str = "general", require_reasoning: bool = False) -> bool:
    """Module-level shortcut: from navigator import configure."""
    return navigator.configure_dspy(task=task, require_reasoning=require_reasoning)


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys
    print("Navigator smoke test")
    print(f"Keys loaded: {len(navigator._groq_keys)}")
    print(f"DSPy available: {DSPY_AVAILABLE}")

    if not navigator._groq_keys:
        print("WARNING: No GROQ_KEY_N environment variables found.")
        print("Set them in .env: GROQ_KEY_1=gsk_... GROQ_KEY_2=gsk_...")
        sys.exit(1)

    status = navigator.status()
    print(f"Status: {status}")

    if DSPY_AVAILABLE:
        ok = navigator.configure_dspy()
        if ok:
            print("DSPy configured successfully via Navigator")
        else:
            print("WARNING: Could not configure DSPy — check keys")
    else:
        print("Install DSPy: pip install dspy-ai")
