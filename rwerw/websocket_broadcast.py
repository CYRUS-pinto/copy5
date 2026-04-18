"""
src/shared/websocket_broadcast.py — Live Dashboard Broadcaster
==============================================================
WHAT: Sends real-time pipeline events to the live dashboard
      running on localhost:8765.

WHY:  The judges need to SEE the pipeline working as it runs.
      This file broadcasts each module's status, findings, and
      scores to the browser dashboard in real time.

HOW:  Call broadcast(event_dict) from any module.
      It's non-blocking — if the dashboard isn't running, it
      silently skips. The pipeline NEVER waits for the dashboard.
"""

import json
import threading
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# Global WebSocket server instance (started by Module 4 or core_cli.py)
_server: Optional[Any] = None
_clients: set = set()
_lock = threading.Lock()


def start_server(port: int = 8765):
    """
    Start the WebSocket broadcast server in a background thread.
    Called once by core_cli.py at pipeline start.
    """
    try:
        import asyncio
        import websockets

        async def handler(websocket):
            with _lock:
                _clients.add(websocket)
            try:
                await websocket.wait_closed()
            finally:
                with _lock:
                    _clients.discard(websocket)

        async def serve():
            async with websockets.serve(handler, "localhost", port):
                logger.info(f"Dashboard WebSocket server on ws://localhost:{port}")
                await asyncio.Future()  # run forever

        def run():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(serve())

        t = threading.Thread(target=run, daemon=True)
        t.start()
        return True
    except ImportError:
        logger.warning("websockets not installed — dashboard broadcast disabled")
        return False
    except Exception as e:
        logger.warning(f"WebSocket server failed to start: {e}")
        return False


def broadcast(event: Dict[str, Any]):
    """
    Send a JSON event to all connected dashboard clients.

    Non-blocking. Silently skips if no clients connected.

    Event schema:
    {
        "module":  "M1" | "M2" | "M3" | "M4" | "PIPELINE",
        "status":  "running" | "pass" | "fail" | "skip" | "complete",
        "label":   "Human-readable status string",
        "data":    { ... any payload fields ... }
    }
    """
    if not _clients:
        return  # No dashboard connected — that's fine

    try:
        import asyncio
        message = json.dumps(event)
        dead = set()
        for ws in list(_clients):
            try:
                # Fire-and-forget — don't await, don't block pipeline
                asyncio.run_coroutine_threadsafe(ws.send(message), ws.loop)
            except Exception:
                dead.add(ws)
        with _lock:
            _clients.difference_update(dead)
    except Exception:
        pass  # Dashboard failure must never crash the pipeline


def emit_module_start(module_id: str, label: str):
    """Shortcut: broadcast module starting event."""
    broadcast({"module": module_id, "status": "running", "label": label, "data": {}})


def emit_module_pass(module_id: str, label: str, data: dict = None):
    """Shortcut: broadcast module success event."""
    broadcast({"module": module_id, "status": "pass", "label": label, "data": data or {}})


def emit_module_skip(module_id: str, reason: str):
    """Shortcut: broadcast module skip event."""
    broadcast({"module": module_id, "status": "skip", "label": f"SKIP: {reason}", "data": {}})


def emit_finding(module_id: str, finding: dict):
    """Shortcut: broadcast a single finding (highlighted in dashboard)."""
    broadcast({"module": module_id, "status": "finding", "label": finding.get("rule_id", "finding"), "data": finding})


def emit_scores(confidence: float, robustness: float, integrity: float, verdict: str):
    """Shortcut: broadcast final score update."""
    broadcast({
        "module": "M4",
        "status": "complete",
        "label": f"Pipeline complete — {verdict}",
        "data": {
            "confidence": round(confidence),
            "robustness": round(robustness),
            "integrity": round(integrity),
            "verdict": verdict,
        }
    })
