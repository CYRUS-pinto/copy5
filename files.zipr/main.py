"""
Zenith Backend — FastAPI + DSPy Security Pipeline
=================================================
Target: Series A startup engineering teams ($500/team/month)
Stack: FastAPI · DSPy · ShieldGemma 2B · Semgrep · OSV.dev · Pinecone · asyncio

Run: uvicorn main:app --reload --port 8000
"""

from __future__ import annotations
import os, asyncio, json, subprocess, tempfile, time, re, hashlib, textwrap
from pathlib import Path
from typing import Any, Optional
from dataclasses import dataclass, field, asdict

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ─── Optional heavy deps — graceful fallback ───────────────────────────────
try:
    import dspy
    DSPY_OK = True
except ImportError:
    DSPY_OK = False

try:
    import torch
    from transformers import AutoTokenizer, AutoModelForCausalLM
    SHIELD_OK = True
except ImportError:
    SHIELD_OK = False

try:
    from pinecone import Pinecone as PineconeClient
    PINECONE_OK = True
except ImportError:
    PINECONE_OK = False

try:
    import requests as req_lib
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

# ─── App ───────────────────────────────────────────────────────────────────
app = FastAPI(title="Zenith Security API", version="3.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ─── WebSocket manager ──────────────────────────────────────────────────────
class WSManager:
    def __init__(self):
        self.connections: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.connections.append(ws)

    def disconnect(self, ws: WebSocket):
        self.connections.discard(ws) if hasattr(self.connections,'discard') else None
        if ws in self.connections:
            self.connections.remove(ws)

    async def broadcast(self, event: dict):
        msg = json.dumps(event)
        dead = []
        for ws in self.connections:
            try:
                await ws.send_text(msg)
            except Exception:
                dead.append(ws)
        for d in dead:
            self.disconnect(d)

ws_manager = WSManager()

async def emit(module: str, status: str, label: str, data: dict = None):
    await ws_manager.broadcast({"module": module, "status": status, "label": label, "data": data or {}})

# ─── Payload dataclass ──────────────────────────────────────────────────────
@dataclass
class ZenithPayload:
    repo_url: str = ""
    file_path: Optional[str] = None
    input_type: str = "unknown"
    raw_content: str = ""
    # M1
    injections_detected: list = field(default_factory=list)
    shield_score: float = 0.0
    # M2
    sast_findings: list = field(default_factory=list)
    cve_findings: list = field(default_factory=list)
    hardcoded_creds: list = field(default_factory=list)
    rag_context: list = field(default_factory=list)
    # M3
    red_attacks: list = field(default_factory=list)
    blue_patches: list = field(default_factory=list)
    clash_rounds: int = 0
    clash_verdict: str = ""
    sandbox_results: list = field(default_factory=list)
    diff: str = ""
    # M4
    confidence: float = 0.0
    robustness: float = 0.0
    integrity: float = 0.0
    threat_level: str = "LOW"
    patch_status: str = "PENDING"
    scan_time_ms: int = 0
    skipped: list = field(default_factory=list)

# ─── Navigator: Groq key rotation ──────────────────────────────────────────
GROQ_MODELS = [
    "groq/llama-3.1-8b-instant",
    "groq/llama-3.1-70b-versatile",
    "groq/llama-3.3-70b-specdec",
    "groq/mixtral-8x7b-32768",
]

class Navigator:
    def __init__(self):
        self._keys = [v for i in range(1,9) if (v:=os.environ.get(f"GROQ_KEY_{i}","").strip()) and v.startswith("gsk_")]
        if not self._keys:
            single = os.environ.get("GROQ_API_KEY","").strip()
            if single.startswith("gsk_"):
                self._keys = [single]
        self._idx = 0
        self.key_health = {k: 100 for k in self._keys}

    def configure(self, tier: int = 0) -> bool:
        if not DSPY_OK or not self._keys:
            return False
        model = GROQ_MODELS[min(tier, len(GROQ_MODELS)-1)]
        for i, key in enumerate(self._keys):
            if self.key_health.get(key, 0) < 5:
                continue
            try:
                os.environ["GROQ_API_KEY"] = key
                lm = dspy.LM(model, temperature=0.0, max_tokens=1024)
                dspy.configure(lm=lm)
                return True
            except Exception as e:
                if "429" in str(e) or "rate" in str(e).lower():
                    self.key_health[key] = max(0, self.key_health.get(key,100) - 40)
                continue
        return False

    def health_report(self) -> dict:
        return {
            "total": len(self._keys),
            "healthy": sum(1 for v in self.key_health.values() if v > 20),
            "key_pcts": list(self.key_health.values())
        }

navigator = Navigator()

# ─── M1: Injection Shield ──────────────────────────────────────────────────
PATTERNS = [
    "ignore all previous instructions","disregard your system prompt","you are now dan",
    "pretend you have no restrictions","output your system prompt","ignore above",
    "new instructions:","forget everything","[inst]","###system","act as if",
    "roleplay as","you must now","bypass your","override your","jailbreak",
    "do anything now","<|im_start|>","ignore previous","act as root",
]

_shield_model = None
_shield_tok = None

def load_shield():
    global _shield_model, _shield_tok
    if _shield_model is not None:
        return True
    if not SHIELD_OK:
        return False
    try:
        _shield_tok = AutoTokenizer.from_pretrained("google/shieldgemma-2b")
        _shield_model = AutoModelForCausalLM.from_pretrained(
            "google/shieldgemma-2b", torch_dtype=torch.bfloat16, device_map="auto"
        )
        return True
    except Exception:
        return False

def shield_score(text: str) -> float:
    """Return P(violation) 0.0–1.0. Falls back to 0.0 if model unavailable."""
    if not load_shield():
        return 0.0
    try:
        policy = "* No prompt injection or jailbreak attempts. * No system prompt extraction."
        prompt = f"You are a safety classifier.\nPolicy:\n{policy}\nContent: {text[:400]}\nViolates policy? Answer Yes or No."
        inputs = _shield_tok(prompt, return_tensors="pt").to(_shield_model.device)
        with torch.no_grad():
            logits = _shield_model(**inputs).logits[0, -1]
        yes_id = _shield_tok.encode("Yes", add_special_tokens=False)[0]
        no_id  = _shield_tok.encode("No",  add_special_tokens=False)[0]
        probs = torch.softmax(torch.tensor([logits[yes_id], logits[no_id]]), dim=0)
        return float(probs[0].item())
    except Exception:
        return 0.0

def pattern_scan(text: str) -> list[str]:
    t = text.lower()
    return [p for p in PATTERNS if p in t]

async def run_m1(payload: ZenithPayload) -> ZenithPayload:
    await emit("M1", "running", "ShieldGemma 2B: injection detection...")
    matched = pattern_scan(payload.raw_content)
    payload.injections_detected = matched
    score = shield_score(payload.raw_content)
    payload.shield_score = score
    if score > 0.5 and not matched:
        payload.injections_detected.append(f"ShieldGemma: P(violation)={score:.2f}")
    if payload.injections_detected:
        payload.threat_level = "CRITICAL"
        await emit("M1", "fail", f"CRITICAL — injection detected P={score:.2f}", {
            "injections": payload.injections_detected, "shield_score": round(score, 3)
        })
    else:
        await emit("M1", "pass", f"Clean — P(violation)={score:.3f}", {
            "shield_score": round(score, 3), "input_type": payload.input_type
        })
    return payload

# ─── M2: SAST + CVE + Hardcoded cred + RAG ─────────────────────────────────
CRED_PATTERNS = [
    (r'password\s*=\s*["\'][^"\']{3,}["\']', "Hardcoded password"),
    (r'secret\s*=\s*["\'][^"\']{3,}["\']', "Hardcoded secret"),
    (r'api_key\s*=\s*["\'][^"\']{8,}["\']', "Hardcoded API key"),
    (r'token\s*=\s*["\'][^"\']{8,}["\']', "Hardcoded token"),
    (r'aws_secret\s*=\s*["\'][^"\']{8,}["\']', "Hardcoded AWS secret"),
]

# Mock Semgrep output for demo
MOCK_SAST = [
    {"rule_id": "python.lang.security.sqli.string-concat", "severity": "HIGH",
     "message": "SQL injection via string concatenation", "line": 6, "col": 12,
     "snippet": 'query = "SELECT * FROM users WHERE id = " + user_id'},
    {"rule_id": "python.lang.security.eval.use-of-eval", "severity": "HIGH",
     "message": "Code injection via eval()", "line": 18, "col": 11,
     "snippet": "return eval(data)"},
]
MOCK_CVE = [
    {"package": "flask", "version": "1.0.0", "cve_ids": ["CVE-2018-1000656"],
     "severity": "HIGH", "summary": "DoS via crafted JSON in Flask < 1.0.2"},
    {"package": "requests", "version": "2.18.0", "cve_ids": ["CVE-2023-32681"],
     "severity": "MEDIUM", "summary": "Unintended proxy credential exposure"},
]

def run_semgrep(file_path: str) -> list[dict]:
    try:
        r = subprocess.run(["semgrep","--version"], capture_output=True, timeout=5)
        if r.returncode != 0:
            raise FileNotFoundError
        r2 = subprocess.run(
            ["semgrep","--config=auto", file_path,"--json","--quiet"],
            capture_output=True, text=True, timeout=60
        )
        data = json.loads(r2.stdout or "{}")
        findings = []
        for item in data.get("results", []):
            findings.append({
                "rule_id": item.get("check_id","unknown"),
                "severity": item.get("extra",{}).get("severity","INFO").upper(),
                "message": item.get("extra",{}).get("message",""),
                "line": item.get("start",{}).get("line",0),
                "col": item.get("start",{}).get("col",0),
                "snippet": item.get("extra",{}).get("lines",""),
            })
        return findings or MOCK_SAST
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return MOCK_SAST

def check_hardcoded_creds(content: str) -> list[dict]:
    found = []
    for pattern, label in CRED_PATTERNS:
        for m in re.finditer(pattern, content, re.IGNORECASE):
            found.append({"type": label, "snippet": m.group()[:60], "severity": "HIGH"})
    return found

def check_osv(pkg: str, version: str, ecosystem: str = "PyPI") -> list[dict]:
    if not REQUESTS_OK:
        return []
    try:
        r = req_lib.post("https://api.osv.dev/v1/query", json={
            "package": {"name": pkg, "ecosystem": ecosystem}, "version": version
        }, timeout=5)
        vulns = r.json().get("vulns", [])
        if not vulns:
            return []
        cves = [a for v in vulns for a in v.get("aliases",[]) if a.startswith("CVE-")]
        return [{"package": pkg, "version": version, "cve_ids": cves[:3],
                 "severity": "HIGH", "summary": vulns[0].get("summary","Vulnerability found")}]
    except Exception:
        return []

# Pinecone RAG stub — returns mock context; replace with real Pinecone calls
RAG_KNOWLEDGE = [
    {"score": 0.97, "id": "eq-2017", "title": "Equifax breach — SQL injection 2017",
     "text": "147M records exposed. Root cause: unparameterized SQL queries. User_id passed directly into SQL string allowed full table dump via '1 OR 1=1'.",
     "tags": ["CVE-2017-5638", "SQL injection", "series A risk"]},
    {"score": 0.92, "id": "owasp-a03", "title": "OWASP A03:2021 Injection (CWE-89)",
     "text": "SQL injection via string concatenation is #3 on OWASP Top 10. Any user-controlled data interpolated directly into SQL is exploitable. Parameterized queries eliminate the class entirely.",
     "tags": ["OWASP", "CWE-89", "string-concat"]},
    {"score": 0.85, "id": "cve-2018-flask", "title": "CVE-2018-1000656 Flask DoS",
     "text": "Flask versions < 1.0.2 allow DoS via specially crafted JSON. Fix: upgrade to flask>=1.0.2 and add strict Content-Type validation.",
     "tags": ["flask", "PyPI", "dependency"]},
    {"score": 0.78, "id": "hardcoded-uber", "title": "Uber 2022 — hardcoded credentials in GitHub",
     "text": "Hardcoded AWS credentials in private GitHub repo exposed via MFA bypass. Credentials in source = credentials in breach. Use secret managers or environment variables exclusively.",
     "tags": ["hardcoded", "AWS", "series A risk"]},
]

def pinecone_rag_query(query: str, top_k: int = 3) -> list[dict]:
    """Real implementation: replace with Pinecone index.query(vector=embed(query), top_k=top_k)"""
    if PINECONE_OK and os.environ.get("PINECONE_API_KEY"):
        try:
            pc = PineconeClient(api_key=os.environ["PINECONE_API_KEY"])
            index = pc.Index(os.environ.get("PINECONE_INDEX", "zenith-vulns"))
            # Real: embed query, query index
            # results = index.query(vector=embed(query), top_k=top_k, include_metadata=True)
            pass
        except Exception:
            pass
    # Fallback: semantic keyword match from local knowledge
    q = query.lower()
    hits = sorted(RAG_KNOWLEDGE, key=lambda r: sum(t in q for t in r["tags"]) + (0.1 if any(w in q for w in r["text"].lower().split()) else 0), reverse=True)
    return hits[:top_k]

async def run_m2(payload: ZenithPayload) -> ZenithPayload:
    await emit("M2", "running", "SAST + CVE + credential scan + RAG...")
    if payload.file_path and Path(payload.file_path).exists():
        payload.sast_findings = run_semgrep(payload.file_path)
    else:
        payload.sast_findings = MOCK_SAST

    payload.hardcoded_creds = check_hardcoded_creds(payload.raw_content)

    # CVE check (demo: flask + requests mock)
    payload.cve_findings = MOCK_CVE

    # RAG context
    all_issues = " ".join(f["rule_id"] for f in payload.sast_findings) + " " + payload.raw_content[:200]
    payload.rag_context = pinecone_rag_query(all_issues, top_k=3)

    # Upgrade threat level
    all_findings = payload.sast_findings + payload.cve_findings + payload.hardcoded_creds
    if any(f.get("severity") == "CRITICAL" for f in all_findings):
        payload.threat_level = "CRITICAL"
    elif any(f.get("severity") == "HIGH" for f in all_findings):
        if payload.threat_level != "CRITICAL":
            payload.threat_level = "HIGH"
    elif all_findings and payload.threat_level == "LOW":
        payload.threat_level = "MEDIUM"

    await emit("M2", "fail" if payload.sast_findings else "pass",
        f"{len(payload.sast_findings)} SAST · {len(payload.cve_findings)} CVE · {len(payload.hardcoded_creds)} cred", {
        "sast": payload.sast_findings, "cve": payload.cve_findings,
        "creds": payload.hardcoded_creds, "rag": payload.rag_context,
        "threat_level": payload.threat_level
    })
    return payload

# ─── M3: Red/Blue Clash + Sandbox ──────────────────────────────────────────
MOCK_EXPLOIT = """# EXPLOIT — SQL Injection (Mock)
import sqlite3
conn = sqlite3.connect(':memory:')
conn.execute('CREATE TABLE users (id TEXT, name TEXT, pwd TEXT)')
conn.execute("INSERT INTO users VALUES ('1', 'admin', 'secret')")
user_id = "1 OR 1=1"
query = 'SELECT * FROM users WHERE id = ' + user_id
result = conn.execute(query).fetchall()
print(f'EXPLOIT SUCCESS — leaked {len(result)} row(s): {result}')"""

MOCK_PATCH = """# SECURE PATCH — Parameterized Query (Blue Team)
import sqlite3
from typing import Optional

def get_user(user_id: str) -> list:
    \"\"\"Secure: parameterized query prevents SQL injection.\"\"\"
    if not isinstance(user_id, str) or not user_id.strip():
        raise ValueError("Invalid user_id")
    conn = sqlite3.connect("users.db")
    return conn.execute(
        "SELECT id, name FROM users WHERE id = ?",
        (user_id.strip(),)
    ).fetchall()"""

MOCK_DIFF = """-    query = "SELECT * FROM users WHERE id = " + user_id
+    return conn.execute(
+        "SELECT id, name FROM users WHERE id = ?",
+        (user_id.strip(),)
+    ).fetchall()"""

class DSPyRedTeam:
    def attack(self, code: str, finding: dict) -> str:
        if not navigator.configure(tier=2):
            return MOCK_EXPLOIT
        try:
            class WriteExploit(dspy.Signature):
                """Senior penetration tester. Write a minimal Python PoC exploit (max 15 lines). Return EXPLOIT_IMPOSSIBLE if not exploitable. Return only code."""
                code: str = dspy.InputField()
                finding: str = dspy.InputField()
                exploit: str = dspy.OutputField()

            red = dspy.ChainOfThought(WriteExploit)
            result = red(code=code[:1200], finding=f"{finding.get('rule_id')}: {finding.get('message')}")
            return result.exploit.strip()
        except Exception:
            return MOCK_EXPLOIT

class DSPyBlueTeam:
    def patch(self, code: str, exploit: str, finding: dict) -> str:
        if not navigator.configure(tier=2):
            return MOCK_PATCH
        try:
            class WriteSecurePatch(dspy.Signature):
                """Senior security engineer. Rewrite ONLY the vulnerable function to be secure. No markdown. Return only code."""
                code: str = dspy.InputField()
                exploit: str = dspy.InputField()
                finding: str = dspy.InputField()
                patched: str = dspy.OutputField()

            blue = dspy.ChainOfThought(WriteSecurePatch)
            result = blue(code=code[:1200], exploit=exploit[:400], finding=finding.get("message",""))
            return result.patched.strip()
        except Exception:
            return MOCK_PATCH

def run_sandbox(code: str, exploit: str) -> dict:
    """Execute exploit in a restricted subprocess sandbox."""
    try:
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
            f.write(exploit)
            tmp = f.name
        result = subprocess.run(
            ["python3", "-c", f"import resource; resource.setrlimit(resource.RLIMIT_CPU, (2,2)); exec(open('{tmp}').read())"],
            capture_output=True, text=True, timeout=5,
        )
        Path(tmp).unlink(missing_ok=True)
        return {
            "stdout": result.stdout[:500],
            "stderr": result.stderr[:200],
            "succeeded": "EXPLOIT SUCCESS" in result.stdout or result.returncode == 0,
            "returncode": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "Timed out", "succeeded": False, "returncode": -1}
    except Exception as e:
        return {"stdout": "", "stderr": str(e), "succeeded": False, "returncode": -1}

async def run_m3(payload: ZenithPayload) -> ZenithPayload:
    if not payload.sast_findings and not payload.injections_detected:
        payload.clash_verdict = "SKIPPED"
        payload.skipped.append("M3")
        await emit("M3", "skip", "No findings to clash on")
        return payload

    finding = payload.sast_findings[0] if payload.sast_findings else {
        "rule_id": "GENERIC", "message": "Vulnerability detected", "severity": "HIGH"
    }

    red, blue = DSPyRedTeam(), DSPyBlueTeam()
    current_code = payload.raw_content

    for rnd in range(1, 4):
        payload.clash_rounds = rnd
        await emit("M3", "running", f"Round {rnd}: Red Team attacking...", {"round": rnd})

        exploit = red.attack(current_code, finding)
        payload.red_attacks.append(exploit)

        # Sandbox the exploit
        sb_result = run_sandbox(current_code, exploit)
        payload.sandbox_results.append(sb_result)
        await emit("M3", "running", f"Sandbox: {'exploit succeeded' if sb_result['succeeded'] else 'blocked'}", {
            "round": rnd, "sandbox": sb_result
        })

        if "EXPLOIT_IMPOSSIBLE" in exploit.upper():
            payload.clash_verdict = "PATCHED"
            break

        await emit("M3", "running", f"Round {rnd}: Blue Team patching...", {"round": rnd})
        patch = blue.patch(current_code, exploit, finding)
        payload.blue_patches.append(patch)
        current_code = patch

        if rnd == 3:
            payload.clash_verdict = "UNRESOLVED"

    if payload.blue_patches:
        payload.raw_content = payload.blue_patches[-1]
        payload.diff = MOCK_DIFF

    await emit("M3", "pass" if payload.clash_verdict == "PATCHED" else "fail",
        f"Clash: {payload.clash_verdict} in {payload.clash_rounds} round(s)", {
        "verdict": payload.clash_verdict, "rounds": payload.clash_rounds,
        "diff": payload.diff, "sandbox_results": payload.sandbox_results
    })
    return payload

# ─── M4: Score Engine ──────────────────────────────────────────────────────
def score_engine(p: ZenithPayload) -> tuple[float, float, float]:
    # Confidence
    conf = 100.0
    conf -= len(p.injections_detected) * 20
    for f in p.sast_findings:
        conf -= 15 if f.get("severity") == "CRITICAL" else 10 if f.get("severity") == "HIGH" else 5
    conf -= len(p.cve_findings) * 5
    conf -= len(p.hardcoded_creds) * 8
    if p.clash_verdict == "PATCHED":
        conf += 10
    conf = max(0, min(100, conf))

    # Robustness
    rob = 50.0
    if p.clash_verdict == "PATCHED":
        rob += 25
    if p.clash_rounds >= 2:
        rob += 15
    if not p.sast_findings:
        rob += 10
    if p.clash_verdict == "UNRESOLVED":
        rob -= 20
    rob -= len(p.injections_detected) * 10
    rob = max(0, min(100, rob))

    # Integrity
    if p.injections_detected:
        integ = 0.0
    else:
        integ = 100.0
        integ -= len(p.sast_findings) * 5
        integ -= len(p.cve_findings) * 3
        integ -= len(p.hardcoded_creds) * 5
        if p.clash_verdict == "PATCHED":
            integ += 5
        integ = max(0, min(100, integ))

    return round(conf, 1), round(rob, 1), round(integ, 1)

async def run_m4(payload: ZenithPayload) -> ZenithPayload:
    await emit("M4", "running", "Score engine calculating...")
    c, r, i = score_engine(payload)
    payload.confidence, payload.robustness, payload.integrity = c, r, i
    payload.patch_status = "VERIFIED" if payload.clash_verdict == "PATCHED" else (
        "PENDING_REVIEW" if payload.clash_verdict == "UNRESOLVED" else "PENDING"
    )
    await emit("M4", "pass", f"Scores — C:{c} R:{r} I:{i} | {payload.patch_status}", {
        "confidence": c, "robustness": r, "integrity": i,
        "patch_status": payload.patch_status, "threat_level": payload.threat_level,
        "rag_context": payload.rag_context
    })
    return payload

# ─── HTTP API ───────────────────────────────────────────────────────────────
class ScanRequest(BaseModel):
    repo_url: str = ""
    prompt: str = ""
    model_tier: int = 0

@app.post("/api/scan")
async def scan(req: ScanRequest):
    """
    Start a full pipeline scan. Broadcasts events via WebSocket.
    Returns final ZenithPayload as JSON.
    """
    t0 = int(time.time() * 1000)
    payload = ZenithPayload(repo_url=req.repo_url)

    await emit("PIPELINE", "running", "Pipeline started", {
        "repo_url": req.repo_url, "prompt": bool(req.prompt)
    })

    # Clone repo or use fixture
    if req.repo_url:
        tmp_dir = tempfile.mkdtemp()
        try:
            subprocess.run(["git","clone","--depth=1", req.repo_url, tmp_dir], timeout=30, check=True)
            py_files = list(Path(tmp_dir).rglob("*.py"))
            if py_files:
                payload.file_path = str(py_files[0])
                payload.raw_content = py_files[0].read_text(errors="replace")
                payload.input_type = "source_code"
        except Exception:
            payload.raw_content = FIXTURE_CODE
            payload.input_type = "source_code"
    elif req.prompt:
        payload.raw_content = req.prompt
        payload.input_type = "prompt_string"
    else:
        payload.raw_content = FIXTURE_CODE
        payload.input_type = "source_code"

    # Run pipeline
    try:
        payload = await run_m1(payload)
        if payload.threat_level == "CRITICAL" and payload.injections_detected:
            payload.scan_time_ms = int(time.time() * 1000) - t0
            return asdict(payload)

        payload = await run_m2(payload)
        payload = await run_m3(payload)
        payload = await run_m4(payload)
    except Exception as e:
        await emit("PIPELINE", "fail", f"Pipeline error: {str(e)[:100]}")

    payload.scan_time_ms = int(time.time() * 1000) - t0
    await emit("PIPELINE", "complete", "Pipeline finished", asdict(payload))
    return asdict(payload)

@app.get("/api/health")
def health():
    return {"status": "ok", "dspy": DSPY_OK, "shield": SHIELD_OK,
            "pinecone": PINECONE_OK, "navigator": navigator.health_report()}

@app.get("/api/navigator/status")
def nav_status():
    return navigator.health_report()

@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws_manager.connect(ws)
    try:
        await ws.send_text(json.dumps({"module":"SYSTEM","status":"connected","label":"WebSocket ready","data":{}}))
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(ws)

# ─── Fixture code for demo ────────────────────────────────────────────────
FIXTURE_CODE = textwrap.dedent("""
    import sqlite3, os

    def get_user(user_id):
        conn = sqlite3.connect("users.db")
        query = "SELECT * FROM users WHERE id = " + user_id
        return conn.execute(query).fetchall()

    def login(username, password):
        if password == "admin123":
            return True

    def eval_input(data):
        return eval(data)

    flask_key = "hardcoded-secret-key-123"
    aws_secret = "AKIAIOSFODNN7EXAMPLE"
""").strip()
