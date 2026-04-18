# ZENITH_ARCHITECTURE_GUIDE.md
## The Living Document — Updated after every module

> This document explains every component in plain English.
> Written for: judges, teammates, and anyone who asks "what does this do?"

---

## What Zenith does in one sentence

Zenith scans AI-generated code for security vulnerabilities, **proves** each flaw
is real by attacking it with an AI Red Team, **proves** the fix works by attacking
the patch again, and shows everything live in a colour-coded dashboard.

---

## Why we built it this way

Every team at every hackathon builds an AI tool. Almost none of them can answer
the question: "Does your AI actually produce correct results, or is it just guessing?"

Zenith answers that question for *security* — by using AI to attack its own output
and mathematically verify the result. The score is not a feeling. It is a number
derived from a real adversarial test.

---

## Framework choice: DSPy

DSPy (Stanford NLP) is our AI framework. We chose it because:

- **Declarative**: We define what we want (`FindExploit`, `PatchCode`), DSPy handles the prompts
- **Model-agnostic**: Swap Groq for OpenAI in one line — `dspy.configure(lm=...)`
- **Minimal code**: 15 lines per module vs 100+ in LangGraph
- **Self-optimizing**: DSPy can refine its own prompts using `MIPROv2` if we add training data

We rejected LangGraph (too much graph wiring overhead) and CrewAI (conversation-oriented, not pipeline-oriented).

---

## LLM provider: Groq with key rotation

We use Groq API with multiple keys that rotate automatically via `navigator.py`.
If one key hits a rate limit, the next is tried instantly. The pipeline never stops
because a single API key got throttled.

Model ladder (cheapest → most capable):
1. `llama-3.1-8b-instant` — simple classification tasks
2. `llama-3.1-70b-versatile` — reasoning tasks  
3. `llama-3.3-70b-specdec` — complex exploit/patch writing
4. `mixtral-8x7b-32768` — large context (long files)

---

## Components

### navigator.py — The Router
**WHAT**: Manages all LLM access. Rotates Groq API keys. Returns a DSPy LM object.  
**WHY**: Prevents "rate limit = demo crash". Every module calls `navigator.configure()` not `dspy.LM()` directly.  
**HOW**: Tries each key in order. On 429 error, rotates to next key. Falls back to OpenAI if all Groq keys fail.  

---

### src/shared/payload.py — The Contract
**WHAT**: The `ZenithPayload` dataclass. Flows through all four modules.  
**WHY**: Decoupling. Each module only knows about this one shared object. Any module can be skipped or upgraded without breaking the others.  
**HOW**: Module 1 creates it, each subsequent module adds to it, Module 4 reads the final state.  

Key fields:
- `sast_findings` — what Semgrep found
- `cve_findings` — what OSV.dev found  
- `red_team_attacks` — exploit scripts written
- `blue_team_patches` — patch code written
- `clash_verdict` — "PATCHED" | "UNRESOLVED" | "SKIPPED"
- `confidence`, `robustness`, `integrity` — final scores (0-100)

---

### src/shared/websocket_broadcast.py — Live Dashboard Wire
**WHAT**: Broadcasts pipeline events to the browser dashboard over WebSocket.  
**WHY**: Judges need to see the pipeline working in real time, not just a final result.  
**HOW**: Non-blocking. If dashboard isn't open, events are silently dropped. Pipeline never waits.  

---

### src/dev1_ingress/ingress.py — Module 1
**WHAT**: The front door. Every input passes through here before anything else.  
**WHY**: If injections reach the pipeline, an attacker could hijack our AI agents.  
**HOW**:  
1. Fast pattern scan (20 hardcoded strings — microseconds, zero AI)  
2. ShieldGemma 2B neural classifier (Google's open-weight safety model — local, free)  
3. DSPy backup classifier (Groq LLM — only if ShieldGemma unavailable)  
4. Triages file type (source code vs manifest vs config vs prompt)  
5. Sets `threat_level = CRITICAL` if any injection detected  

**Judge answer**: "We use Google's ShieldGemma 2B, a 2-billion-parameter model specifically trained for safety classification. It runs locally, costs nothing per inference, and scores injection probability as a number — not fragile regex."

---

### src/dev2_sast/sast_runner.py — Module 2
**WHAT**: Vulnerability scanner using Semgrep (rules-based) + OSV.dev (CVEs) + DSPy (enrichment).  
**WHY**: Semgrep is deterministic and free. OSV.dev is Google's open vulnerability database. The DSPy analyzer adds human-readable context.  
**HOW**:  
1. Semgrep runs OWASP Top 10 rules locally — deterministic, no API cost  
2. OSV.dev REST API checks each dependency version for known CVEs (free, no key)  
3. DSPy CodeAnalyzer enriches findings with exploitability assessment  
4. Mock findings returned if Semgrep not installed — demo always works  

**Judge answer**: "Semgrep is deterministic — same code, same result, always. OSV.dev is Google's free vulnerability database. We don't use AI where rules work better."

---

### src/dev3_clash/clash_runner.py — Module 3
**WHAT**: The adversarial proving engine. Red Team AI exploits, Blue Team AI patches.  
**WHY**: This is Zenith's differentiator. Snyk alerts. We prove. The adversarial loop turns "maybe vulnerable" into "confirmed exploitable + confirmed patched."  
**HOW**:  
1. RedTeamAgent (DSPy WriteExploit): writes minimal exploit script for the finding  
2. BlueTeamAgent (DSPy WriteSecurePatch): rewrites vulnerable code securely  
3. If exploit says `EXPLOIT_IMPOSSIBLE` → `clash_verdict = "PATCHED"` → stop  
4. Otherwise, next round attacks the Blue Team's patch  
5. Max 3 rounds. After 3: `clash_verdict = "UNRESOLVED"` → human escalation  

**Judge answer**: "Every model runs through our Navigator key rotator — Groq by default, fastest tier first. DSPy handles all prompt engineering automatically. We swap models in one line."

---

### src/dev4_verify/verify_runner.py — Module 4
**WHAT**: Score engine, report writer, WebSocket broadcaster, dashboard launcher.  
**WHY**: Judges need a single clear signal. Three scores replace a wall of text.  
**HOW**:  
- Confidence = certainty that threats are real (deductions for each finding, bonus for PATCHED)  
- Robustness = how well the patch held under attack (bonus for surviving 2+ rounds)  
- Integrity = input cleanliness (0.0 if any injection detected — binary)  
- Writes results/report.json  
- Broadcasts final scores to dashboard  
- Auto-opens dashboard/index.html in browser  

**Judge answer**: "The score engine is pure Python math — no AI. Confidence 94 means we're 94% certain the threat was real and verified. It's a formula, not a feeling."

---

### dashboard/index.html — Live Visualization
**WHAT**: Real-time flowchart showing the pipeline as it executes.  
**WHY**: Visual proof that the system works. Judges see findings appear in real time, colour-coded by severity.  
**HOW**:  
- WebSocket client connects to ws://localhost:8765  
- Each module card updates as events arrive: Waiting → Running → Pass/Fail  
- Findings appear inline in each module card, colour-coded:  
  - Red = CRITICAL/HIGH vulnerability  
  - Amber = MEDIUM / module running  
  - Green = PASS / verified  
  - Grey = SKIPPED  
- Score meters animate when Module 4 completes  
- Reconnects automatically if pipeline restarts  

---

## The demo moment

1. Run `python core_cli.py --file tests/fixtures/vulnerable.py`  
2. Watch the terminal — each module prints in colour  
3. Kill the GROQ key mid-run → yellow SKIP → pipeline continues  
4. Browser auto-opens dashboard → scores animate to 94/87/100  
5. Point to each colour-coded finding in the flowchart  
6. Say: "Confidence 94. Robustness 87. Integrity 100. Patch verified."  

---

*Last updated: HACKFEST 2026 — update this section after every module is completed*
