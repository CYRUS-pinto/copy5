# CLAUDE.md — Zenith Project Rules
## Antigravity Agentic Architect Configuration

### Project Identity
- Name: Zenith (codename: VeriGen)
- Track: Open Innovation — HACKFEST 2026
- Time constraint: 28-hour hackathon
- Framework: DSPy (Stanford) — NOT LangGraph, NOT CrewAI

### Absolute Rules
1. NEVER modify core_cli.py or navigator.py unless explicitly asked
2. NEVER hardcode API keys — all keys via os.environ or navigator.get_lm()
3. EVERY function needs a docstring — no exceptions
4. EVERY external API call wrapped in try/except — return error dict, never raise
5. EVERY module has a runnable __main__ block with test fixture
6. Use ZenithPayload dataclass for ALL inter-module communication
7. After every code write, run the test. Fix up to 3 times silently.
8. If fix requires breaking ZenithPayload contract — STOP and ask.

### Branch Rules
- main: skeleton + CLAUDE.md + AGENTS.md + ZENITH_ARCHITECTURE_GUIDE.md only
- feat/dev1-ingress: Module 1 files only
- feat/dev2-sast: Module 2 files only
- feat/dev3-clash: Module 3 files only
- feat/dev4-verify: Module 4 files only
- NEVER commit to main directly

### Navigator LLM Rules
- Always call navigator.get_lm() — NEVER call dspy.LM() directly with a key
- Navigator handles key rotation, fallback, and model selection automatically
- If navigator returns None, print yellow SKIP and continue pipeline

### DSPy Module Rules
- Use dspy.ChainOfThought for all reasoning tasks
- Define Signatures with clear docstrings (DSPy uses them as prompts)
- Keep signatures under 5 fields — complexity kills speed
- Always set temperature=0 for deterministic demo results

### Dashboard Rules
- WebSocket server runs on ws://localhost:8765
- Broadcast events via: from src.shared.websocket_broadcast import broadcast
- Event format: {"module": "M1", "status": "running|pass|fail|skip", "data": {}}
- Dashboard auto-connects — never block the pipeline waiting for dashboard

### Living Document Rule
- After every module completion, add a section to ZENITH_ARCHITECTURE_GUIDE.md
- Explain: WHAT it does, WHY this design, HOW it connects to pipeline
- Write it so a non-coder judge can understand it in 60 seconds

### The 3-Strike Self-Correction Rule
- Write code → Run test → Fail → Analyze LSP error → Fix → Re-test
- You may do this loop 3 times silently without asking permission
- Strike 4: STOP. Print the error. Ask for direction.
- Cognee graph check: before changing shared files, check for dependent modules

### Security Rules (security-guidance active)
- No secrets in code, comments, or git history
- Input validation on ALL user-supplied strings before passing to LLM
- ShieldGemma scores every input — if P(violation) > 0.5, block and log
- Never log raw API keys even in error messages
