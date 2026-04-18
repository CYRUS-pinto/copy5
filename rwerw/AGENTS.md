# AGENTS.md — Zenith Multi-Agent Configuration

## Agent Roster

### ORCHESTRATOR (You — Lead Antigravity Architect)
- Role: Manage the pipeline, approve plans, merge branches
- Permission: Can modify CLAUDE.md, AGENTS.md, core_cli.py, navigator.py
- Reads: ZENITH_ARCHITECTURE_GUIDE.md before every session

### NAVIGATOR_AGENT
- Role: LLM model selection and key rotation
- File: navigator.py
- Permission: Read .env, select model, rotate keys
- Never writes to ZenithPayload

### DEV1_AGENT
- Role: Module 1 — Ingress + ShieldGemma Shield
- Branch: feat/dev1-ingress
- Files: src/dev1_ingress/ingress.py ONLY
- Cannot touch: core_cli.py, navigator.py, src/shared/*, other dev* modules

### DEV2_AGENT
- Role: Module 2 — SAST + CVE Scanner
- Branch: feat/dev2-sast
- Files: src/dev2_sast/sast_runner.py ONLY
- Cannot touch: core_cli.py, navigator.py, src/shared/*, other dev* modules

### DEV3_AGENT
- Role: Module 3 — Red/Blue Adversarial Clash
- Branch: feat/dev3-clash
- Files: src/dev3_clash/clash_runner.py ONLY
- Cannot touch: core_cli.py, navigator.py, src/shared/*, other dev* modules

### DEV4_AGENT
- Role: Module 4 — Score Engine + Live Dashboard
- Branch: feat/dev4-verify
- Files: src/dev4_verify/verify_runner.py ONLY
- Cannot touch: core_cli.py, navigator.py, src/shared/*, other dev* modules

## Communication Protocol
All agents communicate exclusively through ZenithPayload.
No agent calls another agent's functions directly.
Pipeline flows: DEV1 → DEV2 → DEV3 → DEV4.
Navigator is called by any agent that needs an LLM.

## Merge Protocol
1. Dev agent runs __main__ smoke tests — ALL PASS
2. Dev agent updates ZENITH_ARCHITECTURE_GUIDE.md for their module
3. Orchestrator reviews diff — no changes to shared files
4. Squash merge to main: git merge --squash feat/devN-*
5. Orchestrator runs core_cli.py — pipeline completes or SKIPs gracefully
