# Supply-Chain Guardian: Command Reference & Demo Guide

This guide covers three things: how to set up, what every command does, and how to **present** or **test** the system.
Commands are written for Windows (Git Bash or PowerShell). On Linux or macOS, replace `.venv/Scripts/python` with `.venv/bin/python`.

---

## 1. One-time setup

| Command | What it does |
|---|---|
| `python -m venv .venv` | Creates an isolated Python environment for the project. |
| `.venv/Scripts/pip install -r requirements.txt` | Installs FastAPI, networkx, pydantic, rich, httpx and the OpenAI/Gemini SDKs. |
| `git clone --depth 40 https://github.com/juice-shop/juice-shop.git targets/juice-shop` | Downloads OWASP Juice Shop, the deliberately vulnerable target app. The repo is only **read** and is never installed or run. `--depth 40` keeps enough history for commit replay. |
| `copy .env.example .env` *(optional)* | Config file for an LLM key (`OPENAI_API_KEY` / `GEMINI_API_KEY`), offline mode, and so on. Without a key, everything runs deterministically. |

If `--repo` is omitted, every command defaults to `./targets/juice-shop`.

---

## 2. Command reference

### Core modes

| Command | What it represents | What you should see |
|---|---|---|
| `.venv/Scripts/python main.py --mode scan` | **Full read-only scan.** Builds the SBOM, pulls advisories (OSV), runs static checks (lockfiles, hooks, Dockerfile, CI workflows), builds the Attack Tree, scores every finding with the Risk Elo formula, and produces validated 5-field Evidence Cards. | A KPI line (about 98 components, 41 raw alerts, 12 critical, 1 noise), a findings table sorted by Elo, then the top 5 Evidence Cards with `Validator: PASSED`. |
| `.venv/Scripts/python main.py --mode check-pkg --pkg reqeusts@1.0.0` | **Pre-install admission gate.** Judges a package *before* anyone installs it: typosquat distance, release age, install hooks, abandonment, provenance, known or malicious advisories. | `BLOCKED`, with a typosquat of `requests` (1 edit) and "package does not exist on npm". Exit code **3**. |
| `.venv/Scripts/python main.py --mode check-pkg --pkg lodash@4.17.21` | The same gate on a **legitimate** package (the contrast case). | `APPROVED`, with warnings (known advisory, no provenance). Exit code **0**. |
| `.venv/Scripts/python main.py --mode check-pkg --pkg express-safe-jwt-helperz` | The gate on a **made-up / AI-hallucinated** package name ("slopsquatting"). | `BLOCKED`: nonexistent package (dependency-confusion risk). |
| `.venv/Scripts/python main.py --mode check-pkg --pkg pypi:requests==2.31.0` | The gate for a **PyPI** package. | Registry checks against pypi.org. |
| `.venv/Scripts/python main.py --mode replay --commits 5` | **Git-history replay.** Steps through the last N commits read-only (`git show`, no checkout) and only triages commits that change dependencies, lockfiles, Dockerfiles or CI workflows. | One line per commit. Most say "no supply-chain change, orchestrator skipped", which shows the system is efficient rather than noisy. |
| `.venv/Scripts/python main.py --mode daemon --interval 30` | **Zero-day drift watchdog.** Keeps the SBOM and Attack Tree in memory and re-checks advisories every N seconds without re-parsing source code. Stop with Ctrl+C. | "poll #1 ... no new advisories", repeating. |
| `.venv/Scripts/python main.py --mode daemon --interval 10 --max-polls 2 --demo-drift` | Drift watchdog **demo**: injects one clearly-labelled fake advisory (`SCG-DRIFT-DEMO-0001`) on poll 2. | `ZERO-DAY DRIFT: 1 newly disclosed advisory` and critical count +1. |
| `.venv/Scripts/python main.py --mode simulate-attack` | **1-click safe attack simulation.** In a temp sandbox, injects (1) the typosquat `reqeusts` with a fake data-stealing `postinstall` hook and (2) a lockfile integrity tamper with no version bump. Then shows they get caught. | Two CRITICAL cards (Elo **2700** and **2200**), `ATTACK INTERCEPTED AND BLOCKED`, `sandbox removed=True`. Exit code **4** if not blocked. |
| `.venv/Scripts/python main.py --mode serve` | **Web dashboard** at http://127.0.0.1:8000 (bound to your machine only). | See section 4. |

### Useful flags

| Flag | Meaning |
|---|---|
| `--repo PATH` | Scan a different repository. |
| `--no-llm` | Deterministic only; nothing is sent to OpenAI/Gemini. **Recommended for live demos** (no rate limits, identical results each run). |
| `--offline` | No network at all: built-in demo advisories, name-only package checks. Use it as a backup when Wi-Fi fails. |
| `--resolve-lockfile` | Opt-in: builds a full lockfile from registry *metadata only* (`npm --package-lock-only --ignore-scripts`, in a temp folder) so indirect (Tier 2+) dependencies appear. Takes about 45 s the first time, then it's cached. |
| `--no-cache` | Ignores the cached SBOM. |
| `--json-out result.json` | Saves the full result as JSON (for reports or CI). |
| `--keep-sandbox` | Simulation: keeps the temp sandbox so you can inspect the injected files. The path is printed. |
| `--port 9000` | Dashboard port. |
| `--allow-remote --host 0.0.0.0` | Exposes the dashboard on the network. **Avoid**: the API can read repo files. |

### Exit codes (for CI / pre-commit gating)

| Code | Meaning |
|---|---|
| 0 | OK / approved |
| 2 | Bad input (invalid repo path, bad package spec) |
| 3 | `check-pkg` **BLOCKED** the package |
| 4 | `simulate-attack` did **not** fully block the attack |

### Tests

| Command | What it proves |
|---|---|
| `.venv/Scripts/python -m unittest discover -s tests -v` | 15 offline tests: the Elo formula and thresholds, typosquat distance (`reqeusts` = 1 edit), CVSS math, static detectors, lockfile tamper detection, path-traversal and secret-file blocking, the validator rejecting fabricated snippets, scores, commands and paths, and the simulation leaving the repo untouched. |

---

## 3. Key concepts to explain while presenting

**Attack Tree tiers**

- **Tier 0: Exposure.** Public routes (`routes/*.ts`, `server.ts`), install hooks, Dockerfile, CI workflow.
- **Tier 1: Direct package**, e.g. `jsonwebtoken@0.4.0`.
- **Tier 2+: Transitive package**, e.g. `qs` pulled in by `express`.
- **Sink:** the vulnerable function (`jwt.verify`) or the anomaly (typosquat, tampered hash, `:latest` tag).

Every edge points at real evidence (`file:line`, a lockfile entry, or registry metadata).

**Risk Elo (fixed in Python; the AI cannot change it)**

```
Base:  CVSS x 200   |   1800 pre-CVE threat (typosquat / tamper / malicious hook)   |   1000 hygiene issue
+350  public entrypoint -> vulnerable function call confirmed
-600  package imported but vulnerable function never called   (unknown reachability = 0)
+500  auto-executing install hook
+200  public unauthenticated route
-300  devDependency / test-only
+400  provenance: hash mutated w/o version bump, typosquat distance 1, age < 7 days, :latest tag
>= 1800 CRITICAL   1400-1799 HIGH   1000-1399 MEDIUM   < 1000 LOW (downgraded noise)
```

**5-field Evidence Card:** 1 Finding, 2 Location (verified code snippet), 3 Attack path, 4 Risk Elo math, 5 Remediation (copyable fix command).

**Post-Check Validator:** before any card is shown, Python checks six things:

- the file exists;
- the snippet appears verbatim within ±5 lines;
- the package is in the SBOM;
- every attack-path edge exists in the graph;
- the score matches the formula;
- the fix command is on an allow-list.

A failed card gets one retry, then falls back to deterministic output.

---

## 4. Dashboard walkthrough

Start it with `.venv/Scripts/python main.py --mode serve --no-llm` and open http://127.0.0.1:8000.

| UI element | What it does |
|---|---|
| **Repo** box | Path to scan (pre-filled with Juice Shop). |
| **Check Before Install** + package box | Runs the pre-install gate. A red BLOCKED or green APPROVED panel appears with every signal listed. |
| **Full Scan** | Fills the KPIs, graph and cards. |
| **Replay 5 Commits** | Shows a per-commit table (changed deps, anomalies, gate decisions). |
| **Simulate Live Attack** | Switches the graph to the sandbox view with a red INTERCEPTED banner. Use *back to repository graph* to return. |
| **Toggle Drift Watchdog** (+ *demo drift* checkbox) | Starts or stops the background watchdog. The dot pulses green while it runs; the KPIs refresh after each poll. |
| **KPI strip** | Total components, raw alerts, actionable criticals, downgraded noise. The gap between "raw" and "critical" is the value story. |
| **Attack Tree graph** | Blue = exposure, purple = internal module, grey = package, diamonds = threats; red/orange/yellow/green = severity. A red border marks a public route. **Click a node** to highlight its full path and filter the cards to it. |
| **Evidence Cards tab** | Expand a card to see all 5 fields, the Elo math table, validator checkmarks, and a **copy** button for the fix command. |
| **Orchestrator Stream tab** | Live log: tool calls (cyan), warnings (amber), validator results (green), AI thoughts (pink). |
| **Ask Orchestrator tab** | Chat. Try `Why is F-001 critical?`, `jsonwebtoken`, `what is noise?`, `how is the Elo computed?` |

---

## 5. Demo scripts

### A. 5-minute pitch (dashboard)

1. **Before the audience arrives:** run `.venv/Scripts/python main.py --mode scan --no-llm` once to warm the cache, then start `serve --no-llm`.
2. **Full Scan:** "98 components, 41 raw alerts, but only 12 are actionable criticals. Here's why."
3. **Click the `jsonwebtoken` diamond:** the path lights up from a public route to `jwt.verify`. Open the card and show the real code line, the Elo math (`1900 +350 +200 = 2450`) and the green validator checks.
4. **Check Before Install** `reqeusts@1.0.0`: "A developer typo. Blocked before `npm install` ever runs."
5. **Simulate Live Attack:** "A malicious package with a data-stealing hook plus a tampered lockfile. Both are caught at CRITICAL, and nothing was executed: it's a sandbox with scripts disabled and an unreachable registry."
6. **Ask Orchestrator:** `how is the Elo computed?`

### B. 15-minute technical deep dive (terminal + dashboard)

1. Run the `scan` CLI and walk through one Evidence Card field by field.
2. Show **noise reduction**: find a LOW/MEDIUM card where the function is "not called" and explain the -600 rule.
3. Show the **real SQL injection** found through a re-export: `routes/login.ts:34` (`models.sequelize.query(...)`).
4. Run three `check-pkg` cases back to back: `reqeusts@1.0.0` (blocked), `lodash@4.17.21` (approved), a made-up name (blocked).
5. `replay --commits 5`: most commits are skipped, so there's no alert fatigue.
6. `daemon --interval 10 --max-polls 2 --demo-drift`: a new advisory appears and only it gets re-triaged.
7. `simulate-attack --keep-sandbox`: open the printed sandbox folder and show the inert `.npmrc` and mock `package.json`.
8. **If an LLM key is set:** run `scan` without `--no-llm`, watch the stream, and point out any `REJECTED` → `PASSED` validator line, where the AI corrected itself after being caught.
9. Close with the test suite: `python -m unittest discover -s tests -v`.

### C. CI / DevSecOps angle

```bash
# Block a PR that adds a risky dependency (non-zero exit fails the pipeline)
.venv/Scripts/python main.py --mode check-pkg --pkg "$NEW_DEP" --no-llm || exit 1
# Prove the defences still work
.venv/Scripts/python main.py --mode simulate-attack --no-llm --json-out sim.json
```

---

## 6. Ways to test that it really works

| Test | How | Expected |
|---|---|---|
| Unit tests | `python -m unittest discover -s tests -v` | 15 tests, OK |
| Target untouched | Run `simulate-attack`, then `git -C targets/juice-shop status --porcelain` | Empty output |
| Typosquat variety | `check-pkg --pkg expres@4.0.0`, `--pkg lodahs@1.0.0` | Typosquat signal, BLOCKED if distance 1 |
| Offline resilience | `scan --offline` | Runs with demo advisories (labelled "DEMO") |
| Full dependency tree | `scan --resolve-lockfile` | More components; Tier 2 packages in the graph |
| Your own project | `scan --repo C:\path\to\your\node-project` | Works on any repo with a `package.json` |
| API security (server running on 8000) | `curl -s -o NUL -w "%{http_code}" -H "Host: evil.example" http://127.0.0.1:8000/api/config` | `400` (DNS-rebinding blocked) |
| | `curl -s -o NUL -w "%{http_code}" -X POST -H "Origin: http://evil.example" -H "Content-Type: application/json" -d "{}" http://127.0.0.1:8000/api/scan` | `403` (cross-site blocked) |
| | `curl -s -X POST -H "Content-Type: application/json" -d "{\"repo\":\".\",\"pkg\":\"../../etc/passwd\"}" http://127.0.0.1:8000/api/check-pkg` | `400 invalid npm package spec` |
| API docs | http://127.0.0.1:8000/api/docs | Interactive Swagger UI for every endpoint |

---

## 7. Troubleshooting & presenter tips

- **Numbers differ from this guide.** Advisory databases update daily; counts will drift. That's expected.
- **Gemini/OpenAI `429 RESOURCE_EXHAUSTED`.** The free-tier quota is used up. The system falls back automatically; use `--no-llm` for a smooth demo.
- **Slow first scan.** OSV advisory details are cached in `.scg_cache/` after the first run. Warm it up before presenting.
- **No Wi-Fi.** Use `--offline`. Results use built-in demo data and are clearly labelled as such.
- **Port in use.** `--port 9000`.
- **Reset everything.** Delete `.scg_cache/` (cached SBOM, baseline, resolved lockfile).
- **Be honest about limits** (it builds credibility): reachability is pattern-based rather than a full call graph, Juice Shop has no lockfile (hence `--resolve-lockfile`), and the typosquat list is about 300 curated names.
