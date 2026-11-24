# Supply-Chain Guardian: Reviewer Presentation Script

This is a feature-by-feature walkthrough. Each feature lists **what it is**, **the command to run**, **what to point out** and **what it proves**.
Target: OWASP Juice Shop (`targets/juice-shop`), a deliberately vulnerable app that is only **read**, never installed or run.

> Commands work in Git Bash and PowerShell. In PowerShell, use `curl.exe` (not `curl`).
> `--no-llm` keeps runs deterministic and sends nothing to an AI provider. Only Feature 8 uses the LLM.
> Advisory counts come from the live OSV database and may differ slightly from the numbers below.

---

## Pre-flight (do this before reviewers arrive)

```bash
.venv/Scripts/python -m unittest discover -s tests          # expect: Ran 15 tests ... OK
.venv/Scripts/python main.py --mode scan --no-llm           # warms the cache (~5 s)
git -C targets/juice-shop status --porcelain --ignored      # expect: empty (pristine target)
```

Keep a second terminal ready for the dashboard: `.venv/Scripts/python main.py --mode serve --no-llm` → http://127.0.0.1:8000

---

## Feature map

| # | Feature | Command | Time |
|---|---|---|---|
| 1 | Read-only discovery (SBOM) | `--mode scan` | 1 min |
| 2 | Advisory extraction (OSV) | `--mode scan` (logs) | (same run) |
| 3 | Static supply-chain inspector | `--mode scan` (anomalies) | 1 min |
| 4 | Typed Attack Tree + Dependency graph | dashboard graph (toggle) | 2 min |
| 5 | Deterministic Risk Elo engine | Evidence Card + unit tests | 2 min |
| 6 | Reachability & noise reduction | scan table "Reach" column | 1 min |
| 7 | 5-Field Evidence Cards + Post-Check Validator | card + validator test | 2 min |
| 8 | Constrained LLM orchestrator *(optional)* | `--mode scan` with LLM | 2 min |
| 9 | Interactive Q&A | dashboard chat | 1 min |
| 10 | Pre-install admission gate | `--mode check-pkg` ×3 | 2 min |
| 11 | Git-history commit replay | `--mode replay` | 1 min |
| 12 | Zero-day drift daemon | `--mode daemon --demo-drift` | 1 min |
| 13 | Safe live attack simulation | `--mode simulate-attack` | 2 min |
| 14 | Web dashboard | `--mode serve` | (throughout) |
| 15 | Safety guarantees (zero execution) | `git status`, `curl.exe` checks | 2 min |
| 16 | CI gating | exit codes | 1 min |

---

## Feature 1: Read-only discovery (SBOM)

**What it is.** It builds a software bill of materials (every package, version and purl), and records where each package is declared and imported (`file:line`), without installing anything. It uses `cdxgen --no-install-deps` when available; otherwise a built-in parser reads `package.json` and the lockfile.

```bash
.venv/Scripts/python main.py --mode scan --no-llm
```

**Point out:**
- `cdxgen ... SBOM: 98 components ... (source=manifest)`
- `import-index indexed 1321 import sites`
- The yellow `note:`. Juice Shop commits **no lockfile**, so only direct dependencies are known. This is stated honestly rather than hidden.

**Proves:** discovery works with zero package installation.

**Optional:** `--resolve-lockfile` resolves the full dependency tree from registry *metadata only*, in a temp folder, with scripts disabled. This adds the Tier 2+ transitive packages.

---

## Feature 2: Advisory extraction (OSV)

**What it is.** It matches every component against the OSV vulnerability database (CVE/GHSA/MAL IDs, CVSS, patched versions, references). It uses `osv-scanner` when installed; otherwise the OSV.dev API.

**Point out (same scan output):**
- `osv-api 33 raw advisories across 14 packages`
- CVSS is **computed from the CVSS v3 vector**. When only a severity label exists, the card says the score is estimated.

**Proves:** real advisory data is used, not mock data. Demo data is only a labelled fallback when offline.

---

## Feature 3: Static supply-chain inspector

**What it is.** It inspects configuration files for supply-chain risk: lockfile hash mutations, npm lifecycle hooks, Dockerfile base images (`:latest`, untrusted registries, `curl | sh`), and GitHub Actions pinned to mutable tags. Each result records an exact `file:line`.

**Point out (same scan output):**
- `static-inspector 12 static observations (8 scored, 4 informational)`
- The `Dockerfile:22` distroless image has **no tag**, so it floats on implicit `:latest`. That is flagged HIGH.
- `.github/workflows/*.yml` actions pinned to `@v3` or `@main` instead of a commit SHA.
- Juice Shop's own `postinstall` (`cd frontend && npm install ...`) is listed as **informational, not scored**, because it contains no suspicious sinks. This is deliberate false-positive avoidance.

**Proves:** coverage beyond CVEs, plus precision.

---

## Feature 4: Typed Attack Tree

**What it is.** A `networkx` graph in which **every edge is backed by evidence** (`file:line`, a lockfile entry or registry metadata):

`Tier 0 Exposure (route / hook / Dockerfile)` → `Internal module` → `Tier 1 Direct pkg` → `Tier 2+ Transitive` → `Sink (vulnerable function / anomaly)`

**Dashboard steps:**
1. Click **Full Scan**.
2. Show the legend:
   - blue = exposure;
   - purple = module;
   - grey = package;
   - diamond = threat;
   - red border = public unauthenticated route.
3. **Click a `jsonwebtoken` threat diamond.** The full path lights up from a public route to `jwt.verify`. Hover over the highlighted edges to show their evidence labels.

4. Switch the graph toggle to **Dependencies**. This is the full discovery graph: every package found, with risky ones coloured. Type `jsonwebtoken` in **find package…** to jump to it, then flip back to **Attack paths** to show why it matters.

**Proves:** findings are explained as concrete attack paths, not flat lists, and the full discovered inventory is visible too.

---

## Feature 5: Deterministic Risk Elo engine

**What it is.** A fixed Python formula that ranks real-world risk. The AI **cannot** alter it.

```
Base  CVSS×200 | 1800 pre-CVE threat | 1000 hygiene
+350 called from Tier 0   −600 imported but never called   +500 auto-exec hook
+200 public route   −300 dev/test only   +400 provenance (hash tamper, typosquat d=1, age<7d, :latest)
≥1800 CRITICAL · 1400–1799 HIGH · 1000–1399 MEDIUM · <1000 LOW (noise)
```

**Show:** open the `jsonwebtoken` card, field 4: `1900 (CVSS 9.5×200) +350 +200 = 2450 CRITICAL`.

```bash
.venv/Scripts/python -m unittest tests.test_core.EloFormulaTests -v
```

**Proves:** the scoring is reproducible and auditable, and the same input always gives the same score.

---

## Feature 6: Reachability & noise reduction

**What it is.** It checks whether the app actually **calls** the vulnerable function, rather than just depending on the package.

**Point out:**
- The **Reach** column in the scan table: `called`, `not called` or `-` (unknown).
- The KPI gap: **41 raw alerts → 12 actionable criticals**.
- The real Juice Shop SQL-injection line found through a first-party re-export:

```bash
git -C targets/juice-shop grep -n "sequelize.query" routes/login.ts
```

- **Safety rule:** unknown reachability scores **0**, never downgraded. Known internal calls (e.g. Express → `qs.parse`) are treated as reachable, so real risks are not hidden.

**Proves:** prioritisation that cuts alert fatigue without hiding real risk.

---

## Feature 7: 5-Field Evidence Cards + Post-Check Validator

**What it is.** Each finding becomes a card with five fields:
1. Finding
2. Location (code snippet)
3. Attack path
4. Risk Elo math
5. Remediation (copyable fix command)

Before any card is shown, **Python verifies all of the following:**
- the file exists inside the repo;
- the snippet appears verbatim within ±5 lines;
- the purl is in the SBOM;
- every path edge exists in the graph;
- the score equals the formula;
- the fix command is on a safety allow-list.

**Show:** expand any card and point to the green ✓ checks at the bottom. Then run:

```bash
.venv/Scripts/python -m unittest tests.test_core.PipelineSafetyTests.test_validator_rejects_fabrication -v
```

This test forges a fake snippet, a +1 score, a `curl … | sh` fix command and a fake attack path. **All four are rejected.**

**Proves:** no hallucinated evidence can reach the user.

---

## Feature 8: Constrained LLM orchestrator *(optional, needs an API key)*

**What it is.** A ReAct agent (OpenAI or Gemini, `temperature=0.0`) with **4 read-only tools**:
- `get_attack_tree_paths`
- `read_code_lines`
- `inspect_manifest_or_diff`
- `get_advisory_metadata`

It writes the narrative and selects the evidence. It cannot score, write files or execute anything.

```bash
# PowerShell:  $env:SCG_MAX_LLM_FINDINGS=2;  Git Bash:  export SCG_MAX_LLM_FINDINGS=2
.venv/Scripts/python main.py --mode scan
```

**Point out (in the stream):**
- Pink `thought` lines and cyan `tool read_code_lines(...)` calls.
- `Post-Check Validator: REJECTED ... attack_path ...`, followed by the agent calling `get_attack_tree_paths` and then `PASSED`. That is **self-correction under verification** (observed in testing).
- If the provider rate-limits (429), it falls back to deterministic output and the scan still completes.

**Mention:** secret files (`.env`, keys) are unreadable by the tools; tokens are redacted; repo text is fenced as untrusted (prompt-injection defence).

**Proves:** AI is used for explanation, never for authority.

---

## Feature 9: Interactive Q&A

**What it is.** A chat grounded in the current scan. It cites only real finding IDs, and invented IDs are stripped out.

**Dashboard, Ask Orchestrator tab. Type:**
1. `Why is F-001 critical?` (returns the Elo math, evidence file:line, path and fix)
2. `jsonwebtoken` (lists all findings for that package)
3. `what is noise?` (lists the downgraded findings)
4. `how is the Elo computed?`

**Proves:** reviewers or developers can interrogate results without reading raw JSON.

---

## Feature 10: Pre-install admission gate (pre-CVE)

**What it is.** It judges a package **before** `npm install`, using registry metadata only (no tarball download). The signals are:
- typosquat distance (counting a swapped pair of letters as one edit);
- release age under 7 days;
- install hooks containing curl, wget, eval, base64 or env/SSH reads;
- abandonment (no release in over 3 years);
- missing provenance;
- known or malicious (`MAL-`) advisories;
- non-existent ("hallucinated") package names.

Run three contrasting cases:

```bash
.venv/Scripts/python main.py --mode check-pkg --pkg reqeusts@1.0.0 --no-llm
.venv/Scripts/python main.py --mode check-pkg --pkg lodash@4.17.21 --no-llm
.venv/Scripts/python main.py --mode check-pkg --pkg express-safe-jwt-helperz --no-llm
```

| Package | Expected | Why |
|---|---|---|
| `reqeusts@1.0.0` | **BLOCKED** | 1 edit from `requests` (letters swapped) and absent from npm |
| `lodash@4.17.21` | **APPROVED** with warnings | Popular, established; a known advisory and no provenance are reported |
| `express-safe-jwt-helperz` | **BLOCKED** | Does not exist (AI-hallucinated or dependency-confusion name) |

**Point out:** for `reqeusts`, the gate does **not** suggest `npm install requests`, because `requests` is a Python package and a same-named npm package could be anything.

**Dashboard:** type `reqeusts@1.0.0` and click **Check Before Install**. A red BLOCKED panel appears and the candidate is added to the graph.

**Proves:** prevention before a package is ever installed.

---

## Feature 11: Git-history commit replay

**What it is.** It steps through recent commits read-only (`git show <sha>:<file>`, no checkout) and only triages commits that change dependencies, lockfiles, Dockerfiles or workflows.

```bash
.venv/Scripts/python main.py --mode replay --commits 5 --no-llm
```

**Point out:** most commits print `no supply-chain change, orchestrator skipped`. It is efficient and does not re-scan everything on every commit.

**Why `git show` rather than `git worktree`:** a checkout can trigger repo-configured hooks and filters; reading blobs cannot, and it writes nothing to disk.

**Proves:** continuous, history-aware monitoring.

---

## Feature 12: Zero-day drift daemon

**What it is.** A background watchdog that keeps the SBOM and Attack Tree in memory and re-polls advisories, so newly disclosed vulnerabilities are triaged **without re-parsing source code**.

```bash
.venv/Scripts/python main.py --mode daemon --interval 10 --max-polls 2 --demo-drift --no-llm
```

**Point out:**
- poll #1: `no new advisories`
- poll #2: `ZERO-DAY DRIFT: 1 newly disclosed advisory: SCG-DRIFT-DEMO-0001` and the critical count goes up by 1.
- The demo advisory is **clearly labelled synthetic**. Real disclosures don't arrive on cue.

**Dashboard:** tick **demo drift**, then click **Toggle Drift Watchdog**. The dot pulses green and the KPIs refresh after each poll.

**Proves:** protection continues after the initial scan.

---

## Feature 13: Safe live attack simulation

**What it is.** It injects two realistic but **inert** supply-chain attacks into a sandbox copy and shows that they are intercepted:
1. A typosquat dependency `"reqeusts": "1.0.0"` with a data-stealing-shaped `postinstall` hook.
2. A `package-lock.json` integrity hash rewritten **without a version bump**.

```bash
.venv/Scripts/python main.py --mode simulate-attack --no-llm
```

**Point out:**
- Two CRITICAL cards: **Elo 2700** (`1800 +500 hook +400 provenance`) and **Elo 2200** (`1800 +400 hash tamper`).
- `ATTACK INTERCEPTED AND BLOCKED`, `sandbox removed=True`.
- The `safety:` lines, in particular:
  - the sandbox `.npmrc` sets `ignore-scripts=true` and `offline=true` and points the registry at an unreachable address;
  - the payload host uses the reserved `.invalid` domain;
  - the real repo is never modified.

**To inspect the injected files:** add `--keep-sandbox` and open the printed folder.

**Dashboard:** click **Simulate Live Attack**. A red banner appears and the graph switches to the sandbox view (use *back to repository graph* to return).

**Proves:** end-to-end detection of real attack classes, demonstrated safely.

---

## Feature 14: Web dashboard

```bash
.venv/Scripts/python main.py --mode serve --no-llm
```

Open http://127.0.0.1:8000. Self-contained HTML (Tailwind + Cytoscape.js from CDN, no build step). It contains:
- the control bar;
- the KPI strip;
- the interactive Attack Tree;
- a live SSE orchestrator stream;
- expandable evidence cards with syntax-highlighted snippets and **copy** buttons;
- the chat panel.

API docs are at http://127.0.0.1:8000/api/docs.

---

## Feature 15: Safety guarantees (zero execution)

**Show that the target was never touched or installed:**

```bash
git -C targets/juice-shop status --porcelain --ignored     # expect: empty (no node_modules, no changes)
```

**Show the API hardening** (server running on port 8000):

```bash
curl.exe -s -o NUL -w "%{http_code}\n" -H "Host: evil.example" http://127.0.0.1:8000/api/config
curl.exe -s -o NUL -w "%{http_code}\n" -X POST -H "Origin: http://evil.example" -H "Content-Type: application/json" -d "{}" http://127.0.0.1:8000/api/scan
curl.exe -s -X POST -H "Content-Type: application/json" -d "{\"repo\":\".\",\"pkg\":\"../../etc/passwd\"}" http://127.0.0.1:8000/api/check-pkg
```

| Check | Expected | Defends against |
|---|---|---|
| Foreign Host header | `400` | DNS rebinding |
| Cross-origin POST | `403` | CSRF from a malicious website |
| Path-traversal package name | `400 invalid npm package spec` | Injection into registry URLs |

**Show the safety tests:**

```bash
.venv/Scripts/python -m unittest tests.test_core.PipelineSafetyTests -v
```

These cover tools refusing `../`, `.env` and `.git/config`, the simulation leaving the repo byte-identical, and the validator rejecting forgeries.

**Summarise the controls:**
- no `npm`/`pip install`, `docker build` or project scripts ever run;
- git runs with hooks, fsmonitor and external diff disabled;
- the server binds to localhost only;
- all rendered data is HTML-escaped.

---

## Feature 16: CI gating

**What it is.** Exit codes let pipelines and pre-commit hooks enforce decisions:

| Code | Meaning |
|---|---|
| 0 | approved / OK |
| 2 | invalid input |
| 3 | `check-pkg` **BLOCKED** |
| 4 | `simulate-attack` not fully blocked (a regression in the defences) |

```bash
.venv/Scripts/python main.py --mode check-pkg --pkg reqeusts@1.0.0 --no-llm
echo $?            # Git Bash  -> 3
# PowerShell:  echo $LASTEXITCODE   -> 3
.venv/Scripts/python main.py --mode scan --no-llm --json-out report.json   # machine-readable report
```

**Proves:** it fits into a real DevSecOps workflow.

---

## Closing (30 seconds)

> "From 41 raw alerts to 12 verified, reachable critical risks, every one backed by a real file and line, scored by a fixed formula, and checked by a validator before a human sees it. Risky packages are blocked before install, attacks are caught in a sandbox, and nothing in the target is ever executed."

```bash
.venv/Scripts/python -m unittest discover -s tests -v      # finish on green: 15 tests OK
```

---

## Likely reviewer questions

| Question | Answer |
|---|---|
| *What if the LLM lies?* | It cannot score, and every card is verified on disk by Python (Feature 7). A rejected card gets one retry, then deterministic output. Without an API key, the whole system still works. |
| *Why not just use CVSS?* | CVSS ignores context. The same CVE is critical on a public route that calls the function, and noise in a dev-only package that never calls it. |
| *Can static reachability miss calls?* | Yes. It is import/pattern-based, not a full call graph. That is why unknown reachability is never downgraded, and known internal calls are curated. |
| *Does it run any code from the scanned repo?* | No. There are no installs, builds or scripts; git hooks and filters are disabled; registry checks read metadata only. The simulation uses an inert, network-dead sandbox. |
| *Juice Shop has no lockfile, so how are transitive dependencies handled?* | They are stated as a limitation; `--resolve-lockfile` builds one from registry metadata with scripts disabled. |
| *Is code sent to a third party?* | Only in LLM mode (excerpts, with secrets redacted, up to 6 findings). `--no-llm` keeps everything local. |
| *How is the typosquat list built?* | Around 300 curated popular npm/PyPI names. A production version would use live download rankings. |
