# Supply-Chain Guardian, Explained Simply

This file explains every check the system runs and **where each one appears on the website** (http://127.0.0.1:8000).

---

## The big idea in one paragraph

Modern apps are built from hundreds of other people's packages (from npm, PyPI and similar registries). Attackers target those packages. They publish fake look-alikes (`reqeusts` instead of `requests`), hide scripts that run during install, or swap a package's contents. Separately, old packages get known security holes. This system **reads** a project, never running it, and finds those risks. It ranks them by how dangerous they really are *in this specific app*, shows the proof for each one, and blocks bad packages **before** they are installed.

---

## Map of the website

```
┌────────────────────────────────────────────────────────────────────────────┐
│ TOP BAR: Repo box · Check Before Install · Full Scan · Replay · Simulate   │
│          · Toggle Drift Watchdog · demo drift · LLM badge                  │
├────────────────────────────────────────────────────────────────────────────┤
│ KPI STRIP: Total Components │ Raw Alerts │ Critical Risks │ Downgraded Noise│
│ NOTES: grey "note:" lines / red or amber messages                         │
├──────────────────────────────────────────┬─────────────────────────────────┤
│ ATTACK TREE (graph)                      │ TABS: Evidence Cards │ Stream │ │
│                                          │       Ask Orchestrator          │
└──────────────────────────────────────────┴─────────────────────────────────┘
```

---

## 1. Top bar

| Element | What it does in plain words |
|---|---|
| **Repo** box | The folder to inspect. It is pre-filled with Juice Shop, a deliberately insecure practice app. |
| **Check Before Install** (amber) | "Is this package safe to add?" Type something like `reqeusts@1.0.0`. It answers **BLOCKED** or **APPROVED** *before* anyone installs it. |
| **Full Scan** | Inspects the whole project and fills in everything on the page. |
| **Replay 5 Commits** | Looks back through the last 5 saved changes (git commits) to see whether any of them introduced a risky package or setting. |
| **Simulate Live Attack** (red) | Stages two fake but realistic attacks in a throwaway copy, to show that the system catches them. Nothing is executed. |
| **Toggle Drift Watchdog** | Starts or stops a background guard that keeps checking for **newly published** vulnerabilities. The dot is green and pulsing while it runs. Hover over the button to see its poll count. |
| **demo drift** checkbox | When ticked before you start the watchdog, it injects one clearly-fake vulnerability on the 2nd check, so you can see the watchdog react. |
| Spinner + text | Shown while something is running. The buttons are disabled until it finishes. |
| **LLM badge** (top right) | `LLM: gemini · ... · t=0.0` means the AI agent is helping. `LLM: off (deterministic)` means only the built-in rules are used. Either way, the scores are identical. |

---

## 2. KPI strip (the four numbers)

| Box | Meaning |
|---|---|
| **Total Components** | How many packages the project uses. The small text below shows where the list came from (`sbom=manifest`) and where the vulnerability data came from (`advisories=osv-api`). |
| **Raw Scanner Alerts** | Everything a basic scanner would complain about: known vulnerabilities plus risky configuration. This is the "noisy" number. |
| **Actionable Critical Risks** (red) | Problems that are **really** dangerous in *this* app (Risk Elo ≥ 1800). These are the ones to fix first. |
| **Downgraded Noise** (green) | Alerts the system proved are low-risk here (Risk Elo < 1000), for example a vulnerable function that the app never uses. |

> **The story:** about 41 raw alerts reduce to about 12 that really matter. That is the time saved.

**Grey `note:` lines** below the strip are honest caveats. For example: *"No lockfile found: only direct dependencies are known..."* Juice Shop doesn't save an exact package list (a lockfile), so versions are approximated.

---

## 3. The Attack Tree (graph)

It shows **how an attacker could get from the outside world to a weakness**. Read it left/top to right/bottom:

| Shape / colour | Name | Meaning |
|---|---|---|
| 🟦 blue rounded box | **Tier 0: Exposure** | A door into the app: a web route (`routes/login.ts`), the server (`server.ts`), an install script, a Dockerfile, a CI workflow, or the "pre-install gate". |
| 🟪 purple rounded box | **Internal module** | The app's own helper file in between, e.g. `lib/insecurity.ts`. |
| ⚪ grey circle | **Tier 1: Direct package** | A package the app asked for, e.g. `jsonwebtoken@0.4.0`. |
| ⚫ darker grey circle | **Tier 2+: Transitive package** | A package pulled in *by* another package, e.g. `qs` via `express`. |
| ◆ diamond | **Sink / threat** | The actual weakness: a vulnerable function (`jwt.verify`) or a suspicious finding (typosquat, tampered hash). |
| **Red/pink border** on a node | **Public route** | Anyone on the internet can reach it without logging in. This makes the risk worse. |
| Colour of risky nodes | Severity | 🔴 red = CRITICAL · 🟠 orange = HIGH · 🟡 yellow = MEDIUM · 🟢 green = LOW (noise) |
| `⟨Elo 2450⟩` under a label | Risk score | The highest risk that passes through this node. |

**Click a node:**
- Its whole attack path lights up and everything else fades.
- The highlighted arrows show *why* they connect (labels below).
- A **box at the bottom-left** shows the node's type, file and line, Elo, and for routes `public: server.ts:NN unauthenticated mount /path` (the exact line that proves it's public).
- The **Evidence Cards** tab filters to just that node's findings. Click **clear**, or click empty space, to reset.

**Arrow labels (what links two nodes):**

| Label | Meaning |
|---|---|
| `imports` | This file loads that package/file (proof: the `import` line). |
| `depends_on` | This package requires that package (proof: the lockfile). |
| `calls` | The vulnerable function is actually used here (proof: the exact line of code). |
| `affected_by` | The package has the vulnerability, but no call to the vulnerable function was found in the app's code. |
| `resolves` / `tampered` | The lockfile entry for this package / its fingerprint was changed. |
| `triggers` | A config line (Dockerfile, workflow, install script) causes this risk. |
| `would_install` / `flags` | A candidate package from the pre-install gate / the warning signs it raised. |

**Graph header:** the badge says `repository` (the real project) or `simulation sandbox` (after Simulate). After a simulation, click **back to repository graph** to return. **fit** re-centres the view. **find package…** jumps to a node by name.

### Dependencies view (the "discovery" graph)

The **Attack paths / Dependencies** toggle in the graph header switches between two views:

| View | Shows |
|---|---|
| **Attack paths** | Only the risky routes: door → file → package → weakness. |
| **Dependencies** | **Every** package discovered, risky or not, and which package pulls in which. This is the full ingredients list drawn as a tree. |

In the Dependencies view:

| Look | Meaning |
|---|---|
| 🟦 big blue box | The project itself (the root) |
| ⚪ light circle | Direct package (listed in `package.json`) |
| ⚫ small dark circle | Transitive package (pulled in by another package) |
| Dashed amber border | Dev-only (used by developers or tests, not the live app) |
| Red / orange / yellow / green | Has findings, coloured by its worst Risk Elo |
| `N packages · N links` | Totals, shown in the legend |

**Click a package** to light up what it depends on and who depends on it (all the way up to the project). The info box shows direct/transitive, dev-only, where its version came from, *depends on N · used by N*, its finding count, and where it is declared or imported (`file:line`).

> With no lockfile (Juice Shop's default), this is one layer: the project linked to about 98 direct packages. With `--resolve-lockfile` it becomes the full tree: about 1,100 packages, up to 10 levels deep. With more than 300 packages, labels are shown only for direct and risky packages, to keep it readable; use **find package…** for the rest.

---

## 4. Evidence Cards tab

Each risk becomes one card. The **collapsed row** shows: `F-001` (ID) · **CRITICAL** badge · `Elo 2450` · title · **✓ verified** / **✗ unverified**.

Click a card to open its **5 fields**:

| Field | What it tells you |
|---|---|
| **1 · Finding** | What the problem is: the package ID (`pkg:npm/jsonwebtoken@0.4.0`) and the advisory IDs (`GHSA-…`, `CVE-…`). |
| **2 · Location** | **Where** the proof is: a real `file:line` and the actual code, with syntax colouring. |
| **3 · Attack path** | The step-by-step route from a door (Tier 0) to the weakness, with the proof for each step. "Call-chain depth" = how many steps. |
| **4 · Risk Elo** | The score maths, line by line (see section 6), ending in the total and severity. |
| **5 · Remediation** | How to fix it, plus a **copy** button for the command (e.g. `npm install --ignore-scripts --save-exact jsonwebtoken@9.0.0`) and reference links. |

Below the fields: a short plain-English summary (in italics). It also mentions caveats, such as *"version is a guess because there is no lockfile"* or *"CVSS estimated from severity label"*.

### The validator checks (bottom of each card)

`validator (deterministic|llm, fallback, retries N): ✓ … ✓ …`. Before a card is shown, a strict Python checker confirms each item below. **✓ green** = passed, **✗ red** = failed.

| Check name | Plain meaning |
|---|---|
| `finding_exists` | The card is about a real finding from this scan. |
| `local_file_exists` | The file it points to really exists in the project (and isn't outside it). |
| `snippet_verbatim` | The code shown appears **exactly** in that file, within 5 lines of the stated line. Nothing is made up. |
| `purl_known` | The package is really in the project's package list (or is the candidate being checked). |
| `purl_matches_finding` | The card talks about the same package as the finding. |
| `risk_elo_matches_formula` | The score equals what the fixed formula gives. Nobody, including the AI, can change it. |
| `attack_path_verified` | Every step of the path is a real, proven link in the graph and starts at a door (Tier 0). |
| `fix_command_safe` | The suggested command is on a safe list (e.g. `npm install --ignore-scripts …`) and has nothing dangerous like `curl … \| sh`. |

What the author tag means:
- `llm`: the AI wrote the text.
- `deterministic`: the built-in rules wrote it.
- `fallback`: the AI's answer was rejected (or the AI was unavailable), so the safe built-in version is shown.
- `retries 1`: the AI was corrected once.

---

## 5. Orchestrator Stream tab (live log)

A live diary of what the system is doing. The dot on the tab is **green** when connected and **red** when the connection to the server is lost.

**Colours:** cyan = a tool/action being run · pink italic = the AI's thinking · green = success · amber = warning · red = error · grey = info.

| Source name (middle column) | What it is doing |
|---|---|
| `engine` | Starting or finishing a job, plus the summary numbers. |
| `import-index` | Reading the app's code to find every `import` line. |
| `cdxgen` | Building the package list (SBOM). It says "cache hit" if reused. |
| `lockfile-resolver` | (Only with `--resolve-lockfile`) working out the full package tree from registry info, safely. |
| `osv-scanner` / `osv-api` | Looking up known vulnerabilities in the OSV database. |
| `static-inspector` | Checking config files (see section 7). |
| `attack-tree` | Building the graph: "N nodes, N evidence-backed edges, N findings". |
| `orchestrator` | The AI agent: its thoughts (pink) and tool calls such as `tool read_code_lines(...)`. |
| `validator` | `Post-Check Validator: PASSED` / `REJECTED …` / `41/41 cards PASSED`. |
| `pre_cve_gate` | The pre-install check and its decision. |
| `replay` | One line per old commit checked. |
| `drift-daemon` | Watchdog polls, and `ZERO-DAY DRIFT` when something new appears. |
| `simulator` | The fake attacks being set up and the result. |
| `chat` | Problems answering a chat question. |

---

## 6. The Risk Elo score (card field 4)

A single number for "how worried should I be", built step by step:

**Starting point (base):**

| Shown as | Meaning |
|---|---|
| `CVSS 9.5 x 200` | The industry severity score (0–10) times 200. For example, 9.5 gives 1900. |
| `pre-CVE tampering / typosquat / malicious hook` | **1800.** An attack with no CVE number yet, still very dangerous. |
| `static supply-chain hygiene anomaly` | **1000.** A risky setting rather than an attack (e.g. an unpinned version). |

**Adjustments:**

| Shown as | Points | Plain meaning |
|---|---|---|
| `Tier 0 -> vulnerable symbol path confirmed` | **+350** | Proven: a door leads to code that actually *uses* the broken function. |
| `package imported but vulnerable symbol never called` | **−600** | The app has the package but never uses the broken part, so the risk is mostly theoretical. |
| `auto-executing install hook` | **+500** | Code would run automatically during install, before anyone can review it. |
| `reachable from public unauthenticated route` | **+200** | Anyone on the internet can reach it, with no login needed. |
| `isolated to devDependencies / test code` | **−300** | Only used by developers or tests, not in the live app. |
| `provenance: …` | **+400** | Signs of tampering or a fake: changed fingerprint, a typo-name, a package under 7 days old, or a `:latest` image. Counted once. |

**Result:** ≥ 1800 **CRITICAL** · 1400–1799 **HIGH** · 1000–1399 **MEDIUM** · < 1000 **LOW (noise)**.

If the system can't tell whether the broken function is used, it adds **0**. It never lowers a score on a guess.

---

## 7. Static configuration checks

These look at settings files, not code. They appear as cards (if scored) and in the stream as `static-inspector`.

| Check | What it looks for | Why it matters | Score |
|---|---|---|---|
| **Lifecycle hook** | `preinstall` / `install` / `postinstall` / `prepare` scripts in `package.json`. | They run automatically on install. | Listed only (not scored) if harmless. |
| **Suspicious hook** | A hook containing `curl`, `wget`, `bash -c`, `eval`, `base64`, reading `.env`/SSH keys, outbound URLs. | Classic way to steal secrets during install. | 1800 + 500 |
| **Lockfile hash mutation** | A package's fingerprint (integrity hash) changed but its version did not. | The contents were swapped. A strong sign of tampering. | 1800 + 400 |
| **Docker `:latest` tag** | `FROM image` with no tag, or with `:latest`. | You get whatever was pushed most recently, which might be compromised. | 1000 + 400 |
| **Docker tag without digest** | `FROM node:24` (tag but no `@sha256:…`). | Tags can be re-pointed. | Listed only |
| **Untrusted registry** | Base image from an unknown registry. | Unknown source. | 1000 + 400 |
| **Pipe to shell** | `RUN curl … \| sh` in a Dockerfile. | Runs internet code blindly. | 1000 + 400 |
| **Unpinned GitHub Action** | `uses: owner/action@v3` instead of a full commit ID. | The action's code can change under you. | 1000 |

---

## 8. Pre-install gate panel (after "Check Before Install")

A red **BLOCKED** or green **APPROVED** box. It shows the package, then `metadata: registry` (real npm/PyPI data), `mock-tarball` (simulation data) or `unavailable` (offline). Each check is a line:

**✗ red** = serious, causes a block · **! amber** = warning · **✓ grey** = passed.

| Signal name | Plain meaning |
|---|---|
| `nonexistent_package` | The package doesn't exist on the registry. It's likely a typo, an AI-invented name, or a trap. **Blocks.** |
| `version_missing` | That version was never published. **Blocks.** |
| `typosquat` | The name is 1–2 letters off a popular package (`reqeusts` vs `requests`). At 1 letter it **blocks**. Swapped letters count as 1. |
| `release_age` | Published less than 7 days ago. New packages are riskier, so it's safer to wait. |
| `install_hook` | Has an install script. If it contains a dangerous command it **blocks**. "NEWLY ADDED" means the previous version didn't have it. |
| `tarball_sink` | (Simulation) suspicious text inside the package's files. |
| `abandoned` | No new release in over 3 years. |
| `missing_provenance` | No signed proof of where it was built. Informational only, because most packages lack this. |
| `known_vulnerabilities` | Has published security holes. Shows the worst one and its fix version. |
| `known_malicious` | Listed in the database as **malware** (`MAL-…`). **Blocks.** |

The final decision: **BLOCKED** if any ✗ signal fires or the score is ≥ 1800; otherwise **APPROVED** (possibly with warnings). A card for the candidate also appears in the Evidence Cards tab and in the graph (`pre-install admission gate` → `name (candidate)`).

---

## 9. Replay panel (after "Replay 5 Commits")

One row per commit: short ID · commit message · `+added −removed ~changed` packages · number of new risky settings · gate results (`name:BLOCKED`), or `triaged`, or a grey **skipped** (nothing supply-chain-related changed, so no work was wasted).

Old versions are read directly from history (`git show`), without switching files on disk.

---

## 10. Simulation panel (after "Simulate Live Attack")

- Header: **ATTACK INTERCEPTED & BLOCKED · max Elo 2700** (or amber if not fully blocked).
- **Injected:** the two fake attacks:
  1. `reqeusts` (a fake look-alike) with a script shaped like data theft.
  2. A tampered fingerprint on `express` in the lockfile.
- **Safety notes (small grey text):** why nothing could actually happen:
  - only copies were used;
  - installs are disabled;
  - the registry points nowhere;
  - the evil address uses `.invalid`, which can never exist on the internet;
  - the sandbox is deleted afterwards.
- Below it: the gate panel for `reqeusts`, and two CRITICAL cards (**2700** and **2200**). The graph switches to `simulation sandbox`.

---

## 11. Ask Orchestrator tab (chat)

Ask questions in plain English. Good examples:

| Ask | You get |
|---|---|
| `Why is F-001 critical?` | Score maths, the proof location, the attack path, the fix. |
| `jsonwebtoken` | All findings for that package. |
| `what is noise?` | The list of downgraded findings. |
| `how is the Elo computed?` | The formula. |

Under each answer: `deterministic` or `llm`, plus `cites F-…` (which findings it used). The assistant may only mention findings that really exist; any invented ID is removed and flagged.

---

## 12. Mini glossary

| Term | Simple meaning |
|---|---|
| **Package / dependency** | A ready-made code library an app uses. |
| **Direct vs transitive** | Packages you chose, vs packages *they* brought along. |
| **SBOM** | "Software bill of materials": the full list of packages, like an ingredients label. |
| **purl** | A standard ID for a package, e.g. `pkg:npm/express@4.22.1`. |
| **CVE / GHSA** | Public IDs for known security holes. |
| **MAL-** | An ID for a package known to be malware. |
| **CVSS** | The industry 0–10 severity score for a vulnerability. |
| **OSV** | A free public database of vulnerabilities. |
| **Typosquat** | A fake package named like a real one, to catch typos. |
| **Lockfile** | A file recording the *exact* version and fingerprint of every package. |
| **Integrity hash** | A fingerprint of a package's contents. If it changes, the contents changed. |
| **Install hook** | A script that runs automatically when a package is installed. |
| **Provenance** | Proof of where and how a package was built. |
| **Reachability** | Whether the app actually *uses* the vulnerable part. |
| **Zero-day / drift** | A newly published vulnerability affecting packages you already have. |
| **LLM / agent** | The AI that investigates findings using read-only tools. |
| **Validator** | The strict checker that blocks any unproven or altered result. |
| **Sandbox** | A throwaway folder where risky things can be staged safely. |
