# Supply-Chain Guardian

Continuous, **read-only** software supply-chain security: a pre-install admission gate, an
evidence-backed attack tree with a locked Risk Elo formula, a constrained LLM triage agent
whose every answer passes a deterministic Post-Check Validator, plus a CLI and a web dashboard.

## Quick start

```bash
python -m venv .venv && .venv/Scripts/pip install -r requirements.txt   # (bin/ on Linux/macOS)
git clone --depth 40 https://github.com/juice-shop/juice-shop.git targets/juice-shop

python main.py --mode scan                                  # defaults to ./targets/juice-shop
python main.py --mode check-pkg --pkg reqeusts@1.0.0        # exit code 3 when BLOCKED (CI-friendly)
python main.py --mode replay --commits 5
python main.py --mode daemon --interval 30 --max-polls 3 --demo-drift
python main.py --mode simulate-attack                       # exit code 4 if NOT blocked
python main.py --mode serve --port 8000                     # http://127.0.0.1:8000
python -m unittest discover -s tests -v
```

Flags: `--no-llm`, `--offline`, `--resolve-lockfile`, `--json-out out.json`, `--keep-sandbox`.
`cdxgen` and `osv-scanner` are used when on `PATH`; otherwise a built-in lockfile/manifest parser
and the OSV.dev API are used, and as a last resort clearly-labelled demo data.

## Safety model

| Risk | Control |
|---|---|
| Executing untrusted code | Never runs `npm/pip install`, `docker build` or project scripts. All subprocesses: arg lists, `shell=False`, timeouts, `NPM_CONFIG_IGNORE_SCRIPTS=true`. `cdxgen` runs with `--no-install-deps` (its default is to install!). |
| Malicious `.git/config` / `.gitattributes` | Git runs with hooks, fsmonitor, external diff and textconv disabled; the working tree is never diffed (clean filters), history is read via `git show <ref>:<path>`. |
| Commit replay / simulation side effects | No worktree checkouts, no commits, no branches. Simulation uses a temp sandbox (only `package.json` + lockfile) with an `.npmrc` that disables scripts and points at an unroutable registry; deleted afterwards. Payload host uses the reserved `.invalid` TLD. |
| Registry checks | Metadata JSON only; tarballs never downloaded. Package names validated by regex before URL construction. |
| `--resolve-lockfile` (opt-in) | `npm install --package-lock-only --ignore-scripts` on a *copy* of `package.json` in a temp dir; the repo's `.npmrc` is not copied. |
| LLM hallucination | 4 read-only tools only; Elo computed in Python; validator checks file, verbatim snippet (+/-5 lines), purl, graph edges, formula, and an allow-listed fix command; 1 retry then deterministic fallback. |
| Prompt injection via scanned code | Observations fenced as untrusted data; LLM cannot write or execute anything; validator is the actual guarantee. |
| Secret leakage to the LLM | `.env`, keys, `.npmrc`, `encryptionkeys/` etc. unreadable by tools; tokens/private keys redacted from all tool output. |
| Dashboard / API abuse | Binds to 127.0.0.1 (non-loopback needs `--allow-remote`), Host allow-list (DNS rebinding), Origin check + JSON-only POSTs (CSRF), all rendered data HTML-escaped. |

## Known limitations (read before trusting a score)

* **Juice Shop ships no lockfile** (`.npmrc: package-lock=false`). Without `--resolve-lockfile`, only
  direct dependencies are known and semver ranges are approximated by their floor version
  (flagged on each card). Lockfile-hash-mutation checks then only apply to the simulation.
* Reachability is regex/import-based, not a real call graph. It handles direct imports, one
  re-export hop and a curated list of "parent always calls child" pairs (e.g. express -> qs.parse).
  The `-600` "never called" downgrade is the riskiest rule: dynamic dispatch can hide real calls.
  Unknown reachability is scored neutral (0), never downgraded.
* Function-level advisory data is rare for npm, so vulnerable symbols come from a small curated table.
* CVSS is computed from v3 vectors; v4-only advisories fall back to the GHSA severity label (flagged).
* The typosquat list is a curated ~300 names, not a live top-N download ranking.
