"""Synthetic, offline regression cases. No target code is executed."""
import contextlib
import csv
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import next_cache_rce_check as check


def npm(version="16.4.0", lock_version=3):
    if lock_version == 1:
        return {"lockfileVersion": 1, "dependencies": {"next": {"version": version}}}
    return {"lockfileVersion": lock_version, "packages": {"": {"name": "synthetic"}, "node_modules/next": {"version": version}}}


def observation(version="16.4.0", path="package-lock.json", location="node_modules/next"):
    return {"location": location, "version": version, "path": path, "kind": "lockfile"}


class VersionTests(unittest.TestCase):
    def test_boundaries(self):
        for value in ("16.0.0", "16.3.9", "16.4.0"):
            with self.subTest(value=value):
                self.assertEqual("potentially_affected", check.classify_version(value)[0])
        for value in ("16.4.1", "16.4.2"):
            with self.subTest(value=value):
                self.assertEqual("fixed_version_reported", check.classify_version(value)[0])

    def test_unknown_versions(self):
        for value in (None, "", 16, True, "16.4", "v16.4.1", "016.4.1", "16.4.1-rc.1", "16.4.1+vendor", "^16.4.1", ">=16.4.1", "15.5.0", "17.0.0", "16.5.0", "9" * 200):
            with self.subTest(value=value):
                self.assertEqual("unknown", check.classify_version(value)[0])

    def test_conflicting_versions_never_fixed(self):
        report = check.assessment([observation("16.4.0"), observation("16.4.1", "npm-shrinkwrap.json")], [])
        result = report["results"][0]
        self.assertEqual("unknown", result["status"])
        self.assertEqual("unknown", result["version_assessment"])
        self.assertIsNone(result["component"]["version"])

    def test_distinct_nested_installations(self):
        report = check.assessment([observation("16.4.0"), observation("16.4.1", location="node_modules/parent/node_modules/next")], [])
        self.assertEqual(2, len(report["results"]))
        self.assertEqual({"potentially_affected", "fixed_version_reported"}, {r["status"] for r in report["results"]})

    def test_source_context_is_not_attached_to_nested_copy(self):
        candidates = check.source_candidates("export default {cacheComponents:true};", "next.config.ts")
        report = check.assessment([observation("16.4.0", location="node_modules/parent/node_modules/next")], candidates)
        self.assertFalse(any(e["state"] == "candidate" for e in report["results"][0]["evidence"]))

    def test_snapshot_is_verified_and_reproducible(self):
        check.validate_snapshot(check.RULE_SNAPSHOT)
        report = check.assessment([observation()], [])
        self.assertEqual(check.snapshot_digest(check.RULE_SNAPSHOT), report["rules"]["sha256"])


class LockTests(unittest.TestCase):
    def test_supported_versions(self):
        for version in (1, 2, 3):
            with self.subTest(version=version):
                self.assertEqual(["16.4.0"], [v["version"] for v in check.lock_observations(npm(lock_version=version), "package-lock.json")])

    def test_v1_nested_dependency(self):
        data = npm(lock_version=1)
        data["dependencies"]["parent"] = {"version": "1.0.0", "dependencies": {"next": {"version": "16.4.1"}}}
        values = check.lock_observations(data, "package-lock.json")
        self.assertEqual({"node_modules/next", "node_modules/parent/node_modules/next"}, {v["location"] for v in values})

    def test_v2_disagreement_retained(self):
        data = npm(lock_version=2)
        data["dependencies"] = {"next": {"version": "16.4.1"}}
        report = check.assessment(check.lock_observations(data, "package-lock.json"), [])
        self.assertEqual("unknown", report["results"][0]["status"])

    def test_v2_duplicate_agreement(self):
        data = npm(lock_version=2)
        data["dependencies"] = {"next": {"version": "16.4.0"}}
        report = check.assessment(check.lock_observations(data, "package-lock.json"), [])
        self.assertEqual("potentially_affected", report["results"][0]["status"])

    def test_link_is_not_an_exact_version(self):
        data = npm()
        data["packages"]["node_modules/next"]["link"] = True
        self.assertIsNone(check.lock_observations(data, "package-lock.json")[0]["version"])

    def test_explicit_wrong_package_identity_is_rejected(self):
        data = npm("16.4.1")
        data["packages"]["node_modules/next"]["name"] = "other-package"
        with self.assertRaises(check.ScanInputError):
            check.lock_observations(data, "package-lock.json")

    def test_canonical_next_alias_is_preserved(self):
        for lock_version in (1, 2, 3):
            data = npm("16.4.1", lock_version)
            if lock_version == 1:
                data["dependencies"]["other-next"] = {"version": "npm:next@16.4.0"}
            else:
                data["packages"]["node_modules/other-next"] = {"version": "npm:next@16.4.0"}
            with self.subTest(lock_version=lock_version):
                report = check.assessment(check.lock_observations(data, "package-lock.json"), [])
                self.assertEqual({"fixed_version_reported", "potentially_affected"}, {r["status"] for r in report["results"]})

    def test_declared_package_name_identifies_v3_alias(self):
        data = npm("16.4.1")
        data["packages"]["node_modules/other-next"] = {"name": "next", "version": "16.4.0"}
        observed = check.lock_observations(data, "package-lock.json")
        self.assertIn(("node_modules/other-next", "16.4.0"), {(o["location"], o["version"]) for o in observed})

    def test_malformed_lock(self):
        for data in ({"lockfileVersion": 4}, {"lockfileVersion": True}, {"lockfileVersion": 3, "packages": []}, {"lockfileVersion": 1, "dependencies": []}):
            with self.subTest(data=data), self.assertRaises(check.ScanInputError):
                check.lock_observations(data, "package-lock.json")

    def test_unsafe_lock_locations_rejected(self):
        data = npm()
        data["packages"]["../node_modules/next"] = {"version": "16.4.0"}
        with self.assertRaises(check.ScanInputError):
            check.lock_observations(data, "package-lock.json")

    def test_json_ambiguous_or_nonfinite_rejected(self):
        for value in ('{"x":1,"x":2}', '{"x":NaN}', '[1]', '{"x":Infinity}', '{"x":1e999}', "not JSON"):
            with self.subTest(value=value), self.assertRaises(check.ScanInputError):
                check.strict_json(value)

    def test_json_structure_is_bounded_even_in_unused_metadata(self):
        value = {"unused": {"next": [0]}}
        with patch.object(check, "MAX_JSON_DEPTH", 2), self.assertRaises(check.ScanInputError):
            check.strict_json(json.dumps(value))
        with patch.object(check, "MAX_JSON_NODES", 3), self.assertRaises(check.ScanInputError):
            check.strict_json(json.dumps(value))

    def test_nested_dependency_bound(self):
        data = npm(lock_version=1)
        cursor = data["dependencies"]
        for _ in range(check.MAX_DEPTH + 2):
            cursor["p"] = {"dependencies": {}}
            cursor = cursor["p"]["dependencies"]
        with self.assertRaises(check.ScanInputError):
            check.lock_observations(data, "package-lock.json")


class SourceTests(unittest.TestCase):
    def conditions(self, text, path="app/page.ts"):
        return [v["condition"] for v in check.source_candidates(text, path)]

    def test_same_function_typed_array_return(self):
        text = "export async function data() {\n'use cache';\nreturn [new Uint8Array(1), new Uint16Array(2)];\n}"
        found = check.source_candidates(text, "app/page.ts")
        self.assertIn("multiple-typed-array-return", [v["condition"] for v in found])
        self.assertEqual(3, next(v["line"] for v in found if v["condition"] == "multiple-typed-array-return"))

    def test_arrow_function_body(self):
        text = "const data = async () => { 'use cache'; return {a:new Uint8Array(1), b:new Float32Array(1)}; };"
        self.assertIn("multiple-typed-array-return", self.conditions(text))

    def test_typescript_return_annotation(self):
        text = "export async function data(): Promise<Uint8Array[]> { 'use cache'; return [new Uint8Array(1),new Uint8Array(2)]; }"
        self.assertIn("multiple-typed-array-return", self.conditions(text))

    def test_template_interpolation_requires_ast_review(self):
        text = "const x = " + chr(96) + "$" + "{value}" + chr(96) + ";"
        with self.assertRaises(check.ScanInputError):
            check.source_candidates(text, "app/page.ts")

    def test_file_directive_exported_function(self):
        text = "'use cache'; export async function data() { return [new Uint8Array(1),new Uint8Array(1)]; }"
        self.assertIn("multiple-typed-array-return", self.conditions(text))

    def test_file_directive_does_not_mark_private_function(self):
        text = "'use cache'; async function privateData() { return [new Uint8Array(1),new Uint8Array(1)]; }"
        self.assertNotIn("multiple-typed-array-return", self.conditions(text))

    def test_comments_strings_templates_and_regex_are_opaque(self):
        pieces = [
            "// 'use cache'; return [new Uint8Array(1),new Uint8Array(1)];",
            "/* function data(){'use cache'; return [new Uint8Array(1),new Uint8Array(1)]} */",
            "const text = \"'use cache'; return [new Uint8Array(1),new Uint8Array(1)]\";",
            "const text = " + chr(96) + "'use cache'; return [new Uint8Array(1),new Uint8Array(1)]" + chr(96) + ";",
            "const pattern = /use cache.*new Uint8Array.*new Uint8Array/;"
        ]
        for source in pieces:
            with self.subTest(source=source):
                self.assertEqual([], self.conditions(source))

    def test_ambiguous_statement_regex_requires_review(self):
        text = 'if (ready) /function fake(){ "use cache"; return [new Uint8Array(1),new Uint8Array(1)] }/.test(text);'
        with self.assertRaises(check.ScanInputError):
            self.conditions(text)

    def test_unrelated_functions_do_not_combine(self):
        text = "async function one(){'use cache'; return 1;} function two(){return [new Uint8Array(1),new Uint8Array(1)];}"
        self.assertNotIn("multiple-typed-array-return", self.conditions(text))

    def test_nested_function_does_not_combine(self):
        text = "async function outer(){'use cache'; function inner(){return [new Uint8Array(1),new Uint8Array(1)];} return inner;}"
        self.assertNotIn("multiple-typed-array-return", self.conditions(text))

    def test_nested_concise_arrow_does_not_combine(self):
        text = "async function outer(){'use cache'; return () => [new Uint8Array(1),new Uint8Array(1)];}"
        self.assertNotIn("multiple-typed-array-return", self.conditions(text))

    def test_separate_returns_do_not_combine(self):
        text = "async function one(){'use cache'; if(x)return new Uint8Array(1); return new Uint8Array(2);}"
        self.assertNotIn("multiple-typed-array-return", self.conditions(text))

    def test_unrelated_locals_do_not_combine(self):
        text = "async function one(){'use cache'; const x=new Uint8Array(1); const y=new Uint8Array(1); return 3;}"
        self.assertNotIn("multiple-typed-array-return", self.conditions(text))

    def test_return_newline_asi(self):
        text = "async function one(){'use cache'; return\n[new Uint8Array(1),new Uint8Array(1)];}"
        self.assertNotIn("multiple-typed-array-return", self.conditions(text))

    def test_asi_terminated_return_does_not_capture_later_declaration(self):
        text = 'async function cached(){"use cache"; return value\nconst unrelated=[new Uint8Array(1),new Uint8Array(1)];}'
        self.assertNotIn("multiple-typed-array-return", self.conditions(text))

    def test_string_is_not_a_directive_outside_prologue(self):
        text = "async function one(){const s='use cache';return [new Uint8Array(1),new Uint8Array(1)];}"
        self.assertEqual([], self.conditions(text))

    def test_config_false_and_dynamic_are_only_candidates(self):
        for value, label in (("false", "disabled"), ("true", "enabled"), ("process.env.CACHE", "dynamic")):
            found = check.source_candidates("export default {cacheComponents:" + value + "};", "next.config.ts")
            self.assertIn(label, found[0]["detail"])
            report = check.assessment([observation()], found)
            self.assertEqual("potentially_affected", report["results"][0]["status"])
            self.assertTrue(all(p["state"] == "unknown" for p in report["results"][0]["preconditions"]))
            self.assertEqual("unknown", report["results"][0]["mitigation"]["state"])

    def test_configuration_comments_not_settings(self):
        self.assertEqual([], self.conditions("// cacheComponents: true\nconst x='cacheComponents:true';", "next.config.js"))

    def test_ambiguous_return_is_unknown(self):
        found = check.source_candidates("async function x(){'use cache';return values;}", "lib.ts")
        report = check.assessment([observation()], found)
        self.assertEqual("potentially_affected", report["results"][0]["status"])
        self.assertNotIn("multiple-typed-array-return", [r["condition"] for r in found])

    def test_malformed_and_bounded_source(self):
        for text in ("/* unfinished", "const s='unfinished", "function x(){", "(" * 257 + ")" * 257):
            with self.subTest(text=text[:30]), self.assertRaises(check.ScanInputError):
                check.source_candidates(text, "src.js")


class ProjectTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)

    def put(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content if isinstance(content, str) else json.dumps(content), encoding="utf-8")
        return path

    def scan(self):
        obs, candidates, complete, limits, _, inventory_complete = check.inventory_project(self.root)
        return check.assessment(obs, candidates, complete=complete, inventory_complete=inventory_complete, limitations=limits)

    def test_full_synthetic_project(self):
        self.put("package-lock.json", npm())
        self.put("next.config.ts", "export default {cacheComponents:true};")
        self.put("app/page.tsx", "export default async function Page(){'use cache';return [new Uint8Array(1),new Uint8Array(2)];}")
        result = self.scan()["results"][0]
        self.assertEqual("potentially_affected", result["status"])
        self.assertEqual("not_tested", result["exploitability"])
        self.assertEqual("not_tested", result["reachability"]["state"])
        self.assertTrue(all(p["evidence_ids"] for p in result["preconditions"]))

    def test_app_router_file_context_survives_unsupported_jsx(self):
        self.put("package-lock.json", npm())
        self.put("app/page.tsx", "export default function Page(){return <p>synthetic</p>;}")
        report = self.scan()
        self.assertFalse(report["complete"])
        condition = next(p for p in report["results"][0]["preconditions"] if p["id"] == "app-router")
        self.assertTrue(condition["evidence_ids"])
        self.assertEqual("unknown", condition["state"])

    def test_declarations_never_become_installed_version(self):
        for value in ("^16.4.0", "16.4.1"):
            self.put("package.json", {"dependencies": {"next": value}})
            self.assertEqual("unknown", self.scan()["results"][0]["status"])

    def test_installed_metadata_and_conflict(self):
        self.put("node_modules/next/package.json", {"name": "next", "version": "16.4.0"})
        self.assertEqual("potentially_affected", self.scan()["results"][0]["status"])
        self.put("package-lock.json", npm("16.4.1"))
        self.assertEqual("unknown", self.scan()["results"][0]["status"])

    def test_unsupported_lock_is_visible_and_blocks_fixed(self):
        self.put("package-lock.json", npm("16.4.1"))
        self.put("pnpm-lock.yaml", "ignored: deliberately")
        report = self.scan()
        self.assertFalse(report["complete"])
        self.assertEqual("unknown", report["results"][0]["status"])
        self.assertIn("unsupported", " ".join(report["limitations"]))

    def test_no_source_secrets_or_absolute_paths(self):
        secret = "SYNTHETIC_SECRET_DO_NOT_COPY"
        self.put("package-lock.json", npm("https://token:" + secret + "@example.test/16.4.1"))
        self.put(".env", secret)
        self.put("app/page.ts", "// " + secret + "\nexport default function Page(){return null;}")
        output = check.canonical_json(self.scan())
        self.assertNotIn(secret, output)
        self.assertNotIn(str(self.root), output)

    def test_symlinks_are_not_followed(self):
        self.put("package-lock.json", npm("16.4.1"))
        target = self.put("target.txt", "export default {cacheComponents:true}")
        try:
            (self.root / "next.config.js").symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("Symlinks unavailable on this runner.")
        report = self.scan()
        self.assertFalse(report["complete"])
        self.assertEqual("fixed_version_reported", report["results"][0]["status"])

    def test_inventory_symlink_blocks_fixed_assessment(self):
        self.put("package-lock.json", npm("16.4.1"))
        target = self.put("declared.txt", {"dependencies": {"next": "16.4.0"}})
        try:
            (self.root / "package.json").symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("Symlinks unavailable on this runner.")
        report = self.scan()
        self.assertFalse(report["complete"])
        self.assertEqual("unknown", report["results"][0]["status"])

    @unittest.skipUnless(hasattr(os, "mkfifo"), "POSIX FIFO case")
    def test_fifo_source_is_not_opened(self):
        os.mkfifo(self.root / "source.js")
        self.assertFalse(self.scan()["complete"])

    def test_byte_and_file_limits(self):
        self.put("package-lock.json", npm("16.4.1"))
        self.put("large.js", "x" * 50)
        with patch.object(check, "MAX_SOURCE_BYTES", 20):
            report = self.scan()
            self.assertFalse(report["complete"])
            self.assertEqual("fixed_version_reported", report["results"][0]["status"])
        with patch.object(check, "MAX_FILES", 0):
            self.assertFalse(self.scan()["complete"])

    def test_deterministic_json_and_renderers(self):
        self.put("package-lock.json", npm())
        report = self.scan()
        self.assertEqual(check.canonical_json(report), check.canonical_json(self.scan()))
        data = list(csv.DictReader(io.StringIO(check.render_csv(report))))
        self.assertEqual(report["results"][0]["status"], data[0]["status"])
        html = check.render_html(report, brand="<script>SYNTHETIC</script>")
        self.assertNotIn("<script>", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("potentially_affected", html)

    def run_main(self, args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = check.main(args)
        return code, out.getvalue(), err.getvalue()

    def test_cli_findings_and_unknown_exit_codes(self):
        self.assertEqual(0, self.run_main(["--next-version", "16.4.0"])[0])
        self.assertEqual(1, self.run_main(["--next-version", "16.4.0", "--fail-on-finding"])[0])
        self.assertEqual(0, self.run_main(["--next-version", "16.4.1", "--fail-on-finding"])[0])
        self.assertEqual(1, self.run_main(["--next-version", "custom", "--fail-on-unknown"])[0])

    def test_output_overwrite_and_input_protection(self):
        source = self.put("package-lock.json", npm())
        output_directory = tempfile.TemporaryDirectory()
        self.addCleanup(output_directory.cleanup)
        output = Path(output_directory.name) / "report.json"
        args = [str(self.root), "--output", str(output)]
        self.assertEqual(0, self.run_main(args)[0])
        self.assertEqual(2, self.run_main(args)[0])
        self.assertEqual(0, self.run_main(args + ["--force"])[0])
        original = source.read_text()
        self.assertEqual(2, self.run_main([str(self.root), "--output", str(source), "--force"])[0])
        self.assertEqual(original, source.read_text())

    def test_output_cannot_overwrite_unscanned_project_file(self):
        secret = self.put(".env", "SYNTHETIC_DO_NOT_OVERWRITE")
        code, _, _ = self.run_main([str(self.root), "--next-version", "16.4.1", "--output", str(secret), "--force"])
        self.assertEqual(2, code)
        self.assertEqual("SYNTHETIC_DO_NOT_OVERWRITE", secret.read_text())

    def test_interrupted_source_scan_preserves_inventory(self):
        self.put("package-lock.json", npm("16.4.1"))
        self.put("source.js", "const value = 1;")
        with patch.object(check, "source_candidates", side_effect=KeyboardInterrupt):
            code, output, _ = self.run_main([str(self.root)])
        report = json.loads(output)
        self.assertEqual(130, code)
        self.assertFalse(report["complete"])
        self.assertEqual("fixed_version_reported", report["results"][0]["status"])

    def test_interrupted_inventory_retains_observation_without_fixed_claim(self):
        self.put("package-lock.json", npm("16.4.1"))
        self.put("npm-shrinkwrap.json", npm("16.4.0"))
        original = check.bounded_text
        def interrupt_second(root, relative, limit):
            if relative == "npm-shrinkwrap.json":
                raise KeyboardInterrupt
            return original(root, relative, limit)
        with patch.object(check, "bounded_text", side_effect=interrupt_second):
            code, output, _ = self.run_main([str(self.root)])
        report = json.loads(output)
        self.assertEqual(130, code)
        self.assertFalse(report["complete"])
        self.assertEqual("16.4.1", report["results"][0]["component"]["version"])
        self.assertEqual("unknown", report["results"][0]["status"])

    def test_invalid_source_still_protected_from_overwrite(self):
        source = self.put("package-lock.json", "malformed")
        self.assertEqual(2, self.run_main([str(self.root), "--output", str(source), "--force"])[0])
        self.assertEqual("malformed", source.read_text())

    def test_logo_is_protected_from_output_overwrite(self):
        logo = self.root / "logo.png"
        original = b"\x89PNG\r\n\x1a\nSYNTHETIC"
        logo.write_bytes(original)
        code, _, _ = self.run_main(["--next-version", "16.4.1", "--format", "html", "--logo", str(logo), "--output", str(logo), "--force"])
        self.assertEqual(2, code)
        self.assertEqual(original, logo.read_bytes())

    def test_incomplete_cli_produces_report_and_operational_status(self):
        self.put("package-lock.json", "malformed")
        code, output, _ = self.run_main([str(self.root)])
        self.assertEqual(2, code)
        self.assertFalse(json.loads(output)["complete"])

    def test_offline_no_process_or_network(self):
        self.put("package-lock.json", npm())
        self.put("next.config.js", "throw new Error('THIS MUST NEVER RUN'); export default {cacheComponents:true};")
        with patch("socket.socket", side_effect=AssertionError("network")), patch("subprocess.Popen", side_effect=AssertionError("process")):
            self.assertEqual("potentially_affected", self.scan()["results"][0]["status"])


if __name__ == "__main__":
    unittest.main()
