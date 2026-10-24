# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-CompleteTech-Commercial
# Copyright (c) 2026 CompleteTech LLC. See LICENSING.md.
"""Synthetic contract regressions, vendorable beside a standalone checker."""
import csv
import io
import json
import os
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest import mock

import next_cache_rce_check as contract


def version_evidence():
    return [{"id": "version-1", "kind": "version", "state": "present", "detail": "Synthetic reported version"}]


def affected(**overrides):
    fields = {"asset_id": "sample-1", "component": "synthetic-component", "rule_id": "SYNTHETIC-ONLY",
              "status": "potentially_affected", "version": "1.2.3", "version_assessment": "affected",
              "evidence": version_evidence(), "sources": ["https://example.com/synthetic-advisory"]}
    fields.update(overrides)
    return contract.make_result(**fields)


def report(result=None, **overrides):
    return contract.make_report("synthetic-check", "0.1.0", "synthetic-1", "2026-10-23",
                                [result or affected()], **overrides)


def synthetic_rule():
    return {"id": "SYNTHETIC-ONLY", "revision": 1, "title": "Synthetic schema fixture; not an advisory",
            "component": "synthetic-component", "advisories": [], "enabled": True,
            "verification_status": "verified", "verified_at": "2026-10-23", "version_scheme": "semver",
            "affected": [{"branch": "1.x", "introduced": "1.0.0", "fixed": "1.2.4", "last_affected": None,
                          "source_ids": ["fixture"]}],
            "preconditions": [{"id": "feature", "description": "Synthetic precondition", "source_ids": ["fixture"]}],
            "mitigations": [], "sources": [{"id": "fixture", "url": "https://example.com/synthetic-advisory",
                                            "publisher": "Synthetic test fixture", "verified_at": "2026-10-23"}],
            "notes": ["This fixture must never be shipped as an active advisory."]}


class ContractSemanticsTests(unittest.TestCase):
    def test_unknown_defaults_do_not_claim_absence_or_exploitability(self):
        result = contract.make_result("sample-1", "synthetic-component", "SYNTHETIC-ONLY")
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["reachability"]["state"], "not_tested")
        self.assertEqual(result["exploitability"], "not_tested")
        self.assertEqual(result["threat"]["kev"]["state"], "unknown")

    def test_forged_exploitability_is_rejected(self):
        value = report()
        value["results"][0]["exploitability"] = "confirmed"
        with self.assertRaises(contract.ContractError):
            contract.validate_report(value)

    def test_version_status_cannot_be_forged_without_consistent_evidence(self):
        for evidence in ([], [{"id": "version-1", "kind": "version", "state": "conflicting", "detail": "Conflict"}],
                         [{"id": "version-1", "kind": "source", "state": "candidate", "detail": "Candidate"}]):
            with self.subTest(evidence=evidence), self.assertRaises(contract.ContractError):
                affected(evidence=evidence)
        with self.assertRaises(contract.ContractError):
            affected(version=None)

    def test_vendor_or_custom_build_cannot_be_cleared_by_upstream_version(self):
        for build in ("vendor", "custom"):
            with self.subTest(build=build), self.assertRaises(contract.ContractError):
                affected(status="fixed_version_reported", version_assessment="fixed_reported", build_source=build)
        value = affected(status="fixed_version_reported", version_assessment="fixed_reported", build_source="unknown")
        self.assertEqual(value["component"]["build_source"], "unknown")
        self.assertEqual(value["exploitability"], "not_tested")

    def test_candidate_source_match_cannot_establish_precondition(self):
        evidence = version_evidence() + [{"id": "source-1", "kind": "source", "state": "candidate",
                                          "detail": "Potential use", "path": "app/page.ts", "line": 8}]
        with self.assertRaises(contract.ContractError):
            affected(status="precondition_present", evidence=evidence,
                     preconditions=[{"id": "feature", "state": "present", "evidence_ids": ["source-1"]}])
        value = affected(evidence=evidence, preconditions=[{"id": "feature", "state": "unknown", "evidence_ids": ["source-1"]}])
        self.assertEqual(value["status"], "potentially_affected")

    def test_precondition_absence_requires_matching_observation(self):
        evidence = version_evidence() + [{"id": "config-1", "kind": "configuration", "state": "unknown", "detail": "Incomplete export"}]
        with self.assertRaises(contract.ContractError):
            affected(evidence=evidence, preconditions=[{"id": "feature", "state": "absent", "evidence_ids": ["config-1"]}])

    def test_likely_exposed_requires_authorized_matching_asset_and_component(self):
        evidence = version_evidence() + [
            {"id": "config-1", "kind": "configuration", "state": "present", "detail": "Required feature configured"},
            {"id": "reach-1", "kind": "reachability", "state": "present", "detail": "Authorized metadata observation"},
        ]
        conditions = [{"id": "feature", "state": "present", "evidence_ids": ["config-1"]}]
        reachability = {"state": "metadata_observed", "authorized": True, "asset_id": "sample-1",
                        "component": "synthetic-component", "evidence_ids": ["reach-1"]}
        valid = affected(status="likely_exposed", evidence=evidence, preconditions=conditions, reachability=reachability)
        self.assertEqual(valid["exploitability"], "not_tested")
        for key, value in (("authorized", False), ("asset_id", "other"), ("component", "other"), ("evidence_ids", ["config-1"])):
            bad = dict(reachability, **{key: value})
            with self.subTest(key=key), self.assertRaises(contract.ContractError):
                affected(status="likely_exposed", evidence=evidence, preconditions=conditions, reachability=bad)

    def test_external_exploitation_never_substitutes_for_reachability(self):
        threat = {"kev": {"state": "listed", "as_of": "2026-10-23", "source": "https://example.com/catalog"},
                  "vendor_exploitation": {"state": "reported", "as_of": "2026-10-23", "source": "https://example.com/advisory"}}
        value = affected(threat=threat)
        self.assertEqual(value["reachability"]["state"], "not_tested")
        self.assertEqual(value["exploitability"], "not_tested")
        with self.assertRaises(contract.ContractError):
            affected(status="likely_exposed", threat=threat)
        threat["kev"]["as_of"] = None
        with self.assertRaises(contract.ContractError):
            affected(threat=threat)

    def test_mitigation_preserves_affected_version_and_needs_evidence(self):
        evidence = version_evidence() + [{"id": "mitigation-1", "kind": "mitigation", "state": "present", "detail": "Synthetic complete configuration"}]
        value = affected(status="mitigated_configuration", evidence=evidence,
                         mitigation={"state": "observed", "evidence_ids": ["mitigation-1"]})
        self.assertEqual(value["version_assessment"], "affected")
        with self.assertRaises(contract.ContractError):
            affected(status="mitigated_configuration", mitigation={"state": "observed", "evidence_ids": []})

    def test_duplicate_and_unresolved_evidence_references_are_rejected(self):
        with self.assertRaises(contract.ContractError):
            affected(evidence=version_evidence() * 2)
        with self.assertRaises(contract.ContractError):
            affected(preconditions=[{"id": "feature", "state": "unknown", "evidence_ids": ["missing"]}])

    def test_closed_schema_rejects_secret_buckets_boolean_integers_and_bad_dates(self):
        for field, value in (("environment", {"TOKEN": "sensitive"}), ("schema_version", "2.0"), ("complete", 1)):
            data = report()
            data[field] = value
            with self.subTest(field=field), self.assertRaises(contract.ContractError):
                contract.validate_report(data)
        data = report()
        data["rules"]["verified_at"] = "2026-02-30"
        with self.assertRaises(contract.ContractError):
            contract.validate_report(data)
        evidence = version_evidence() + [{"id": "source-1", "kind": "source", "state": "candidate", "detail": "Candidate",
                                          "path": "app/page.ts", "line": True}]
        with self.assertRaises(contract.ContractError):
            affected(evidence=evidence)

    def test_unsafe_paths_source_urls_and_terminal_controls_are_rejected(self):
        for path in ("/home/person/app.ts", "../app.ts", "a/../app.ts", "C:/app.ts", "app\\page.ts", "a//b", "a/", "a\n"):
            with self.subTest(path=path), self.assertRaises(contract.ContractError):
                affected(evidence=version_evidence() + [{"id": "source-1", "kind": "source", "state": "candidate",
                                                        "detail": "Candidate", "path": path, "line": 1}])
        for source in ("javascript:alert(1)", "https://user:secret@example.com/advisory", "https://@example.com/x", "https://example.com/?token=secret"):
            with self.subTest(source=source), self.assertRaises(contract.ContractError):
                affected(sources=[source])
        with self.assertRaises(contract.ContractError):
            affected(asset_id="sample-1\n")
        with self.assertRaises(contract.ContractError):
            affected(reasons=["terminal\x1b[31m"])


class RuleAndReportTests(unittest.TestCase):
    def test_enabled_rules_require_verified_boundaries_and_source_references(self):
        contract.validate_rule(synthetic_rule())
        for field, value in (("verification_status", "unverified"), ("sources", []), ("affected", []), ("verified_at", None)):
            rule = synthetic_rule()
            rule[field] = value
            with self.subTest(field=field), self.assertRaises(contract.ContractError):
                contract.validate_rule(rule)
        rule = synthetic_rule()
        rule["preconditions"][0]["source_ids"] = ["unresolved"]
        with self.assertRaises(contract.ContractError):
            contract.validate_rule(rule)

    def test_rule_and_snapshot_dates_are_consistent_and_hash_is_stable(self):
        snapshot = {"schema_version": "1.0", "snapshot_id": "synthetic-1", "created_at": "2026-10-23", "rules": [synthetic_rule()]}
        first = contract.snapshot_digest(snapshot)
        reordered = dict(reversed(list(snapshot.items())))
        self.assertEqual(first, contract.snapshot_digest(reordered))
        snapshot["rules"][0]["revision"] = 2
        self.assertNotEqual(first, contract.snapshot_digest(snapshot))
        snapshot["created_at"] = "2026-10-22"
        with self.assertRaises(contract.ContractError):
            contract.snapshot_digest(snapshot)

    def test_reports_are_deterministic_without_wall_clock_or_input_mutation(self):
        result = affected()
        value = report(result)
        result["reasons"].append("changed later")
        self.assertEqual(value["results"][0]["reasons"], [])
        first = contract.canonical_json(value)
        second = contract.canonical_json(dict(reversed(list(value.items()))))
        self.assertEqual(first, second)
        self.assertNotIn("generated_at", first)

    def test_html_escapes_every_untrusted_text_and_contains_no_external_assets(self):
        result = affected(component='<img src=x onerror="alert(1)">', reasons=["<script>alert(1)</script>"], recommendation='<a href="javascript:x">x</a>')
        rendered = contract.render_html(report(result), brand='<script>alert("brand")</script>')
        self.assertNotIn("<script>", rendered)
        self.assertNotIn("<img src=x", rendered)
        self.assertIn("&lt;script&gt;", rendered)
        self.assertIn("Content-Security-Policy", rendered)
        self.assertNotIn('<script src=', rendered)
        self.assertNotIn('<link ', rendered)

    def test_csv_neutralizes_formulas_and_preserves_assessment_dimensions(self):
        for prefix in ("=", "+", "-", "@", "  ="):
            result = affected(component=prefix + "formula", recommendation=prefix + "formula")
            row = next(csv.DictReader(io.StringIO(contract.render_csv(report(result)))))
            self.assertTrue(row["component"].startswith("'"))
            self.assertTrue(row["recommendation"].startswith("'"))
            self.assertEqual(row["status"], result["status"])
            self.assertEqual(json.loads(row["threat"]), result["threat"])
            self.assertEqual(row["exploitability"], "not_tested")

    def test_incomplete_run_is_visible_in_every_format(self):
        value = report(complete=False, limitations=["Synthetic input limit reached"])
        self.assertFalse(json.loads(contract.canonical_json(value))["complete"])
        self.assertIn("Incomplete assessment", contract.render_html(value))
        row = next(csv.DictReader(io.StringIO(contract.render_csv(value))))
        self.assertEqual(row["complete"], "False")
        self.assertIn("input limit reached", row["limitations"])

    def test_empty_incomplete_csv_has_explicit_summary_record(self):
        value = contract.make_report("synthetic-check", "0.1.0", "synthetic-1", "2026-10-23", [],
                                     complete=False, limitations=["No inputs completed before interruption"])
        row = next(csv.DictReader(io.StringIO(contract.render_csv(value))))
        self.assertEqual(row["record_type"], "summary")
        self.assertEqual(row["complete"], "False")
        self.assertIn("interruption", row["limitations"])

    def test_logo_is_bounded_raster_and_embedded_without_network(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "logo.png"
            path.write_bytes(b"\x89PNG\r\n\x1a\nsynthetic")
            self.assertIn("data:image/png;base64,", contract.render_html(report(), logo=path))
            path.write_bytes(b'<svg xmlns="http://www.w3.org/2000/svg"><script/></svg>')
            with self.assertRaises(contract.ContractError):
                contract.render_html(report(), logo=path)
            path.write_bytes(b"\x89PNG\r\n\x1a\n" + b"a" * (1024 * 1024))
            with self.assertRaises(contract.ContractError):
                contract.render_html(report(), logo=path)


class InputAndOutputTests(unittest.TestCase):
    def test_reader_rejects_duplicates_nonfinite_and_oversize_without_value_disclosure(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "private-secret-filename.json"
            for payload in ('{"secret":1,"secret":2}', '{"secret":NaN}', '{"secret":1e999}', "[" * 100 + "0" + "]" * 100, "{" + "a" * 1000):
                path.write_text(payload, encoding="utf-8")
                with self.subTest(payload=payload[:20]), self.assertRaises(contract.ContractError) as exc:
                    contract.load_json(path, max_bytes=512)
                self.assertNotIn("private-secret-filename", str(exc.exception))
                self.assertNotIn('"secret"', str(exc.exception))

    def test_special_file_and_input_symlink_cannot_block_or_redirect_reader(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source.json"
            source.write_text("{}", encoding="utf-8")
            with self.assertRaises(contract.ContractError):
                contract.load_json(Path(temporary))
            if hasattr(os, "mkfifo"):
                fifo = Path(temporary) / "pipe.json"
                os.mkfifo(fifo)
                with self.assertRaises(contract.ContractError):
                    contract.load_json(fifo)
            link = Path(temporary) / "link.json"
            try:
                link.symlink_to(source)
            except OSError:
                return
            with self.assertRaises(contract.ContractError):
                contract.load_json(link)

    def test_reader_and_reports_need_no_network_or_process(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "sample.json"
            path.write_text(contract.canonical_json(report()), encoding="utf-8")
            with mock.patch("socket.socket", side_effect=AssertionError("network forbidden")), mock.patch("subprocess.Popen", side_effect=AssertionError("process forbidden")):
                value = contract.validate_report(contract.load_json(path))
                contract.render_csv(value)
                contract.render_html(value)

    def test_no_clobber_force_and_protected_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.json"
            contract.save_report(path, "original")
            with self.assertRaises(OSError):
                contract.save_report(path, "replacement")
            self.assertEqual(path.read_text(), "original")
            with self.assertRaises(contract.ContractError):
                contract.save_report(path, "replacement", force=True, protected_paths=[path])
            contract.save_report(path, "replacement", force=True)
            self.assertEqual(path.read_text(), "replacement")
            self.assertEqual(list(Path(temporary).glob(".checker-report-*")), [])

    def test_protected_hardlink_alias_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            original = Path(temporary) / "input.json"
            alias = Path(temporary) / "output.json"
            original.write_text("private source", encoding="utf-8")
            try:
                os.link(original, alias)
            except OSError:
                self.skipTest("filesystem has no hard links")
            with self.assertRaises(contract.ContractError):
                contract.save_report(alias, "replacement", force=True, protected_paths=[original])
            self.assertEqual(original.read_text(), "private source")

    def test_output_symlink_is_rejected_without_following_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            original = Path(temporary) / "input.json"
            alias = Path(temporary) / "output.json"
            original.write_text("private source", encoding="utf-8")
            try:
                alias.symlink_to(original)
            except OSError:
                self.skipTest("symlinks are unavailable")
            with self.assertRaises(contract.ContractError):
                contract.save_report(alias, "replacement", force=True)
            self.assertEqual(original.read_text(), "private source")

    def test_failed_publish_cleans_temporary_file_and_preserves_existing(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.json"
            path.write_text("original", encoding="utf-8")
            with mock.patch.object(contract.os, "replace", side_effect=OSError("synthetic failure")):
                with self.assertRaises(OSError):
                    contract.save_report(path, "replacement", force=True)
            self.assertEqual(path.read_text(), "original")
            self.assertEqual(list(Path(temporary).glob(".checker-report-*")), [])


if __name__ == "__main__":
    unittest.main()
