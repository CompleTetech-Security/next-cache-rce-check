"""Synthetic run-envelope regressions; no project execution or networking."""
import csv
import hashlib
import io
import json
import socket
import subprocess
import sys
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest import mock

import next_cache_rce_check as check

STAMP = "2026-10-25T12:34:56Z"
DIGEST = "a" * 64


def report(**overrides):
    options = dict(generated_at=STAMP, executable_sha256=DIGEST)
    options.update(overrides)
    return check.assessment([{"location": "node_modules/next", "version": "16.4.0", "path": "", "kind": "reported_version"}], [], **options)


class ProvenanceTests(unittest.TestCase):
    def test_all_formats_retain_canonical_envelope_and_assessment_stays_pure(self):
        with mock.patch.object(socket, "socket", side_effect=AssertionError("offline")):
            first = report()
            second = report(generated_at="2026-10-26T01:02:03Z", executable_sha256="b" * 64)
            self.assertEqual(first["results"], second["results"])
            self.assertEqual(first["rules"], second["rules"])
            self.assertNotEqual(check.canonical_json(first), check.canonical_json(second))
            self.assertEqual(check.canonical_json(first), check.canonical_json(report()))
            for rendered in (check.canonical_json(first), check.render_csv(first), check.render_html(first)):
                for value in (STAMP, DIGEST, first["tool"]["name"], first["tool"]["version"], *first["rules"].values()):
                    self.assertIn(value, rendered)
            row = next(csv.DictReader(io.StringIO(check.render_csv(first))))
            self.assertEqual(row["complete"], "True")
            self.assertEqual(row["rules_sha256"], first["rules"]["sha256"])
            self.assertEqual(row["generated_at"], STAMP)

    def test_empty_complete_and_incomplete_summaries_keep_same_provenance(self):
        for complete in (True, False):
            value = check.make_report("synthetic", "1.0", "snapshot", "2026-10-23", [], complete=complete,
                                      generated_at=STAMP, executable_sha256=DIGEST, snapshot_digest="c" * 64)
            row = next(csv.DictReader(io.StringIO(check.render_csv(value))))
            self.assertEqual(row["record_type"], "summary")
            self.assertEqual(row["generated_at"], STAMP)
            self.assertEqual(row["tool"], "synthetic")
            self.assertEqual(row["executable_sha256"], DIGEST)
            self.assertEqual(row["rules_snapshot_id"], "snapshot")
            self.assertEqual(row["rules_sha256"], "c" * 64)
            self.assertEqual(row["complete"], str(complete))
        value = check.make_report("synthetic", "=synthetic", "snapshot", "2026-10-23", [],
                                  generated_at=STAMP, executable_sha256=DIGEST)
        row = next(csv.DictReader(io.StringIO(check.render_csv(value))))
        self.assertEqual(row["tool_version"], "'=synthetic")

    def test_invalid_or_forged_envelopes_fail_conservatively(self):
        for bad in ("2026-02-30T12:00:00Z", "2026-10-25", "2026-10-25T12:00:00+00:00", "2026-10-25T12:00:00Z\n"):
            with self.subTest(bad=bad), self.assertRaises(check.ContractError):
                report(generated_at=bad)
        for bad in ("", "A" * 64, "=synthetic", "a" * 63):
            with self.subTest(bad=bad), self.assertRaises(check.ContractError):
                report(executable_sha256=bad)
        for field in ("generated_at", "tool"):
            value = deepcopy(report())
            del value[field]
            with self.assertRaises(check.ContractError):
                check.canonical_json(value)

    def test_cli_captures_one_context_before_interrupted_inventory(self):
        progress = ([], [], False, ["Synthetic interruption"], [], False)
        with mock.patch.object(check, "utc_now", return_value=STAMP) as clock, \
             mock.patch.object(check, "executable_digest", return_value=DIGEST) as digest, \
             mock.patch.object(check, "inventory_project", side_effect=check.ScanInterrupted(progress)), \
             mock.patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(check.main(["synthetic-project", "--format", "json"]), 130)
        value = json.loads(output.getvalue())
        self.assertFalse(value["complete"])
        self.assertEqual(value["generated_at"], STAMP)
        self.assertEqual(value["tool"]["executable_sha256"], DIGEST)
        clock.assert_called_once_with()
        digest.assert_called_once_with()

    def test_default_digest_identifies_actual_standalone_bytes_and_schema_matches(self):
        value = report(executable_sha256=None)
        self.assertEqual(value["tool"]["executable_sha256"], hashlib.sha256(Path(check.__file__).read_bytes()).hexdigest())
        exported = json.loads(Path("schemas/report-v1.schema.json").read_text(encoding="utf-8"))
        exported.pop("$id")
        exported.pop("$schema")
        self.assertEqual(exported, check.REPORT_SCHEMA)

    def test_missing_executable_identity_fails_as_operational_error(self):
        with mock.patch.object(check, "executable_digest", side_effect=OSError("synthetic")), \
             mock.patch("sys.stderr", new_callable=io.StringIO) as error:
            self.assertEqual(check.main(["--next-version", "16.4.0"]), 2)
        self.assertNotIn("synthetic", error.getvalue())

    def test_copied_standalone_digest_tracks_replaced_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "standalone.py"
            original = Path(check.__file__).read_bytes()
            script.write_bytes(original)
            first = self.run_standalone(script)
            script.write_bytes(original + b"\n# Synthetic replacement bytes\n")
            second = self.run_standalone(script)
            self.assertEqual(first["results"], second["results"])
            self.assertNotEqual(first["tool"]["executable_sha256"], second["tool"]["executable_sha256"])

    def test_installed_symlink_hashes_executing_target_without_relaxing_input_reader(self):
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "standalone.py"
            script.write_bytes(Path(check.__file__).read_bytes())
            link = Path(directory) / "installed.py"
            try:
                link.symlink_to(script)
            except (OSError, NotImplementedError):
                self.skipTest("Executable symlinks unavailable on this platform")
            self.run_standalone(link)
            with self.assertRaises(check.ContractError):
                check._read_regular_file(link, check.MAX_JSON_BYTES)

    def run_standalone(self, script):
        run = subprocess.run([sys.executable, str(script), "--next-version", "16.4.0", "--format", "json"],
                             capture_output=True, text=True, timeout=20, cwd=script.parent)
        self.assertEqual(run.returncode, 0, run.stderr)
        result = json.loads(run.stdout)
        self.assertEqual(result["tool"]["executable_sha256"], hashlib.sha256(script.read_bytes()).hexdigest())
        return result


if __name__ == "__main__":
    unittest.main()
