# Repository instructions

Read [README.md](README.md), [CONTRIBUTING.md](CONTRIBUTING.md), and
[SECURITY.md](SECURITY.md) before changing this project.

## Project map

- `next_cache_rce_check.py`: generated, standalone Python 3.10+ executable.
- `src/checker.py`: product-specific analyzer and CLI.
- `vendor/common.py`: locally vendored canonical contract and output helpers.
- `rules/snapshot.json`: dated, verified GHSA-673q-mjm6-r5xr advisory snapshot.
- `tools/build.py`: deterministic single-file build; `--check` detects stale output.
- `test_*.py`: synthetic, local-only analyzer and contract tests.
- `docs/METHODOLOGY.md`, `docs/REFERENCE.md`, `docs/CONTRACT.md`: scope and formats.
- `examples/synthetic-project`, `docs/example-report.html`: artificial examples only.

## Implementation constraints

This repository covers one exploit/advisory. Keep the shipped Python checker
usable as one file without third-party runtime or test dependencies. Do not
execute project JavaScript, TypeScript, package managers, hooks, configuration,
or Node.js. Do not add network requests, exploit probes, or automatic installs.

Never equate a declaration or source pattern with effective deployed state.
Keep missing, conflicting, qualified, prerelease, malformed, and uncovered-future
versions uncertain. Source matches remain candidates; absent matches do not
prove safety. Exploitability remains `not_tested`, and this lexical checker must
not emit `precondition_present`, `likely_exposed`, or `mitigated_configuration`.
An exact reported fix version is not independent patch attestation.

Bound untrusted reads and traversal. Preserve symlink/special-file exclusions,
secret-minimizing evidence, output escaping, formula-neutralized CSV, protected
inputs, outside-project output destinations, and no-clobber reports. Preserve
completed observations in an incomplete report after an interrupted project scan. Source-only truncation must be visible without
erasing an independently established reported version. Incomplete inventory
must not yield a fixed assessment.

Update thresholds and the snapshot date only after verifying maintainer sources.
Update meaningful boundary tests and documentation together. Edit vendored
helpers locally, review the change, then rebuild; no runtime dependency on
another checker repository is allowed.

## Validation and delivery

```sh
python tools/build.py --check
python -m unittest -v
python next_cache_rce_check.py --help
git diff --check
```

Use synthetic fixtures. Keep private source, credentials, real assessment
reports, and environment information out of commits. Verify CI for the actual
published commit; distinguish local checks from hosted results. Follow
[LICENSING.md](LICENSING.md) and [BRAND_ASSETS.md](BRAND_ASSETS.md).
