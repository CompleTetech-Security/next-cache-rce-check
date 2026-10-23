# Contributing

Open an issue for a focused bug or improvement, then submit a pull request.
For a flaw in this checker, follow [SECURITY.md](SECURITY.md).

## Development

Python 3.10+ is sufficient. No third-party Python packages, JavaScript runtime,
package install, network connection, or shared checker repository is required.

```sh
python tools/build.py
python tools/build.py --check
python -m unittest -v
python next_cache_rce_check.py --help
git diff --check
```

Edit `src/checker.py`, `vendor/common.py`, or `rules/snapshot.json`, then rebuild
the committed executable. Keep meaningful tests for version boundaries,
conflicting inventory, lexical context, incomplete coverage, output protection,
and report semantics. Do not add tests that merely assert prose.

Advisory changes must cite primary maintainer evidence and update the snapshot,
methodology, and boundary cases together. Candidate syntax is not execution or
deployment evidence. Preserve `exploitability: not_tested` and all explicit
uncertainty. This checker must not install dependencies, invoke package-manager
commands, import project modules, or contact target systems.

Reduce reported cases to synthetic fixtures. Do not commit real project data,
credentials, source snippets from private projects, or real assessment reports.
Keep CLI, schemas, examples, and documentation aligned. Follow [AGENTS.md](AGENTS.md).

## Licensing of contributions

next-cache-rce-check follows the AGPL-3.0 / commercial model described in
[LICENSING.md](LICENSING.md). By submitting a contribution, you confirm that you
have the right to submit it. You license it to the public under AGPL-3.0 and
grant CompleteTech LLC a perpetual, worldwide, royalty-free, irrevocable license
to use, modify, sublicense, and distribute it under any license, including a
commercial license. You keep the copyright in your contribution.
