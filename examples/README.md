# Synthetic example

`synthetic-project` contains artificial npm metadata and source patterns for an
offline demonstration. It has no credentials, real target data, or exploit
payload. Its abbreviated lockfile is not a production dependency installation.
Do not install or deploy this fixture.

From the repository root:

```sh
python next_cache_rce_check.py examples/synthetic-project --asset-id synthetic-demo
python next_cache_rce_check.py examples/synthetic-project --asset-id synthetic-demo --format html --logo assets/logo.png --output example.html
```

Expect `potentially_affected`, candidate evidence for all four preconditions,
and `exploitability: not_tested`. The checked-in
[example report](../docs/example-report.html) uses only this fixture.
