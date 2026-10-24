# CLI and input reference

Requires Python **3.10+**, using only the standard library.

```text
python next_cache_rce_check.py [PROJECT] [--next-version VERSION ...]
    [--asset-id LABEL] [--format {json,csv,html}] [--output PATH] [--force]
    [--brand NAME] [--logo PATH] [--fail-on-finding] [--fail-on-unknown]
```

`--help` shows available arguments and `--version` prints the tool version.
Supply an explicit project or at least one reported version. The current
directory is never scanned by default. Paths are local; URLs are not inputs.

## Arguments

| Argument | Behavior |
| --- | --- |
| `PROJECT` | Stable project root directory. Root symlinks are rejected. Inspect each application separately. |
| `--next-version` | An observation about the root Next.js instance. Repeat to preserve multiple observations; disagreement is unknown. |
| `--asset-id` | Non-sensitive label, 1–80 ASCII letters/digits/dot/colon/hyphen/underscore, starting with letter/digit. Default `project`. |
| `--format` | JSON (default), CSV, or self-contained HTML. All derive from the same canonical report. |
| `--output` | Destination outside the assessed project directory; otherwise stdout. The parent directory must already exist. |
| `--force` | Replace an existing report atomically outside the project tree. Never overwrite scanned inputs, the running executable, or a supplied logo. Symlink outputs are rejected. |
| `--brand` | HTML report display name, escaped as text. Default `CompleteTech LLC`. |
| `--logo` | Optional local PNG/JPEG/GIF/WebP, bounded to 1 MiB, embedded into HTML. No remote image is fetched. |
| `--fail-on-finding` | Completed report exits 1 when any result is `potentially_affected`. |
| `--fail-on-unknown` | Completed report exits 1 when any result is `unknown`. |

Exit 0 means processing completed under the selected policy. Exit 1 is a
requested policy failure, exit 2 is invalid input, operational failure, or
incomplete coverage, and exit 130 is interruption. Exit 2 takes precedence over
exit 1. Incomplete and interrupted project scans preserve completed observations
in a report with `complete: false`. An interrupt during inventory leaves
inventory incomplete; an interrupt during source-only analysis retains the
independently established version assessment. Root validation failures, output
errors, or interruption during output may prevent report creation.

## Files inspected

At the project root the checker reads existing `package-lock.json`,
`npm-shrinkwrap.json`, and `package.json`. It additionally reads direct
`node_modules/next/package.json` if present. npm lock versions 1, 2, and 3 are
supported. Canonical `npm:next@VERSION` aliases and entries explicitly named
`next` are retained under their actual package locations; contradictory explicit
package identities are rejected. Linked package entries have no trusted exact
version. Nested Next.js
lockfile instances receive distinct results, but nested installed package trees
and workspace relationships are not traversed.

Existing `yarn.lock`, `pnpm-lock.yaml`, `bun.lock`, and `bun.lockb` are reported
as unsupported without parsing their contents. A separate `--next-version`
invocation can assess an independently verified version. Adding a reported
version to an incomplete project scan does not conceal unsupported inventory.

The source walker recognizes `.js`, `.jsx`, `.ts`, `.tsx`, `.mjs`, `.cjs`, `.mts`,
and `.cts`. It skips directories named `node_modules`, `.git`, `.next`, `dist`,
`build`, `coverage`, `.turbo`, and `.cache`. It does not implement `.gitignore`
semantics; source files elsewhere under the root may be inspected. Conventional
App Router context requires page/layout/route filenames under `app` or `src/app`.
Configuration candidates come from `next.config.js`, `.mjs`, `.cjs`, `.ts`, or
`.mts` at any inspected source location; they are not assumed effective.

## Bounds and uncertainty

| Bound | Maximum |
| --- | --- |
| Each JSON input | 4 MiB |
| JSON nesting / nodes | 40 levels / 200,000 nodes, including unused metadata |
| Each source input | 1 MiB |
| Total decoded UTF-8 input bytes | 16 MiB |
| Source files | 500 |
| Directory entries / lockfile package entries | 10,000 each |
| Directory / v1 dependency depth | 20 |
| Source tokens | 100,000 per file |
| Delimiter nesting | 256 |
| Function contexts | 1,000 per source file |
| Dependency observations | 256 total |
| Source candidates | 700 total |
| Evidence references per condition | 100, while all bounded candidate evidence remains in the result |
| Relative path | 240 characters, without control characters, backslashes, colon, or traversal |

Reaching a bound, unreadable files, malformed JSON, lexical failures, excluded
symlinks, or non-regular source files produces explicit incomplete coverage.
Duplicate JSON keys and non-finite numbers are rejected. The lexer rejects
unterminated literals, template interpolation, and ambiguous slash contexts
(including JSX closing tags and possible statement-level regular expressions). Unsupported or ambiguous
syntax is never proof that a vulnerable path is absent.

The scanner expects a stable directory tree. Its path checks and regular-file
reads prevent ordinary symlink traversal but cannot provide full isolation from
an adversary racing changes in ancestor directories. A stable copy is the
appropriate inspection boundary.

## Canonical output

The [report contract](CONTRACT.md) defines schema version 1.0 and the
[JSON Schema](../schemas/report-v1.schema.json) describes the serialized shape.
Validation additionally enforces evidence references, date/URL/path semantics,
status prerequisites, and the invariant `exploitability: not_tested`.

The report includes tool version, snapshot ID, verification date, canonical
snapshot SHA-256, completeness, limitations, and results. Each result separates
reported version, candidate evidence, precondition states, mitigation,
reachability, and external threat evidence. A stable SHA-256-derived location
suffix distinguishes dependency instances within the caller's asset label.

JSON is deterministic for the same inputs and snapshot; it contains no scan-time
clock or host identity. CSV adds a `record_type` column and repeats essential
report metadata. HTML escapes text, embeds optional local raster branding, uses
a restrictive content security policy, and needs no script or network resource.
The CSV renderer neutralizes formula-like cell prefixes before export.

Only controlled descriptions, exact accepted versions, relative paths/lines, and
the caller's asset label are emitted. Source text, package URLs, malformed
version values, absolute paths, and environment data are not copied. File names
and labels may still be sensitive. Store real reports outside this repository.
