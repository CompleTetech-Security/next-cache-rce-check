# Security evidence contract v1.0

Each checker repository owns its implementation, embedded advisory snapshot,
and copy of this contract. The executable is self-contained and does not import
another checker repository or a hosted rules service. The helpers are vendored
source, not a mandatory shared runtime.

## Scope and trust

The contract separates reported component versions, configuration observations,
candidate source patterns, mitigation, authorized reachability, and external
threat reports. Local `exploitability` is always `not_tested`.

An inventory or source scan is evidence supplied by the operator. A valid
document does not establish that the evidence describes production, that the
observations are authentic, or that a vulnerability can be exploited. Validation
checks data shape and internal consistency; it does not authenticate evidence.

The product-specific classifier must implement the advisory's exact version
scheme, covered release branches, product/edition/platform restrictions,
effective configuration defaults, and required preconditions. The shared
validator deliberately does not assume that every vendor build is a semantic
version or determine whether a reported version was ever released.

## Result document

The top level has exactly these fields:

| Field | Meaning |
| --- | --- |
| `schema_version` | Constant string `1.0`. |
| `tool` | Checker name, tool version, and required lowercase `executable_sha256` identifying standalone executable bytes. |
| `generated_at` | Real UTC run-generation timestamp in `YYYY-MM-DDTHH:MM:SSZ`; not acquisition time or deployed-patch attestation. |
| `rules` | Snapshot ID, verification date, and canonical snapshot SHA-256 or `null` when unavailable. |
| `complete` | Whether the intended input set was assessed without interruption or scan limits. |
| `limitations` | Controlled descriptions of skipped inputs, unsupported formats, truncation, or incomplete coverage. |
| `results` | Ordered component/rule assessments, including unknown results. |

Unknown fields are rejected. Unsupported schema versions are operational errors,
not a reason to reinterpret the input as a different format. Dates use real
`YYYY-MM-DD` calendar dates. The envelope generates a UTC run timestamp unless
one is explicitly injected; timestamps and executable digests are validated.
These required envelope fields extend the closed schema, so strict consumers
must update with this distribution.

Every result contains:

| Field | Meaning |
| --- | --- |
| `asset_id` | Opaque operator-facing identifier, not a discovered hostname or absolute path. |
| `component` | Name, reported version or `null`, and reported build source. |
| `rule_id` | Stable advisory-specific rule identifier. |
| `status` | Overall assessment using the minimum evidence below. |
| `version_assessment` | `affected`, `fixed_reported`, `not_affected`, `unsupported`, or `unknown`. |
| `confidence` | `low`, `medium`, `high`, or `unknown`; confidence in the stated assessment, never exploitability. Default: `unknown`. |
| `evidence` | Individually identified, typed, bounded observations. |
| `preconditions` | Rule conditions with `present`, `absent`, `unknown`, or `conflicting` state and evidence references. |
| `mitigation` | `observed`, `not_observed`, `unknown`, or `conflicting`, with evidence references. |
| `reachability` | `not_tested`, `metadata_observed`, or `unknown`, explicit authorization, identity, and evidence references. |
| `threat` | Separate KEV and vendor-reported exploitation records. |
| `exploitability` | Constant `not_tested`. |
| `reasons` | Controlled descriptions of assessment reasons and uncertainty. |
| `recommendation` | Advisory-specific next action. |
| `sources` | HTTPS primary-source references without credentials, query strings, or fragments. |

Build source is one of `upstream`, `vendor`, `custom`, or `unknown`.
`fixed_version_reported` permits unknown provenance because it asserts only a
reported threshold; vendor and custom builds cannot be cleared using the
upstream number. Their patch status requires their own verified evidence and
product-specific rule handling.

## Minimum assessment evidence

Version evidence may carry `observed_version`: a bounded plain exact
`major.minor.patch` value (each numeric part is at most six digits, without
leading zeroes). It belongs to that evidence item's source path/category,
including when disagreement leaves `component.version` null. The field is
omitted for malformed or qualified input and is forbidden on other evidence
kinds. JSON and CSV retain it structurally; HTML displays it with the source.
Its presence does not attest deployed state or change a conflict's unknown result.

| Status | Required evidence |
| --- | --- |
| `unknown` | Missing, ambiguous, conflicting, unsupported, or otherwise insufficient evidence. |
| `potentially_affected` | Consistent reported version evidence matching a verified affected range. |
| `precondition_present` | Affected version plus all declared required preconditions established by observed evidence. |
| `likely_exposed` | The preceding conditions plus explicitly authorized reachability metadata for the same asset and component. |
| `mitigated_configuration` | Affected version remains recorded; the rule's documented mitigation is observed with sufficient coverage. |
| `fixed_version_reported` | Consistent reported version meets that product/branch's verified fix; no vendor/custom provenance override. |
| `unsupported_runtime` | Consistent version and a sourced rule stating that its release line is unsupported. |

`not_affected` is a version-assessment dimension. It does not automatically yield
a fixed-version or safe overall status. A version below an advisory's introduced
boundary may be outside the affected interval while still unsupported or outside
the scanner's assurance scope.

A condition cannot be established using a `candidate`, `unknown`, or conflicting
observation. A missing setting in an incomplete export is unknown. The caller
must include **every** advisory-required precondition; a structural validator
cannot infer an omitted condition from a rule ID alone.

The overall status does not erase the dimensions. Mitigation does not rewrite
an affected version to fixed. A fixed-version observation does not assert that
the package is deployed. A CISA KEV listing does not establish local reachability
or exploitation. A high confidence value does not change these meanings.

## Evidence records

Evidence has required `id`, `kind`, `state`, and `detail` fields. Kinds are
`version`, `configuration`, `source`, `reachability`, `mitigation`, and
`inventory`. States are `present`, `absent`, `unknown`, `conflicting`, and
`candidate`.

The optional `path` is a normalized relative path using `/`. Absolute paths,
drive letters, backslashes, empty segments, and `.` or `..` segments are
rejected. An optional positive `line` requires `path`. Inventory-only and
network-only observations must not invent source locations.

Evidence identifiers are unique within a result. Referenced evidence must
exist. Established conditions require observed evidence with the matching
state. Authorized reachability references must point to observed reachability
metadata, with an exact matching asset/component identity.

Identifiers are bounded to 128 ASCII letters/digits plus `_`, `.`, `:`, or `-`,
starting with a letter or digit. Ordinary text fields exclude terminal control
characters. This is not a general secret detector: callers must emit controlled
summaries and explicitly permitted facts. Do not copy arbitrary exception text,
source lines, environment variables, configuration contents, tokens, credentials,
or process arguments into `detail`, `reasons`, labels, or other text fields.

## External threat metadata

`threat.kev` contains `state` (`listed`, `not_listed`, or `unknown`), `as_of`
(date or `null`), and `source` (URL or `null`).

`threat.vendor_exploitation` uses `reported`, `not_reported`, or `unknown` with
the same date/source fields. Every assertion other than `unknown` requires a
dated source. Absence from an unverified or incomplete catalog remains unknown.
These fields describe an external report, not the assessed deployment.

## Rule and snapshot provenance

The rule contract defines identity, revision, component, advisory identifiers,
verification state/date, version scheme, branch boundaries, preconditions,
mitigations, sources, and notes. Every branch, precondition, and mitigation
references one or more identified primary sources. Source records name their
publisher, canonical URL, and verification date.

An enabled rule must be verified, have a verification date, have identified
sources, and contain affected branch boundaries. Referenced sources must exist.
Rule dates cannot predate their source verification dates, and a snapshot cannot
predate its rules. Product-specific tests must independently verify the actual
boundary arithmetic and all applicability conditions.

A snapshot has `schema_version`, `snapshot_id`, `created_at`, and `rules`.
Its integrity identifier is SHA-256 of UTF-8 canonical JSON: keys sorted,
compact separators, Unicode preserved, finite numbers only, and a final newline.
Array order is significant. An identical snapshot yields the same digest.
This checksum is **not** a publisher signature or authorization to trust a file.

The pilots ship reviewed embedded snapshots. There is no signed-feed updater,
network download, key storage, key rotation, or rollback mechanism in this
release. Future authenticated distribution requires a separate reviewed design.
Unverified research leads must remain disabled or outside the active snapshot.

## Deterministic formats

Canonical JSON uses the same stable encoding as snapshot hashing. With a fixed
injected `generated_at` and `executable_sha256`, the full report is deterministic.
The CLI captures both once before inventory; the pure classification results do
not depend on them. There is no absolute input path or implicit filename label.
Callers must traverse and order observations deterministically; list order is
preserved to avoid silently changing the meaning of configuration operations.

CSV has a `record_type` column. Ordinary rows use `result` and retain structured
dimensions as JSON text in cells. If no result completed, one `summary` row
preserves `complete`, `limitations`, the rule date, and `not_tested` status.
Both result and summary rows append tool name/version, executable SHA-256, UTC
generation timestamp, rules snapshot ID and SHA-256; original columns retain
their positions. Rule verification dates are distinct from observation time.
Consumers must distinguish this row from an asset finding. Formula prefixes
`=`, `+`, `-`, and `@`, including after leading whitespace, are neutralized.

HTML is an offline, script-free report with escaped values, source links, light
and dark styling, print support, and a restrictive Content Security Policy.
An explicitly supplied local PNG/JPEG/GIF/WebP logo up to 1 MiB can be embedded;
SVG and external image URLs are not accepted. Company brand permissions remain
separate from the code license.

## Bounds and file handling

The JSON reader accepts regular files only, rejects symlinks and special files,
checks file identity when opening, and reads at most 4 MiB by default. FIFOs
cannot block the reader. It rejects duplicate keys, non-finite numbers including
overflowed exponents, syntax/encoding errors, more than 200,000 value nodes,
and nesting deeper than 40 levels. Object keys and scalar content remain bounded
by the overall byte limit; contract field lengths are validated separately.

Reports support at most 10,000 results; a result allows at most 1,000 evidence
records, 100 preconditions, and 100 source URLs. Product-specific collectors may
choose stricter limits. Hitting a scan limit must remain visible in coverage.

Output uses a temporary file in the destination directory, flush/fsync, and
atomic no-clobber publication. `--force` may explicitly replace an existing
report, but input files, their aliases, and supplied logos remain protected.
The caller must pass every protected input path to `save_report`. Output
symlinks are rejected. Temporary files are removed after publication failure.

Exit policy is owned by the CLI: normally 0 for completed work; 1 for configured
findings; 2 for malformed input, operational failure, or incomplete coverage;
130 for interruption. Unknown results require an explicit CI policy and are
never automatically equivalent to fixed. A CLI may offer separate finding and
unknown gates; it must document precedence. On interruption preserve completed
results with `complete: false`.

## Schema validation

The JSON Schema files describe the structural v1.0 contracts using the
2020-12 vocabulary. A general JSON Schema validator must enable format checking
for dates/URLs; `relative-path` is an application format. The embedded standard-
library validator implements the bounded vocabulary used here and applies
additional semantic checks for cross-record references and assessment states.
It is not a general JSON Schema implementation and never resolves external
references or downloads schemas.

Always use the checker-specific parser and classifier as well as structural
validation. No schema can establish whether a primary source is trustworthy,
whether a source observation is accurate, or whether all required production
conditions were actually collected.
