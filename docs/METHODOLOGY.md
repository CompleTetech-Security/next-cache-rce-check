# Assessment methodology

Tool version: **0.1.0**. Advisory snapshot: **next-cache-2026-10-23.1**.
Verified on **2026-10-23**. Scope: **GHSA-673q-mjm6-r5xr only**.

## Primary evidence

| Source | What it establishes |
| --- | --- |
| [Next.js maintainer advisory](https://github.com/vercel/next.js/security/advisories/GHSA-673q-mjm6-r5xr) | Affected npm package `next`, versions 16.0.0–16.4.0 inclusive; fixed 16.4.1; App Router, Cache Components, use-cache and multiple typed-array return preconditions; upgrade recommendation and no known workaround. |
| [Next.js 16.4.1 release](https://github.com/vercel/next.js/releases/tag/v16.4.1) | Published fixed release and the advisory linkage. |
| [use-cache directive documentation](https://nextjs.org/docs/app/api-reference/directives/use-cache) | Function-scope and file-scope directive forms; exported functions at file scope. |
| [cacheComponents configuration documentation](https://nextjs.org/docs/app/api-reference/config/next-config-js/cacheComponents) | Configuration surface inspected as candidate syntax. |

The advisory was published October 14, 2026. No CVE was assigned in the
maintainer advisory when verified. The checker does not invent one. The snapshot
contains no exploitation-in-the-wild or CISA KEV assertion; both threat states
remain `unknown`, without an unsupported absence claim.

## Version evidence

The classifier accepts plain `major.minor.patch` strings with no prefix,
qualifier, build metadata, or prerelease. Versions in 16.0.0–16.4.0 produce
`potentially_affected`. Exact 16.4.x versions at or above 16.4.1 produce
`fixed_version_reported`. Other release lines are outside this snapshot and
remain `unknown`. The comparison is upstream-version triage, not release
existence verification or vendor-backport attestation.

npm lockfile v1 dependency maps and v2/v3 package maps produce location-scoped
observations. For v2 the legacy dependency map is also retained, so contradictory
views are not silently reconciled. Direct installed metadata is an additional
observation at `node_modules/next`. Different values at the same location make
that dependency's assessment unknown. Each nested Next.js copy receives a
separate stable asset suffix. Canonical `npm:next@VERSION` aliases and explicit
package-name identities are retained; contradictory identities are rejected.
An exact `package.json` declaration is not an
observation of a resolved or installed package. Lockfiles are resolved metadata,
not proof that the dependency is installed or deployed.

The build-source field remains `unknown`, including for plain versions read
from installed metadata. A well-formed version alone does not authenticate
package contents. Reports retain source categories, relative evidence paths,
and each accepted exact `observed_version`, including conflicting candidates,
in JSON, CSV evidence and HTML. Malformed, qualified and URL-shaped raw version
strings are omitted; conflicting observations still yield `unknown`.

## Static context

The analyzer tokenizes bounded text. It skips comments and treats strings,
plain templates, and recognized regular-expression literals as opaque. It
recognizes common function/arrow blocks, simple TypeScript return annotations,
directive prologues, and a subset of direct return expressions. Multiple typed
array constructions must occur in one return expression inside the same cached
function. Nested function bodies, separate return statements, and unrelated
local constructions are excluded from that combination.

A conventional `app` or `src/app` page, layout, or route is an App Router
candidate. A property named `cacheComponents` in a recognized configuration file
is a configuration candidate. A valid-looking use-cache directive and direct
multiple-array return are source candidates. Relative paths and line numbers
support manual review, with controlled descriptions instead of source excerpts.

The lexer is not a JavaScript/TypeScript parser. It does not resolve exports
through aliases, imported functions, actual runtime values, constructor
shadowing, configuration wrappers, conditional settings, source transformations,
concise arrow returns, arbitrary TypeScript types, or JSX semantics. Template
interpolation and ambiguous slash contexts (including JSX closing tags and
statement-level regular expressions after a closing parenthesis) are explicitly
excluded and make coverage incomplete. Some
unsupported syntax can yield no candidate without a lexical error. These
limits prevent absence claims, and every candidate remains uncertain even when
all four kinds are found. Candidate references do not imply the same deployed
route reaches every candidate.

Only root dependency results receive project source candidates. A nested copy's
configuration cannot be inferred from a different application's root source.
Workspace graphs and separate nested projects require separate invocations.

## Decisions and omissions

- Exact affected version evidence is sufficient for `potentially_affected`, even
  when source conditions are absent from the candidate list or scan coverage is
  incomplete. This is a remediation-priority signal, not confirmation of RCE.
- Fixed-version evidence is independent of source completeness. A source limit
  leaves `complete: false` and exit 2, while preserving a valid reported-version
  comparison. Incomplete or unsupported inventory can conceal conflicting
  dependencies and prevents `fixed_version_reported`.
- No literal false configuration setting is called a verified mitigation. The
  advisory gives no known workaround, and this scanner does not evaluate the
  effective configuration.
- `precondition_present`, `likely_exposed`, and `mitigated_configuration` are
  reserved in the common report contract but are never emitted by this CLI.
  Local exploitability and reachability remain `not_tested`.
- The tool does not inspect source maps, bundles, HTTP endpoints, containers,
  process state, executable dependencies, secret files, or arbitrary package
  manager formats. It never executes a payload or application code.

## Updating this rule

Verify the maintainer advisory and tagged release, record the evidence and
verification date in `rules/snapshot.json`, then update the classifier and
meaningful boundary tests. Review changes to application conditions separately
from version thresholds. Rebuild the standalone script, run all local tests,
and verify CI for the published commit. A changed hash identifies a new
snapshot; it does not authenticate its author. This initial release has no
runtime feed, online rule fetch, or unsigned-feed fallback.
