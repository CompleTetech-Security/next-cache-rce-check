# Security policy

## Reporting a flaw in this checker

Use this repository's **Security → Report a vulnerability** option when
available. Otherwise contact CompleteTech LLC through
[complete.tech](https://complete.tech) to arrange private reporting. Include the
affected commit, a minimal synthetic local reproduction, expected and actual
behavior, and impact. Omit credentials and third-party private information.

Only the current default branch is maintained. Reproduce against its latest
revision when possible. No response-time guarantee is made.

## Assessment scope

The checker performs offline triage for GHSA-673q-mjm6-r5xr. It reads bounded
metadata and source syntax. A reported version or static pattern is not a
confirmed exploitable vulnerability. Findings about applications belong with
their owners' security contacts or disclosure programs.

Use project copies you are authorized to inspect. The checker is not designed
to process a directory that an adversary changes concurrently. Work from a
stable read-only copy when inspecting untrusted material; the symlink checks do
not provide a full operating-system sandbox against filesystem races. Keep
real source and reports outside this repository.
