# JSR Provenance Release Design

## Goal

Publish `@bonakodo/secp256k1` from a verifiable GitHub Actions workflow so
the latest JSR version has a Sigstore Rekor transparency-log entry and earns
the JSR provenance score.

## Current State

Version `1.0.0` was published successfully by GitHub Actions and produced
Rekor log entry `2164636199`. The workflow run was associated with Git ref
`refs/tags/v0.1.0`, however, while the package metadata declared version
`1.0.0`. JSR therefore does not credit the latest package version with
provenance. Published JSR versions are immutable, so `1.0.0` cannot be
replaced in place.

Version `1.0.1` was subsequently published from the matching `v1.0.1` tag,
but JSR rejected Deno's provenance bundle. JSR now validates the attested
digest against the uploaded tarball, while Deno 2.9.2 still attests the JSR
version manifest digest and does not fail when the provenance endpoint rejects
that bundle. JSR therefore exposes `rekorLogId: null` for `1.0.1` even though
Deno created an unassociated Rekor entry.

## Design

Release patch version `1.0.1` without changing the package API or runtime
behavior. The release commit will update the version in `deno.jsonc` and add
a validation step to `.github/workflows/publish.yml` that reads the package
version and requires the triggering tag to equal `v<version>`.

The repository-only design and implementation-plan documents will be excluded
from the published package so the patch release retains the established public
artifact boundary.

The existing publish job remains responsible for OIDC authentication. It
retains `id-token: write`, runs only after the reusable test workflow passes,
performs `deno publish --dry-run`, and then runs `deno publish`. Pushing the
single matching `v1.0.1` tag will invoke this workflow and allow JSR to create
the provenance statement automatically.

## Failure Handling

The tag/version validation runs before package validation and publication. A
mismatched tag exits with an explicit error showing both the expected and
actual tag. No registry mutation occurs when this guard fails. Test or dry-run
failures likewise prevent the publish command from running.

## One-Time Provenance Repair

A version-fixed manual GitHub Actions workflow will repair `1.0.1` without
republishing or modifying its immutable package bytes. It downloads JSR's
stored tarball, hashes those exact bytes, creates a SLSA statement for
`pkg:jsr/@bonakodo/secp256k1@1.0.1`, and signs it through Sigstore using the
workflow's GitHub OIDC identity. It then requests a separate JSR-scoped GitHub
OIDC token and submits the converted Sigstore bundle to JSR's provenance
endpoint.

The repair must fail unless the OIDC requests, Fulcio signing, Rekor upload,
JSR submission, and JSR version readback all succeed. The workflow will use a
dedicated dependency lockfile and a pinned Sigstore client. After JSR reports a
non-null Rekor log id and the score marks provenance complete, the one-time
workflow, repair script, tests, and lockfile will be removed from the branch.
Their executed source remains verifiable in Git history and the workflow run.

## Verification

Before release:

- Parse `deno.jsonc` and confirm version `1.0.1`.
- Exercise the tag/version guard locally with one matching and one mismatching
  tag value.
- Confirm the publish dry run does not include `docs/`.
- Run `deno fmt --check --config deno.jsonc`.
- Run `deno lint --config deno.jsonc`.
- Run `deno publish --dry-run`.
- Inspect the final diff and repository status.

After pushing the release commit and `v1.0.1` tag:

- Wait for the GitHub Actions `Publish` workflow to succeed.
- Confirm its publish log reports a provenance transparency-log URL.
- Confirm the Rekor entry is publicly retrievable.
- Confirm JSR lists `1.0.1` as latest and marks “Has provenance” complete.

After the one-time repair:

- Confirm the repair workflow succeeds from `master` with `id-token: write`.
- Confirm JSR's version API returns the repair's Rekor log id for `1.0.1`.
- Confirm the public Rekor entry carries this repository's workflow identity.
- Confirm JSR marks “Has provenance” complete.
- Remove the one-time repair files and rerun the repository checks.

## Scope

This change is limited to the JSR package version, the publish workflow guard,
and the design and implementation-plan documents required by the repository's
development workflow. It does not alter source code, exports, dependencies,
tests, the native library submodule, or `deno.lock`.
