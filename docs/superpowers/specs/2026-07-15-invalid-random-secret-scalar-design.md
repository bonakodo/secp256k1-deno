# Invalid Random Secret Scalar Design

**Date:** 2026-07-15

## Problem

`SecretKey.generate()` and BIP324 key-exchange generation currently retry when
Web Crypto returns a 32-byte value that is not a valid secp256k1 secret scalar.
This conflicts with libsecp256k1's guidance: an invalid uniformly random scalar
indicates a severely broken randomness source and must not be retried. Retrying
can conceal catastrophic RNG failure instead of failing closed.

BIP324 also implements scalar-range validation locally, duplicating the native
validation rule used by `SecretKey`.

## Design

Add one shared `SecretKeyRandomError` for the invalid-random-scalar condition.
The error will be re-exported from both `signing.ts` and `bip324.ts`, so callers
can handle the same failure consistently from either public subpath.

Move secret-scalar validation into a small shared internal helper backed by
`secp256k1_ec_seckey_verify`. Both generation paths will:

1. Allocate a 32-byte candidate.
2. Call `crypto.getRandomValues()` exactly once.
3. Validate the candidate exactly once with libsecp256k1.
4. Throw `SecretKeyRandomError` if validation rejects it.
5. Wipe temporary secret material on every exit path.

Existing Web Crypto exceptions and native configuration, loading, capability,
and context errors will continue to propagate unchanged. Valid generation and
the public shape of generated key handles remain unchanged.

## Testing

Regression tests will replace `crypto.getRandomValues` temporarily with a
deterministic source that returns an invalid all-zero scalar. Tests for both
`SecretKey.generate()` and BIP324 exchange generation will assert:

- the shared `SecretKeyRandomError` is thrown;
- the random source is called exactly once; and
- the error exported by both public modules has the same class identity.

Focused native tests will first be observed failing before implementation and
passing afterward. The complete test suite, formatting, type checking, and
coverage checks will then verify that the change introduces no regressions.

## Scope

This change only covers invalid secret scalars returned by Web Crypto. It does
not wrap Web Crypto failures, change unrelated randomness consumers, or alter
the behavior of caller-supplied secret-key validation.
