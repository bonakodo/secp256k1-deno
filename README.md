# secp256k1 for Deno

Bitcoin-focused, safe-by-default Deno bindings to the native
[`bitcoin-core/secp256k1`](https://github.com/bitcoin-core/secp256k1) library.
The typed API covers ECDSA and Taproot verification, signing, BIP341 tweaks,
historical lax-DER verification, BIP324 key exchange, and MuSig2.

This package supports Deno only. It does not download, build, or bundle native
binaries.

## Install libsecp256k1

Install libsecp256k1 yourself through your operating system or build the
vendored upstream source. Version 1.0 targets libsecp256k1 ABI 6. Optional APIs
also require their upstream modules:

| Package API                               | Native module                      |
| ----------------------------------------- | ---------------------------------- |
| ECDSA verification/signing and key tweaks | core                               |
| Taproot and x-only keys                   | `extrakeys`, `schnorrsig`          |
| BIP324                                    | `ellswift`                         |
| MuSig2                                    | `musig`, `extrakeys`, `schnorrsig` |

For example, Homebrew provides ABI 6 on supported macOS releases:

```sh
brew install secp256k1
```

To build every supported module from the checked-out upstream source:

```sh
cmake -S secp256k1 -B secp256k1/build \
  -DBUILD_SHARED_LIBS=ON \
  -DSECP256K1_ENABLE_MODULE_RECOVERY=ON \
  -DSECP256K1_ENABLE_MODULE_ECDH=ON \
  -DSECP256K1_ENABLE_MODULE_EXTRAKEYS=ON \
  -DSECP256K1_ENABLE_MODULE_SCHNORRSIG=ON \
  -DSECP256K1_ENABLE_MODULE_ELLSWIFT=ON \
  -DSECP256K1_ENABLE_MODULE_MUSIG=ON
cmake --build secp256k1/build --parallel
```

## Native configuration

`DENO_SECP256K1_PATH` is mandatory for the version 1 API. Its value must be
either an absolute path or exactly `auto`. Unset, empty, relative, and
whitespace-padded values fail closed.

For production nodes, select one absolute path. No fallback is attempted:

```sh
export DENO_SECP256K1_PATH=/usr/lib/x86_64-linux-gnu/libsecp256k1.so.6
deno run \
  --allow-env=DENO_SECP256K1_PATH \
  --allow-ffi="$DENO_SECP256K1_PATH" \
  node.ts
```

Root verification, signing, Taproot, historical verification, and key-tweak
operations support path-scoped FFI permission. BIP324 and MuSig2 currently use
Deno pointer APIs that require unscoped `--allow-ffi`:

```sh
deno run --allow-env=DENO_SECP256K1_PATH --allow-ffi node.ts
```

`DENO_SECP256K1_PATH=auto` delegates lookup to the operating-system loader and
also requires unscoped `--allow-ffi`. Auto mode tries only ABI-6 names:

- Linux x86_64/aarch64: `libsecp256k1.so.6`
- macOS x86_64/aarch64: `libsecp256k1.6.dylib`, then the matching Homebrew
  location (`/usr/local/lib` or `/opt/homebrew/lib`)
- Windows: unsupported; provide an absolute DLL path

Auto mode trusts every candidate location searched by the platform loader.
Native FFI code executes outside Deno's sandbox, and an absolute path can still
refer to a symlink or load transitive dependencies. Pin and protect the native
library and its dependencies as part of your node's deployment.

## Verification

Use non-throwing parsers for peer-controlled bytes. Native configuration and
runtime failures normally throw typed, catchable errors, so infrastructure
failure is never mistaken for an invalid transaction or signature. The
exception is libsecp256k1's `secp256k1_selftest()`, which runs before the first
context use and may abort the process on failure.

```ts
import {
  Digest32,
  EcdsaDerSignature,
  PublicKey,
  verifyEcdsaDer,
} from 'jsr:@bonakodo/secp256k1@1';

const digest = Digest32.tryFromBytes(transactionDigest);
const signature = EcdsaDerSignature.tryFromBytes(derWithoutSighashByte);
const publicKey = PublicKey.tryParse(serializedPublicKey);

const valid = digest !== null && signature !== null && publicKey !== null &&
  verifyEcdsaDer(signature, digest, publicKey);
```

The package accepts already computed 32-byte Bitcoin signature digests. Script
execution, transaction serialization, sighash selection, and policy checks
remain the node's responsibility.

## Signing and Taproot

```ts
import { Digest32, verifyTaprootSignature } from 'jsr:@bonakodo/secp256k1@1';
import {
  SecretKey,
  signTaprootSignature,
} from 'jsr:@bonakodo/secp256k1@1/signing.ts';

using secretKey = SecretKey.generate();
const digest = Digest32.fromBytes(taprootSighash);
const signature = signTaprootSignature(digest, secretKey);
const { key: outputKey } = secretKey.xOnlyPublicKey();
console.assert(verifyTaprootSignature(signature, digest, outputKey));
```

`SecretKey`, BIP324 shared secrets, and protocol nonce handles are disposable
stateful values. Destruction overwrites package-owned buffers on a best-effort
basis. JavaScript cannot erase bytes already exported or copied by application
code, the runtime, or native dependencies.

## Entrypoints

| Import                               | Purpose                                                        |
| ------------------------------------ | -------------------------------------------------------------- |
| `@bonakodo/secp256k1`                | Safe ECDSA and Taproot verification plus native initialization |
| `@bonakodo/secp256k1/signing.ts`     | Disposable secret keys and Bitcoin signing                     |
| `@bonakodo/secp256k1/taproot.ts`     | BIP341 public and secret key tweaking                          |
| `@bonakodo/secp256k1/historical.ts`  | Bitcoin Core-compatible pre-BIP66 lax-DER verification         |
| `@bonakodo/secp256k1/key-tweaks.ts`  | Additive key tweaks for BIP32-like derivation                  |
| `@bonakodo/secp256k1/diagnostics.ts` | Lazy native initialization and capability status               |
| `@bonakodo/secp256k1/bip324.ts`      | Role-bound ElligatorSwift shared-secret derivation             |
| `@bonakodo/secp256k1/musig2.ts`      | Indexed, nonce-safe BIP327 signing                             |

`historical` exposes one cryptographic compatibility primitive. It is not a
Bitcoin consensus engine and does not decide activation heights, script flags,
sighash types, or transaction validity.

Runnable end-to-end samples are in [`examples/`](./examples/).

## Tested platforms

CI builds the vendored all-module library and runs both Deno 2.0.0 and current
stable on Linux x86_64/aarch64, macOS x86_64/aarch64, and Windows x86_64.
GitHub's `macos-15-intel` line is the final standard hosted Intel macOS runner;
Windows Arm64 is not in the declared support matrix. Windows supports explicit
DLL paths only.

## Release checklist

Before publishing, confirm the JSR package settings that are not source
configuration:

- Description and GitHub repository link are current.
- Deno is the only marked compatible runtime.
- GitHub Actions publishing remains linked for OIDC provenance.

## License

MIT. See [`LICENSE`](./LICENSE).
