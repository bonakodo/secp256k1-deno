# libsecp256k1-deno

This module provides Deno native bindings to [bitcoin-core/secp256k1](https://github.com/bitcoin-core/secp256k1).

Works on deno version 1.13 or greater, because it uses [Foreign Function Interface API](https://deno.land/manual@v1.20.4/runtime/ffi_api) (FFI).

By design, this module does not have any third-party Deno dependencies.

## Installation

This module doesn't come with the `libsecp256k1` library. You have to install it separately or [build from sources](https://github.com/bitcoin-core/secp256k1#build-steps) manually.

In Ubuntu or Debian run `apt-get install libsecp256k1-0`, in Alpine — `apk add libsecp256k1`.

By default, the module will look for `secp256k1.dll` on Windows, `libsecp256k1.so` on Linux, or `libsecp256k1.dylib` on macOS in the library path. If the library is not in the dynamic library load path, you can specify the full path to the library in the `DENO_SECP256K1_PATH` environment variable.

## Required permissions and Deno flags

This module uses FFI (unstable API), and therefore requires the `--allow-ffi` and `--unstable` flags.
Additionally, to read the `DENO_SECP256K1_PATH` environment variable, it requires the `--allow-env` flag.

To run the examples below, launch Deno as follows: `deno run --allow-ffi --allow-env --unstable example.ts`

## ECDSA signing and verification

```typescript
// Import the library
import * as secp256k1 from 'https://deno.land/x/libsecp256k1@0.0.2/mod.ts';

// Produce a message hash
const message = 'Hello, Deno!';
const messageHash = new Uint8Array(
  await crypto.subtle.digest('SHA-256', new TextEncoder().encode(message)),
);

// Generate a secret key
const secretKey = new Uint8Array(32);
do {
  crypto.getRandomValues(secretKey);
} while (!secp256k1.secretKeyVerify(secretKey));

// Sign the message
const signature = secp256k1.ecdsaSign(messageHash, secretKey);

// Get a public key in compressed format
const publicKey = secp256k1.publicKeyCreate(secretKey);

// Verify the signature
secp256k1.ecdsaVerify(signature, messageHash, publicKey);
// true
```

## Schnorr signing and verification (experimental)

Schnorr signing is experimental and must be explicitly enabled during `libsecp256k1` library build step by specifying the `--enable-module-schnorrsig` flag. This deno module provides bindings to the recoverable signing functions as well, therefore `--enable-module-recovery` is mandatory too.

Build the C library as follows:

```bash
$ ./configure --enable-module-recovery --enable-module-schnorrsig
$ make
```

Note that some Linux distributions build the `libsecp256k1` package with the experimental flags enabled. Please refer to the table below.

| Distribution (docker tag) | Recoverable        | Schnorr                                                 |
| ------------------------- | ------------------ | ------------------------------------------------------- |
| debian:bullseye           | :white_check_mark: | :white_check_mark:                                      |
| ubuntu:focal              | :white_check_mark: | :x:                                                     |
| ubuntu:impish             | :white_check_mark: | :white_check_mark:                                      |
| ubuntu:jammy              | :white_check_mark: | :white_check_mark: (+ secp256k1_schnorrsig_sign_custom) |
| alpine:3.15               | :white_check_mark: | :x:                                                     |
| alphine:edge (20220328)   | :white_check_mark: | :x:                                                     |

To use Schnorr bindings import `mod-experimental.ts` instead of `mod.ts`.

```typescript
// Import the experimental library
import * as secp256k1 from 'https://deno.land/x/libsecp256k1@0.0.2/mod-experimental.ts';

// Produce a tagged message hash
const message = 'Hello, Deno!';
const tag = 'BIP0340/challenge';
const messageHash = secp256k1.taggedSha256(message, tag);

// Generate a secret key
const secretKey = new Uint8Array(32);
do {
  crypto.getRandomValues(secretKey);
} while (!secp256k1.secretKeyVerify(secretKey));

// Sign the message
const signature = secp256k1.schnorrSign(messageHash, secretKey);

// Get a public key in x-only format
const publicKey = secp256k1.createXOnlyPublicKey(secretKey);

// Verify the signature
secp256k1.schnorrVerify(signature, messageHash, publicKey);
// true
```

## License

Check [LICENSE](./LICENSE) for details.

Copyright © 2022 Bonakodo Limited
