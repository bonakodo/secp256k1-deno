# secp256k1-deno

Native bindings to [bitcoin-core/secp256k1](https://github.com/bitcoin-core/secp256k1) for Deno using [Foreign Function Interface (FFI) API](https://docs.deno.com/runtime/reference/deno_namespace_apis/#ffi).

This module has no third-party Deno dependencies except for testing.

## Install libsecp256k1

This module requires the `libsecp256k1` native library. Install it via your package manager or build it from source.

### Install via Package Manager

- **Ubuntu/Debian**:

```bash
sudo apt-get install libsecp256k1-0
```

- **Alpine Linux**:

```bash
sudo apk add libsecp256k1
```

- **MacOS**:

```bash
brew install secp256k1
```

**Note:** Some Linux distributions may provide `libsecp256k1` without certain modules (e.g., `--enable-module-schnorrsig`). In such cases, you need to build the library from source with the required modules enabled.

### Build from source

Follow the [build steps](https://github.com/bitcoin-core/secp256k1?tab=readme-ov-file#building-with-autotools) in the bitcoin-core/secp256k1 repository. Ensure you enable the necessary modules:

```bash
./autogen.sh
./configure --enable-module-schnorrsig
make
sudo make install
```

### Configure Library Path

By default, the module searches for the library file:

- **Windows**: `secp256k1.dll`
- **Linux**: `libsecp256k1.so`
- **macOS**: `libsecp256k1.dylib`

If the library is not in your system’s dynamic library load path, specify the full path using the `DENO_SECP256K1_PATH` environment variable:

```bash
# For example, on MacOS using Homebrew
export DENO_SECP256K1_PATH=/opt/homebrew/lib/libsecp256k1.dylib
```

## Required Permissions

This module requires the following Deno flags:

- `--allow-ffi`
- `--allow-env=DENO_SECP256K1_PATH`

To run the examples below, use:

```bash
deno run --allow-ffi --allow-env=DENO_SECP256K1_PATH example.ts
```

## ECDSA Signing and Verification

```typescript
// example.ts

// Import the module
import * as secp256k1 from 'jsr:@bonakodo/secp256k1';

// Prepare a message hash
const message = 'Hello, Deno!';
const encoder = new TextEncoder();
const messageBytes = encoder.encode(message);
const messageHash = new Uint8Array(
  await crypto.subtle.digest('SHA-256', messageBytes),
);

// Generate a secret key
let secretKey = new Uint8Array(32);
do {
  crypto.getRandomValues(secretKey);
} while (!secp256k1.secretKeyVerify(secretKey));

// Sign the message
const signature = secp256k1.ecdsaSign(messageHash, secretKey);

// Get the public key in compressed format
const publicKey = secp256k1.publicKeyCreate(secretKey);

// Verify the signature
const isValid = secp256k1.ecdsaVerify(signature, messageHash, publicKey);
console.log(isValid); // true
```

## Schnorr Signatures

```typescript
// example.ts
import * as secp256k1 from 'jsr:@bonakodo/secp256k1';

// Prepare a tagged message hash
const message = 'Hello, Deno!';
const tag = 'BIP0340/challenge';
const messageHash = secp256k1.taggedSha256(message, tag);

// Generate a secret key
let secretKey = new Uint8Array(32);
do {
  crypto.getRandomValues(secretKey);
} while (!secp256k1.secretKeyVerify(secretKey));

// Sign the message using Schnorr signatures
const signature = secp256k1.schnorrSign(messageHash, secretKey);

// Get the public key in x-only format
const publicKey = secp256k1.createXOnlyPublicKey(secretKey);

// Verify the signature
const isValid = secp256k1.schnorrVerify(signature, messageHash, publicKey);
console.log(isValid); // true
```

## License

This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.

© 2024 Bonakodo Limited
