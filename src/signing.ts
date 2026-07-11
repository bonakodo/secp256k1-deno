/**
 * Disposable secret keys and safe Bitcoin ECDSA and Taproot signing.
 *
 * Secret keys are stateful handles. Call {@link SecretKey.destroy}, or use a
 * `using` declaration, as soon as a key is no longer needed. Destruction is
 * best effort: JavaScript cannot erase copies previously returned by
 * {@link SecretKey.exportBytes}.
 *
 * @module
 * @since 1.0.0
 */

import type { Digest32 } from './api/digest.ts';
import { PublicKey, XOnlyPublicKey } from './api/keys.ts';
import { invalidInput } from './api/input.ts';
import { EcdsaSignature, SchnorrSignature } from './api/signatures.ts';
import { withSigningContext, withStaticContext } from './native/context.ts';
import { getNativeSymbols, requireCapability } from './native/loader.ts';

export { Digest32 } from './api/digest.ts';
export { CompressedPublicKey, PublicKey, XOnlyPublicKey } from './api/keys.ts';
export type { PublicKeyEncoding } from './api/keys.ts';
export { EcdsaSignature, SchnorrSignature } from './api/signatures.ts';

const SECRET_KEY_SIZE = 32;
const PUBLIC_KEY_SIZE = 64;
const KEYPAIR_SIZE = 96;
const X_ONLY_PUBLIC_KEY_SIZE = 64;
const EC_COMPRESSED = 258;

/**
 * Thrown when an operation attempts to use a destroyed secret key.
 *
 * @since 1.0.0
 */
export class SecretKeyDestroyedError extends Error {
  /**
   * Creates a secret-key lifecycle error.
   *
   * @since 1.0.0
   */
  constructor() {
    super('SecretKey has been destroyed');
    this.name = 'SecretKeyDestroyedError';
  }
}

/**
 * A disposable, non-serializing handle to a valid secp256k1 secret key.
 *
 * Construction and export copy all 32 bytes. The handle does not provide
 * string or JSON serialization. `destroy()` overwrites its owned buffer, but
 * cannot erase copies already exported by application code.
 *
 * @example Generate and dispose a key
 * ```ts
 * #!/usr/bin/env -S deno run --allow-env=DENO_SECP256K1_PATH --allow-ffi
 * import { SecretKey } from "jsr:@bonakodo/secp256k1@1/signing";
 *
 * using secretKey = SecretKey.generate();
 * const publicKey = secretKey.publicKey();
 * console.assert(publicKey.toCompressedBytes().length === 33);
 * ```
 *
 * @since 1.0.0
 */
export class SecretKey implements Disposable {
  readonly #bytes: Uint8Array;
  #destroyed = false;

  private constructor(bytes: Uint8Array) {
    this.#bytes = bytes;
  }

  /**
   * Generates a key with Web Crypto and rejects invalid curve scalars.
   *
   * @returns A new independently owned disposable key.
   * @throws Native configuration, loading, or runtime errors unchanged.
   * @since 1.0.0
   */
  static generate(): SecretKey {
    const candidate = new Uint8Array(SECRET_KEY_SIZE);
    try {
      while (true) {
        crypto.getRandomValues(candidate);
        if (isValidSecretKey(candidate)) {
          return new SecretKey(candidate.slice());
        }
      }
    } finally {
      candidate.fill(0);
    }
  }

  /**
   * Creates a key from exactly 32 bytes representing a scalar in `1..n-1`.
   *
   * @param bytes Big-endian secret-key bytes, copied on success.
   * @returns A new independently owned disposable key.
   * @throws {Secp256k1InputError} If the length or scalar is invalid.
   * @throws Native configuration, loading, or runtime errors unchanged.
   * @since 1.0.0
   */
  static fromBytes(bytes: Uint8Array): SecretKey {
    if (bytes.length !== SECRET_KEY_SIZE || !isValidSecretKey(bytes)) {
      return invalidInput(
        'SecretKey',
        'expected a 32-byte secp256k1 scalar in the range 1..n-1',
      );
    }
    return new SecretKey(bytes.slice());
  }

  /**
   * Reports whether this handle has been destroyed.
   *
   * @returns `true` after the first call to {@link SecretKey.destroy}.
   * @since 1.0.0
   */
  get destroyed(): boolean {
    return this.#destroyed;
  }

  /**
   * Explicitly exports a detached 32-byte secret-key copy.
   *
   * The caller owns the returned bytes and is responsible for overwriting
   * them. Prefer public-key and signing methods when export is unnecessary.
   *
   * @returns A detached mutable copy of the secret scalar.
   * @throws {SecretKeyDestroyedError} If this handle was destroyed.
   * @since 1.0.0
   */
  exportBytes(): Uint8Array {
    this.#assertLive();
    return this.#bytes.slice();
  }

  /**
   * Derives the canonical compressed secp256k1 public key.
   *
   * @returns A new immutable public-key value.
   * @throws {SecretKeyDestroyedError} If this handle was destroyed.
   * @throws Native configuration, loading, or runtime errors unchanged.
   * @since 1.0.0
   */
  publicKey(): PublicKey {
    const symbols = getNativeSymbols();
    const secret = this.exportBytes();
    try {
      return withSigningContext((context) => {
        const internal = new Uint8Array(PUBLIC_KEY_SIZE);
        if (
          symbols.secp256k1_ec_pubkey_create(context, internal, secret) !== 1
        ) {
          throw new Error('Native public-key derivation failed');
        }
        const serialized = new Uint8Array(33);
        const length = new BigUint64Array([33n]);
        if (
          symbols.secp256k1_ec_pubkey_serialize(
              context,
              serialized,
              length,
              internal,
              EC_COMPRESSED,
            ) !== 1 || length[0] !== 33n
        ) {
          throw new Error('Native public-key serialization failed');
        }
        return PublicKey.parse(serialized);
      });
    } finally {
      secret.fill(0);
    }
  }

  /**
   * Derives this key's BIP340 x-only public key and original Y parity.
   *
   * @returns A copied x-only key and `0` for even Y or `1` for odd Y.
   * @throws {SecretKeyDestroyedError} If this handle was destroyed.
   * @throws {NativeCapabilityError} If the extrakeys module is unavailable.
   * @throws Native configuration, loading, or runtime errors unchanged.
   * @see https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
   * @since 1.0.0
   */
  xOnlyPublicKey(): { key: XOnlyPublicKey; parity: 0 | 1 } {
    const symbols = requireCapability('extrakeys');
    const secret = this.exportBytes();
    const keypair = new Uint8Array(KEYPAIR_SIZE);
    const internal = new Uint8Array(X_ONLY_PUBLIC_KEY_SIZE);
    try {
      return withSigningContext((context) => {
        if (symbols.secp256k1_keypair_create(context, keypair, secret) !== 1) {
          throw new Error('Native keypair creation failed');
        }
        const parity = new Int32Array(1);
        if (
          symbols.secp256k1_keypair_xonly_pub(
            context,
            internal,
            parity,
            keypair,
          ) !== 1
        ) {
          throw new Error('Native x-only public-key derivation failed');
        }
        const serialized = new Uint8Array(32);
        if (
          symbols.secp256k1_xonly_pubkey_serialize(
            context,
            serialized,
            internal,
          ) !== 1
        ) {
          throw new Error('Native x-only public-key serialization failed');
        }
        return {
          key: XOnlyPublicKey.parse(serialized),
          parity: parity[0] === 0 ? 0 : 1,
        };
      });
    } finally {
      secret.fill(0);
      keypair.fill(0);
      internal.fill(0);
    }
  }

  /**
   * Best-effort overwrites the owned key and permanently invalidates the handle.
   *
   * Repeated calls are harmless. Previously exported copies are unaffected.
   *
   * @since 1.0.0
   */
  destroy(): void {
    if (this.#destroyed) return;
    this.#bytes.fill(0);
    this.#destroyed = true;
  }

  /**
   * Disposes this key for `using` declarations.
   *
   * @since 1.0.0
   */
  [Symbol.dispose](): void {
    this.destroy();
  }

  #assertLive(): void {
    if (this.#destroyed) throw new SecretKeyDestroyedError();
  }
}

/**
 * Creates a deterministic low-S ECDSA signature over a Bitcoin digest.
 *
 * libsecp256k1's default RFC6979 nonce function is used. This function accepts
 * an already computed 32-byte digest; transaction serialization and sighash
 * selection remain the caller's responsibility.
 *
 * @param digest The exact 32-byte Bitcoin signature digest.
 * @param secretKey A live disposable signing key.
 * @returns A valid immutable low-S ECDSA signature.
 * @throws {SecretKeyDestroyedError} If `secretKey` was destroyed.
 * @throws Native configuration, loading, or runtime errors unchanged.
 * @see https://www.rfc-editor.org/rfc/rfc6979
 * @since 1.0.0
 */
export function signEcdsa(
  digest: Digest32,
  secretKey: SecretKey,
): EcdsaSignature {
  const symbols = getNativeSymbols();
  const secret = secretKey.exportBytes();
  const message = digest.toBytes();
  try {
    const compact = withSigningContext((context) => {
      const internal = new Uint8Array(64);
      if (
        symbols.secp256k1_ecdsa_sign(
          context,
          internal,
          message,
          secret,
          null,
          null,
        ) !== 1
      ) {
        throw new Error('Native ECDSA signing failed');
      }
      const output = new Uint8Array(64);
      if (
        symbols.secp256k1_ecdsa_signature_serialize_compact(
          context,
          output,
          internal,
        ) !== 1
      ) {
        throw new Error('Native ECDSA signature serialization failed');
      }
      return output;
    });
    const signature = EcdsaSignature.fromBytes(compact);
    if (signature === null || !signature.isLowS()) {
      throw new Error('Native ECDSA signing produced an invalid signature');
    }
    return signature;
  } finally {
    secret.fill(0);
    message.fill(0);
  }
}

/**
 * Creates and post-verifies a BIP340 signature over a Taproot digest.
 *
 * Fresh 32-byte Web Crypto auxiliary randomness is generated for each call.
 * The native result is verified against the derived x-only public key before it
 * is returned. This API intentionally signs only 32-byte Bitcoin digests.
 *
 * @param digest The exact 32-byte Taproot signature digest.
 * @param secretKey A live disposable signing key.
 * @returns A post-verified immutable 64-byte Schnorr signature.
 * @throws {SecretKeyDestroyedError} If `secretKey` was destroyed.
 * @throws {NativeCapabilityError} If extrakeys or schnorrsig is unavailable.
 * @throws Native configuration, loading, randomness, or runtime errors unchanged.
 * @see https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
 * @since 1.0.0
 */
export function signTaprootSignature(
  digest: Digest32,
  secretKey: SecretKey,
): SchnorrSignature {
  const extraSymbols = requireCapability('extrakeys');
  const schnorrSymbols = requireCapability('schnorrsig');
  const secret = secretKey.exportBytes();
  const message = digest.toBytes();
  const auxiliaryRandom = new Uint8Array(32);
  const keypair = new Uint8Array(KEYPAIR_SIZE);
  const xOnly = new Uint8Array(X_ONLY_PUBLIC_KEY_SIZE);
  try {
    crypto.getRandomValues(auxiliaryRandom);
    const serialized = withSigningContext((context) => {
      if (
        extraSymbols.secp256k1_keypair_create(context, keypair, secret) !== 1
      ) {
        throw new Error('Native keypair creation failed');
      }
      if (
        extraSymbols.secp256k1_keypair_xonly_pub(
          context,
          xOnly,
          null,
          keypair,
        ) !== 1
      ) {
        throw new Error('Native x-only public-key derivation failed');
      }
      const signature = new Uint8Array(64);
      if (
        schnorrSymbols.secp256k1_schnorrsig_sign32(
          context,
          signature,
          message,
          keypair,
          auxiliaryRandom,
        ) !== 1
      ) {
        throw new Error('Native Taproot signing failed');
      }
      if (
        schnorrSymbols.secp256k1_schnorrsig_verify(
          context,
          signature,
          message,
          32n,
          xOnly,
        ) !== 1
      ) {
        throw new Error('Native Taproot signature post-verification failed');
      }
      return signature;
    });
    return SchnorrSignature.fromBytes(serialized);
  } finally {
    secret.fill(0);
    message.fill(0);
    auxiliaryRandom.fill(0);
    keypair.fill(0);
    xOnly.fill(0);
  }
}

function isValidSecretKey(bytes: Uint8Array): boolean {
  const symbols = getNativeSymbols();
  return withStaticContext((context) =>
    symbols.secp256k1_ec_seckey_verify(context, bytes) === 1
  );
}
