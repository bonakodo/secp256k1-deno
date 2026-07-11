/**
 * Additive secp256k1 key tweaks for Bitcoin key derivation.
 *
 * This module deliberately omits multiplicative tweaks. Taproot callers should
 * use `taproot.ts`, which derives the BIP341 tweak internally.
 *
 * @example Add one to a secret key
 * ```ts
 * #!/usr/bin/env -S deno run --allow-env=DENO_SECP256K1_PATH --allow-ffi
 * import { addTweakToSecretKey, Tweak32 } from "./key_tweaks.ts";
 * import { SecretKey } from "./signing.ts";
 *
 * const one = new Uint8Array(32);
 * one[31] = 1;
 * using key = SecretKey.fromBytes(one);
 * using child = addTweakToSecretKey(key, Tweak32.fromBytes(one));
 * console.assert(child.exportBytes()[31] === 2);
 * ```
 *
 * @module
 */

import { invalidInput } from './api/input.ts';
import { nativePublicKey, PublicKey } from './api/keys.ts';
import { withSigningContext, withStaticContext } from './native/context.ts';
import { getNativeSymbols } from './native/loader.ts';
import { SecretKey } from './signing.ts';

export { CompressedPublicKey, PublicKey } from './api/keys.ts';
export type { PublicKeyEncoding } from './api/keys.ts';

const GROUP_ORDER = Uint8Array.from([
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xfe,
  0xba,
  0xae,
  0xdc,
  0xe6,
  0xaf,
  0x48,
  0xa0,
  0x3b,
  0xbf,
  0xd2,
  0x5e,
  0x8c,
  0xd0,
  0x36,
  0x41,
  0x41,
]);
const EC_COMPRESSED = 258;

/** The reason an otherwise valid additive tweak could not be applied. */
export type KeyTweakErrorCode = 'secret-key-zero' | 'public-key-infinity';

/** Thrown when additive key arithmetic produces an invalid curve result. */
export class KeyTweakError extends Error {
  /** Stable machine-readable failure reason. */
  readonly code: KeyTweakErrorCode;

  /**
   * Creates an additive key-tweak result error.
   *
   * @param code The invalid result produced by the addition.
   * @since 1.0.0
   */
  constructor(code: KeyTweakErrorCode) {
    super(
      code === 'secret-key-zero'
        ? 'Additive tweak produced the zero secret key'
        : 'Additive tweak produced the point at infinity',
    );
    this.name = 'KeyTweakError';
    this.code = code;
  }
}

/**
 * An immutable 32-byte additive scalar in the range `0..n-1`.
 *
 * Zero is valid and produces an independently owned copy of the input key.
 * Inputs and outputs are copied.
 *
 * @since 1.0.0
 */
export class Tweak32 {
  readonly #bytes: Uint8Array;

  private constructor(bytes: Uint8Array) {
    this.#bytes = bytes;
  }

  /**
   * Parses an exact big-endian scalar in the range `0..n-1`.
   *
   * @param bytes Exactly 32 bytes, copied on success.
   * @returns An immutable additive tweak.
   * @throws {Secp256k1InputError} If the length is wrong or value is `>= n`.
   * @since 1.0.0
   */
  static fromBytes(bytes: Uint8Array): Tweak32 {
    if (bytes.length !== 32 || compare32(bytes, GROUP_ORDER) >= 0) {
      return invalidInput(
        'Tweak32',
        'expected a 32-byte scalar in the range 0..n-1',
      );
    }
    return new Tweak32(bytes.slice());
  }

  /**
   * Tries to parse untrusted additive-tweak bytes.
   *
   * @param bytes Candidate big-endian scalar bytes.
   * @returns A copied tweak, or `null` for wrong length or value `>= n`.
   * @since 1.0.0
   */
  static tryFromBytes(bytes: Uint8Array): Tweak32 | null {
    return bytes.length === 32 && compare32(bytes, GROUP_ORDER) < 0
      ? new Tweak32(bytes.slice())
      : null;
  }

  /**
   * Returns the exact 32-byte big-endian scalar.
   *
   * @returns A detached mutable copy.
   * @since 1.0.0
   */
  toBytes(): Uint8Array {
    return this.#bytes.slice();
  }
}

/**
 * Adds a scalar to a secret key without mutating either input.
 *
 * @param secretKey A live secret-key handle.
 * @param tweak An additive scalar, including zero.
 * @returns A new independently disposable secret key.
 * @throws {SecretKeyDestroyedError} If `secretKey` was destroyed.
 * @throws {KeyTweakError} If the result is zero modulo the group order.
 * @throws Native configuration, loading, or runtime errors unchanged.
 * @since 1.0.0
 */
export function addTweakToSecretKey(
  secretKey: SecretKey,
  tweak: Tweak32,
): SecretKey {
  const symbols = getNativeSymbols();
  const result = secretKey.exportBytes();
  const tweakBytes = tweak.toBytes();
  try {
    const valid = withSigningContext((context) =>
      symbols.secp256k1_ec_seckey_tweak_add(
        context,
        result,
        tweakBytes,
      ) === 1
    );
    if (!valid) throw new KeyTweakError('secret-key-zero');
    return SecretKey.fromBytes(result);
  } finally {
    result.fill(0);
    tweakBytes.fill(0);
  }
}

/**
 * Adds `tweak * G` to a public key without mutating either input.
 *
 * @param publicKey A validated compressed, uncompressed, or hybrid key value.
 * @param tweak An additive scalar, including zero.
 * @returns A new key in canonical compressed SEC form.
 * @throws {KeyTweakError} If the result is the point at infinity.
 * @throws Native configuration, loading, or runtime errors unchanged.
 * @since 1.0.0
 */
export function addTweakToPublicKey(
  publicKey: PublicKey,
  tweak: Tweak32,
): PublicKey {
  const symbols = getNativeSymbols();
  const internal = nativePublicKey(publicKey);
  const tweakBytes = tweak.toBytes();
  try {
    return withStaticContext((context) => {
      if (
        symbols.secp256k1_ec_pubkey_tweak_add(
          context,
          internal,
          tweakBytes,
        ) !== 1
      ) {
        throw new KeyTweakError('public-key-infinity');
      }
      const output = new Uint8Array(33);
      const length = new BigUint64Array([33n]);
      if (
        symbols.secp256k1_ec_pubkey_serialize(
            context,
            output,
            length,
            internal,
            EC_COMPRESSED,
          ) !== 1 || length[0] !== 33n
      ) {
        throw new Error('Native tweaked public-key serialization failed');
      }
      return PublicKey.parse(output);
    });
  } finally {
    tweakBytes.fill(0);
  }
}

function compare32(left: Uint8Array, right: Uint8Array): number {
  for (let index = 0; index < 32; index++) {
    if (left[index] < right[index]) return -1;
    if (left[index] > right[index]) return 1;
  }
  return 0;
}
