/**
 * BIP341 Taproot public- and secret-key tweaking.
 *
 * The TapTweak hash is always derived internally from the x-only internal key
 * and an optional Merkle root. Passing `null` means no script tree and hashes
 * an empty suffix; it is distinct from a 32-byte all-zero Merkle root.
 *
 * @example Derive a key-path-only output key
 * ```ts
 * #!/usr/bin/env -S deno run --allow-env=DENO_SECP256K1_PATH --allow-ffi
 * import {
 *   taprootTweakPublicKey,
 *   XOnlyPublicKey,
 * } from "jsr:@bonakodo/secp256k1@1/taproot.ts";
 *
 * const internalKey = XOnlyPublicKey.parse(
 *   Uint8Array.from([0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac,
 *     0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b,
 *     0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b,
 *     0x16, 0xf8, 0x17, 0x98]),
 * );
 * const output = taprootTweakPublicKey({ internalKey, merkleRoot: null });
 * console.assert(output.outputKey.toBytes().length === 32);
 * ```
 *
 * @module
 * @since 1.0.0
 */

import { invalidInput } from './api/input.ts';
import * as keys from './api/keys.ts';
import { nativeXOnlyPublicKey } from './api/keys.ts';
import { withSigningContext, withStaticContext } from './native/context.ts';
import { getNativeSymbols, requireCapability } from './native/loader.ts';
import { SecretKey } from './signing.ts';

// This explicit alias keeps the duplicate entrypoint export documented by JSR
// while preserving the identity of the immutable source binding.
/** A validated 32-byte x-only public key used by Taproot. */
export import XOnlyPublicKey = keys.XOnlyPublicKey;

const TAP_TWEAK_TAG = new TextEncoder().encode('TapTweak');
const KEYPAIR_SIZE = 96;
const X_ONLY_PUBLIC_KEY_SIZE = 64;
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

/**
 * The reason a derived BIP341 TapTweak could not be applied.
 *
 * @since 1.0.0
 */
export type TaprootTweakErrorCode =
  | 'invalid-tweak'
  | 'public-key-infinity'
  | 'secret-key-zero';

/**
 * Thrown when a BIP341 tweak scalar or resulting key is invalid.
 *
 * @since 1.0.0
 */
export class TaprootTweakError extends Error {
  /**
   * Stable machine-readable failure reason.
   *
   * @since 1.0.0
   */
  readonly code: TaprootTweakErrorCode;

  /**
   * Creates a Taproot tweak error.
   *
   * @param code The invalid scalar or curve result.
   * @since 1.0.0
   */
  constructor(code: TaprootTweakErrorCode) {
    const messages: Record<TaprootTweakErrorCode, string> = {
      'invalid-tweak': 'BIP341 TapTweak hash is not a valid curve scalar',
      'public-key-infinity': 'BIP341 public-key tweak produced infinity',
      'secret-key-zero': 'BIP341 secret-key tweak produced zero',
    };
    super(messages[code]);
    this.name = 'TaprootTweakError';
    this.code = code;
  }
}

/**
 * An immutable exact 32-byte BIP341 Taproot Merkle root.
 *
 * This value represents a present script tree. Use `null`, not an all-zero
 * instance, when a Taproot output has no script tree.
 *
 * @see https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
 * @since 1.0.0
 */
export class TapMerkleRoot {
  readonly #bytes: Uint8Array;

  private constructor(bytes: Uint8Array) {
    this.#bytes = bytes;
  }

  /**
   * Creates a Merkle-root value from exactly 32 bytes.
   *
   * @param bytes The TapBranch root, copied on success.
   * @returns An immutable Merkle-root value.
   * @throws {Secp256k1InputError} If `bytes` is not exactly 32 bytes.
   * @since 1.0.0
   */
  static fromBytes(bytes: Uint8Array): TapMerkleRoot {
    if (bytes.length !== 32) {
      return invalidInput('TapMerkleRoot', 'expected exactly 32 bytes');
    }
    return new TapMerkleRoot(bytes.slice());
  }

  /**
   * Tries to create a Merkle-root value from untrusted bytes.
   *
   * @param bytes Candidate TapBranch root bytes.
   * @returns A copied value, or `null` unless the length is exactly 32.
   * @since 1.0.0
   */
  static tryFromBytes(bytes: Uint8Array): TapMerkleRoot | null {
    return bytes.length === 32 ? new TapMerkleRoot(bytes.slice()) : null;
  }

  /**
   * Returns the exact 32-byte Taproot Merkle root.
   *
   * @returns A detached mutable copy.
   * @since 1.0.0
   */
  toBytes(): Uint8Array {
    return this.#bytes.slice();
  }
}

/**
 * Result of tweaking a BIP341 internal public key.
 *
 * @since 1.0.0
 */
export interface TaprootPublicKeyTweakResult {
  /**
   * The immutable 32-byte x-only Taproot output key.
   *
   * @since 1.0.0
   */
  readonly outputKey: XOnlyPublicKey;
  /**
   * The Y parity committed to by a Taproot control block.
   *
   * @since 1.0.0
   */
  readonly outputKeyParity: 0 | 1;
}

/**
 * Result of tweaking a BIP341 internal secret key.
 *
 * @since 1.0.0
 */
export interface TaprootSecretKeyTweakResult {
  /**
   * A new independently disposable output-key secret.
   *
   * @since 1.0.0
   */
  readonly secretKey: SecretKey;
  /**
   * The Y parity committed to by a Taproot control block.
   *
   * @since 1.0.0
   */
  readonly outputKeyParity: 0 | 1;
}

/**
 * Input for BIP341 public-key tweaking.
 *
 * @since 1.0.0
 */
export interface TaprootPublicKeyTweakInput {
  /**
   * The validated even-Y x-only internal public key.
   *
   * @since 1.0.0
   */
  readonly internalKey: XOnlyPublicKey;
  /**
   * A script-tree root, or `null` when no script tree exists.
   *
   * @since 1.0.0
   */
  readonly merkleRoot: TapMerkleRoot | null;
}

/**
 * Input for BIP341 secret-key tweaking.
 *
 * @since 1.0.0
 */
export interface TaprootSecretKeyTweakInput {
  /**
   * A live secret whose x-only public key is the internal key.
   *
   * @since 1.0.0
   */
  readonly internalKey: SecretKey;
  /**
   * A script-tree root, or `null` when no script tree exists.
   *
   * @since 1.0.0
   */
  readonly merkleRoot: TapMerkleRoot | null;
}

/**
 * Input for checking a claimed BIP341 tweak result.
 *
 * @since 1.0.0
 */
export interface TaprootTweakCheckInput extends TaprootPublicKeyTweakInput {
  /**
   * The claimed 32-byte x-only Taproot output key.
   *
   * @since 1.0.0
   */
  readonly outputKey: XOnlyPublicKey;
  /**
   * The claimed output point's Y parity.
   *
   * @since 1.0.0
   */
  readonly outputKeyParity: 0 | 1;
}

/**
 * Derives a BIP341 Taproot output key from an internal public key.
 *
 * @param input Internal key and optional script-tree root.
 * @returns The x-only output key and its Y parity.
 * @throws {TaprootTweakError} If the tweak is out of range or yields infinity.
 * @throws {NativeCapabilityError} If extrakeys is unavailable.
 * @throws Native configuration, loading, or runtime errors unchanged.
 * @see https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
 * @since 1.0.0
 */
export function taprootTweakPublicKey(
  input: TaprootPublicKeyTweakInput,
): TaprootPublicKeyTweakResult {
  const symbols = requireCapability('extrakeys');
  const internal = nativeXOnlyPublicKey(input.internalKey);
  const tweak = deriveTapTweak(input.internalKey, input.merkleRoot);
  try {
    if (!isValidTapTweak(tweak)) {
      throw new TaprootTweakError('invalid-tweak');
    }
    return withStaticContext((context) => {
      const output = new Uint8Array(64);
      if (
        symbols.secp256k1_xonly_pubkey_tweak_add(
          context,
          output,
          internal,
          tweak,
        ) !== 1
      ) {
        throw new TaprootTweakError('public-key-infinity');
      }
      const outputXOnly = new Uint8Array(X_ONLY_PUBLIC_KEY_SIZE);
      const parity = new Int32Array(1);
      if (
        symbols.secp256k1_xonly_pubkey_from_pubkey(
          context,
          outputXOnly,
          parity,
          output,
        ) !== 1
      ) {
        throw new Error('Native Taproot output-key conversion failed');
      }
      const serialized = new Uint8Array(32);
      if (
        symbols.secp256k1_xonly_pubkey_serialize(
          context,
          serialized,
          outputXOnly,
        ) !== 1
      ) {
        throw new Error('Native Taproot output-key serialization failed');
      }
      return {
        outputKey: XOnlyPublicKey.parse(serialized),
        outputKeyParity: parity[0] === 0 ? 0 : 1,
      };
    });
  } finally {
    tweak.fill(0);
  }
}

/**
 * Derives a BIP341 Taproot output secret using x-only parity normalization.
 *
 * The original key remains live and unchanged. The returned key is independent
 * and must be disposed separately.
 *
 * @param input Live internal secret and optional script-tree root.
 * @returns A new output secret and the output public key's Y parity.
 * @throws {SecretKeyDestroyedError} If `internalKey` was destroyed.
 * @throws {TaprootTweakError} If the tweak is out of range or yields zero.
 * @throws {NativeCapabilityError} If extrakeys is unavailable.
 * @throws Native configuration, loading, or runtime errors unchanged.
 * @see https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
 * @since 1.0.0
 */
export function taprootTweakSecretKey(
  input: TaprootSecretKeyTweakInput,
): TaprootSecretKeyTweakResult {
  const symbols = requireCapability('extrakeys');
  const original = input.internalKey.exportBytes();
  const keypair = new Uint8Array(KEYPAIR_SIZE);
  const outputSecret = new Uint8Array(32);
  const outputXOnly = new Uint8Array(X_ONLY_PUBLIC_KEY_SIZE);
  let tweak: Uint8Array | undefined;
  try {
    const internalPublicKey = input.internalKey.xOnlyPublicKey().key;
    const derivedTweak = deriveTapTweak(internalPublicKey, input.merkleRoot);
    tweak = derivedTweak;
    if (!isValidTapTweak(derivedTweak)) {
      throw new TaprootTweakError('invalid-tweak');
    }
    return withSigningContext((context) => {
      if (
        symbols.secp256k1_keypair_create(context, keypair, original) !== 1
      ) {
        throw new Error('Native keypair creation failed');
      }
      if (
        symbols.secp256k1_keypair_xonly_tweak_add(
          context,
          keypair,
          derivedTweak,
        ) !== 1
      ) {
        throw new TaprootTweakError('secret-key-zero');
      }
      if (
        symbols.secp256k1_keypair_sec(context, outputSecret, keypair) !== 1
      ) {
        throw new Error('Native tweaked secret-key extraction failed');
      }
      const parity = new Int32Array(1);
      if (
        symbols.secp256k1_keypair_xonly_pub(
          context,
          outputXOnly,
          parity,
          keypair,
        ) !== 1
      ) {
        throw new Error('Native tweaked public-key extraction failed');
      }
      return {
        secretKey: SecretKey.fromBytes(outputSecret),
        outputKeyParity: parity[0] === 0 ? 0 : 1,
      };
    });
  } finally {
    original.fill(0);
    tweak?.fill(0);
    keypair.fill(0);
    outputSecret.fill(0);
    outputXOnly.fill(0);
  }
}

/**
 * Checks a claimed BIP341 output key and parity without throwing on mismatch.
 *
 * @param input Internal key, optional root, claimed output key, and parity.
 * @returns `true` only when all claimed output data matches the BIP341 tweak.
 * @throws {NativeCapabilityError} If extrakeys is unavailable.
 * @throws Native configuration, loading, or runtime errors unchanged.
 * @since 1.0.0
 */
export function checkTaprootTweak(input: TaprootTweakCheckInput): boolean {
  const symbols = requireCapability('extrakeys');
  const internal = nativeXOnlyPublicKey(input.internalKey);
  const tweak = deriveTapTweak(input.internalKey, input.merkleRoot);
  try {
    if (!isValidTapTweak(tweak)) return false;
    return withStaticContext((context) =>
      symbols.secp256k1_xonly_pubkey_tweak_add_check(
        context,
        input.outputKey.toBytes(),
        input.outputKeyParity,
        internal,
        tweak,
      ) === 1
    );
  } finally {
    tweak.fill(0);
  }
}

function isValidTapTweak(tweak: Uint8Array): boolean {
  for (let index = 0; index < 32; index++) {
    if (tweak[index] < GROUP_ORDER[index]) return true;
    if (tweak[index] > GROUP_ORDER[index]) return false;
  }
  return false;
}

function deriveTapTweak(
  internalKey: XOnlyPublicKey,
  merkleRoot: TapMerkleRoot | null,
): Uint8Array {
  const symbols = getNativeSymbols();
  const keyBytes = internalKey.toBytes();
  const rootBytes = merkleRoot?.toBytes();
  const message = new Uint8Array(rootBytes === undefined ? 32 : 64);
  message.set(keyBytes);
  if (rootBytes !== undefined) message.set(rootBytes, 32);
  try {
    return withStaticContext((context) => {
      const output = new Uint8Array(32);
      if (
        symbols.secp256k1_tagged_sha256(
          context,
          output,
          TAP_TWEAK_TAG,
          BigInt(TAP_TWEAK_TAG.length),
          message,
          BigInt(message.length),
        ) !== 1
      ) {
        throw new Error('Native TapTweak tagged hash failed');
      }
      return output;
    });
  } finally {
    keyBytes.fill(0);
    rootBytes?.fill(0);
    message.fill(0);
  }
}
