import { withStaticContext } from '../native/context.ts';
import { getNativeSymbols, requireCapability } from '../native/loader.ts';
import { invalidInput } from './input.ts';

const PUBLIC_KEY_SIZE = 64;
const X_ONLY_PUBLIC_KEY_SIZE = 64;
const EC_COMPRESSED = 258;
const EC_UNCOMPRESSED = 2;

/**
 * The SEC encoding accepted when a {@link PublicKey} was parsed.
 *
 * Hybrid encodings are historically relevant to Bitcoin consensus, while
 * compressed/uncompressed restrictions belong in the caller's script and
 * policy validation.
 *
 * @see https://github.com/bitcoin-core/secp256k1/blob/master/include/secp256k1.h
 * @since 1.0.0
 */
export type PublicKeyEncoding = 'compressed' | 'uncompressed' | 'hybrid';

/**
 * An immutable, validated secp256k1 public key with source SEC metadata.
 *
 * Compressed (33-byte), uncompressed (65-byte), and hybrid (65-byte) SEC
 * encodings accepted by libsecp256k1 are supported. All input and output byte
 * arrays are copied. Use `tryParse` for peer-controlled bytes.
 *
 * @example
 * ```ts
 * #!/usr/bin/env -S deno run --allow-env=DENO_SECP256K1_PATH --allow-ffi
 * import { PublicKey } from "../mod.ts";
 *
 * const bytes = Uint8Array.from([
 *   0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0,
 *   0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d,
 *   0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
 * ]);
 * const key = PublicKey.parse(bytes);
 * console.assert(key.sourceEncoding === "compressed");
 * ```
 *
 * @see https://github.com/bitcoin-core/secp256k1/blob/master/include/secp256k1.h
 * @since 1.0.0
 */
export class PublicKey {
  readonly #compressed: Uint8Array;
  readonly #sourceEncoding: PublicKeyEncoding;

  private constructor(
    compressed: Uint8Array,
    sourceEncoding: PublicKeyEncoding,
  ) {
    this.#compressed = compressed;
    this.#sourceEncoding = sourceEncoding;
  }

  /**
   * The valid SEC encoding used by the original parsed input.
   *
   * @returns `compressed`, `uncompressed`, or historically valid `hybrid`.
   * @since 1.0.0
   */
  get sourceEncoding(): PublicKeyEncoding {
    return this.#sourceEncoding;
  }

  /**
   * Parses and validates a compressed, uncompressed, or hybrid SEC key.
   *
   * @param bytes A 33-byte compressed or 65-byte uncompressed/hybrid key.
   * @returns A validated key that owns a copy of the input value.
   * @throws {Secp256k1InputError} If the SEC encoding or curve point is invalid.
   * @throws Native configuration and loading errors unchanged.
   * @since 1.0.0
   */
  static parse(bytes: Uint8Array): PublicKey {
    return PublicKey.tryParse(bytes) ??
      invalidInput('PublicKey', 'invalid SEC-encoded secp256k1 point');
  }

  /**
   * Tries to parse an untrusted SEC-encoded public key.
   *
   * @param bytes Candidate compressed, uncompressed, or hybrid SEC bytes.
   * @returns A copied, validated key, or `null` for malformed input.
   * @throws Native configuration and loading errors unchanged.
   * @since 1.0.0
   */
  static tryParse(bytes: Uint8Array): PublicKey | null {
    const encoding = sourceEncoding(bytes);
    if (encoding === null) return null;

    const internal = parsePublicKeyBytes(bytes);
    if (internal === null) return null;
    return new PublicKey(serializePublicKey(internal, true), encoding);
  }

  /**
   * Serializes this key in canonical 33-byte compressed SEC form.
   *
   * @returns A detached byte array.
   * @since 1.0.0
   */
  toCompressedBytes(): Uint8Array {
    return this.#compressed.slice();
  }

  /**
   * Serializes this key in canonical 65-byte uncompressed SEC form.
   *
   * Hybrid source encodings are intentionally canonicalized to prefix `0x04`.
   *
   * @returns A detached byte array.
   * @throws Native configuration and loading errors unchanged.
   * @since 1.0.0
   */
  toUncompressedBytes(): Uint8Array {
    const internal = requirePublicKeyBytes(this.#compressed);
    return serializePublicKey(internal, false);
  }

  /**
   * Returns this point as the canonical compressed-key value type.
   *
   * @returns An immutable value containing a private copy.
   * @since 1.0.0
   */
  toCompressed(): CompressedPublicKey {
    return CompressedPublicKey.parse(this.#compressed);
  }

  /**
   * Converts this point to its BIP340 x-only key and Y parity.
   *
   * @returns The x-only key and `0` for even Y or `1` for odd Y.
   * @throws {NativeCapabilityError} If the native extrakeys module is absent.
   * @throws Native configuration and loading errors unchanged.
   * @see https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
   * @since 1.0.0
   */
  toXOnly(): { key: XOnlyPublicKey; parity: 0 | 1 } {
    const symbols = requireCapability('extrakeys');
    const publicKey = requirePublicKeyBytes(this.#compressed);

    return withStaticContext((context) => {
      const xOnly = new Uint8Array(X_ONLY_PUBLIC_KEY_SIZE);
      const parity = new Int32Array(1);
      if (
        symbols.secp256k1_xonly_pubkey_from_pubkey(
          context,
          xOnly,
          parity,
          publicKey,
        ) !== 1
      ) {
        throw new Error('Native x-only public-key conversion failed');
      }
      const serialized = new Uint8Array(32);
      if (
        symbols.secp256k1_xonly_pubkey_serialize(
          context,
          serialized,
          xOnly,
        ) !== 1
      ) {
        throw new Error('Native x-only public-key serialization failed');
      }
      return {
        key: XOnlyPublicKey.parse(serialized),
        parity: parity[0] === 0 ? 0 : 1,
      };
    });
  }
}

/**
 * An immutable canonical 33-byte compressed SEC public key.
 *
 * This distinct type is suitable for ordered key collections such as MuSig2.
 * Inputs and outputs are copied, and the represented curve point is validated.
 *
 * @since 1.0.0
 */
export class CompressedPublicKey {
  readonly #bytes: Uint8Array;

  private constructor(bytes: Uint8Array) {
    this.#bytes = bytes;
  }

  /**
   * Parses a canonical 33-byte compressed SEC public key.
   *
   * @param bytes Candidate compressed SEC bytes; copied on success.
   * @returns A validated compressed public key.
   * @throws {Secp256k1InputError} If the encoding or curve point is invalid.
   * @throws Native configuration and loading errors unchanged.
   * @since 1.0.0
   */
  static parse(bytes: Uint8Array): CompressedPublicKey {
    return CompressedPublicKey.tryParse(bytes) ??
      invalidInput(
        'CompressedPublicKey',
        'expected a valid canonical 33-byte compressed SEC key',
      );
  }

  /**
   * Tries to parse an untrusted canonical compressed SEC key.
   *
   * @param bytes Candidate bytes; copied on success.
   * @returns A validated key, or `null` for malformed input.
   * @throws Native configuration and loading errors unchanged.
   * @since 1.0.0
   */
  static tryParse(bytes: Uint8Array): CompressedPublicKey | null {
    if (bytes.length !== 33 || (bytes[0] !== 0x02 && bytes[0] !== 0x03)) {
      return null;
    }
    const parsed = PublicKey.tryParse(bytes);
    return parsed === null
      ? null
      : new CompressedPublicKey(parsed.toCompressedBytes());
  }

  /**
   * Returns the canonical 33-byte compressed SEC encoding.
   *
   * @returns A detached byte array.
   * @since 1.0.0
   */
  toBytes(): Uint8Array {
    return this.#bytes.slice();
  }

  /**
   * Widens this value to a general validated public key.
   *
   * @returns A new immutable public-key value.
   * @since 1.0.0
   */
  toPublicKey(): PublicKey {
    return PublicKey.parse(this.#bytes);
  }
}

/**
 * An immutable validated 32-byte BIP340 x-only public key.
 *
 * Parsing checks that the X coordinate corresponds to a secp256k1 point with
 * even Y. Inputs and outputs are copied. Use `tryParse` for peer input.
 *
 * @see https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
 * @since 1.0.0
 */
export class XOnlyPublicKey {
  readonly #bytes: Uint8Array;

  private constructor(bytes: Uint8Array) {
    this.#bytes = bytes;
  }

  /**
   * Parses and validates exactly 32 serialized x-only key bytes.
   *
   * @param bytes Candidate BIP340 x-only key; copied on success.
   * @returns A validated immutable key.
   * @throws {Secp256k1InputError} If length or point validation fails.
   * @throws {NativeCapabilityError} If the native extrakeys module is absent.
   * @throws Native configuration and loading errors unchanged.
   * @since 1.0.0
   */
  static parse(bytes: Uint8Array): XOnlyPublicKey {
    return XOnlyPublicKey.tryParse(bytes) ??
      invalidInput('XOnlyPublicKey', 'invalid 32-byte x-only public key');
  }

  /**
   * Tries to parse an untrusted 32-byte BIP340 x-only public key.
   *
   * @param bytes Candidate bytes; copied on success.
   * @returns A validated key, or `null` for malformed input.
   * @throws {NativeCapabilityError} If the native extrakeys module is absent.
   * @throws Native configuration and loading errors unchanged.
   * @since 1.0.0
   */
  static tryParse(bytes: Uint8Array): XOnlyPublicKey | null {
    if (bytes.length !== 32) return null;
    const symbols = requireCapability('extrakeys');
    const copy = bytes.slice();
    const valid = withStaticContext((context) => {
      const internal = new Uint8Array(X_ONLY_PUBLIC_KEY_SIZE);
      return symbols.secp256k1_xonly_pubkey_parse(
        context,
        internal,
        copy,
      ) === 1;
    });
    return valid ? new XOnlyPublicKey(copy) : null;
  }

  /**
   * Returns the canonical 32-byte x-only serialization.
   *
   * @returns A detached byte array.
   * @since 1.0.0
   */
  toBytes(): Uint8Array {
    return this.#bytes.slice();
  }
}

/** @internal Parses a public value into libsecp256k1's opaque representation. */
export function nativePublicKey(key: PublicKey): Uint8Array {
  return requirePublicKeyBytes(key.toCompressedBytes());
}

/** @internal Parses an x-only value into libsecp256k1's opaque representation. */
export function nativeXOnlyPublicKey(key: XOnlyPublicKey): Uint8Array {
  const symbols = requireCapability('extrakeys');
  const internal = new Uint8Array(X_ONLY_PUBLIC_KEY_SIZE);
  const valid = withStaticContext((context) =>
    symbols.secp256k1_xonly_pubkey_parse(
      context,
      internal,
      key.toBytes(),
    ) === 1
  );
  if (!valid) throw new Error('Native x-only public-key reparse failed');
  return internal;
}

function sourceEncoding(bytes: Uint8Array): PublicKeyEncoding | null {
  if (bytes.length === 33 && (bytes[0] === 0x02 || bytes[0] === 0x03)) {
    return 'compressed';
  }
  if (bytes.length === 65 && bytes[0] === 0x04) return 'uncompressed';
  if (bytes.length === 65 && (bytes[0] === 0x06 || bytes[0] === 0x07)) {
    return 'hybrid';
  }
  return null;
}

function parsePublicKeyBytes(bytes: Uint8Array): Uint8Array | null {
  const symbols = getNativeSymbols();
  return withStaticContext((context) => {
    const internal = new Uint8Array(PUBLIC_KEY_SIZE);
    return symbols.secp256k1_ec_pubkey_parse(
        context,
        internal,
        bytes,
        BigInt(bytes.length),
      ) === 1
      ? internal
      : null;
  });
}

function requirePublicKeyBytes(bytes: Uint8Array): Uint8Array {
  const internal = parsePublicKeyBytes(bytes);
  if (internal === null) throw new Error('Native public-key reparse failed');
  return internal;
}

function serializePublicKey(
  internal: Uint8Array,
  compressed: boolean,
): Uint8Array {
  const symbols = getNativeSymbols();
  return withStaticContext((context) => {
    const length = compressed ? 33 : 65;
    const output = new Uint8Array(length);
    const outputLength = new BigUint64Array([BigInt(length)]);
    if (
      symbols.secp256k1_ec_pubkey_serialize(
          context,
          output,
          outputLength,
          internal,
          compressed ? EC_COMPRESSED : EC_UNCOMPRESSED,
        ) !== 1 || outputLength[0] !== BigInt(length)
    ) {
      throw new Error('Native public-key serialization failed');
    }
    return output;
  });
}
