import { withStaticContext } from '../native/context.ts';
import { getNativeSymbols } from '../native/loader.ts';
import { copyExact, invalidInput } from './input.ts';

const ECDSA_SIGNATURE_SIZE = 64;

/**
 * An immutable strict-DER ECDSA signature candidate.
 *
 * Construction validates only Bitcoin's strict DER signature syntax and
 * preserves the original bytes. Scalar validity is deliberately deferred to
 * `decode`, so syntactically valid zero or out-of-range values produce `null`
 * rather than a fake all-zero signature.
 *
 * @see https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki
 * @since 1.0.0
 */
export class EcdsaDerSignature {
  readonly #bytes: Uint8Array;

  private constructor(bytes: Uint8Array) {
    this.#bytes = bytes;
  }

  /**
   * Creates a candidate from a complete strict-DER ECDSA encoding.
   *
   * The Bitcoin transaction sighash-type byte is not part of this value.
   *
   * @param bytes An 8-to-72-byte DER signature candidate; copied on success.
   * @returns A syntax-validated immutable candidate.
   * @throws {Secp256k1InputError} If strict DER syntax is invalid.
   * @since 1.0.0
   */
  static fromBytes(bytes: Uint8Array): EcdsaDerSignature {
    return EcdsaDerSignature.tryFromBytes(bytes) ??
      invalidInput('EcdsaDerSignature', 'invalid strict DER encoding');
  }

  /**
   * Tries to create a strict-DER candidate from untrusted bytes.
   *
   * This syntax check does not initialize the native library.
   *
   * @param bytes Candidate DER bytes; copied on success.
   * @returns A candidate for valid strict syntax, otherwise `null`.
   * @since 1.0.0
   */
  static tryFromBytes(bytes: Uint8Array): EcdsaDerSignature | null {
    return isStrictDerSignature(bytes)
      ? new EcdsaDerSignature(bytes.slice())
      : null;
  }

  /**
   * Returns the exact original strict-DER encoding.
   *
   * @returns A detached byte array.
   * @since 1.0.0
   */
  toBytes(): Uint8Array {
    return this.#bytes.slice();
  }

  /**
   * Decodes this candidate into valid ECDSA scalars.
   *
   * @returns A signature when `1 <= R,S < n`; otherwise `null`.
   * @throws Native configuration and loading errors unchanged.
   * @since 1.0.0
   */
  decode(): EcdsaSignature | null {
    const symbols = getNativeSymbols();
    const compact = withStaticContext((context) => {
      const internal = new Uint8Array(ECDSA_SIGNATURE_SIZE);
      if (
        symbols.secp256k1_ecdsa_signature_parse_der(
          context,
          internal,
          this.#bytes,
          BigInt(this.#bytes.length),
        ) !== 1
      ) {
        return null;
      }
      return serializeCompact(internal);
    });
    return compact === null ? null : EcdsaSignature.fromBytes(compact);
  }
}

/**
 * An immutable 64-byte compact ECDSA signature candidate.
 *
 * Construction checks length only. Call `decode` to require valid non-zero R
 * and S scalars below the secp256k1 group order.
 *
 * @since 1.0.0
 */
export class EcdsaCompactSignature {
  readonly #bytes: Uint8Array;

  private constructor(bytes: Uint8Array) {
    this.#bytes = bytes;
  }

  /**
   * Creates a candidate from exactly 64 compact bytes (`R || S`).
   *
   * @param bytes Compact candidate bytes; copied on success.
   * @returns An immutable length-checked candidate.
   * @throws {Secp256k1InputError} If `bytes` is not exactly 64 bytes.
   * @since 1.0.0
   */
  static fromBytes(bytes: Uint8Array): EcdsaCompactSignature {
    return EcdsaCompactSignature.tryFromBytes(bytes) ??
      invalidInput('EcdsaCompactSignature', 'expected exactly 64 bytes');
  }

  /**
   * Tries to create a compact candidate from untrusted bytes.
   *
   * @param bytes Candidate bytes; copied on success.
   * @returns A candidate for exactly 64 bytes, otherwise `null`.
   * @since 1.0.0
   */
  static tryFromBytes(bytes: Uint8Array): EcdsaCompactSignature | null {
    const copy = copyExact(bytes, 64);
    return copy === null ? null : new EcdsaCompactSignature(copy);
  }

  /**
   * Returns the original 64-byte compact candidate.
   *
   * @returns A detached byte array.
   * @since 1.0.0
   */
  toBytes(): Uint8Array {
    return this.#bytes.slice();
  }

  /**
   * Decodes this candidate into valid ECDSA scalars.
   *
   * @returns A signature when `1 <= R,S < n`; otherwise `null`.
   * @throws Native configuration and loading errors unchanged.
   * @since 1.0.0
   */
  decode(): EcdsaSignature | null {
    return EcdsaSignature.fromBytes(this.#bytes);
  }
}

/**
 * Immutable mathematically valid secp256k1 ECDSA scalars.
 *
 * Instances always satisfy `1 <= R,S < n`. Serialization methods return
 * detached arrays, and normalization returns a new value without mutation.
 *
 * @since 1.0.0
 */
export class EcdsaSignature {
  readonly #compact: Uint8Array;

  private constructor(compact: Uint8Array) {
    this.#compact = compact;
  }

  /**
   * Decodes exactly 64 compact bytes into valid non-zero ECDSA scalars.
   *
   * This is equivalent to `EcdsaCompactSignature.fromBytes(bytes).decode()`.
   *
   * @param bytes Compact `R || S` bytes; copied on success.
   * @returns A valid signature, or `null` for wrong length or invalid scalars.
   * @throws Native configuration and loading errors unchanged for 64-byte input.
   * @since 1.0.0
   */
  static fromBytes(bytes: Uint8Array): EcdsaSignature | null {
    if (bytes.length !== 64 || isZero(bytes, 0) || isZero(bytes, 32)) {
      return null;
    }
    const symbols = getNativeSymbols();
    const compact = bytes.slice();
    const valid = withStaticContext((context) => {
      const internal = new Uint8Array(ECDSA_SIGNATURE_SIZE);
      return symbols.secp256k1_ecdsa_signature_parse_compact(
        context,
        internal,
        compact,
      ) === 1;
    });
    return valid ? new EcdsaSignature(compact) : null;
  }

  /**
   * Reports whether S is in Bitcoin's low-S range.
   *
   * @returns `true` when normalization would not change S.
   * @throws Native configuration and loading errors unchanged.
   * @since 1.0.0
   */
  isLowS(): boolean {
    const symbols = getNativeSymbols();
    const internal = nativeEcdsaSignature(this);
    return withStaticContext((context) =>
      symbols.secp256k1_ecdsa_signature_normalize(
        context,
        null,
        internal,
      ) === 0
    );
  }

  /**
   * Returns an immutable low-S equivalent of this signature.
   *
   * @returns A new signature; this instance is never mutated.
   * @throws Native configuration and loading errors unchanged.
   * @see https://github.com/bitcoin/bips/blob/master/bip-0146.mediawiki
   * @since 1.0.0
   */
  normalize(): EcdsaSignature {
    const symbols = getNativeSymbols();
    const input = nativeEcdsaSignature(this);
    const output = new Uint8Array(ECDSA_SIGNATURE_SIZE);
    withStaticContext((context) => {
      symbols.secp256k1_ecdsa_signature_normalize(context, output, input);
    });
    const normalized = EcdsaSignature.fromBytes(serializeCompact(output));
    if (normalized === null) {
      throw new Error('Native ECDSA normalization produced invalid scalars');
    }
    return normalized;
  }

  /**
   * Serializes this valid signature in strict DER form.
   *
   * The Bitcoin transaction sighash-type byte is not appended.
   *
   * @returns A detached 8-to-72-byte DER encoding.
   * @throws Native configuration and loading errors unchanged.
   * @since 1.0.0
   */
  toDer(): Uint8Array {
    const symbols = getNativeSymbols();
    const internal = nativeEcdsaSignature(this);
    return withStaticContext((context) => {
      const output = new Uint8Array(72);
      const length = new BigUint64Array([72n]);
      if (
        symbols.secp256k1_ecdsa_signature_serialize_der(
          context,
          output,
          length,
          internal,
        ) !== 1
      ) {
        throw new Error('Native DER signature serialization failed');
      }
      return output.slice(0, Number(length[0]));
    });
  }

  /**
   * Serializes this signature as 64-byte compact `R || S`.
   *
   * @returns A detached byte array.
   * @since 1.0.0
   */
  toCompact(): Uint8Array {
    return this.#compact.slice();
  }
}

/**
 * An immutable 64-byte BIP340 Schnorr signature candidate.
 *
 * Construction checks length only because all 64-byte strings are safe
 * verification candidates. `verifyTaprootSignature` performs scalar and
 * equation validation and returns `false` for invalid signatures.
 *
 * @see https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
 * @since 1.0.0
 */
export class SchnorrSignature {
  readonly #bytes: Uint8Array;

  private constructor(bytes: Uint8Array) {
    this.#bytes = bytes;
  }

  /**
   * Creates a Schnorr candidate from exactly 64 bytes.
   *
   * @param bytes Candidate BIP340 signature; copied on success.
   * @returns An immutable length-checked candidate.
   * @throws {Secp256k1InputError} If `bytes` is not exactly 64 bytes.
   * @since 1.0.0
   */
  static fromBytes(bytes: Uint8Array): SchnorrSignature {
    return SchnorrSignature.tryFromBytes(bytes) ??
      invalidInput('SchnorrSignature', 'expected exactly 64 bytes');
  }

  /**
   * Tries to create a Schnorr candidate from untrusted bytes.
   *
   * @param bytes Candidate bytes; copied on success.
   * @returns A candidate for exactly 64 bytes, otherwise `null`.
   * @since 1.0.0
   */
  static tryFromBytes(bytes: Uint8Array): SchnorrSignature | null {
    const copy = copyExact(bytes, 64);
    return copy === null ? null : new SchnorrSignature(copy);
  }

  /**
   * Returns the original 64-byte candidate.
   *
   * @returns A detached byte array.
   * @since 1.0.0
   */
  toBytes(): Uint8Array {
    return this.#bytes.slice();
  }
}

/** @internal Parses valid scalars into libsecp256k1's opaque representation. */
export function nativeEcdsaSignature(signature: EcdsaSignature): Uint8Array {
  const symbols = getNativeSymbols();
  const internal = new Uint8Array(ECDSA_SIGNATURE_SIZE);
  const valid = withStaticContext((context) =>
    symbols.secp256k1_ecdsa_signature_parse_compact(
      context,
      internal,
      signature.toCompact(),
    ) === 1
  );
  if (!valid) throw new Error('Native ECDSA signature reparse failed');
  return internal;
}

function serializeCompact(internal: Uint8Array): Uint8Array {
  const symbols = getNativeSymbols();
  return withStaticContext((context) => {
    const output = new Uint8Array(64);
    if (
      symbols.secp256k1_ecdsa_signature_serialize_compact(
        context,
        output,
        internal,
      ) !== 1
    ) {
      throw new Error('Native compact signature serialization failed');
    }
    return output;
  });
}

function isZero(bytes: Uint8Array, offset: number): boolean {
  for (let index = offset; index < offset + 32; index++) {
    if (bytes[index] !== 0) return false;
  }
  return true;
}

function isStrictDerSignature(bytes: Uint8Array): boolean {
  if (bytes.length < 8 || bytes.length > 72) return false;
  if (bytes[0] !== 0x30 || bytes[1] !== bytes.length - 2) return false;
  if (bytes[2] !== 0x02) return false;

  const rLength = bytes[3];
  if (rLength === 0 || 5 + rLength >= bytes.length) return false;
  if ((bytes[4] & 0x80) !== 0) return false;
  if (rLength > 1 && bytes[4] === 0 && (bytes[5] & 0x80) === 0) return false;

  const sTag = 4 + rLength;
  if (bytes[sTag] !== 0x02) return false;
  const sLength = bytes[sTag + 1];
  const sStart = sTag + 2;
  if (sLength === 0 || sStart + sLength !== bytes.length) return false;
  if ((bytes[sStart] & 0x80) !== 0) return false;
  if (
    sLength > 1 && bytes[sStart] === 0 && (bytes[sStart + 1] & 0x80) === 0
  ) return false;
  return true;
}
