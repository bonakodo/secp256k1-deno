import { copyExact, invalidInput } from './input.ts';

/**
 * An immutable 32-byte digest supplied to Bitcoin signature verification.
 *
 * The class does not hash data or assign sighash semantics. Node code remains
 * responsible for constructing the correct legacy, SegWit, or Taproot digest.
 * Inputs and outputs are copied.
 *
 * @example
 * ```ts
 * import { Digest32 } from "../mod.ts";
 *
 * const digest = Digest32.fromBytes(new Uint8Array(32));
 * console.assert(digest.toBytes().length === 32);
 * ```
 *
 * @see https://developer.bitcoin.org/devguide/transactions.html#signature-hash-types
 * @since 1.0.0
 */
export class Digest32 {
  readonly #bytes: Uint8Array;

  private constructor(bytes: Uint8Array) {
    this.#bytes = bytes;
  }

  /**
   * Creates a digest from exactly 32 bytes, copying the input.
   *
   * @param bytes Bitcoin signature digest bytes.
   * @returns An immutable digest value.
   * @throws {Secp256k1InputError} If `bytes` is not exactly 32 bytes.
   * @since 1.0.0
   */
  static fromBytes(bytes: Uint8Array): Digest32 {
    return Digest32.tryFromBytes(bytes) ??
      invalidInput('Digest32', 'expected exactly 32 bytes');
  }

  /**
   * Tries to create a digest from untrusted bytes.
   *
   * @param bytes Candidate digest bytes; the input is copied on success.
   * @returns A digest for exactly 32 bytes, otherwise `null`.
   * @since 1.0.0
   */
  static tryFromBytes(bytes: Uint8Array): Digest32 | null {
    const copy = copyExact(bytes, 32);
    return copy === null ? null : new Digest32(copy);
  }

  /**
   * Returns a detached 32-byte copy.
   *
   * @returns A new byte array on every call.
   * @since 1.0.0
   */
  toBytes(): Uint8Array {
    return this.#bytes.slice();
  }
}
