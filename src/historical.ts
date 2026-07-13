/**
 * Bitcoin Core-compatible pre-BIP66 lax-DER ECDSA verification.
 *
 * This module exposes one historical cryptographic compatibility primitive,
 * not a Bitcoin consensus engine. Script flags, activation heights, sighash
 * types, transaction digest construction, and script execution remain entirely
 * caller-owned.
 *
 * @example Treat malformed peer bytes as invalid
 * ```ts
 * import {
 *   Digest32,
 *   verifyHistoricalEcdsa,
 * } from "jsr:@bonakodo/secp256k1@1/historical.ts";
 *
 * const valid = verifyHistoricalEcdsa(
 *   new Uint8Array(),
 *   Digest32.fromBytes(new Uint8Array(32)),
 *   new Uint8Array(),
 * );
 * console.assert(!valid);
 * ```
 *
 * @module
 * @since 1.0.0
 */

import * as digest from './api/digest.ts';
import * as keys from './api/keys.ts';
import { nativePublicKey } from './api/keys.ts';
import { withStaticContext } from './native/context.ts';
import { getNativeSymbols } from './native/loader.ts';

// Explicit aliases keep duplicate entrypoint exports documented by JSR while
// preserving the identity of these immutable source bindings.
/** An immutable 32-byte digest supplied to historical ECDSA verification. */
// deno-lint-ignore no-unused-vars
export import Digest32 = digest.Digest32;
/** A canonical compressed SEC public key. */
// deno-lint-ignore no-unused-vars
export import CompressedPublicKey = keys.CompressedPublicKey;
/** A validated SEC public key, including historical hybrid encodings. */
export import PublicKey = keys.PublicKey;
export type { PublicKeyEncoding } from './api/keys.ts';

/**
 * Verifies an ECDSA signature with Bitcoin Core's pre-BIP66 lax-DER parser.
 *
 * The signature must contain DER bytes only; do not include Bitcoin's trailing
 * sighash-type byte. Compressed, uncompressed, and historically valid hybrid
 * SEC public-key encodings are accepted. High-S values are normalized before
 * verification, matching historical Bitcoin behavior.
 *
 * Malformed signatures, invalid scalars, invalid public keys, empty signatures,
 * and equation mismatches return `false`. Native configuration and runtime
 * failures propagate so node software cannot mistake infrastructure failure for
 * invalid peer data.
 *
 * @param signature Candidate lax-DER bytes without a sighash-type byte.
 * @param digest The exact 32-byte signature digest selected by the caller.
 * @param publicKey A validated key or peer-controlled serialized SEC bytes.
 * @returns `true` only when the historical parser and ECDSA equation accept.
 * @throws Native configuration, loading, or runtime errors unchanged.
 * @see https://github.com/bitcoin-core/secp256k1/blob/master/contrib/lax_der_parsing.c
 * @see https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki
 * @since 1.0.0
 */
export function verifyHistoricalEcdsa(
  signature: Uint8Array,
  digest: Digest32,
  publicKey: PublicKey | Uint8Array,
): boolean {
  const compact = parseLaxDer(signature);
  if (compact === null) return false;

  const parsedKey = publicKey instanceof PublicKey
    ? publicKey
    : PublicKey.tryParse(publicKey);
  if (parsedKey === null) return false;

  const symbols = getNativeSymbols();
  const nativeKey = nativePublicKey(parsedKey);
  const message = digest.toBytes();
  return withStaticContext((context) => {
    const parsedSignature = new Uint8Array(64);
    if (
      symbols.secp256k1_ecdsa_signature_parse_compact(
        context,
        parsedSignature,
        compact,
      ) !== 1
    ) {
      return false;
    }
    const normalized = new Uint8Array(64);
    symbols.secp256k1_ecdsa_signature_normalize(
      context,
      normalized,
      parsedSignature,
    );
    return symbols.secp256k1_ecdsa_verify(
      context,
      normalized,
      message,
      nativeKey,
    ) === 1;
  });
}

function parseLaxDer(input: Uint8Array): Uint8Array | null {
  let position = 0;
  if (position === input.length || input[position++] !== 0x30) return null;
  if (position === input.length) return null;

  let lengthByte = input[position++];
  if ((lengthByte & 0x80) !== 0) {
    lengthByte -= 0x80;
    if (lengthByte > input.length - position) return null;
    position += lengthByte;
  }

  if (position === input.length || input[position++] !== 0x02) return null;
  const rLength = readIntegerLength(input, position);
  if (rLength === null) return null;
  position = rLength.next;
  if (rLength.length > BigInt(input.length - position)) return null;
  const rPosition = position;
  position += Number(rLength.length);

  if (position === input.length || input[position++] !== 0x02) return null;
  const sLength = readIntegerLength(input, position);
  if (sLength === null) return null;
  position = sLength.next;
  if (sLength.length > BigInt(input.length - position)) return null;
  const sPosition = position;

  const compact = new Uint8Array(64);
  if (!copyLaxScalar(input, rPosition, Number(rLength.length), compact, 0)) {
    return compact;
  }
  if (!copyLaxScalar(input, sPosition, Number(sLength.length), compact, 32)) {
    compact.fill(0);
  }
  return compact;
}

function readIntegerLength(
  input: Uint8Array,
  initialPosition: number,
): { readonly length: bigint; readonly next: number } | null {
  let position = initialPosition;
  if (position === input.length) return null;
  let lengthByte = input[position++];
  if ((lengthByte & 0x80) === 0) {
    return { length: BigInt(lengthByte), next: position };
  }

  lengthByte -= 0x80;
  if (lengthByte > input.length - position) return null;
  while (lengthByte > 0 && input[position] === 0) {
    position++;
    lengthByte--;
  }
  if (lengthByte >= 8) return null;

  let length = 0n;
  while (lengthByte > 0) {
    length = (length << 8n) + BigInt(input[position++]);
    lengthByte--;
  }
  return { length, next: position };
}

function copyLaxScalar(
  input: Uint8Array,
  initialPosition: number,
  initialLength: number,
  compact: Uint8Array,
  offset: 0 | 32,
): boolean {
  let position = initialPosition;
  let length = initialLength;
  while (length > 0 && input[position] === 0) {
    position++;
    length--;
  }
  if (length > 32) return false;
  if (length > 0) {
    compact.set(
      input.subarray(position, position + length),
      offset + 32 - length,
    );
  }
  return true;
}
