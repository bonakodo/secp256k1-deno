import { withStaticContext } from '../native/context.ts';
import { getNativeSymbols, requireCapability } from '../native/loader.ts';
import type { Digest32 } from './digest.ts';
import {
  nativePublicKey,
  nativeXOnlyPublicKey,
  type PublicKey,
  type XOnlyPublicKey,
} from './keys.ts';
import {
  type EcdsaDerSignature,
  type EcdsaSignature,
  nativeEcdsaSignature,
  type SchnorrSignature,
} from './signatures.ts';

/**
 * Verifies valid ECDSA scalars against a 32-byte Bitcoin digest.
 *
 * A private native copy is normalized before verification, so mathematically
 * equivalent high-S signatures are accepted. Enforce Bitcoin script or relay
 * low-S rules separately by checking `signature.isLowS()` where required.
 *
 * @param signature Valid non-zero ECDSA scalars.
 * @param digest Caller-computed 32-byte Bitcoin signature digest.
 * @param publicKey Valid compressed, uncompressed, or hybrid public key.
 * @returns `true` only when the ECDSA equation verifies.
 * @throws Native configuration and loading errors unchanged.
 * @see https://github.com/bitcoin/bips/blob/master/bip-0146.mediawiki
 * @since 1.0.0
 */
export function verifyEcdsa(
  signature: EcdsaSignature,
  digest: Digest32,
  publicKey: PublicKey,
): boolean {
  const symbols = getNativeSymbols();
  const input = nativeEcdsaSignature(signature);
  const normalized = new Uint8Array(64);
  const key = nativePublicKey(publicKey);
  return withStaticContext((context) => {
    symbols.secp256k1_ecdsa_signature_normalize(
      context,
      normalized,
      input,
    );
    return symbols.secp256k1_ecdsa_verify(
      context,
      normalized,
      digest.toBytes(),
      key,
    ) === 1;
  });
}

/**
 * Decodes and verifies a strict-DER ECDSA candidate.
 *
 * Syntactically valid zero or out-of-range scalars return `false`; malformed
 * DER should be rejected earlier with `EcdsaDerSignature.tryFromBytes`.
 * High-S signatures are normalized internally as in {@link verifyEcdsa}.
 *
 * @param signature Strict-DER syntax candidate without a sighash-type byte.
 * @param digest Caller-computed 32-byte Bitcoin signature digest.
 * @param publicKey Valid secp256k1 public key.
 * @returns `false` for invalid scalars or a failed ECDSA equation.
 * @throws Native configuration and loading errors unchanged.
 * @since 1.0.0
 */
export function verifyEcdsaDer(
  signature: EcdsaDerSignature,
  digest: Digest32,
  publicKey: PublicKey,
): boolean {
  const decoded = signature.decode();
  return decoded === null ? false : verifyEcdsa(decoded, digest, publicKey);
}

/**
 * Verifies a 64-byte BIP340 signature over a 32-byte Taproot digest.
 *
 * This Bitcoin-specific API intentionally accepts only transaction-sized
 * digests rather than exposing arbitrary-message Schnorr verification.
 * Candidate scalar and equation failures return `false`.
 *
 * @param signature Length-checked 64-byte Schnorr candidate.
 * @param digest Caller-computed 32-byte Taproot signature digest.
 * @param publicKey Valid BIP340 x-only output key.
 * @returns `true` only when BIP340 verification succeeds.
 * @throws {NativeCapabilityError} If extrakeys or schnorrsig is unavailable.
 * @throws Native configuration and loading errors unchanged.
 * @see https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
 * @see https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
 * @since 1.0.0
 */
export function verifyTaprootSignature(
  signature: SchnorrSignature,
  digest: Digest32,
  publicKey: XOnlyPublicKey,
): boolean {
  const symbols = requireCapability('schnorrsig');
  const key = nativeXOnlyPublicKey(publicKey);
  return withStaticContext((context) =>
    symbols.secp256k1_schnorrsig_verify(
      context,
      signature.toBytes(),
      digest.toBytes(),
      32n,
      key,
    ) === 1
  );
}
