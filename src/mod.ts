/**
 * Safe, Bitcoin-specific secp256k1 verification primitives backed by a
 * user-installed native libsecp256k1.
 *
 * Configure `DENO_SECP256K1_PATH` with an absolute library path for production
 * nodes, or `auto` for platform loader discovery. Network-facing code should
 * use `tryParse` and `tryFromBytes`; malformed peer data then becomes `null`,
 * while native configuration failures still propagate.
 *
 * @example Verify a BIP340 signature over a Taproot digest
 * ```ts
 * #!/usr/bin/env -S deno run --allow-env=DENO_SECP256K1_PATH --allow-ffi
 * import {
 *   Digest32,
 *   SchnorrSignature,
 *   verifyTaprootSignature,
 *   XOnlyPublicKey,
 * } from "./mod.ts";
 *
 * const digest = Digest32.fromBytes(new Uint8Array(32));
 * const signature = SchnorrSignature.fromBytes(new Uint8Array(64));
 * const key = XOnlyPublicKey.tryParse(new Uint8Array(32));
 * console.assert(key === null || !verifyTaprootSignature(signature, digest, key));
 * ```
 *
 * @module
 */

export { Digest32 } from './api/digest.ts';
export { Secp256k1InputError } from './api/input.ts';
export { CompressedPublicKey, PublicKey, XOnlyPublicKey } from './api/keys.ts';
export type { PublicKeyEncoding } from './api/keys.ts';
export {
  EcdsaCompactSignature,
  EcdsaDerSignature,
  EcdsaSignature,
  SchnorrSignature,
} from './api/signatures.ts';
export {
  verifyEcdsa,
  verifyEcdsaDer,
  verifyTaprootSignature,
} from './api/verify.ts';

export { initializeNative, nativeStatus } from './native/mod.ts';
export type {
  NativeInitializationOptions,
  NativeStatus,
} from './native/mod.ts';
export {
  NativeCapabilityError,
  NativeConfigError,
  NativeContextError,
  NativeCoreCompatibilityError,
  NativeLoadError,
} from './native/mod.ts';
export type {
  NativeCapability,
  NativeCapabilityState,
  NativeCapabilityStatus,
  NativeCapabilityStatuses,
  NativeConfigErrorCode,
  NativeContextErrorCode,
  NativeErrorTarget,
  NativeInitializationError,
  NativeLoadAttempt,
} from './native/mod.ts';
