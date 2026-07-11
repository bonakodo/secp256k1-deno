/**
 * Capability-aware loading and diagnostics for a user-installed
 * libsecp256k1.
 *
 * @example Inspect capabilities after explicit initialization
 * ```ts
 * import {
 *   initializeNative,
 *   nativeStatus,
 * } from "jsr:@bonakodo/secp256k1@1/diagnostics";
 *
 * initializeNative({ require: ["extrakeys", "schnorrsig"] });
 * console.assert(nativeStatus().state === "loaded");
 * ```
 *
 * @module
 * @since 1.0.0
 */

export { initializeNative, nativeStatus } from './loader.ts';
export type { NativeInitializationOptions, NativeStatus } from './loader.ts';
export {
  NativeCapabilityError,
  NativeConfigError,
  NativeContextError,
  NativeCoreCompatibilityError,
  NativeLoadError,
} from './errors.ts';
export type {
  NativeConfigErrorCode,
  NativeContextErrorCode,
  NativeErrorTarget,
  NativeInitializationError,
  NativeLoadAttempt,
} from './errors.ts';
export type {
  NativeCapability,
  NativeCapabilityState,
  NativeCapabilityStatus,
  NativeCapabilityStatuses,
} from './symbols.ts';
