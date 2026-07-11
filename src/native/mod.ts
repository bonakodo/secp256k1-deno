/**
 * Capability-aware loading and diagnostics for a user-installed
 * libsecp256k1.
 *
 * Native loading failures are reported as typed, catchable errors. Before the
 * first context use, libsecp256k1's `secp256k1_selftest()` runs and may abort
 * the process on failure instead of throwing.
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
