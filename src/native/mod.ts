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
 * } from "jsr:@bonakodo/secp256k1@1/diagnostics.ts";
 *
 * initializeNative({ require: ["extrakeys", "schnorrsig"] });
 * console.assert(nativeStatus().state === "loaded");
 * ```
 *
 * @module
 * @since 1.0.0
 */

import * as errors from './errors.ts';
import * as loader from './loader.ts';

// Explicit aliases keep duplicate entrypoint exports documented by JSR while
// preserving the identity of these immutable source bindings.
/** Selects and validates libsecp256k1 for the current Deno isolate. */
// deno-lint-ignore no-unused-vars
export import initializeNative = loader.initializeNative;
/** Reports the current native loader state and detected capabilities. */
// deno-lint-ignore no-unused-vars
export import nativeStatus = loader.nativeStatus;
export type { NativeInitializationOptions, NativeStatus } from './loader.ts';
/** Reports a requested optional native capability that is unavailable. */
// deno-lint-ignore no-unused-vars
export import NativeCapabilityError = errors.NativeCapabilityError;
/** Reports invalid native-library configuration. */
// deno-lint-ignore no-unused-vars
export import NativeConfigError = errors.NativeConfigError;
/** Reports native context creation or randomization failure. */
// deno-lint-ignore no-unused-vars
export import NativeContextError = errors.NativeContextError;
/** Reports a loaded library that is incompatible with the required core ABI. */
// deno-lint-ignore no-unused-vars
export import NativeCoreCompatibilityError = errors.NativeCoreCompatibilityError;
/** Reports failure to load a compatible native library candidate. */
// deno-lint-ignore no-unused-vars
export import NativeLoadError = errors.NativeLoadError;
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
