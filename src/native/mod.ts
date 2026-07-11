/**
 * Capability-aware loading and diagnostics for a user-installed
 * libsecp256k1.
 *
 * @module
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
