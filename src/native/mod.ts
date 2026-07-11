/** Public loader surface and internal typed access for native-backed modules. */

export {
  getNativeSymbols,
  initializeNative,
  nativeStatus,
  requireCapability,
} from './loader.ts';
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
  NativeLoadAttempt,
} from './errors.ts';
export type {
  LoadedCapabilitySymbols,
  LoadedCoreSymbols,
  NativeCapability,
  NativeCapabilityState,
  NativeCapabilityStatus,
  NativeCapabilityStatuses,
} from './symbols.ts';
