/** Capability-aware, per-isolate native libsecp256k1 loader. */

import { nativeLibraryCandidates, type NativeTarget } from './config.ts';
import {
  NativeCapabilityError,
  NativeConfigError,
  NativeCoreCompatibilityError,
  type NativeInitializationError,
  type NativeLoadAttempt,
  NativeLoadError,
} from './errors.ts';
import {
  CAPABILITY_SYMBOLS,
  type LoadedCapabilitySymbols,
  type LoadedCoreSymbols,
  type NativeCapability,
  type NativeCapabilityStatus,
  type NativeCapabilityStatuses,
  nativeSymbolDefinitions,
  type NativeSymbols,
} from './symbols.ts';

/** Minimal retained dynamic-library resource. */
export interface NativeLibraryHandle {
  /** Nullable values produced by the all-optional descriptor table. */
  readonly symbols: NativeSymbols;
  /** Releases the native library resource. */
  close(): void;
}

/** Injectable process boundary used by the production singleton and tests. */
export interface NativeLoaderRuntime {
  /** Current target used for path validation and auto candidates. */
  readonly target: NativeTarget;
  /** Reads the mandatory native-library environment value. */
  readPath(): string | undefined;
  /** Opens one candidate with the all-optional descriptor table. */
  open(candidate: string): NativeLibraryHandle;
}

/** Optional capability requirements checked after core initialization. */
export interface NativeInitializationOptions {
  /** Capabilities that must be available for this call to succeed. */
  readonly require?: readonly NativeCapability[];
}

/** Side-effect-free snapshot of per-isolate native loader state. */
export interface NativeStatus {
  /** Loader lifecycle state. */
  readonly state: 'uninitialized' | 'loaded' | 'failed';
  /** Verbatim selected candidate, or null when no handle was retained. */
  readonly selectedCandidate: string | null;
  /** Independent symbol-derived capability states. */
  readonly capabilities: NativeCapabilityStatuses;
  /** Cached terminal configuration or loading error. */
  readonly error: NativeInitializationError | null;
}

/** State and operations of an isolated native-loader instance. */
export interface NativeLoader {
  /** Initializes core and checks any requested optional capabilities. */
  initialize(options?: NativeInitializationOptions): NativeStatus;
  /** Returns current state without reading environment or opening a library. */
  status(): NativeStatus;
  /** Returns raw symbols after core has been proven complete. */
  getNativeSymbols(): LoadedCoreSymbols;
  /** Requires and narrows one capability without poisoning loaded core. */
  requireCapability<C extends NativeCapability>(
    capability: C,
  ): LoadedCapabilitySymbols<C>;
}

type LoaderState =
  | { readonly kind: 'uninitialized' }
  | {
    readonly kind: 'loaded';
    readonly candidate: string;
    readonly handle: NativeLibraryHandle;
    readonly capabilities: NativeCapabilityStatuses;
  }
  | {
    readonly kind: 'failed';
    readonly error: NativeInitializationError;
    readonly capabilities: NativeCapabilityStatuses;
  };

/** Classifies every capability from nullable symbol values alone. */
export function classifyNativeCapabilities(
  symbols: NativeSymbols,
): NativeCapabilityStatuses {
  const entries = (Object.keys(CAPABILITY_SYMBOLS) as NativeCapability[]).map(
    (capability): [NativeCapability, NativeCapabilityStatus] => {
      const names = CAPABILITY_SYMBOLS[capability];
      const missingSymbols = names.filter((name) => symbols[name] === null);
      const state = missingSymbols.length === 0
        ? 'available'
        : missingSymbols.length === names.length
        ? 'unavailable'
        : 'incompatible';
      return [capability, { state, missingSymbols }];
    },
  );
  return Object.fromEntries(entries) as NativeCapabilityStatuses;
}

/** Creates an isolated loader; production code uses the module singleton. */
export function createNativeLoader(runtime: NativeLoaderRuntime): NativeLoader {
  let state: LoaderState = { kind: 'uninitialized' };

  function status(): NativeStatus {
    if (state.kind === 'loaded') {
      return statusSnapshot(
        'loaded',
        state.candidate,
        state.capabilities,
        null,
      );
    }
    if (state.kind === 'failed') {
      return statusSnapshot('failed', null, state.capabilities, state.error);
    }
    return statusSnapshot(
      'uninitialized',
      null,
      unavailableCapabilities(),
      null,
    );
  }

  function initialize(
    options: NativeInitializationOptions = {},
  ): NativeStatus {
    if (state.kind === 'failed') throw state.error;

    if (state.kind === 'uninitialized') {
      let value: string | undefined;
      try {
        value = runtime.readPath();
      } catch (cause) {
        const error = new NativeConfigError(
          'environment-unavailable',
          undefined,
          runtime.target,
          { cause },
        );
        state = {
          kind: 'failed',
          error,
          capabilities: unavailableCapabilities(),
        };
        throw error;
      }

      let candidates: readonly string[];
      try {
        candidates = nativeLibraryCandidates(value, runtime.target);
      } catch (cause) {
        if (!(cause instanceof NativeConfigError)) throw cause;
        state = {
          kind: 'failed',
          error: cause,
          capabilities: unavailableCapabilities(),
        };
        throw cause;
      }
      const attempts: NativeLoadAttempt[] = [];
      let failedCapabilities = unavailableCapabilities();

      for (const candidate of candidates) {
        let handle: NativeLibraryHandle;
        try {
          handle = runtime.open(candidate);
        } catch (cause) {
          attempts.push({ candidate, cause });
          continue;
        }

        const capabilities = classifyNativeCapabilities(handle.symbols);
        const core = capabilities.core;
        if (core.state !== 'available') {
          const cause = new NativeCoreCompatibilityError(
            candidate,
            capabilities,
          );
          attempts.push({ candidate, cause });
          failedCapabilities = capabilities;
          handle.close();
          continue;
        }

        state = { kind: 'loaded', candidate, handle, capabilities };
        break;
      }

      if (state.kind === 'uninitialized') {
        const error = new NativeLoadError(attempts);
        state = { kind: 'failed', error, capabilities: failedCapabilities };
        throw error;
      }
    }

    for (const capability of options.require ?? []) {
      requireLoadedCapability(capability);
    }
    return status();
  }

  function getNativeSymbols(): LoadedCoreSymbols {
    initialize();
    if (state.kind !== 'loaded') throw new Error('unreachable loader state');
    return state.handle.symbols as LoadedCoreSymbols;
  }

  function requireLoadedCapability<C extends NativeCapability>(
    capability: C,
  ): LoadedCapabilitySymbols<C> {
    if (state.kind !== 'loaded') initialize();
    if (state.kind !== 'loaded') throw new Error('unreachable loader state');
    const capabilityStatus = state.capabilities[capability];
    if (capabilityStatus.state !== 'available') {
      throw new NativeCapabilityError(
        capability,
        capabilityStatus.state,
        capabilityStatus.missingSymbols,
      );
    }
    return state.handle.symbols as LoadedCapabilitySymbols<C>;
  }

  return {
    initialize,
    status,
    getNativeSymbols,
    requireCapability: requireLoadedCapability,
  };
}

function unavailableCapabilities(): NativeCapabilityStatuses {
  const entries = (Object.keys(CAPABILITY_SYMBOLS) as NativeCapability[]).map(
    (capability): [NativeCapability, NativeCapabilityStatus] => [
      capability,
      {
        state: 'unavailable',
        missingSymbols: [...CAPABILITY_SYMBOLS[capability]],
      },
    ],
  );
  return Object.fromEntries(entries) as NativeCapabilityStatuses;
}

function statusSnapshot(
  state: NativeStatus['state'],
  selectedCandidate: string | null,
  capabilities: NativeCapabilityStatuses,
  error: NativeInitializationError | null,
): NativeStatus {
  const capabilityEntries = (
    Object.keys(capabilities) as NativeCapability[]
  ).map((capability): [NativeCapability, NativeCapabilityStatus] => [
    capability,
    {
      state: capabilities[capability].state,
      missingSymbols: [...capabilities[capability].missingSymbols],
    },
  ]);
  return {
    state,
    selectedCandidate,
    capabilities: Object.fromEntries(
      capabilityEntries,
    ) as NativeCapabilityStatuses,
    error,
  };
}

const isolateLoader = createNativeLoader({
  target: Deno.build,
  readPath(): string | undefined {
    return Deno.env.get('DENO_SECP256K1_PATH');
  },
  open(candidate: string): NativeLibraryHandle {
    return Deno.dlopen(candidate, nativeSymbolDefinitions);
  },
});

/** Initializes the one retained native library handle for this Deno isolate. */
export function initializeNative(
  options: NativeInitializationOptions = {},
): NativeStatus {
  return isolateLoader.initialize(options);
}

/** Returns native loader state without environment access or FFI loading. */
export function nativeStatus(): NativeStatus {
  return isolateLoader.status();
}

/** Returns internal raw symbols only after core completeness is established. */
export function getNativeSymbols(): LoadedCoreSymbols {
  return isolateLoader.getNativeSymbols();
}

/** Requires one capability and returns raw symbols narrowed for that group. */
export function requireCapability<C extends NativeCapability>(
  capability: C,
): LoadedCapabilitySymbols<C> {
  return isolateLoader.requireCapability(capability);
}
