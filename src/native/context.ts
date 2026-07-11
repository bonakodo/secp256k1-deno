/** Safe internal lifecycle helpers for static and secret-bearing contexts. */

import { NativeContextError } from './errors.ts';
import { getNativeSymbols } from './loader.ts';
import type { LoadedCoreSymbols } from './symbols.ts';

/** Required flag for mutable contexts in the supported libsecp256k1 ABI. */
export const SECP256K1_CONTEXT_NONE = 1;

type NativeContext = NonNullable<Deno.PointerValue>;

/** Injectable unsafe operations and randomness used by context helpers. */
export interface NativeContextRuntime {
  /** Dereferences the address of an exported native context pointer. */
  dereferenceStatic(address: Deno.PointerValue): Deno.PointerValue;
  /** Fills a context-randomization seed or throws. */
  randomFill(seed: Uint8Array): void;
}

interface NativeContextHelpers {
  withStaticContext<T>(operation: (context: NativeContext) => T): T;
  withSigningContext<T>(operation: (context: NativeContext) => T): T;
}

const defaultContextRuntime: NativeContextRuntime = {
  dereferenceStatic(address: Deno.PointerValue): Deno.PointerValue {
    if (address === null) return null;
    return new Deno.UnsafePointerView(address).getPointer(0);
  },
  randomFill(seed: Uint8Array): void {
    crypto.getRandomValues(seed);
  },
};

/** Creates context helpers around an already core-validated symbol table. */
export function createNativeContextHelpers(
  symbols: LoadedCoreSymbols,
  runtime: NativeContextRuntime = defaultContextRuntime,
): NativeContextHelpers {
  let staticContextSelfTested = false;

  function withStaticContext<T>(
    operation: (context: NativeContext) => T,
  ): T {
    if (!staticContextSelfTested) {
      symbols.secp256k1_selftest();
      staticContextSelfTested = true;
    }
    const context = runtime.dereferenceStatic(
      symbols.secp256k1_context_static,
    );
    if (context === null) {
      throw new NativeContextError('static-context-unavailable');
    }
    return operation(context);
  }

  function withSigningContext<T>(
    operation: (context: NativeContext) => T,
  ): T {
    const context = symbols.secp256k1_context_create(
      SECP256K1_CONTEXT_NONE,
    );
    if (context === null) {
      throw new NativeContextError('context-create-failed');
    }

    try {
      const seed = new Uint8Array(32);
      runtime.randomFill(seed);
      if (!symbols.secp256k1_context_randomize(context, seed)) {
        throw new NativeContextError('context-randomize-failed');
      }
      return operation(context);
    } finally {
      symbols.secp256k1_context_destroy(context);
    }
  }

  return { withStaticContext, withSigningContext };
}

let isolateContextHelpers: NativeContextHelpers | undefined;

function contextHelpers(): NativeContextHelpers {
  isolateContextHelpers ??= createNativeContextHelpers(getNativeSymbols());
  return isolateContextHelpers;
}

/**
 * Runs a synchronous internal operation with the self-tested static context.
 */
export function withStaticContext<T>(
  operation: (context: NativeContext) => T,
): T {
  return contextHelpers().withStaticContext(operation);
}

/**
 * Runs a synchronous internal secret operation with a randomized disposable
 * context. The callback must finish before this function returns.
 */
export function withSigningContext<T>(
  operation: (context: NativeContext) => T,
): T {
  return contextHelpers().withSigningContext(operation);
}
