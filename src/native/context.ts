/** Safe internal lifecycle helpers for static and secret-bearing contexts. */

import { NativeContextError } from './errors.ts';
import { getNativeSymbols } from './loader.ts';
import { dereferenceStaticPointer, type LoadedCoreSymbols } from './symbols.ts';

/** Required flag for mutable contexts in the supported libsecp256k1 ABI. */
export const SECP256K1_CONTEXT_NONE = 1;

type NativeContext = NonNullable<Deno.PointerValue>;
type NativeContextOperation = (context: NativeContext) => unknown;
type ForbiddenContextResult = NativeContext | PromiseLike<unknown>;
type SafeContextOperation<Operation extends NativeContextOperation> =
  Extract<ReturnType<Operation>, ForbiddenContextResult> extends never
    ? Operation
    : never;

/** Injectable unsafe operations and randomness used by context helpers. */
export interface NativeContextRuntime {
  /** Dereferences the address of an exported native context pointer. */
  dereferenceStatic(address: Deno.PointerValue): Deno.PointerValue;
  /** Fills a context-randomization seed or throws. */
  randomFill(seed: Uint8Array): void;
}

interface NativeContextHelpers {
  withStaticContext<Operation extends NativeContextOperation>(
    operation: SafeContextOperation<Operation>,
  ): ReturnType<Operation>;
  withSigningContext<Operation extends NativeContextOperation>(
    operation: SafeContextOperation<Operation>,
  ): ReturnType<Operation>;
}

const defaultContextRuntime: NativeContextRuntime = {
  dereferenceStatic(address: Deno.PointerValue): Deno.PointerValue {
    return dereferenceStaticPointer(address);
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

  function withStaticContext<Operation extends NativeContextOperation>(
    operation: SafeContextOperation<Operation>,
  ): ReturnType<Operation> {
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
    return operation(context) as ReturnType<Operation>;
  }

  function withSigningContext<Operation extends NativeContextOperation>(
    operation: SafeContextOperation<Operation>,
  ): ReturnType<Operation> {
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
      return operation(context) as ReturnType<Operation>;
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
  operation: SafeContextOperation<(context: NativeContext) => T>,
): T {
  return contextHelpers().withStaticContext(operation);
}

/**
 * Runs a synchronous internal secret operation with a randomized disposable
 * context. The callback must finish before this function returns.
 */
export function withSigningContext<T>(
  operation: SafeContextOperation<(context: NativeContext) => T>,
): T {
  return contextHelpers().withSigningContext(operation);
}
