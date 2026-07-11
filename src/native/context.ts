/** Safe internal lifecycle helpers for verification and signing contexts. */

import { NativeContextError } from './errors.ts';
import { getNativeSymbols } from './loader.ts';
import type { LoadedCoreSymbols } from './symbols.ts';

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
  randomFill(seed: Uint8Array): void {
    crypto.getRandomValues(seed);
  },
};

/** Creates context helpers around an already core-validated symbol table. */
export function createNativeContextHelpers(
  symbols: LoadedCoreSymbols,
  runtime: NativeContextRuntime = defaultContextRuntime,
): NativeContextHelpers {
  let selfTested = false;
  let verificationContext: NativeContext | undefined;

  function selfTestOnce(): void {
    if (selfTested) return;
    symbols.secp256k1_selftest();
    selfTested = true;
  }

  function createRandomizedContext(): NativeContext {
    selfTestOnce();
    const context = symbols.secp256k1_context_create(
      SECP256K1_CONTEXT_NONE,
    );
    if (context === null) {
      throw new NativeContextError('context-create-failed');
    }

    const seed = new Uint8Array(32);
    try {
      runtime.randomFill(seed);
      if (!symbols.secp256k1_context_randomize(context, seed)) {
        throw new NativeContextError('context-randomize-failed');
      }
      return context;
    } catch (cause) {
      symbols.secp256k1_context_destroy(context);
      throw cause;
    } finally {
      seed.fill(0);
    }
  }

  function withStaticContext<Operation extends NativeContextOperation>(
    operation: SafeContextOperation<Operation>,
  ): ReturnType<Operation> {
    verificationContext ??= createRandomizedContext();
    return operation(verificationContext) as ReturnType<Operation>;
  }

  function withSigningContext<Operation extends NativeContextOperation>(
    operation: SafeContextOperation<Operation>,
  ): ReturnType<Operation> {
    const context = createRandomizedContext();
    try {
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
 * Runs a synchronous internal operation with the retained verification
 * context. The callback must finish before this function returns.
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
