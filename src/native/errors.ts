/** Typed errors produced by native libsecp256k1 configuration and loading. */

import type {
  NativeCapability,
  NativeCapabilityState,
  NativeCapabilityStatuses,
} from './symbols.ts';

/**
 * Machine-readable reasons why native-library configuration is invalid.
 *
 * @since 1.0.0
 */
export type NativeConfigErrorCode =
  | 'missing'
  | 'empty'
  | 'not-absolute'
  | 'unsupported-auto'
  | 'environment-unavailable';

/**
 * Minimal platform description retained by configuration errors.
 *
 * @since 1.0.0
 */
export interface NativeErrorTarget {
  /**
   * Deno operating-system identifier.
   *
   * @since 1.0.0
   */
  readonly os: string;
  /**
   * Deno CPU-architecture identifier.
   *
   * @since 1.0.0
   */
  readonly arch: string;
}

/**
 * Reports invalid or unavailable `DENO_SECP256K1_PATH` configuration.
 *
 * @since 1.0.0
 */
export class NativeConfigError extends Error {
  /**
   * Stable reason for the configuration failure.
   *
   * @since 1.0.0
   */
  readonly code: NativeConfigErrorCode;

  /**
   * Original environment value, preserved without normalization.
   *
   * @since 1.0.0
   */
  readonly value: string | undefined;

  /**
   * Platform against which the value was interpreted.
   *
   * @since 1.0.0
   */
  readonly target: NativeErrorTarget;

  /**
   * Creates a structured native configuration error.
   *
   * @param code Stable configuration failure reason.
   * @param value Original environment value, if readable.
   * @param target Platform used to interpret the value.
   * @param options Optional underlying environment-access error.
   * @since 1.0.0
   */
  constructor(
    code: NativeConfigErrorCode,
    value: string | undefined,
    target: NativeErrorTarget,
    options?: ErrorOptions,
  ) {
    super(configErrorMessage(code), options);
    this.name = 'NativeConfigError';
    this.code = code;
    this.value = value;
    this.target = { ...target };
  }
}

/**
 * One candidate and the original structured reason it was rejected.
 *
 * @since 1.0.0
 */
export interface NativeLoadAttempt {
  /**
   * Candidate string passed verbatim to `Deno.dlopen`.
   *
   * @since 1.0.0
   */
  readonly candidate: string;
  /**
   * Original open error or structured core-compatibility error.
   *
   * @since 1.0.0
   */
  readonly cause: unknown;
}

/**
 * Reports a library that opened but did not provide a complete core ABI.
 *
 * @since 1.0.0
 */
export class NativeCoreCompatibilityError extends Error {
  /**
   * Candidate string that opened with an incomplete core.
   *
   * @since 1.0.0
   */
  readonly candidate: string;

  /**
   * Core state inferred from symbol presence.
   *
   * @since 1.0.0
   */
  readonly state: NativeCapabilityState;

  /**
   * Required core symbols not exported by the candidate.
   *
   * @since 1.0.0
   */
  readonly missingSymbols: readonly string[];

  /**
   * Complete independent capability classification for the candidate.
   *
   * @since 1.0.0
   */
  readonly capabilities: NativeCapabilityStatuses;

  /**
   * Creates a structured core compatibility failure.
   *
   * @param candidate Exact candidate string passed to the native loader.
   * @param capabilities Independently classified symbol groups.
   * @since 1.0.0
   */
  constructor(
    candidate: string,
    capabilities: NativeCapabilityStatuses,
  ) {
    super('Native libsecp256k1 core symbols are incomplete');
    this.name = 'NativeCoreCompatibilityError';
    this.candidate = candidate;
    this.state = capabilities.core.state;
    this.missingSymbols = [...capabilities.core.missingSymbols];
    this.capabilities = copyCapabilities(capabilities);
  }
}

/**
 * Reports exhaustion of all candidates for a valid native configuration.
 *
 * Causes are preserved without parsing platform-dependent loader messages.
 *
 * @since 1.0.0
 */
export class NativeLoadError extends Error {
  /**
   * Every candidate and its original rejection cause, in attempt order.
   *
   * @since 1.0.0
   */
  readonly attempts: readonly NativeLoadAttempt[];

  /**
   * Creates a terminal native loading error.
   *
   * @param attempts Candidate failures in deterministic attempt order.
   * @since 1.0.0
   */
  constructor(attempts: readonly NativeLoadAttempt[]) {
    const lastCause = attempts.at(-1)?.cause;
    super('Unable to load a compatible native libsecp256k1 library', {
      cause: lastCause,
    });
    this.name = 'NativeLoadError';
    this.attempts = attempts.map((attempt) => ({ ...attempt }));
  }
}

/**
 * Terminal errors cached by native-library initialization.
 *
 * @since 1.0.0
 */
export type NativeInitializationError = NativeConfigError | NativeLoadError;

/**
 * Reports a requested optional capability that is not usable.
 *
 * @since 1.0.0
 */
export class NativeCapabilityError extends Error {
  /**
   * Capability requested by the caller.
   *
   * @since 1.0.0
   */
  readonly capability: NativeCapability;

  /**
   * Detected capability state.
   *
   * @since 1.0.0
   */
  readonly state: NativeCapabilityState;

  /**
   * Symbols needed to make the capability usable.
   *
   * @since 1.0.0
   */
  readonly missingSymbols: readonly string[];

  /**
   * Creates a structured capability requirement failure.
   *
   * @param capability Requested symbol group.
   * @param state Complete absence or partial incompatibility.
   * @param missingSymbols Symbols required to make the group usable.
   * @since 1.0.0
   */
  constructor(
    capability: NativeCapability,
    state: NativeCapabilityState,
    missingSymbols: readonly string[],
  ) {
    const detail = capability === 'ellswift' &&
        missingSymbols.includes(
          'secp256k1_ellswift_xdh_hash_function_bip324',
        )
      ? ': BIP324 hash callback is unavailable'
      : '';
    super(`Native capability "${capability}" is ${state}${detail}`);
    this.name = 'NativeCapabilityError';
    this.capability = capability;
    this.state = state;
    this.missingSymbols = [...missingSymbols];
  }
}

/**
 * Machine-readable reasons why a native context could not be prepared.
 *
 * @since 1.0.0
 */
export type NativeContextErrorCode =
  | 'static-context-unavailable'
  | 'context-create-failed'
  | 'context-randomize-failed';

/**
 * Reports failure to prepare a safe native operation context.
 *
 * @since 1.0.0
 */
export class NativeContextError extends Error {
  /**
   * Stable reason for context preparation failure.
   *
   * @since 1.0.0
   */
  readonly code: NativeContextErrorCode;

  /**
   * Creates a typed native context error.
   *
   * @param code Stable context preparation failure.
   * @since 1.0.0
   */
  constructor(code: NativeContextErrorCode) {
    super(contextErrorMessage(code));
    this.name = 'NativeContextError';
    this.code = code;
  }
}

function configErrorMessage(code: NativeConfigErrorCode): string {
  switch (code) {
    case 'missing':
      return 'DENO_SECP256K1_PATH is required';
    case 'empty':
      return 'DENO_SECP256K1_PATH must not be empty';
    case 'not-absolute':
      return 'DENO_SECP256K1_PATH must be exactly "auto" or an absolute path';
    case 'unsupported-auto':
      return 'DENO_SECP256K1_PATH=auto is unsupported on this platform';
    case 'environment-unavailable':
      return 'DENO_SECP256K1_PATH could not be read';
  }
}

function contextErrorMessage(code: NativeContextErrorCode): string {
  switch (code) {
    case 'static-context-unavailable':
      return 'Native static context pointer is unavailable';
    case 'context-create-failed':
      return 'Native signing context creation failed';
    case 'context-randomize-failed':
      return 'Native signing context randomization failed';
  }
}

function copyCapabilities(
  capabilities: NativeCapabilityStatuses,
): NativeCapabilityStatuses {
  const copy = (capability: NativeCapability) => ({
    state: capabilities[capability].state,
    missingSymbols: [...capabilities[capability].missingSymbols],
  });
  return {
    core: copy('core'),
    extrakeys: copy('extrakeys'),
    schnorrsig: copy('schnorrsig'),
    ellswift: copy('ellswift'),
    musig: copy('musig'),
  };
}
