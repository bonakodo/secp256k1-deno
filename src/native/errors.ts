/** Typed errors produced by native libsecp256k1 configuration and loading. */

import type { NativeCapability, NativeCapabilityState } from './symbols.ts';

/** Machine-readable reasons why native-library configuration is invalid. */
export type NativeConfigErrorCode =
  | 'missing'
  | 'empty'
  | 'not-absolute'
  | 'unsupported-auto'
  | 'environment-unavailable';

/** Minimal platform description retained by configuration errors. */
export interface NativeErrorTarget {
  /** Deno operating-system identifier. */
  readonly os: string;
  /** Deno CPU-architecture identifier. */
  readonly arch: string;
}

/** Reports invalid or unavailable `DENO_SECP256K1_PATH` configuration. */
export class NativeConfigError extends Error {
  /** Stable reason for the configuration failure. */
  readonly code: NativeConfigErrorCode;

  /** Original environment value, preserved without normalization. */
  readonly value: string | undefined;

  /** Platform against which the value was interpreted. */
  readonly target: NativeErrorTarget;

  /** Creates a structured native configuration error. */
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

/** One candidate and the original structured reason it was rejected. */
export interface NativeLoadAttempt {
  /** Candidate string passed verbatim to `Deno.dlopen`. */
  readonly candidate: string;
  /** Original open error or structured core-compatibility error. */
  readonly cause: unknown;
}

/** Reports a library that opened but did not provide a complete core ABI. */
export class NativeCoreCompatibilityError extends Error {
  /** Candidate string that opened with an incomplete core. */
  readonly candidate: string;

  /** Core state inferred from symbol presence. */
  readonly state: NativeCapabilityState;

  /** Required core symbols not exported by the candidate. */
  readonly missingSymbols: readonly string[];

  /** Creates a structured core compatibility failure. */
  constructor(
    candidate: string,
    state: NativeCapabilityState,
    missingSymbols: readonly string[],
  ) {
    super('Native libsecp256k1 core symbols are incomplete');
    this.name = 'NativeCoreCompatibilityError';
    this.candidate = candidate;
    this.state = state;
    this.missingSymbols = [...missingSymbols];
  }
}

/** Reports exhaustion of all candidates for a valid native configuration. */
export class NativeLoadError extends Error {
  /** Every candidate and its original rejection cause, in attempt order. */
  readonly attempts: readonly NativeLoadAttempt[];

  /** Creates a terminal native loading error. */
  constructor(attempts: readonly NativeLoadAttempt[]) {
    const lastCause = attempts.at(-1)?.cause;
    super('Unable to load a compatible native libsecp256k1 library', {
      cause: lastCause,
    });
    this.name = 'NativeLoadError';
    this.attempts = attempts.map((attempt) => ({ ...attempt }));
  }
}

/** Reports a requested optional capability that is not usable. */
export class NativeCapabilityError extends Error {
  /** Capability requested by the caller. */
  readonly capability: NativeCapability;

  /** Detected capability state. */
  readonly state: NativeCapabilityState;

  /** Symbols needed to make the capability usable. */
  readonly missingSymbols: readonly string[];

  /** Creates a structured capability requirement failure. */
  constructor(
    capability: NativeCapability,
    state: NativeCapabilityState,
    missingSymbols: readonly string[],
  ) {
    super(`Native capability "${capability}" is ${state}`);
    this.name = 'NativeCapabilityError';
    this.capability = capability;
    this.state = state;
    this.missingSymbols = [...missingSymbols];
  }
}

/** Machine-readable reasons why a native context could not be prepared. */
export type NativeContextErrorCode =
  | 'static-context-unavailable'
  | 'context-create-failed'
  | 'context-randomize-failed';

/** Reports failure to prepare a safe native operation context. */
export class NativeContextError extends Error {
  /** Stable reason for context preparation failure. */
  readonly code: NativeContextErrorCode;

  /** Creates a typed native context error. */
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
