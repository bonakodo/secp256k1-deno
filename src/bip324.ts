/**
 * Role-safe ElligatorSwift key exchange for Bitcoin's BIP324 transport.
 *
 * This module covers only the BIP324 ElligatorSwift ECDH operation. It does
 * not implement BIP324's HKDF expansion, packet encryption, or transport
 * state machine. `DENO_SECP256K1_PATH` must name an absolute user-installed
 * libsecp256k1 path. Although other package operations support path-scoped
 * FFI permission, key derivation requires unscoped `--allow-ffi` because
 * Deno's `UnsafePointerView` is needed to validate libsecp256k1's exported
 * BIP324 hash-callback pointer.
 *
 * @example Complete one initiator/responder key exchange.
 * ```ts
 * #!/usr/bin/env -S deno test --allow-env=DENO_SECP256K1_PATH --allow-ffi
 * import { Bip324KeyExchange } from "jsr:@bonakodo/secp256k1@1/bip324.ts";
 *
 * using initiator = Bip324KeyExchange.initiator();
 * using responder = Bip324KeyExchange.responder();
 * const initiatorEncoding = initiator.encoding;
 * const responderEncoding = responder.encoding;
 * using initiatorSecret = initiator.deriveSharedSecret(responderEncoding);
 * using responderSecret = responder.deriveSharedSecret(initiatorEncoding);
 * const left = initiatorSecret.consumeBytes();
 * const right = responderSecret.consumeBytes();
 * try {
 *   console.assert(left.length === 32);
 *   console.assert(left.every((byte, index) => byte === right[index]));
 * } finally {
 *   left.fill(0);
 *   right.fill(0);
 * }
 * ```
 *
 * @see https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki
 * @see https://github.com/bitcoin-core/secp256k1/blob/master/include/secp256k1_ellswift.h
 * @module
 * @since 1.0.0
 */

import { withSigningContext } from './native/context.ts';
import { requireEllSwift, requireEllSwiftSymbols } from './native/loader.ts';

const ELLSWIFT_ENCODING_SIZE = 64;
const SECRET_SIZE = 32;
const GROUP_ORDER = Uint8Array.from([
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xfe,
  0xba,
  0xae,
  0xdc,
  0xe6,
  0xaf,
  0x48,
  0xa0,
  0x3b,
  0xbf,
  0xd2,
  0x5e,
  0x8c,
  0xd0,
  0x36,
  0x41,
  0x41,
]);

type Bip324Role = 'initiator' | 'responder';

/**
 * Stable reasons for rejecting BIP324 API input.
 *
 * @since 1.0.0
 */
export type Bip324InputErrorCode =
  | 'invalid-ellswift-length'
  | 'invalid-peer-encoding';

/**
 * Stable reasons why a stateful BIP324 handle cannot be used.
 *
 * @since 1.0.0
 */
export type Bip324StateErrorCode =
  | 'exchange-consumed'
  | 'shared-secret-consumed';

/**
 * Stable reasons why a native BIP324 operation failed.
 *
 * @since 1.0.0
 */
export type Bip324NativeErrorCode =
  | 'ellswift-create-failed'
  | 'hash-callback-unavailable'
  | 'ellswift-xdh-failed';

/**
 * Reports programmer-facing malformed BIP324 input.
 *
 * Peer-controlled serialized encodings should be passed to
 * {@link EllSwiftEncoding.tryFromBytes}, which returns `null` instead.
 *
 * @since 1.0.0
 */
export class Bip324InputError extends TypeError {
  /**
   * Stable reason for the rejected input.
   *
   * @since 1.0.0
   */
  readonly code: Bip324InputErrorCode;

  /**
   * Creates a typed BIP324 input error.
   *
   * @param code Stable reason for the rejected input.
   * @since 1.0.0
   */
  constructor(code: Bip324InputErrorCode) {
    super(inputErrorMessage(code));
    this.name = 'Bip324InputError';
    this.code = code;
  }
}

/**
 * Reports reuse of a consumed or destroyed secret-bearing handle.
 *
 * @since 1.0.0
 */
export class Bip324StateError extends Error {
  /**
   * Stable reason why the handle is unavailable.
   *
   * @since 1.0.0
   */
  readonly code: Bip324StateErrorCode;

  /**
   * Creates a typed BIP324 state error.
   *
   * @param code Stable reason why the handle is unavailable.
   * @since 1.0.0
   */
  constructor(code: Bip324StateErrorCode) {
    super(stateErrorMessage(code));
    this.name = 'Bip324StateError';
    this.code = code;
  }
}

/**
 * Reports an unexpected failure in libsecp256k1's BIP324 operations.
 *
 * Native library configuration, loading, capability, and context errors keep
 * their native-layer types. Callback-pointer permission failures are wrapped
 * with `hash-callback-unavailable` and retained as the error `cause`.
 *
 * @since 1.0.0
 */
export class Bip324NativeError extends Error {
  /**
   * Stable reason for the native failure.
   *
   * @since 1.0.0
   */
  readonly code: Bip324NativeErrorCode;

  /**
   * Creates a typed BIP324 native-operation error.
   *
   * @param code Stable reason for the native failure.
   * @param options Optional underlying failure, retained as `cause`.
   * @since 1.0.0
   */
  constructor(code: Bip324NativeErrorCode, options?: ErrorOptions) {
    super(nativeErrorMessage(code), options);
    this.name = 'Bip324NativeError';
    this.code = code;
  }
}

/**
 * An immutable 64-byte ElligatorSwift wire encoding.
 *
 * Construction performs length validation only. Every 64-byte string maps to
 * an ElligatorSwift X coordinate, so this value makes no authenticity,
 * ownership, or peer-identity claim. Input and output arrays are copied.
 *
 * @see https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki
 * @since 1.0.0
 */
export class EllSwiftEncoding {
  readonly #bytes: Uint8Array;

  private constructor(bytes: Uint8Array) {
    this.#bytes = bytes;
  }

  /**
   * Creates an encoding from exactly 64 bytes.
   *
   * This validates only the byte length; it does not authenticate a peer or
   * claim that a separately supplied secret key corresponds to the encoding.
   *
   * @param bytes Candidate ElligatorSwift wire bytes; copied on success.
   * @returns An immutable encoding that owns a private copy.
   * @throws {Bip324InputError} If `bytes` is not exactly 64 bytes.
   * @since 1.0.0
   */
  static fromBytes(bytes: Uint8Array): EllSwiftEncoding {
    const encoding = EllSwiftEncoding.tryFromBytes(bytes);
    if (encoding === null) {
      throw new Bip324InputError('invalid-ellswift-length');
    }
    return encoding;
  }

  /**
   * Tries to create an encoding from peer-controlled bytes.
   *
   * @param bytes Candidate wire bytes; copied when exactly 64 bytes long.
   * @returns An immutable encoding, or `null` for any other byte length.
   * @since 1.0.0
   */
  static tryFromBytes(bytes: Uint8Array): EllSwiftEncoding | null {
    return bytes.length === ELLSWIFT_ENCODING_SIZE
      ? new EllSwiftEncoding(bytes.slice())
      : null;
  }

  /**
   * Returns the 64-byte ElligatorSwift wire encoding.
   *
   * @returns A detached copy on every call.
   * @since 1.0.0
   */
  toBytes(): Uint8Array {
    return this.#bytes.slice();
  }
}

let createSharedSecret: (bytes: Uint8Array) => Bip324SharedSecret;

/**
 * A disposable, one-shot handle to a 32-byte BIP324 ECDH secret.
 *
 * {@link consumeBytes} is the only way to obtain the bytes. It may be called
 * exactly once and destroys the internal copy before returning. The returned
 * array belongs to the caller and must be wiped with `fill(0)` after HKDF use.
 * `destroy` and explicit resource management perform best-effort wiping if the
 * value has not been consumed. JavaScript cannot guarantee erasure of copies
 * made by the runtime or native library.
 *
 * @since 1.0.0
 */
export class Bip324SharedSecret implements Disposable {
  #bytes: Uint8Array | null;

  private constructor(bytes: Uint8Array) {
    this.#bytes = bytes.slice();
  }

  static {
    createSharedSecret = (bytes) => new Bip324SharedSecret(bytes);
  }

  /**
   * Takes the shared secret and permanently consumes this handle.
   *
   * @returns A detached 32-byte copy that the caller must wipe after use.
   * @throws {Bip324StateError} If already consumed or destroyed.
   * @since 1.0.0
   */
  consumeBytes(): Uint8Array {
    const bytes = this.#bytes;
    if (bytes === null) {
      throw new Bip324StateError('shared-secret-consumed');
    }
    this.#bytes = null;
    const output = bytes.slice();
    bytes.fill(0);
    return output;
  }

  /**
   * Best-effort wipes and consumes this handle without exposing the secret.
   *
   * Calling this method more than once has no effect.
   *
   * @since 1.0.0
   */
  destroy(): void {
    this.#bytes?.fill(0);
    this.#bytes = null;
  }

  /**
   * Best-effort wipes this handle for explicit resource management.
   *
   * @since 1.0.0
   */
  [Symbol.dispose](): void {
    this.destroy();
  }
}

/**
 * A role-bound, disposable BIP324 ephemeral key exchange.
 *
 * Use {@link Bip324KeyExchange.initiator} for BIP324 party A and
 * {@link Bip324KeyExchange.responder} for party B. The role fixes encoding
 * order during derivation, preventing callers from accidentally deriving a
 * different transcript. Derivation consumes and wipes the ephemeral secret
 * before any native work begins and remains consumed after every outcome.
 *
 * @see https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki
 * @since 1.0.0
 */
export class Bip324KeyExchange implements Disposable {
  readonly #role: Bip324Role;
  readonly #encoding: Uint8Array;
  #secret: Uint8Array | null;

  private constructor(
    role: Bip324Role,
    encoding: Uint8Array,
    secret: Uint8Array,
  ) {
    this.#role = role;
    this.#encoding = encoding;
    this.#secret = secret;
  }

  /**
   * Generates a fresh exchange bound to the initiating BIP324 role (party A).
   *
   * A uniformly sampled valid secp256k1 scalar and independent 32-byte
   * ElligatorSwift auxiliary randomness are obtained from Web Crypto.
   *
   * @returns A disposable exchange containing a new ephemeral secret.
   * @throws {Bip324NativeError} If native ElligatorSwift creation fails.
   * @throws {NativeCapabilityError} If libsecp256k1 lacks ElligatorSwift.
   * @throws Native configuration, loading, and context errors unchanged.
   * @since 1.0.0
   */
  static initiator(): Bip324KeyExchange {
    return Bip324KeyExchange.#generate('initiator');
  }

  /**
   * Generates a fresh exchange bound to the responding BIP324 role (party B).
   *
   * A uniformly sampled valid secp256k1 scalar and independent 32-byte
   * ElligatorSwift auxiliary randomness are obtained from Web Crypto.
   *
   * @returns A disposable exchange containing a new ephemeral secret.
   * @throws {Bip324NativeError} If native ElligatorSwift creation fails.
   * @throws {NativeCapabilityError} If libsecp256k1 lacks ElligatorSwift.
   * @throws Native configuration, loading, and context errors unchanged.
   * @since 1.0.0
   */
  static responder(): Bip324KeyExchange {
    return Bip324KeyExchange.#generate('responder');
  }

  /**
   * Returns this exchange's public 64-byte ElligatorSwift encoding.
   *
   * The returned immutable value owns a fresh copy and never exposes the
   * ephemeral secret.
   *
   * @returns A copied immutable wire encoding.
   * @since 1.0.0
   */
  get encoding(): EllSwiftEncoding {
    return EllSwiftEncoding.fromBytes(this.#encoding);
  }

  /**
   * Derives the BIP324 shared secret and consumes the ephemeral secret.
   *
   * Encoding order is always initiator then responder. This exchange is
   * marked consumed before capability lookup, callback-pointer dereferencing,
   * or XDH, and remains consumed after success or failure. Current Deno
   * requires unscoped `--allow-ffi` for the callback-pointer dereference.
   *
   * @param peer The remote party's copied 64-byte ElligatorSwift encoding.
   * @returns A disposable one-shot shared-secret handle.
   * @throws {Bip324InputError} If called from JavaScript with another value.
   * @throws {Bip324StateError} If this exchange was consumed or destroyed.
   * @throws {Bip324NativeError} If callback permission or native XDH fails.
   * @throws {NativeCapabilityError} If ElligatorSwift or its BIP324 hash
   * callback is unavailable.
   * @throws Native configuration, loading, and context errors unchanged.
   * @since 1.0.0
   */
  deriveSharedSecret(peer: EllSwiftEncoding): Bip324SharedSecret {
    const secret = this.#secret;
    if (secret === null) {
      throw new Bip324StateError('exchange-consumed');
    }
    this.#secret = null;

    const localEncoding = this.#encoding.slice();
    let peerEncoding: Uint8Array | null = null;
    const output = new Uint8Array(SECRET_SIZE);
    try {
      if (!(peer instanceof EllSwiftEncoding)) {
        throw new Bip324InputError('invalid-peer-encoding');
      }
      peerEncoding = peer.toBytes();
      const initiatorEncoding = this.#role === 'initiator'
        ? localEncoding
        : peerEncoding;
      const responderEncoding = this.#role === 'responder'
        ? localEncoding
        : peerEncoding;
      let capability: ReturnType<typeof requireEllSwift>;
      try {
        capability = requireEllSwift();
      } catch (cause) {
        if (cause instanceof Deno.errors.NotCapable) {
          throw new Bip324NativeError('hash-callback-unavailable', { cause });
        }
        throw cause;
      }
      const { symbols, bip324HashCallback } = capability;

      const succeeded = withSigningContext((context) =>
        symbols.secp256k1_ellswift_xdh(
          context,
          output,
          initiatorEncoding,
          responderEncoding,
          secret,
          this.#role === 'initiator' ? 0 : 1,
          bip324HashCallback,
          null,
        ) === 1
      );
      if (!succeeded) {
        throw new Bip324NativeError('ellswift-xdh-failed');
      }
      return createSharedSecret(output);
    } finally {
      secret.fill(0);
      localEncoding.fill(0);
      peerEncoding?.fill(0);
      output.fill(0);
    }
  }

  /**
   * Best-effort wipes and consumes the ephemeral secret without deriving.
   *
   * The public encoding remains available. Calling this method more than once
   * has no effect.
   *
   * @since 1.0.0
   */
  destroy(): void {
    this.#secret?.fill(0);
    this.#secret = null;
  }

  /**
   * Best-effort wipes the ephemeral secret for explicit resource management.
   *
   * @since 1.0.0
   */
  [Symbol.dispose](): void {
    this.destroy();
  }

  static #generate(role: Bip324Role): Bip324KeyExchange {
    const symbols = requireEllSwiftSymbols();
    const secret = new Uint8Array(SECRET_SIZE);
    const auxiliaryRandomness = new Uint8Array(SECRET_SIZE);
    const encoding = new Uint8Array(ELLSWIFT_ENCODING_SIZE);
    try {
      fillSecretKey(secret);
      crypto.getRandomValues(auxiliaryRandomness);
      const succeeded = withSigningContext((context) =>
        symbols.secp256k1_ellswift_create(
          context,
          encoding,
          secret,
          auxiliaryRandomness,
        ) === 1
      );
      if (!succeeded) {
        throw new Bip324NativeError('ellswift-create-failed');
      }
      return new Bip324KeyExchange(role, encoding, secret);
    } catch (cause) {
      secret.fill(0);
      encoding.fill(0);
      throw cause;
    } finally {
      auxiliaryRandomness.fill(0);
    }
  }
}

function fillSecretKey(candidate: Uint8Array): void {
  do {
    crypto.getRandomValues(candidate);
  } while (!isValidSecretKey(candidate));
}

function isValidSecretKey(candidate: Uint8Array): boolean {
  let nonzero = false;
  let order = 0;
  for (let index = 0; index < candidate.length; index++) {
    nonzero ||= candidate[index] !== 0;
    if (order === 0) {
      order = Math.sign(candidate[index] - GROUP_ORDER[index]);
    }
  }
  return nonzero && order < 0;
}

function inputErrorMessage(code: Bip324InputErrorCode): string {
  switch (code) {
    case 'invalid-ellswift-length':
      return 'EllSwiftEncoding requires exactly 64 bytes';
    case 'invalid-peer-encoding':
      return 'peer must be an EllSwiftEncoding';
  }
}

function stateErrorMessage(code: Bip324StateErrorCode): string {
  switch (code) {
    case 'exchange-consumed':
      return 'BIP324 key exchange was already consumed or destroyed';
    case 'shared-secret-consumed':
      return 'BIP324 shared secret was already consumed or destroyed';
  }
}

function nativeErrorMessage(code: Bip324NativeErrorCode): string {
  switch (code) {
    case 'ellswift-create-failed':
      return 'Native ElligatorSwift key generation failed';
    case 'hash-callback-unavailable':
      return 'Native BIP324 hash callback is unavailable';
    case 'ellswift-xdh-failed':
      return 'Native BIP324 ElligatorSwift XDH failed';
  }
}
