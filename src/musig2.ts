/**
 * Safe, indexed MuSig2 signing for Bitcoin Taproot.
 *
 * This module implements the standard BIP327 signing flow around a
 * user-installed libsecp256k1. Public keys are aggregated in caller-provided
 * order and duplicate keys are supported, so every nonce and partial signature
 * is associated with a stable participant index.
 *
 * Secret nonces are opaque, non-exportable, and consumed before any signing
 * attempt. Never reuse a MuSig2 secret nonce: nonce reuse can reveal the
 * participant's secret key. Public wire values copy all input and output bytes.
 *
 * MuSig2 uses native pointer arrays. Current Deno pointer APIs therefore require
 * unscoped `--allow-ffi` in addition to access to `DENO_SECP256K1_PATH`.
 *
 * @example Parse an untrusted public nonce
 * ```ts
 * #!/usr/bin/env -S deno run --allow-env=DENO_SECP256K1_PATH --allow-ffi
 * import { MuSigPublicNonce } from "jsr:@bonakodo/secp256k1@1/musig2.ts";
 *
 * const peerBytes = new Uint8Array(66);
 * const nonce = MuSigPublicNonce.tryFromBytes(peerBytes);
 * console.assert(nonce === null);
 * ```
 *
 * @see https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki
 * @see https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
 * @see https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
 * @module
 * @since 1.0.0
 */

import { Digest32 } from './api/digest.ts';
import { copyExact, invalidInput } from './api/input.ts';
import {
  CompressedPublicKey,
  nativePublicKey,
  nativeXOnlyPublicKey,
  PublicKey,
  XOnlyPublicKey,
} from './api/keys.ts';
import { SchnorrSignature } from './api/signatures.ts';
import { withSigningContext, withStaticContext } from './native/context.ts';
import { getNativeSymbols, requireCapability } from './native/loader.ts';

export {
  CompressedPublicKey,
  Digest32,
  PublicKey,
  SchnorrSignature,
  XOnlyPublicKey,
};
export type { PublicKeyEncoding } from './api/keys.ts';

const PUBLIC_NONCE_BYTES = 66;
const AGGREGATE_NONCE_BYTES = 66;
const PARTIAL_SIGNATURE_BYTES = 32;
const PUBLIC_KEY_SIZE = 64;
const X_ONLY_PUBLIC_KEY_SIZE = 64;
const KEYPAIR_SIZE = 96;
const KEY_AGGREGATION_CACHE_SIZE = 197;
const SECRET_NONCE_SIZE = 132;
const PUBLIC_NONCE_SIZE = 132;
const AGGREGATE_NONCE_SIZE = 132;
const SESSION_SIZE = 133;
const PARTIAL_SIGNATURE_SIZE = 36;
const EC_COMPRESSED = 258;

/**

 * Stable state-error codes for MuSig2 programmer misuse.

 *

 * @since 1.0.0

 */
export type MuSigStateErrorCode =
  | 'empty-participants'
  | 'invalid-participant-index'
  | 'duplicate-participant-index'
  | 'missing-participant-index'
  | 'extra-participant-index'
  | 'nonce-already-consumed'
  | 'nonce-binding-mismatch'
  | 'secret-key-mismatch'
  | 'nonce-generation-started'
  | 'already-tweaked'
  | 'invalid-secret-key';

/**
 * Reports unsafe or inconsistent MuSig2 state supplied by the caller.
 *
 * Malformed peer wire bytes are instead handled by `tryFromBytes`,
 * `tryCreate`, and verification methods returning `null` or `false`.
 *
 * @since 1.0.0
 */
export class MuSigStateError extends Error {
  /**
   * Machine-readable misuse category.
   *
   * @since 1.0.0
   */
  readonly code: MuSigStateErrorCode;

  /**
   * Creates a MuSig2 state error.
   *
   * @param code Stable misuse category.
   * @param message Human-readable context.
   * @param options Optional underlying cause.
   * @since 1.0.0
   */
  constructor(
    code: MuSigStateErrorCode,
    message: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = 'MuSigStateError';
    this.code = code;
  }
}

/**
 * Reports a native MuSig2 operation that failed after inputs were validated.
 *
 * @since 1.0.0
 */
export class MuSigNativeError extends Error {
  /**
   * Native operation that failed.
   *
   * @since 1.0.0
   */
  readonly operation: string;

  /**
   * Creates a native-operation error.
   *
   * @param operation Short native operation name.
   * @since 1.0.0
   */
  constructor(operation: string) {
    super(`Native MuSig2 operation failed: ${operation}`);
    this.name = 'MuSigNativeError';
    this.operation = operation;
  }
}

/**
 * Reports failure to obtain fresh secret nonce randomness.
 *
 * @since 1.0.0
 */
export class MuSigRandomError extends Error {
  /**
   * Creates a random-source error.
   *
   * @param options Underlying random-source failure.
   * @since 1.0.0
   */
  constructor(options?: ErrorOptions) {
    super('Unable to generate fresh MuSig2 secret nonce randomness', options);
    this.name = 'MuSigRandomError';
  }
}

/**
 * Minimal secret-key contract consumed by MuSig2 signing.
 *
 * The returned byte array is copied and wiped by this module. JavaScript cannot
 * erase copies retained by the key implementation. The library's Bitcoin
 * `SecretKey` handle satisfies this structural contract.
 *
 * @since 1.0.0
 */
export interface MuSigSigningKey {
  /**
   * Exports exactly 32 secret scalar bytes.
   *
   * @returns A caller-owned secret byte array.
   * @since 1.0.0
   */
  exportBytes(): Uint8Array;
}

/**
 * Structural 32-byte Taproot Merkle-root value accepted by MuSig2 tweaking.
 *
 * `null` means no script tree and is distinct from 32 zero bytes.
 *
 * @since 1.0.0
 */
export interface MuSigTapMerkleRoot {
  /**
   * Returns the 32-byte Taproot Merkle root.
   *
   * @returns A caller-owned byte array.
   * @since 1.0.0
   */
  toBytes(): Uint8Array;
}

/**

 * A public nonce associated with one ordered participant.

 *

 * @since 1.0.0

 */
export interface IndexedMuSigPublicNonce {
  /**
   * Stable zero-based index in the ordered key aggregation.
   *
   * @since 1.0.0
   */
  readonly participantIndex: number;
  /**
   * Participant's validated public nonce.
   *
   * @since 1.0.0
   */
  readonly publicNonce: MuSigPublicNonce;
}

/**

 * A partial signature associated with one ordered participant.

 *

 * @since 1.0.0

 */
export interface IndexedMuSigPartialSignature {
  /**
   * Stable zero-based index in the ordered key aggregation.
   *
   * @since 1.0.0
   */
  readonly participantIndex: number;
  /**
   * Participant's validated partial signature.
   *
   * @since 1.0.0
   */
  readonly partialSignature: MuSigPartialSignature;
}

/**

 * Input used to verify a participant's exact nonce and partial binding.

 *

 * @since 1.0.0

 */
export interface MuSigPartialVerification {
  /**
   * Stable zero-based participant index.
   *
   * @since 1.0.0
   */
  readonly participantIndex: number;
  /**
   * Public nonce supplied for this participant and session.
   *
   * @since 1.0.0
   */
  readonly publicNonce: MuSigPublicNonce;
  /**
   * Candidate partial signature.
   *
   * @since 1.0.0
   */
  readonly partialSignature: MuSigPartialSignature;
}

/**

 * Result of applying the single BIP341 tweak to a key aggregation.

 *

 * @since 1.0.0

 */
export interface MuSigTaprootTweakResult {
  /**
   * New aggregation context containing the tweaked native cache.
   *
   * @since 1.0.0
   */
  readonly keyAggregation: MuSigKeyAggregation;
  /**
   * Tweaked Taproot output key.
   *
   * @since 1.0.0
   */
  readonly outputKey: XOnlyPublicKey;
  /**
   * Y parity of the full tweaked output point.
   *
   * @since 1.0.0
   */
  readonly outputKeyParity: 0 | 1;
}

/**

 * Arguments used to generate a single-use secret nonce.

 *

 * @since 1.0.0

 */
export interface MuSigSecretNonceGeneration {
  /**
   * Stable zero-based participant index.
   *
   * @since 1.0.0
   */
  readonly participantIndex: number;
  /**
   * Secret key matching that exact participant entry.
   *
   * @since 1.0.0
   */
  readonly secretKey: MuSigSigningKey;
  /**
   * Bitcoin transaction digest to bind into nonce derivation.
   *
   * @since 1.0.0
   */
  readonly digest: Digest32;
  /**
   * Ordered, optionally Taproot-tweaked key aggregation.
   *
   * @since 1.0.0
   */
  readonly keyAggregation: MuSigKeyAggregation;
}

/**

 * Arguments used to create a signing session.

 *

 * @since 1.0.0

 */
export interface MuSigSessionCreation {
  /**
   * Aggregate nonce received or produced for this round.
   *
   * @since 1.0.0
   */
  readonly aggregateNonce: MuSigAggregateNonce;
  /**
   * Exactly one indexed public nonce per participant.
   *
   * @since 1.0.0
   */
  readonly publicNonces: readonly IndexedMuSigPublicNonce[];
  /**
   * Bitcoin transaction digest being signed.
   *
   * @since 1.0.0
   */
  readonly digest: Digest32;
  /**
   * The exact key aggregation used during nonce generation.
   *
   * @since 1.0.0
   */
  readonly keyAggregation: MuSigKeyAggregation;
}

/**

 * Arguments used for one local partial-signing attempt.

 *

 * @since 1.0.0

 */
export interface MuSigPartialSigning {
  /**
   * Opaque single-use nonce generated for this session data.
   *
   * @since 1.0.0
   */
  readonly secretNonce: MuSigSecretNonce;
  /**
   * Secret key matching the nonce's indexed participant.
   *
   * @since 1.0.0
   */
  readonly secretKey: MuSigSigningKey;
}

/**
 * Immutable validated 66-byte BIP327 public nonce.
 *
 * Parsing validates both compressed points through libsecp256k1. Inputs and
 * outputs are copied. Prefer `tryFromBytes` for peer-controlled bytes.
 *
 * @see https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki
 * @since 1.0.0
 */
export class MuSigPublicNonce {
  readonly #bytes: Uint8Array;

  private constructor(bytes: Uint8Array) {
    this.#bytes = bytes;
  }

  /**
   * Parses a 66-byte public nonce.
   *
   * @param bytes Serialized BIP327 public nonce; copied on success.
   * @returns A validated immutable nonce.
   * @throws {Secp256k1InputError} If length or point parsing fails.
   * @throws {NativeCapabilityError} If native MuSig support is unavailable.
   * @since 1.0.0
   */
  static fromBytes(bytes: Uint8Array): MuSigPublicNonce {
    return MuSigPublicNonce.tryFromBytes(bytes) ??
      invalidInput('MuSigPublicNonce', 'invalid 66-byte public nonce');
  }

  /**
   * Tries to parse an untrusted public nonce.
   *
   * @param bytes Candidate wire bytes.
   * @returns A copied nonce, or `null` for malformed peer input.
   * @throws Native configuration and capability errors unchanged.
   * @since 1.0.0
   */
  static tryFromBytes(bytes: Uint8Array): MuSigPublicNonce | null {
    const copy = copyExact(bytes, PUBLIC_NONCE_BYTES);
    if (copy === null || parsePublicNonce(copy) === null) return null;
    return new MuSigPublicNonce(copy);
  }

  /**
   * Returns detached BIP327 wire bytes.
   *
   * @returns A new 66-byte array.
   * @since 1.0.0
   */
  toBytes(): Uint8Array {
    return this.#bytes.slice();
  }
}

/**
 * Immutable validated 66-byte BIP327 aggregate nonce.
 *
 * @see https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki
 * @since 1.0.0
 */
export class MuSigAggregateNonce {
  readonly #bytes: Uint8Array;

  private constructor(bytes: Uint8Array) {
    this.#bytes = bytes;
  }

  /**
   * Parses a 66-byte aggregate nonce.
   *
   * @param bytes Serialized aggregate nonce; copied on success.
   * @returns A validated immutable aggregate nonce.
   * @throws {Secp256k1InputError} If length or point parsing fails.
   * @throws {NativeCapabilityError} If native MuSig support is unavailable.
   * @since 1.0.0
   */
  static fromBytes(bytes: Uint8Array): MuSigAggregateNonce {
    return MuSigAggregateNonce.tryFromBytes(bytes) ??
      invalidInput('MuSigAggregateNonce', 'invalid 66-byte aggregate nonce');
  }

  /**
   * Tries to parse an untrusted aggregate nonce.
   *
   * @param bytes Candidate wire bytes.
   * @returns A copied nonce, or `null` for malformed peer input.
   * @throws Native configuration and capability errors unchanged.
   * @since 1.0.0
   */
  static tryFromBytes(bytes: Uint8Array): MuSigAggregateNonce | null {
    const copy = copyExact(bytes, AGGREGATE_NONCE_BYTES);
    if (copy === null || parseAggregateNonce(copy) === null) return null;
    return new MuSigAggregateNonce(copy);
  }

  /**
   * Aggregates exactly one public nonce per participant index.
   *
   * @param keyAggregation Ordered key aggregation defining all indexes.
   * @param publicNonces Complete indexed public-nonce set.
   * @returns The immutable aggregate nonce.
   * @throws {MuSigStateError} If indexes are empty, missing, duplicated, or extra.
   * @throws Native configuration, capability, and operation errors unchanged.
   * @since 1.0.0
   */
  static aggregate(
    keyAggregation: MuSigKeyAggregation,
    publicNonces: readonly IndexedMuSigPublicNonce[],
  ): MuSigAggregateNonce {
    const aggregation = keyAggregationState(keyAggregation);
    const ordered = orderIndexed(
      publicNonces,
      aggregation.participants.length,
      'public nonce',
    );
    const nativeNonces = ordered.map((entry) =>
      requirePublicNonce(entry.publicNonce)
    );
    const pointers = pointerArray(nativeNonces);
    const symbols = requireCapability('musig');
    const nativeAggregate = new Uint8Array(AGGREGATE_NONCE_SIZE);

    withStaticContext((context) => {
      if (
        symbols.secp256k1_musig_nonce_agg(
          context,
          nativeAggregate,
          pointers,
          BigInt(nativeNonces.length),
        ) !== 1
      ) {
        throw new MuSigNativeError('nonce-aggregate');
      }
    });
    return new MuSigAggregateNonce(serializeAggregateNonce(nativeAggregate));
  }

  /**
   * Returns detached BIP327 wire bytes.
   *
   * @returns A new 66-byte array.
   * @since 1.0.0
   */
  toBytes(): Uint8Array {
    return this.#bytes.slice();
  }
}

/**
 * Immutable validated 32-byte BIP327 partial signature.
 *
 * Scalar parsing does not prove that the partial belongs to a session. Use
 * `MuSigSession.verifyPartial` for that check.
 *
 * @see https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki
 * @since 1.0.0
 */
export class MuSigPartialSignature {
  readonly #bytes: Uint8Array;

  private constructor(bytes: Uint8Array) {
    this.#bytes = bytes;
  }

  /**
   * Parses a 32-byte partial-signature scalar.
   *
   * @param bytes Serialized partial signature; copied on success.
   * @returns A validated immutable partial signature.
   * @throws {Secp256k1InputError} If length or scalar parsing fails.
   * @throws {NativeCapabilityError} If native MuSig support is unavailable.
   * @since 1.0.0
   */
  static fromBytes(bytes: Uint8Array): MuSigPartialSignature {
    return MuSigPartialSignature.tryFromBytes(bytes) ??
      invalidInput(
        'MuSigPartialSignature',
        'invalid 32-byte partial signature',
      );
  }

  /**
   * Tries to parse an untrusted partial signature.
   *
   * @param bytes Candidate wire bytes.
   * @returns A copied partial, or `null` for malformed peer input.
   * @throws Native configuration and capability errors unchanged.
   * @since 1.0.0
   */
  static tryFromBytes(bytes: Uint8Array): MuSigPartialSignature | null {
    const copy = copyExact(bytes, PARTIAL_SIGNATURE_BYTES);
    if (copy === null || parsePartialSignature(copy) === null) return null;
    return new MuSigPartialSignature(copy);
  }

  /**
   * Returns detached BIP327 wire bytes.
   *
   * @returns A new 32-byte array.
   * @since 1.0.0
   */
  toBytes(): Uint8Array {
    return this.#bytes.slice();
  }
}

interface KeyAggregationState {
  readonly identity: object;
  readonly participants: readonly CompressedPublicKey[];
  readonly cache: Uint8Array;
  readonly aggregatePublicKey: CompressedPublicKey;
  readonly aggregateXOnlyPublicKey: XOnlyPublicKey;
  readonly taprootTweaked: boolean;
  nonceGenerationStarted: boolean;
}

const KEY_AGGREGATIONS = new WeakMap<
  MuSigKeyAggregation,
  KeyAggregationState
>();

/**
 * Ordered MuSig2 participant keys and their native aggregation cache.
 *
 * Caller order is consensus-relevant to BIP327 key aggregation. It is preserved
 * exactly, duplicate keys are allowed, and participant identity is always the
 * resulting zero-based index. Use `sortMuSigPublicKeys` explicitly only when a
 * higher-level protocol requires canonical lexicographic ordering.
 *
 * @see https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki
 * @since 1.0.0
 */
export class MuSigKeyAggregation {
  private constructor(state: KeyAggregationState) {
    KEY_AGGREGATIONS.set(this, state);
  }

  /**
   * Aggregates public keys in their exact caller-provided order.
   *
   * @param publicKeys Non-empty ordered keys; duplicates are preserved.
   * @returns A new key aggregation with stable participant indexes.
   * @throws {MuSigStateError} If `publicKeys` is empty.
   * @throws Native configuration, capability, and operation errors unchanged.
   * @since 1.0.0
   */
  static fromOrderedPublicKeys(
    publicKeys: readonly CompressedPublicKey[],
  ): MuSigKeyAggregation {
    if (publicKeys.length === 0) {
      throw new MuSigStateError(
        'empty-participants',
        'MuSig2 key aggregation requires at least one participant',
      );
    }
    const participants = publicKeys.map((key) =>
      CompressedPublicKey.parse(key.toBytes())
    );
    const nativeKeys = participants.map((key) =>
      nativePublicKey(key.toPublicKey())
    );
    const pointers = pointerArray(nativeKeys);
    const symbols = requireCapability('musig');
    requireCapability('extrakeys');
    const cache = new Uint8Array(KEY_AGGREGATION_CACHE_SIZE);
    const aggregateXOnly = new Uint8Array(X_ONLY_PUBLIC_KEY_SIZE);

    withStaticContext((context) => {
      if (
        symbols.secp256k1_musig_pubkey_agg(
          context,
          aggregateXOnly,
          cache,
          pointers,
          BigInt(nativeKeys.length),
        ) !== 1
      ) {
        throw new MuSigNativeError('public-key-aggregate');
      }
    });

    const aggregateFull = new Uint8Array(PUBLIC_KEY_SIZE);
    withStaticContext((context) => {
      if (
        symbols.secp256k1_musig_pubkey_get(
          context,
          aggregateFull,
          cache,
        ) !== 1
      ) {
        throw new MuSigNativeError('aggregate-public-key-get');
      }
    });

    return new MuSigKeyAggregation({
      identity: Object.freeze({}),
      participants,
      cache,
      aggregatePublicKey: serializeCompressedPublicKey(aggregateFull),
      aggregateXOnlyPublicKey: serializeXOnlyPublicKey(aggregateXOnly),
      taprootTweaked: false,
      nonceGenerationStarted: false,
    });
  }

  /**

   * Number of ordered participant entries, including duplicates.

   *

   * @since 1.0.0

   */
  get participantCount(): number {
    return keyAggregationState(this).participants.length;
  }

  /**
   * Returns the key assigned to one participant index.
   *
   * @param participantIndex Stable zero-based participant index.
   * @returns An immutable copy of the indexed compressed key.
   * @throws {MuSigStateError} If the index is outside the aggregation.
   * @since 1.0.0
   */
  participantPublicKey(participantIndex: number): CompressedPublicKey {
    const state = keyAggregationState(this);
    assertParticipantIndex(participantIndex, state.participants.length);
    return CompressedPublicKey.parse(
      state.participants[participantIndex].toBytes(),
    );
  }

  /**
   * Returns all keys in aggregation order.
   *
   * @returns A detached array of immutable key copies.
   * @since 1.0.0
   */
  orderedPublicKeys(): readonly CompressedPublicKey[] {
    return keyAggregationState(this).participants.map((key) =>
      CompressedPublicKey.parse(key.toBytes())
    );
  }

  /**
   * Returns the current full aggregate public key.
   *
   * @returns A canonical compressed public key.
   * @since 1.0.0
   */
  aggregatePublicKey(): CompressedPublicKey {
    return CompressedPublicKey.parse(
      keyAggregationState(this).aggregatePublicKey.toBytes(),
    );
  }

  /**
   * Returns the current BIP340 aggregate x-only public key.
   *
   * After `taprootTweak`, this is the Taproot output key.
   *
   * @returns An immutable x-only public key.
   * @since 1.0.0
   */
  aggregateXOnlyPublicKey(): XOnlyPublicKey {
    return XOnlyPublicKey.parse(
      keyAggregationState(this).aggregateXOnlyPublicKey.toBytes(),
    );
  }

  /**
   * Applies the single BIP341 TapTweak to a copied native aggregation cache.
   *
   * This must be called before generating any nonce from this aggregation.
   * `null` hashes only the internal x-only key and means no script tree.
   *
   * @param merkleRoot A structural 32-byte root value, or `null` for no tree.
   * @returns A new tweaked aggregation, output key, and output-key parity.
   * @throws {MuSigStateError} If nonce generation started or a tweak was applied.
   * @throws {Secp256k1InputError} If the root does not return exactly 32 bytes.
   * @throws Native configuration, capability, and operation errors unchanged.
   * @see https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
   * @since 1.0.0
   */
  taprootTweak(
    merkleRoot: MuSigTapMerkleRoot | null,
  ): MuSigTaprootTweakResult {
    const state = keyAggregationState(this);
    if (state.nonceGenerationStarted) {
      throw new MuSigStateError(
        'nonce-generation-started',
        'Taproot tweaking must occur before MuSig2 nonce generation',
      );
    }
    if (state.taprootTweaked) {
      throw new MuSigStateError(
        'already-tweaked',
        'A MuSig2 key aggregation accepts only one BIP341 TapTweak',
      );
    }

    const root = merkleRoot?.toBytes();
    if (root !== undefined && root.length !== 32) {
      invalidInput('MuSigTapMerkleRoot', 'expected exactly 32 bytes');
    }
    const message = root === undefined
      ? state.aggregateXOnlyPublicKey.toBytes()
      : concatenate(state.aggregateXOnlyPublicKey.toBytes(), root);
    const tweak = taggedHash('TapTweak', message);
    const cache = state.cache.slice();
    const outputFull = new Uint8Array(PUBLIC_KEY_SIZE);
    const symbols = requireCapability('musig');
    const extra = requireCapability('extrakeys');

    try {
      withStaticContext((context) => {
        if (
          symbols.secp256k1_musig_pubkey_xonly_tweak_add(
            context,
            outputFull,
            cache,
            tweak,
          ) !== 1
        ) {
          throw new MuSigNativeError('taproot-tweak');
        }
      });
    } finally {
      tweak.fill(0);
    }

    const outputXOnly = new Uint8Array(X_ONLY_PUBLIC_KEY_SIZE);
    const parity = new Int32Array(1);
    withStaticContext((context) => {
      if (
        extra.secp256k1_xonly_pubkey_from_pubkey(
          context,
          outputXOnly,
          parity,
          outputFull,
        ) !== 1
      ) {
        throw new MuSigNativeError('taproot-output-key-convert');
      }
    });
    const outputKey = serializeXOnlyPublicKey(outputXOnly);
    const keyAggregation = new MuSigKeyAggregation({
      identity: Object.freeze({}),
      participants: state.participants.map((key) =>
        CompressedPublicKey.parse(key.toBytes())
      ),
      cache,
      aggregatePublicKey: serializeCompressedPublicKey(outputFull),
      aggregateXOnlyPublicKey: outputKey,
      taprootTweaked: true,
      nonceGenerationStarted: false,
    });
    return {
      keyAggregation,
      outputKey: XOnlyPublicKey.parse(outputKey.toBytes()),
      outputKeyParity: parity[0] === 0 ? 0 : 1,
    };
  }
}

/**
 * Returns a canonical lexicographic copy of compressed participant keys.
 *
 * Key aggregation never sorts implicitly. Use this helper only when the
 * surrounding protocol explicitly commits to lexicographic compressed-key
 * ordering. Duplicate entries remain distinct.
 *
 * @param publicKeys Keys to copy and sort by their 33-byte SEC encodings.
 * @returns A newly allocated sorted array.
 * @since 1.0.0
 */
export function sortMuSigPublicKeys(
  publicKeys: readonly CompressedPublicKey[],
): readonly CompressedPublicKey[] {
  return publicKeys
    .map((key) => CompressedPublicKey.parse(key.toBytes()))
    .sort((left, right) => compareBytes(left.toBytes(), right.toBytes()));
}

interface SecretNonceState {
  readonly participantIndex: number;
  readonly publicNonce: MuSigPublicNonce;
  readonly nativeSecretNonce: Uint8Array;
  readonly keyAggregationIdentity: object;
  readonly digest: Uint8Array;
  readonly participantPublicKey: Uint8Array;
  sessionIdentity?: object;
  consumed: boolean;
}

const SECRET_NONCES = new WeakMap<MuSigSecretNonce, SecretNonceState>();

/**
 * Opaque, non-exportable, single-use MuSig2 secret nonce handle.
 *
 * The handle exposes only its public nonce and participant index. A signing
 * attempt consumes and wipes native secret nonce storage before validating all
 * bindings, including attempts with the wrong key or session. Never copy or
 * reuse secret nonce material; nonce reuse can reveal the signing key.
 *
 * @see https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki
 * @since 1.0.0
 */
export class MuSigSecretNonce implements Disposable {
  private constructor(state: SecretNonceState) {
    SECRET_NONCES.set(this, state);
  }

  /**
   * Generates fresh randomness and binds every available signing input.
   *
   * The native nonce derivation receives the secret key, exact indexed public
   * key, digest, key aggregation cache, and an index-specific extra input.
   * Session randomness and temporary secret-key copies are wiped immediately.
   *
   * @param options Indexed key, digest, and aggregation bindings.
   * @returns An opaque single-use secret nonce handle.
   * @throws {MuSigRandomError} If secure randomness is unavailable.
   * @throws {MuSigStateError} If the index or secret key is invalid or mismatched.
   * @throws Native configuration, capability, and operation errors unchanged.
   * @since 1.0.0
   */
  static generate(options: MuSigSecretNonceGeneration): MuSigSecretNonce {
    const aggregation = keyAggregationState(options.keyAggregation);
    assertParticipantIndex(
      options.participantIndex,
      aggregation.participants.length,
    );
    const secret = exportSecretKey(options.secretKey);
    const random = new Uint8Array(32);
    let keypair: Uint8Array | undefined;
    let unclaimedSecretNonce: Uint8Array | undefined;

    try {
      const derived = deriveKeypair(secret);
      keypair = derived.keypair;
      const expected = aggregation.participants[options.participantIndex]
        .toBytes();
      if (!bytesEqual(derived.compressedPublicKey, expected)) {
        throw new MuSigStateError(
          'secret-key-mismatch',
          'Secret key does not match the indexed MuSig2 participant',
        );
      }

      try {
        crypto.getRandomValues(random);
      } catch (cause) {
        throw new MuSigRandomError({ cause });
      }
      const extraInput = participantBinding(options.participantIndex);
      const nativeSecretNonce = new Uint8Array(SECRET_NONCE_SIZE);
      unclaimedSecretNonce = nativeSecretNonce;
      const nativePublicNonce = new Uint8Array(PUBLIC_NONCE_SIZE);
      const symbols = requireCapability('musig');
      try {
        withSigningContext((context) => {
          if (
            symbols.secp256k1_musig_nonce_gen(
              context,
              nativeSecretNonce,
              nativePublicNonce,
              random,
              secret,
              derived.nativePublicKey,
              options.digest.toBytes(),
              aggregation.cache,
              extraInput,
            ) !== 1
          ) {
            throw new MuSigNativeError('nonce-generate');
          }
        });
      } finally {
        random.fill(0);
        extraInput.fill(0);
      }

      const result = new MuSigSecretNonce({
        participantIndex: options.participantIndex,
        publicNonce: MuSigPublicNonce.fromBytes(
          serializePublicNonce(nativePublicNonce),
        ),
        nativeSecretNonce,
        keyAggregationIdentity: aggregation.identity,
        digest: options.digest.toBytes(),
        participantPublicKey: expected,
        consumed: false,
      });
      aggregation.nonceGenerationStarted = true;
      unclaimedSecretNonce = undefined;
      return result;
    } finally {
      random.fill(0);
      secret.fill(0);
      keypair?.fill(0);
      unclaimedSecretNonce?.fill(0);
    }
  }

  /**

   * Stable zero-based participant index bound during generation.

   *

   * @since 1.0.0

   */
  get participantIndex(): number {
    return secretNonceState(this).participantIndex;
  }

  /**
   * Returns the immutable public nonce corresponding to this secret nonce.
   *
   * @returns A copied public wire value.
   * @since 1.0.0
   */
  get publicNonce(): MuSigPublicNonce {
    return MuSigPublicNonce.fromBytes(
      secretNonceState(this).publicNonce.toBytes(),
    );
  }

  /**

   * Whether a signing attempt has permanently consumed this handle.

   *

   * @since 1.0.0

   */
  get consumed(): boolean {
    return secretNonceState(this).consumed;
  }

  /**
   * Permanently consumes this handle and overwrites its native secret nonce.
   *
   * Disposal is idempotent. The participant index and public nonce remain
   * available because they contain no secret material, but every later signing
   * attempt fails with the same `nonce-already-consumed` state error as nonce
   * reuse after signing.
   *
   * @since 1.0.0
   */
  destroy(): void {
    const state = secretNonceState(this);
    if (state.consumed) return;
    state.consumed = true;
    state.nativeSecretNonce.fill(0);
  }

  /**
   * Disposes this secret nonce for `using` declarations.
   *
   * @since 1.0.0
   */
  [Symbol.dispose](): void {
    this.destroy();
  }

  /**
   * Returns this nonce's public indexed protocol value.
   *
   * @returns A detached participant index and immutable public nonce.
   * @since 1.0.0
   */
  indexedPublicNonce(): IndexedMuSigPublicNonce {
    return {
      participantIndex: this.participantIndex,
      publicNonce: this.publicNonce,
    };
  }
}

interface SessionState {
  readonly identity: object;
  readonly keyAggregation: MuSigKeyAggregation;
  readonly keyAggregationIdentity: object;
  readonly digest: Uint8Array;
  readonly nativeSession: Uint8Array;
  readonly publicNonces: readonly MuSigPublicNonce[];
}

const SESSIONS = new WeakMap<MuSigSession, SessionState>();

/**
 * A MuSig2 signing session bound to keys, indexed nonces, and one digest.
 *
 * Sessions verify exact participant-index, public-key, and public-nonce
 * bindings before accepting partial signatures. Peer-invalid signatures return
 * `false` or `null`; state misuse and native failures throw typed errors.
 *
 * @see https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki
 * @since 1.0.0
 */
export class MuSigSession {
  private constructor(state: SessionState) {
    SESSIONS.set(this, state);
  }

  /**
   * Creates a session and rejects inconsistent trusted inputs.
   *
   * @param options Aggregate nonce, complete indexed nonce set, digest, and keys.
   * @returns A bound signing session.
   * @throws {Secp256k1InputError} If the aggregate nonce does not match the set.
   * @throws {MuSigStateError} If participant indexes are incomplete or invalid.
   * @throws Native configuration, capability, and operation errors unchanged.
   * @since 1.0.0
   */
  static create(options: MuSigSessionCreation): MuSigSession {
    return MuSigSession.tryCreate(options) ??
      invalidInput(
        'MuSigSession',
        'aggregate nonce does not match indexed public nonces',
      );
  }

  /**
   * Tries to create a session from peer-provided aggregate data.
   *
   * Participant-index misuse still throws. A well-formed but inconsistent
   * aggregate nonce returns `null` without entering native signing.
   *
   * @param options Aggregate nonce, complete indexed nonce set, digest, and keys.
   * @returns A bound session, or `null` for inconsistent peer aggregate data.
   * @throws {MuSigStateError} If participant indexes are incomplete or invalid.
   * @throws Native configuration and capability errors unchanged.
   * @since 1.0.0
   */
  static tryCreate(options: MuSigSessionCreation): MuSigSession | null {
    const aggregation = keyAggregationState(options.keyAggregation);
    const ordered = orderIndexed(
      options.publicNonces,
      aggregation.participants.length,
      'public nonce',
    );
    const computed = MuSigAggregateNonce.aggregate(
      options.keyAggregation,
      ordered,
    );
    if (!bytesEqual(computed.toBytes(), options.aggregateNonce.toBytes())) {
      return null;
    }

    const nativeAggregate = requireAggregateNonce(options.aggregateNonce);
    const nativeSession = new Uint8Array(SESSION_SIZE);
    const symbols = requireCapability('musig');
    const processed = withStaticContext((context) =>
      symbols.secp256k1_musig_nonce_process(
        context,
        nativeSession,
        nativeAggregate,
        options.digest.toBytes(),
        aggregation.cache,
      ) === 1
    );
    if (!processed) return null;

    return new MuSigSession({
      identity: Object.freeze({}),
      keyAggregation: options.keyAggregation,
      keyAggregationIdentity: aggregation.identity,
      digest: options.digest.toBytes(),
      nativeSession,
      publicNonces: ordered.map((entry) =>
        MuSigPublicNonce.fromBytes(entry.publicNonce.toBytes())
      ),
    });
  }

  /**
   * Consumes a secret nonce and creates a locally verified partial signature.
   *
   * The nonce is marked consumed before checking the session, participant, or
   * supplied secret key and is wiped in `finally` on every outcome. This avoids
   * accidentally retrying a nonce after any failed signing attempt.
   *
   * @param options Opaque nonce and matching secret key.
   * @returns An indexed, immutable partial signature.
   * @throws {MuSigStateError} If the nonce was used or any binding mismatches.
   * @throws Native configuration, capability, and operation errors unchanged.
   * @since 1.0.0
   */
  signPartial(options: MuSigPartialSigning): IndexedMuSigPartialSignature {
    const session = sessionState(this);
    const nonce = consumeSecretNonce(options.secretNonce);

    let secret: Uint8Array | undefined;
    let keypair: Uint8Array | undefined;
    try {
      const aggregation = keyAggregationState(session.keyAggregation);
      const sessionNonce = session.publicNonces[nonce.participantIndex];
      if (
        nonce.keyAggregationIdentity !== session.keyAggregationIdentity ||
        !bytesEqual(nonce.digest, session.digest) ||
        sessionNonce === undefined ||
        !bytesEqual(sessionNonce.toBytes(), nonce.publicNonce.toBytes())
      ) {
        throw new MuSigStateError(
          'nonce-binding-mismatch',
          'Secret nonce is not bound to this MuSig2 session',
        );
      }
      if (nonce.sessionIdentity === undefined) {
        nonce.sessionIdentity = session.identity;
      }
      if (nonce.sessionIdentity !== session.identity) {
        throw new MuSigStateError(
          'nonce-binding-mismatch',
          'Secret nonce is bound to a different MuSig2 session',
        );
      }

      secret = exportSecretKey(options.secretKey);
      const derived = deriveKeypair(secret);
      keypair = derived.keypair;
      if (
        !bytesEqual(derived.compressedPublicKey, nonce.participantPublicKey) ||
        !bytesEqual(
          derived.compressedPublicKey,
          aggregation.participants[nonce.participantIndex].toBytes(),
        )
      ) {
        throw new MuSigStateError(
          'secret-key-mismatch',
          'Secret key does not match the consumed MuSig2 nonce participant',
        );
      }

      const nativePartial = new Uint8Array(PARTIAL_SIGNATURE_SIZE);
      const symbols = requireCapability('musig');
      withSigningContext((context) => {
        if (
          symbols.secp256k1_musig_partial_sign(
            context,
            nativePartial,
            nonce.nativeSecretNonce,
            keypair!,
            aggregation.cache,
            session.nativeSession,
          ) !== 1
        ) {
          throw new MuSigNativeError('partial-sign');
        }
      });

      if (
        !verifyNativePartial(
          nativePartial,
          nonce.publicNonce,
          aggregation.participants[nonce.participantIndex],
          aggregation.cache,
          session.nativeSession,
        )
      ) {
        throw new MuSigNativeError('local-partial-verification');
      }
      return {
        participantIndex: nonce.participantIndex,
        partialSignature: MuSigPartialSignature.fromBytes(
          serializePartialSignature(nativePartial),
        ),
      };
    } finally {
      nonce.nativeSecretNonce.fill(0);
      secret?.fill(0);
      keypair?.fill(0);
    }
  }

  /**
   * Verifies an exact indexed participant nonce and partial signature.
   *
   * @param candidate Indexed nonce and partial signature supplied by a peer.
   * @returns `false` for wrong indexes, wrong nonce binding, or invalid partials.
   * @throws Native configuration and capability errors unchanged.
   * @since 1.0.0
   */
  verifyPartial(candidate: MuSigPartialVerification): boolean {
    const session = sessionState(this);
    const aggregation = keyAggregationState(session.keyAggregation);
    if (
      !Number.isSafeInteger(candidate.participantIndex) ||
      candidate.participantIndex < 0 ||
      candidate.participantIndex >= aggregation.participants.length
    ) {
      return false;
    }
    if (
      !bytesEqual(
        session.publicNonces[candidate.participantIndex].toBytes(),
        candidate.publicNonce.toBytes(),
      )
    ) {
      return false;
    }
    const nativePartial = parsePartialSignature(
      candidate.partialSignature.toBytes(),
    );
    if (nativePartial === null) return false;
    return verifyNativePartial(
      nativePartial,
      candidate.publicNonce,
      aggregation.participants[candidate.participantIndex],
      aggregation.cache,
      session.nativeSession,
    );
  }

  /**
   * Verifies and aggregates exactly one partial signature per participant.
   *
   * Every partial is verified before aggregation. The resulting 64-byte
   * signature is then verified against this session's effective aggregate
   * x-only key and digest before it is returned.
   *
   * @param partialSignatures Complete indexed partial-signature set.
   * @returns A verified BIP340 signature, or `null` for peer-invalid partials.
   * @throws {MuSigStateError} If indexes are empty, missing, duplicated, or extra.
   * @throws Native configuration, capability, and operation errors unchanged.
   * @since 1.0.0
   */
  aggregatePartials(
    partialSignatures: readonly IndexedMuSigPartialSignature[],
  ): SchnorrSignature | null {
    const session = sessionState(this);
    const aggregation = keyAggregationState(session.keyAggregation);
    const ordered = orderIndexed(
      partialSignatures,
      aggregation.participants.length,
      'partial signature',
    );
    const nativePartials: Uint8Array[] = [];
    for (let index = 0; index < ordered.length; index++) {
      const partial = ordered[index].partialSignature;
      if (
        !this.verifyPartial({
          participantIndex: index,
          publicNonce: session.publicNonces[index],
          partialSignature: partial,
        })
      ) {
        return null;
      }
      const nativePartial = parsePartialSignature(partial.toBytes());
      if (nativePartial === null) return null;
      nativePartials.push(nativePartial);
    }

    const pointers = pointerArray(nativePartials);
    const signatureBytes = new Uint8Array(64);
    const symbols = requireCapability('musig');
    withStaticContext((context) => {
      if (
        symbols.secp256k1_musig_partial_sig_agg(
          context,
          signatureBytes,
          session.nativeSession,
          pointers,
          BigInt(nativePartials.length),
        ) !== 1
      ) {
        throw new MuSigNativeError('partial-signature-aggregate');
      }
    });

    const schnorr = requireCapability('schnorrsig');
    const nativeOutputKey = nativeXOnlyPublicKey(
      aggregation.aggregateXOnlyPublicKey,
    );
    const valid = withStaticContext((context) =>
      schnorr.secp256k1_schnorrsig_verify(
        context,
        signatureBytes,
        session.digest,
        32n,
        nativeOutputKey,
      ) === 1
    );
    return valid ? SchnorrSignature.fromBytes(signatureBytes) : null;
  }
}

function keyAggregationState(
  aggregation: MuSigKeyAggregation,
): KeyAggregationState {
  const state = KEY_AGGREGATIONS.get(aggregation);
  if (state === undefined) throw new TypeError('Invalid MuSigKeyAggregation');
  return state;
}

function secretNonceState(nonce: MuSigSecretNonce): SecretNonceState {
  const state = SECRET_NONCES.get(nonce);
  if (state === undefined) throw new TypeError('Invalid MuSigSecretNonce');
  return state;
}

function consumeSecretNonce(nonce: MuSigSecretNonce): SecretNonceState {
  const state = secretNonceState(nonce);
  if (state.consumed) {
    throw new MuSigStateError(
      'nonce-already-consumed',
      'MuSig2 secret nonce has already been consumed',
    );
  }
  state.consumed = true;
  return state;
}

function sessionState(session: MuSigSession): SessionState {
  const state = SESSIONS.get(session);
  if (state === undefined) throw new TypeError('Invalid MuSigSession');
  return state;
}

function parsePublicNonce(bytes: Uint8Array): Uint8Array | null {
  const symbols = requireCapability('musig');
  const native = new Uint8Array(PUBLIC_NONCE_SIZE);
  return withStaticContext((context) =>
      symbols.secp256k1_musig_pubnonce_parse(context, native, bytes) === 1
    )
    ? native
    : null;
}

function requirePublicNonce(nonce: MuSigPublicNonce): Uint8Array {
  const native = parsePublicNonce(nonce.toBytes());
  if (native === null) throw new MuSigNativeError('public-nonce-reparse');
  return native;
}

function serializePublicNonce(native: Uint8Array): Uint8Array {
  const symbols = requireCapability('musig');
  const bytes = new Uint8Array(PUBLIC_NONCE_BYTES);
  const valid = withStaticContext((context) =>
    symbols.secp256k1_musig_pubnonce_serialize(context, bytes, native) === 1
  );
  if (!valid) throw new MuSigNativeError('public-nonce-serialize');
  return bytes;
}

function parseAggregateNonce(bytes: Uint8Array): Uint8Array | null {
  const symbols = requireCapability('musig');
  const native = new Uint8Array(AGGREGATE_NONCE_SIZE);
  return withStaticContext((context) =>
      symbols.secp256k1_musig_aggnonce_parse(context, native, bytes) === 1
    )
    ? native
    : null;
}

function requireAggregateNonce(nonce: MuSigAggregateNonce): Uint8Array {
  const native = parseAggregateNonce(nonce.toBytes());
  if (native === null) throw new MuSigNativeError('aggregate-nonce-reparse');
  return native;
}

function serializeAggregateNonce(native: Uint8Array): Uint8Array {
  const symbols = requireCapability('musig');
  const bytes = new Uint8Array(AGGREGATE_NONCE_BYTES);
  const valid = withStaticContext((context) =>
    symbols.secp256k1_musig_aggnonce_serialize(context, bytes, native) === 1
  );
  if (!valid) throw new MuSigNativeError('aggregate-nonce-serialize');
  return bytes;
}

function parsePartialSignature(bytes: Uint8Array): Uint8Array | null {
  const symbols = requireCapability('musig');
  const native = new Uint8Array(PARTIAL_SIGNATURE_SIZE);
  return withStaticContext((context) =>
      symbols.secp256k1_musig_partial_sig_parse(context, native, bytes) === 1
    )
    ? native
    : null;
}

function serializePartialSignature(native: Uint8Array): Uint8Array {
  const symbols = requireCapability('musig');
  const bytes = new Uint8Array(PARTIAL_SIGNATURE_BYTES);
  const valid = withStaticContext((context) =>
    symbols.secp256k1_musig_partial_sig_serialize(context, bytes, native) === 1
  );
  if (!valid) throw new MuSigNativeError('partial-signature-serialize');
  return bytes;
}

function verifyNativePartial(
  partial: Uint8Array,
  publicNonce: MuSigPublicNonce,
  publicKey: CompressedPublicKey,
  cache: Uint8Array,
  session: Uint8Array,
): boolean {
  const symbols = requireCapability('musig');
  const nativeNonce = requirePublicNonce(publicNonce);
  const nativeKey = nativePublicKey(publicKey.toPublicKey());
  return withStaticContext((context) =>
    symbols.secp256k1_musig_partial_sig_verify(
      context,
      partial,
      nativeNonce,
      nativeKey,
      cache,
      session,
    ) === 1
  );
}

function serializeCompressedPublicKey(
  native: Uint8Array,
): CompressedPublicKey {
  const symbols = getNativeSymbols();
  const bytes = new Uint8Array(33);
  const length = new BigUint64Array([33n]);
  const valid = withStaticContext((context) =>
    symbols.secp256k1_ec_pubkey_serialize(
      context,
      bytes,
      length,
      native,
      EC_COMPRESSED,
    ) === 1
  );
  if (!valid || length[0] !== 33n) {
    throw new MuSigNativeError('public-key-serialize');
  }
  return CompressedPublicKey.parse(bytes);
}

function serializeXOnlyPublicKey(native: Uint8Array): XOnlyPublicKey {
  const symbols = requireCapability('extrakeys');
  const bytes = new Uint8Array(32);
  const valid = withStaticContext((context) =>
    symbols.secp256k1_xonly_pubkey_serialize(context, bytes, native) === 1
  );
  if (!valid) throw new MuSigNativeError('x-only-public-key-serialize');
  return XOnlyPublicKey.parse(bytes);
}

function exportSecretKey(secretKey: MuSigSigningKey): Uint8Array {
  let exported: Uint8Array;
  try {
    exported = secretKey.exportBytes();
  } catch (cause) {
    throw new MuSigStateError(
      'invalid-secret-key',
      'Unable to export MuSig2 signing key',
      { cause },
    );
  }
  const secret = copyExact(exported, 32);
  exported.fill(0);
  if (secret === null) {
    throw new MuSigStateError(
      'invalid-secret-key',
      'MuSig2 signing key must export exactly 32 bytes',
    );
  }
  try {
    const symbols = getNativeSymbols();
    const valid = withStaticContext((context) =>
      symbols.secp256k1_ec_seckey_verify(context, secret) === 1
    );
    if (!valid) {
      throw new MuSigStateError(
        'invalid-secret-key',
        'MuSig2 signing key is not a valid secp256k1 scalar',
      );
    }
    return secret;
  } catch (cause) {
    secret.fill(0);
    throw cause;
  }
}

function deriveKeypair(secret: Uint8Array): {
  keypair: Uint8Array;
  nativePublicKey: Uint8Array;
  compressedPublicKey: Uint8Array;
} {
  const symbols = requireCapability('extrakeys');
  const keypair = new Uint8Array(KEYPAIR_SIZE);
  const nativeKey = new Uint8Array(PUBLIC_KEY_SIZE);
  try {
    withSigningContext((context) => {
      if (
        symbols.secp256k1_keypair_create(context, keypair, secret) !== 1 ||
        symbols.secp256k1_keypair_pub(context, nativeKey, keypair) !== 1
      ) {
        throw new MuSigNativeError('keypair-create');
      }
    });
    return {
      keypair,
      nativePublicKey: nativeKey,
      compressedPublicKey: serializeCompressedPublicKey(nativeKey).toBytes(),
    };
  } catch (cause) {
    keypair.fill(0);
    throw cause;
  }
}

function taggedHash(tag: string, message: Uint8Array): Uint8Array {
  const symbols = getNativeSymbols();
  const output = new Uint8Array(32);
  const tagBytes = new TextEncoder().encode(tag);
  const valid = withStaticContext((context) =>
    symbols.secp256k1_tagged_sha256(
      context,
      output,
      tagBytes,
      BigInt(tagBytes.length),
      message,
      BigInt(message.length),
    ) === 1
  );
  if (!valid) throw new MuSigNativeError('tagged-hash');
  return output;
}

function participantBinding(participantIndex: number): Uint8Array {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, BigInt(participantIndex), false);
  return taggedHash('DenoMuSig/participant', bytes);
}

function pointerArray(buffers: readonly Uint8Array[]): BigUint64Array {
  return new BigUint64Array(
    buffers.map((buffer) => {
      const pointer = Deno.UnsafePointer.of(buffer);
      if (pointer === null) throw new MuSigNativeError('pointer-array');
      return BigInt(Deno.UnsafePointer.value(pointer));
    }),
  );
}

function orderIndexed<T extends { readonly participantIndex: number }>(
  entries: readonly T[],
  participantCount: number,
  valueName: string,
): T[] {
  if (entries.length === 0) {
    throw new MuSigStateError(
      'empty-participants',
      `MuSig2 ${valueName} set must not be empty`,
    );
  }
  const ordered = new Array<T | undefined>(participantCount);
  for (const entry of entries) {
    if (
      !Number.isSafeInteger(entry.participantIndex) ||
      entry.participantIndex < 0
    ) {
      throw new MuSigStateError(
        'invalid-participant-index',
        `Invalid MuSig2 ${valueName} participant index`,
      );
    }
    if (entry.participantIndex >= participantCount) {
      throw new MuSigStateError(
        'extra-participant-index',
        `Extra MuSig2 ${valueName} participant index ${entry.participantIndex}`,
      );
    }
    if (ordered[entry.participantIndex] !== undefined) {
      throw new MuSigStateError(
        'duplicate-participant-index',
        `Duplicate MuSig2 ${valueName} participant index ${entry.participantIndex}`,
      );
    }
    ordered[entry.participantIndex] = entry;
  }
  for (let index = 0; index < ordered.length; index++) {
    if (ordered[index] === undefined) {
      throw new MuSigStateError(
        'missing-participant-index',
        `Missing MuSig2 ${valueName} participant index ${index}`,
      );
    }
  }
  return ordered as T[];
}

function assertParticipantIndex(index: number, count: number): void {
  if (!Number.isSafeInteger(index) || index < 0) {
    throw new MuSigStateError(
      'invalid-participant-index',
      'MuSig2 participant index must be a non-negative safe integer',
    );
  }
  if (index >= count) {
    throw new MuSigStateError(
      'extra-participant-index',
      `MuSig2 participant index ${index} is outside this aggregation`,
    );
  }
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index++) {
    difference |= left[index] ^ right[index];
  }
  return difference === 0;
}

function compareBytes(left: Uint8Array, right: Uint8Array): number {
  for (let index = 0; index < Math.min(left.length, right.length); index++) {
    if (left[index] !== right[index]) return left[index] - right[index];
  }
  return left.length - right.length;
}

function concatenate(left: Uint8Array, right: Uint8Array): Uint8Array {
  const output = new Uint8Array(left.length + right.length);
  output.set(left);
  output.set(right, left.length);
  return output;
}
