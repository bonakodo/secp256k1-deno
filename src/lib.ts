/**
 * Legacy version 0.5.3 mutable-buffer API.
 *
 * This compatibility entrypoint preserves historical loading, mutation, and
 * exception behavior. New Bitcoin node code should use the typed version 1
 * entrypoints, which validate peer input and model secret ownership explicitly.
 *
 * @deprecated Migrate to `jsr:@bonakodo/secp256k1` and its typed subpaths.
 * @module
 * @since 1.0.0
 */

import * as secp256k1 from './ffi.ts';
import { assert3365, assertLength } from './assertLength.ts';

const SECP256K1_EC_COMPRESSED = 258;
const SECP256K1_EC_UNCOMPRESSED = 2;
const context = secp256k1.secp256k1_context_create(769); // SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY
const randomize = new Uint8Array(32);
crypto.getRandomValues(randomize);
assertNative(
  secp256k1.secp256k1_context_randomize(context, randomize),
  'Could not randomize secp256k1 context',
);

function assertNative(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

/**
 * Re-randomizes the retained legacy native context.
 *
 * @param seed Exactly 32 caller-owned bytes, or `null`; never mutated.
 * @throws If the length is wrong or native randomization fails.
 * @deprecated Prefer version 1 operations, which manage contexts internally.
 * @since 1.0.0
 */
export function contextRandomize(seed: Uint8Array | null): void {
  if (seed !== null) {
    assertLength(32, seed);
  }
  assertNative(
    secp256k1.secp256k1_context_randomize(context, seed),
    'Could not randomize secp256k1 context',
  );
}

/* Secret key functions */
/**
 * Validates a 32-byte secp256k1 secret scalar.
 *
 * @param secretKey Exactly 32 caller-owned bytes; never mutated.
 * @returns Whether the scalar is in `1..n-1`.
 * @throws If the byte length is not 32.
 * @deprecated Use `SecretKey.fromBytes` from the signing entrypoint.
 * @since 1.0.0
 */
export function secretKeyVerify(secretKey: Uint8Array): boolean {
  assertLength(32, secretKey);
  return secp256k1.secp256k1_ec_seckey_verify(context, secretKey);
}

/**
 * Negates a secret scalar in the caller's 32-byte buffer.
 *
 * @param secretKey Mutable 32-byte scalar, modified in place.
 * @returns Whether native negation succeeded.
 * @throws If the byte length is not 32.
 * @deprecated Use typed version 1 key operations.
 * @since 1.0.0
 */
export function secretKeyNegate(secretKey: Uint8Array): boolean {
  assertLength(32, secretKey);
  return secp256k1.secp256k1_ec_seckey_negate(context, secretKey);
}

/**
 * Adds a scalar tweak to a secret key in place.
 *
 * @param secretKey Mutable 32-byte secret scalar.
 * @param tweak Caller-owned 32-byte big-endian scalar.
 * @returns Whether the resulting scalar is valid.
 * @throws If either byte length is not 32.
 * @deprecated Use `addTweakToSecretKey` and `Tweak32`.
 * @since 1.0.0
 */
export function secretKeyTweakAdd(
  secretKey: Uint8Array,
  tweak: Uint8Array,
): boolean {
  assertLength(32, secretKey, tweak);
  return secp256k1.secp256k1_ec_seckey_tweak_add(context, secretKey, tweak);
}

/**
 * Multiplies a secret key by a scalar tweak in place.
 *
 * @param secretKey Mutable 32-byte secret scalar.
 * @param tweak Caller-owned 32-byte big-endian scalar.
 * @returns Whether the resulting scalar is valid.
 * @throws If either byte length is not 32.
 * @deprecated Multiplicative tweaks are intentionally absent from version 1.
 * @since 1.0.0
 */
export function secretKeyTweakMul(
  secretKey: Uint8Array,
  tweak: Uint8Array,
): boolean {
  assertLength(32, secretKey, tweak);
  return secp256k1.secp256k1_ec_seckey_tweak_mul(context, secretKey, tweak);
}

/* Public key functions */
function publicKeyParse(publicKey: Uint8Array): Uint8Array {
  assert3365(publicKey);
  const output = new Uint8Array(64);
  const parseResult = secp256k1.secp256k1_ec_pubkey_parse(
    context,
    output,
    publicKey,
    BigInt(publicKey.length),
  );
  if (!parseResult) throw new Error('Invalid public key format');
  return output;
}

function publicKeySerialize(
  parsedPublicKey: Uint8Array,
  compressed = true,
): Uint8Array {
  assertLength(64, parsedPublicKey);
  let outputLength, flags;
  if (compressed) {
    outputLength = 33;
    flags = SECP256K1_EC_COMPRESSED;
  } else {
    outputLength = 65;
    flags = SECP256K1_EC_UNCOMPRESSED;
  }
  const output = new Uint8Array(outputLength);
  const serializeResult = secp256k1.secp256k1_ec_pubkey_serialize(
    context,
    output,
    outputLength,
    parsedPublicKey,
    flags,
  );
  assertNative(serializeResult, 'Could not serialize public key');
  return output;
}

/**
 * Checks a serialized compressed or uncompressed SEC public key.
 *
 * @param publicKey Caller-owned 33- or 65-byte encoding; never mutated.
 * @returns `false` for malformed length, encoding, or curve points.
 * @deprecated Use `PublicKey.tryParse`.
 * @since 1.0.0
 */
export function publicKeyVerify(publicKey: Uint8Array): boolean {
  try {
    publicKeyParse(publicKey);
    return true;
  } catch (_e) {
    return false;
  }
}
/**
 * Derives a serialized public key from a secret scalar.
 *
 * @param secretKey Exactly 32 caller-owned secret bytes.
 * @param compressed Whether to return 33 bytes instead of 65 bytes.
 * @returns A newly allocated SEC public-key encoding.
 * @throws For wrong lengths, invalid scalars, or native failure.
 * @deprecated Use `SecretKey.publicKey`.
 * @since 1.0.0
 */
export function publicKeyCreate(
  secretKey: Uint8Array,
  compressed = true,
): Uint8Array {
  assertLength(32, secretKey);
  const publicKey = new Uint8Array(64);
  const createResult = secp256k1.secp256k1_ec_pubkey_create(
    context,
    publicKey,
    secretKey,
  );
  assertNative(createResult, 'Could not create a public key');
  return publicKeySerialize(publicKey, compressed);
}
/**
 * Re-serializes a valid SEC public key.
 *
 * @param publicKey Caller-owned 33- or 65-byte SEC encoding.
 * @param compressed Whether to return 33 bytes instead of 65 bytes.
 * @returns A newly allocated canonical encoding.
 * @throws If parsing or serialization fails.
 * @deprecated Use `PublicKey` serialization methods.
 * @since 1.0.0
 */
export function publicKeyConvert(
  publicKey: Uint8Array,
  compressed = true,
): Uint8Array {
  const parsed = publicKeyParse(publicKey);
  return publicKeySerialize(parsed, compressed);
}

/**
 * Negates a serialized public point without mutating the input.
 *
 * @param publicKey Caller-owned 33- or 65-byte SEC encoding.
 * @param compressed Whether to return 33 bytes instead of 65 bytes.
 * @returns A newly allocated SEC encoding of the negated point.
 * @throws If parsing, negation, or serialization fails.
 * @deprecated Use typed version 1 key operations.
 * @since 1.0.0
 */
export function publicKeyNegate(
  publicKey: Uint8Array,
  compressed = true,
): Uint8Array {
  const parsed = publicKeyParse(publicKey);
  const negateResult = secp256k1.secp256k1_ec_pubkey_negate(context, parsed); // mutates `parsed`
  assertNative(negateResult, 'Failed to negate the public key');
  return publicKeySerialize(parsed, compressed);
}

/**
 * Adds serialized public points.
 *
 * @param publicKeys Caller-owned SEC encodings, preserved in caller order.
 * @param compressed Whether to return 33 bytes instead of 65 bytes.
 * @returns A newly allocated SEC encoding of the sum.
 * @throws For unsupported architectures, invalid keys, infinity, or FFI failure.
 * @deprecated Use the protocol-specific version 1 APIs.
 * @since 1.0.0
 */
export function publicKeyCombine(
  publicKeys: Uint8Array[],
  compressed = true,
): Uint8Array {
  // Fail if the architecture is not 64-bit as we pass 64-bit pointers array
  const arch = Deno.build.arch;
  if (arch !== 'aarch64' && arch !== 'x86_64') {
    throw new Error('32 bit architectures are not currently supported');
  }

  const parsedKeys = publicKeys.map(publicKeyParse);
  const pointers = new BigUint64Array(
    parsedKeys.map((pk) =>
      BigInt(Deno.UnsafePointer.value(Deno.UnsafePointer.of(pk)))
    ),
  );

  const result = new Uint8Array(64);
  const combineResult = secp256k1.secp256k1_ec_pubkey_combine(
    context,
    result,
    pointers,
    BigInt(publicKeys.length),
  );
  assertNative(combineResult, 'Could not combine keys');
  return publicKeySerialize(result, compressed);
}
/**
 * Adds `tweak * G` to a public key without mutating caller buffers.
 *
 * @param publicKey Caller-owned 33- or 65-byte SEC encoding.
 * @param tweak Caller-owned 32-byte big-endian scalar.
 * @param compressed Whether to return 33 bytes instead of 65 bytes.
 * @returns A newly allocated SEC encoding of the result.
 * @throws If input parsing or native arithmetic fails.
 * @deprecated Use `addTweakToPublicKey` and `Tweak32`.
 * @since 1.0.0
 */
export function publicKeyTweakAdd(
  publicKey: Uint8Array,
  tweak: Uint8Array,
  compressed = true,
): Uint8Array {
  const parsed = publicKeyParse(publicKey);
  const addResult = secp256k1.secp256k1_ec_pubkey_tweak_add(
    context,
    parsed, // mutates `parsed`
    tweak,
  );
  assertNative(addResult, 'Could not add the tweak to the public key');
  return publicKeySerialize(parsed, compressed);
}

/**
 * Multiplies a public point by a scalar tweak.
 *
 * @param publicKey Caller-owned 33- or 65-byte SEC encoding.
 * @param tweak Caller-owned 32-byte big-endian scalar.
 * @param compressed Whether to return 33 bytes instead of 65 bytes.
 * @returns A newly allocated SEC encoding of the result.
 * @throws If input parsing or native arithmetic fails.
 * @deprecated Multiplicative tweaks are intentionally absent from version 1.
 * @since 1.0.0
 */
export function publicKeyTweakMul(
  publicKey: Uint8Array,
  tweak: Uint8Array,
  compressed = true,
): Uint8Array {
  const parsed = publicKeyParse(publicKey);
  const mulResult = secp256k1.secp256k1_ec_pubkey_tweak_mul(
    context,
    parsed, // mutates `parsed`
    tweak,
  );
  assertNative(mulResult, 'Could not multiply the public key by the tweak');
  return publicKeySerialize(parsed, compressed);
}

/* Signature functions */

/**
 * Legacy alias for a mutable 64-byte compact ECDSA signature.
 *
 * @deprecated Use `EcdsaCompactSignature` or `EcdsaSignature`.
 * @since 1.0.0
 */
export type CompactSignature = Uint8Array;
/**
 * Normalizes a compact ECDSA signature in place.
 *
 * @param signature Mutable 64-byte `R || S` buffer.
 * @returns The same buffer after low-S normalization.
 * @throws If length, scalar parsing, or serialization fails.
 * @deprecated Use `EcdsaSignature.normalize`.
 * @since 1.0.0
 */
export function signatureNormalize(signature: CompactSignature): Uint8Array {
  assertLength(64, signature);
  const parsedSignature = new Uint8Array(64);
  const parseResult = secp256k1.secp256k1_ecdsa_signature_parse_compact(
    context,
    parsedSignature,
    signature,
  );
  assertNative(parseResult, 'Could not parse the compact signature');
  const normalizedSignature = new Uint8Array(64);
  secp256k1.secp256k1_ecdsa_signature_normalize(
    context,
    normalizedSignature,
    parsedSignature,
  );
  const serializeResult = secp256k1.secp256k1_ecdsa_signature_serialize_compact(
    context,
    signature,
    normalizedSignature,
  );
  assertNative(
    serializeResult,
    'Could not serialize the signature to the compact format',
  );
  return signature;
}

/**
 * Serializes a compact ECDSA signature as strict DER.
 *
 * @param signature Caller-owned 64-byte `R || S` signature.
 * @returns A newly allocated DER encoding without a sighash-type byte.
 * @throws If parsing or serialization fails.
 * @deprecated Use `EcdsaSignature.toDer`.
 * @since 1.0.0
 */
export function signatureExport(signature: CompactSignature): Uint8Array {
  const parsedSignature = new Uint8Array(64);
  const parseResult = secp256k1.secp256k1_ecdsa_signature_parse_compact(
    context,
    parsedSignature,
    signature,
  );
  assertNative(parseResult, 'Could not parse the signature');
  const result = new Uint8Array(72);
  const resultLength = new BigUint64Array([72n]); // size_t is 64 bits
  const serializeResult = secp256k1.secp256k1_ecdsa_signature_serialize_der(
    context,
    result,
    resultLength,
    parsedSignature,
  );
  assertNative(
    serializeResult,
    'Could not serialize the signature to the DER format',
  );
  return result.slice(0, Number(resultLength[0]));
}

/**
 * Legacy alias for mutable DER-encoded ECDSA bytes.
 *
 * @deprecated Use `EcdsaDerSignature`.
 * @since 1.0.0
 */
export type DerSignature = Uint8Array;
/**
 * Parses DER ECDSA bytes into compact form.
 *
 * @param signature Caller-owned DER bytes without a sighash-type byte.
 * @returns A newly allocated 64-byte compact signature.
 * @throws If native DER parsing or serialization fails.
 * @deprecated Use `EcdsaDerSignature.fromBytes(signature).decode()`.
 * @since 1.0.0
 */
export function signatureImport(signature: DerSignature): CompactSignature {
  const parsedSignature = new Uint8Array(64);
  const parseResult = secp256k1.secp256k1_ecdsa_signature_parse_der(
    context,
    parsedSignature,
    signature,
    signature.length,
  );
  assertNative(parseResult, 'Could not parse the signature in DER format');
  const result = new Uint8Array(64);
  const serializeResult = secp256k1.secp256k1_ecdsa_signature_serialize_compact(
    context,
    result,
    parsedSignature,
  );
  assertNative(serializeResult, 'Could not serialize signature');
  return result;
}

/**
 * Signs a 32-byte digest with deterministic legacy ECDSA.
 *
 * @param messageHash Exactly 32 caller-owned digest bytes.
 * @param secretKey Exactly 32 caller-owned secret bytes.
 * @returns A newly allocated 64-byte low-S compact signature.
 * @throws For wrong lengths, invalid keys, or native failure.
 * @deprecated Use `signEcdsa` with `Digest32` and `SecretKey`.
 * @since 1.0.0
 */
export function ecdsaSign(
  messageHash: Uint8Array,
  secretKey: Uint8Array,
): CompactSignature {
  assertLength(32, secretKey, messageHash);
  const signature = new Uint8Array(64);
  const signResult = secp256k1.secp256k1_ecdsa_sign(
    context,
    signature,
    messageHash,
    secretKey,
    null,
    null,
  );
  assertNative(signResult, 'Could not sign the message');
  const result = new Uint8Array(64);
  const serializeResult = secp256k1.secp256k1_ecdsa_signature_serialize_compact(
    context,
    result,
    signature,
  );
  assertNative(serializeResult, 'Could not serialize signature');
  return result;
}

/**
 * Creates a recoverable ECDSA compact signature.
 *
 * @param messageHash Exactly 32 caller-owned digest bytes.
 * @param secretKey Exactly 32 caller-owned secret bytes.
 * @returns New signature bytes and a recovery id in `0..3`.
 * @throws For wrong lengths, invalid keys, or native failure.
 * @deprecated Recovery conventions are outside the Bitcoin-node version 1 API.
 * @since 1.0.0
 */
export function ecdsaSignRecoverable(
  messageHash: Uint8Array,
  secretKey: Uint8Array,
): { signature: CompactSignature; recid: number } {
  assertLength(32, secretKey, messageHash);
  const recoverableSignature = new Uint8Array(65);
  const signResult = secp256k1.secp256k1_ecdsa_sign_recoverable(
    context,
    recoverableSignature,
    messageHash,
    secretKey,
    null,
    null,
  );
  assertNative(signResult, 'Could not sign the message');

  const signature = new Uint8Array(64);
  const recid = new Uint8Array(4);
  const serializeResult = secp256k1
    .secp256k1_ecdsa_recoverable_signature_serialize_compact(
      context,
      signature,
      recid,
      recoverableSignature,
    );
  assertNative(serializeResult, 'Could not serialize signature');
  return {
    signature,
    recid: new DataView(recid.buffer).getInt32(0, true),
  };
}

/**
 * Verifies a compact ECDSA signature using legacy exception semantics.
 *
 * @param signature Caller-owned 64-byte compact signature.
 * @param messageHash Exactly 32 caller-owned digest bytes.
 * @param publicKey Caller-owned 33- or 65-byte SEC public key.
 * @returns Whether the ECDSA equation verifies.
 * @throws For malformed lengths, encodings, scalars, or native failure.
 * @deprecated Use typed parsers and `verifyEcdsa`.
 * @since 1.0.0
 */
export function ecdsaVerify(
  signature: CompactSignature,
  messageHash: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  assertLength(32, messageHash);
  assert3365(publicKey);
  const parsedSignature = new Uint8Array(64);
  const signatureParseResult = secp256k1
    .secp256k1_ecdsa_signature_parse_compact(
      context,
      parsedSignature,
      signature,
    );
  assertNative(signatureParseResult, 'Could not parse compact signature');
  const parsedPublicKey = new Uint8Array(64);
  const pubkeyParseResult = secp256k1.secp256k1_ec_pubkey_parse(
    context,
    parsedPublicKey,
    publicKey,
    BigInt(publicKey.length),
  );
  assertNative(pubkeyParseResult, 'Could not parse the public key');
  return secp256k1.secp256k1_ecdsa_verify(
    context,
    parsedSignature,
    messageHash,
    parsedPublicKey,
  );
}

/**
 * Recovers a public key from a compact ECDSA signature.
 *
 * @param signature Caller-owned 64-byte compact signature.
 * @param recid Recovery id in `0..3`.
 * @param messageHash Exactly 32 caller-owned digest bytes.
 * @param compressed Whether to return 33 bytes instead of 65 bytes.
 * @returns A newly allocated recovered SEC public key.
 * @throws For malformed input or native recovery failure.
 * @deprecated Recovery conventions are outside the Bitcoin-node version 1 API.
 * @since 1.0.0
 */
export function ecdsaRecover(
  signature: CompactSignature,
  recid: number,
  messageHash: Uint8Array,
  compressed = true,
): Uint8Array {
  assertLength(64, signature);
  assertLength(32, messageHash);
  if (!Number.isInteger(recid) || recid < 0 || recid > 3) {
    throw new Error('The recovery id must be an integer between 0 and 3');
  }

  const recoverableSignature = new Uint8Array(65);
  const parseResult = secp256k1
    .secp256k1_ecdsa_recoverable_signature_parse_compact(
      context,
      recoverableSignature,
      signature,
      recid,
    );
  assertNative(parseResult, 'Could not parse the recoverable signature');

  const publicKey = new Uint8Array(64);
  const recoverResult = secp256k1.secp256k1_ecdsa_recover(
    context,
    publicKey,
    recoverableSignature,
    messageHash,
  );
  assertNative(recoverResult, 'Could not recover the public key');
  return publicKeySerialize(publicKey, compressed);
}

/**
 * Computes the legacy libsecp256k1 ECDH hash output.
 *
 * @param publicKey Caller-owned 33- or 65-byte SEC public key.
 * @param secretKey Exactly 32 caller-owned secret bytes.
 * @returns A newly allocated 32-byte shared-secret hash.
 * @throws For malformed keys or native ECDH failure.
 * @deprecated Use the BIP324 entrypoint for Bitcoin transport key exchange.
 * @since 1.0.0
 */
export function ecdh(
  publicKey: Uint8Array,
  secretKey: Uint8Array,
): Uint8Array {
  const parsedPublicKey = publicKeyParse(publicKey);
  assertLength(32, secretKey);
  const output = new Uint8Array(32);
  const ecdhResult = secp256k1.secp256k1_ecdh(
    context,
    output,
    parsedPublicKey,
    secretKey,
    null,
    null,
  );
  assertNative(ecdhResult, 'Could not compute the ECDH shared secret');
  return output;
}

/**
 * Legacy alias for libsecp256k1's opaque 64-byte x-only key representation.
 *
 * @deprecated Use `XOnlyPublicKey`, which serializes as 32 bytes.
 * @since 1.0.0
 */
export type XOnlyPubkey = Uint8Array;

/**
 * Creates an opaque 96-byte native keypair representation.
 *
 * @param secretKey Exactly 32 caller-owned secret bytes.
 * @returns A newly allocated opaque keypair buffer containing secret material.
 * @throws For wrong length, invalid scalar, or native failure.
 * @deprecated Use `SecretKey`; do not persist opaque native structures.
 * @since 1.0.0
 */
export function keypairCreate(secretKey: Uint8Array): Uint8Array {
  assertLength(32, secretKey);
  const keypair = new Uint8Array(96);
  const createResult = secp256k1.secp256k1_keypair_create(
    context,
    keypair,
    secretKey,
  );
  assertNative(createResult, 'Could not create a key pair from the secret key');
  return keypair;
}

/**
 * Computes libsecp256k1 tagged SHA-256 over arbitrary bytes.
 *
 * @param message UTF-8 text or caller-owned message bytes.
 * @param tag UTF-8 text or caller-owned tag bytes.
 * @returns A newly allocated 32-byte digest.
 * @throws If native hashing fails.
 * @deprecated Version 1 derives protocol-specific tags internally.
 * @since 1.0.0
 */
export function taggedSha256(
  message: string | Uint8Array,
  tag: string | Uint8Array,
): Uint8Array {
  if (typeof message === 'string') {
    message = new Uint8Array(new TextEncoder().encode(message));
  }
  if (typeof tag === 'string') {
    tag = new Uint8Array(new TextEncoder().encode(tag));
  }
  const hash = new Uint8Array(32);
  const hashResult = secp256k1.secp256k1_tagged_sha256(
    context,
    hash,
    tag,
    BigInt(tag.length),
    message,
    BigInt(message.length),
  );
  assertNative(hashResult, 'Could not calculate the tagged SHA256 hash');
  return hash;
}

/**
 * Parses serialized x-only bytes into an opaque native representation.
 *
 * @param compressedPublicKey Exactly 32 caller-owned x-coordinate bytes.
 * @returns A newly allocated opaque 64-byte native representation.
 * @throws For wrong length, invalid point, or native failure.
 * @deprecated Use `XOnlyPublicKey.parse`.
 * @since 1.0.0
 */
export function convertToXOnlyPublicKey(
  compressedPublicKey: Uint8Array,
): XOnlyPubkey {
  assertLength(32, compressedPublicKey);
  const xOnlyPublicKey: XOnlyPubkey = new Uint8Array(64);
  const parseResult = secp256k1.secp256k1_xonly_pubkey_parse(
    context,
    xOnlyPublicKey,
    compressedPublicKey,
  );
  assertNative(
    parseResult,
    'Could not convert the serialized public key to x-only public key',
  );
  return xOnlyPublicKey;
}

/**
 * Derives an opaque native x-only public key from a secret.
 *
 * @param secretKey Exactly 32 caller-owned secret bytes.
 * @returns A newly allocated opaque 64-byte native representation.
 * @throws For wrong length, invalid scalar, or native failure.
 * @deprecated Use `SecretKey.xOnlyPublicKey`.
 * @since 1.0.0
 */
export function createXOnlyPublicKey(secretKey: Uint8Array): XOnlyPubkey {
  assertLength(32, secretKey);
  const keypair = new Uint8Array(96);
  const createResult = secp256k1.secp256k1_keypair_create(
    context,
    keypair,
    secretKey,
  );
  assertNative(createResult, 'Could not create a key pair from the secret key');
  const xOnlyPublicKey = new Uint8Array(64);
  const xOnlyResult = secp256k1.secp256k1_keypair_xonly_pub(
    context,
    xOnlyPublicKey,
    null,
    keypair,
  );
  assertNative(xOnlyResult, 'Could not create a key pair from the secret key');
  return xOnlyPublicKey;
}

/**
 * Signs a 32-byte digest with the legacy BIP340 API.
 *
 * @param messageHash Exactly 32 caller-owned digest bytes.
 * @param secretKey Exactly 32 caller-owned secret bytes.
 * @param auxiliaryRandom Optional 32-byte auxiliary randomness.
 * @returns A newly allocated 64-byte Schnorr signature.
 * @throws For wrong lengths, invalid keys, randomness failure, or native failure.
 * @deprecated Use `signTaprootSignature`, which post-verifies its result.
 * @since 1.0.0
 */
export function schnorrSign(
  messageHash: Uint8Array,
  secretKey: Uint8Array,
  auxiliaryRandom?: Uint8Array,
): Uint8Array {
  assertLength(32, messageHash);
  assertLength(32, secretKey);
  if (auxiliaryRandom) {
    assertLength(32, auxiliaryRandom);
  } else {
    auxiliaryRandom = new Uint8Array(32);
    crypto.getRandomValues(auxiliaryRandom);
  }
  const keypair = new Uint8Array(96);
  const keypairCreateResult = secp256k1.secp256k1_keypair_create(
    context,
    keypair,
    secretKey,
  );
  assertNative(
    keypairCreateResult,
    'Could not create a keypair from the secret key',
  );

  const signature = new Uint8Array(64);
  const signResult = secp256k1.secp256k1_schnorrsig_sign32(
    context,
    signature,
    messageHash,
    keypair,
    auxiliaryRandom,
  );
  assertNative(signResult, 'Could not sign with Schnorr');
  return signature;
}

/**
 * Verifies a legacy BIP340 signature over a 32-byte digest.
 *
 * @param signature Caller-owned 64-byte Schnorr signature.
 * @param messageHash Exactly 32 caller-owned digest bytes.
 * @param xOnlyPublicKey Opaque 64-byte native x-only key representation.
 * @returns Whether the BIP340 equation verifies.
 * @throws For wrong lengths or native failure.
 * @deprecated Use `verifyTaprootSignature` and `XOnlyPublicKey`.
 * @since 1.0.0
 */
export function schnorrVerify(
  signature: Uint8Array,
  messageHash: Uint8Array,
  xOnlyPublicKey: XOnlyPubkey,
): boolean {
  assertLength(32, messageHash);
  assertLength(64, signature);
  assertLength(64, xOnlyPublicKey);
  return secp256k1.secp256k1_schnorrsig_verify(
    context,
    signature,
    messageHash,
    32n,
    xOnlyPublicKey,
  );
}
