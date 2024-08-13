import * as secp256k1 from './ffi.ts';
import { assert3365, assertLength } from './assertLength.ts';

const SECP256K1_EC_COMPRESSED = 258;
const SECP256K1_EC_UNCOMPRESSED = 2;
const context = secp256k1.secp256k1_context_create(769); // SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY
const randomize = new Uint8Array(32);
crypto.getRandomValues(randomize);
if (!secp256k1.secp256k1_context_randomize(context, randomize)) {
  throw new Error('Could not randomize secp256k1 context');
}

/* Secret key functions */
export function secretKeyVerify(secretKey: Uint8Array): boolean {
  assertLength(32, secretKey);
  return secp256k1.secp256k1_ec_seckey_verify(context, secretKey);
}

export function secretKeyNegate(secretKey: Uint8Array): boolean {
  assertLength(32, secretKey);
  return secp256k1.secp256k1_ec_seckey_negate(context, secretKey);
}

export function secretKeyTweakAdd(
  secretKey: Uint8Array,
  tweak: Uint8Array,
): boolean {
  assertLength(32, secretKey, tweak);
  return secp256k1.secp256k1_ec_seckey_tweak_add(context, secretKey, tweak);
}

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
  if (!serializeResult) throw new Error('Could not serialize public key');
  return output;
}

export function publicKeyVerify(publicKey: Uint8Array): boolean {
  try {
    publicKeyParse(publicKey);
    return true;
  } catch (_e) {
    return false;
  }
}
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
  if (!createResult) throw new Error('Could not create a public key');
  return publicKeySerialize(publicKey, compressed);
}
export function publicKeyConvert(
  publicKey: Uint8Array,
  compressed = true,
): Uint8Array {
  const parsed = publicKeyParse(publicKey);
  return publicKeySerialize(parsed, compressed);
}

export function publicKeyNegate(publicKey: Uint8Array): Uint8Array {
  const parsed = publicKeyParse(publicKey);
  const negateResult = secp256k1.secp256k1_ec_pubkey_negate(context, parsed); // mutates `parsed`
  if (!negateResult) throw new Error('Failed to negate the public key');
  return parsed;
}

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
  if (!combineResult) throw new Error('Could not combine keys');
  return publicKeySerialize(result, compressed);
}
/**
 * Tweak a public key by adding tweak times the generator to it.
 */
export function publicKeyTweakAdd(
  publicKey: Uint8Array,
  tweak: Uint8Array,
  compressed = true,
) {
  const parsed = publicKeyParse(publicKey);
  const addResult = secp256k1.secp256k1_ec_pubkey_tweak_add(
    context,
    parsed, // mutates `parsed`
    tweak,
  );
  if (!addResult) throw new Error('Could not add the tweak to the public key');
  return publicKeySerialize(parsed, compressed);
}

/**
 * Tweak a public key by multiplying it by a tweak value.
 */
export function publicKeyTweakMul(
  publicKey: Uint8Array,
  tweak: Uint8Array,
  compressed = true,
) {
  const parsed = publicKeyParse(publicKey);
  const mulResult = secp256k1.secp256k1_ec_pubkey_tweak_mul(
    context,
    parsed, // mutates `parsed`
    tweak,
  );
  if (!mulResult) {
    throw new Error('Could not multiply the public key by the tweak');
  }
  return publicKeySerialize(parsed, compressed);
}

/* Signature functions */

export type CompactSignature = Uint8Array;
/**
 * Normalizes signature in place
 * @param signature mutable signature parameter
 */
export function signatureNormalize(signature: CompactSignature): Uint8Array {
  assertLength(64, signature);
  const parsedSignature = new Uint8Array(64);
  const parseResult = secp256k1.secp256k1_ecdsa_signature_parse_compact(
    context,
    parsedSignature,
    signature,
  );
  if (!parseResult) throw new Error('Could not parse the compact signature');
  const normalizedSignature = new Uint8Array(64);
  const normalizeResult = secp256k1.secp256k1_ecdsa_signature_normalize(
    context,
    normalizedSignature,
    parsedSignature,
  );
  if (!normalizeResult) throw new Error('Could not normalize the signature');
  const serializeResult = secp256k1.secp256k1_ecdsa_signature_serialize_compact(
    context,
    signature,
    normalizedSignature,
  );
  if (!serializeResult) {
    throw new Error('Could not serialize the signature to the compact format');
  }
  return signature;
}

/**
 * Export an ECDSA signature to DER format.
 * @param signature
 */
export function signatureExport(signature: CompactSignature): Uint8Array {
  const parsedSignature = new Uint8Array(64);
  const parseResult = secp256k1.secp256k1_ecdsa_signature_parse_compact(
    context,
    parsedSignature,
    signature,
  );
  if (!parseResult) throw new Error('Could not parse the signature');
  const result = new Uint8Array(72);
  const resultLength = new BigUint64Array([72n]); // size_t is 64 bits
  const serializeResult = secp256k1.secp256k1_ecdsa_signature_serialize_der(
    context,
    result,
    resultLength,
    parsedSignature,
  );
  if (!serializeResult) {
    throw new Error('Could not serialize the signature to the DER format');
  }
  return result.slice(0, Number(resultLength[0]));
}

export type DerSignature = Uint8Array;
export function signatureImport(signature: DerSignature): CompactSignature {
  const parsedSignature = new Uint8Array(64);
  const parseResult = secp256k1.secp256k1_ecdsa_signature_parse_der(
    context,
    parsedSignature,
    signature,
    signature.length,
  );
  if (!parseResult) {
    throw new Error('Could not parse the signature in DER format');
  }
  const result = new Uint8Array(64);
  const serializeResult = secp256k1.secp256k1_ecdsa_signature_serialize_compact(
    context,
    result,
    parsedSignature,
  );
  if (!serializeResult) throw new Error('Could not serialize signature');
  return result;
}

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
  if (!signResult) throw new Error('Could not sign the message');
  const result = new Uint8Array(64);
  const serializeResult = secp256k1.secp256k1_ecdsa_signature_serialize_compact(
    context,
    result,
    signature,
  );
  if (!serializeResult) throw new Error('Could not serialize signature');
  return result;
}

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
  if (!signatureParseResult) {
    throw new Error('Could not parse compact signature');
  }
  const parsedPublicKey = new Uint8Array(64);
  const pubkeyParseResult = secp256k1.secp256k1_ec_pubkey_parse(
    context,
    parsedPublicKey,
    publicKey,
    BigInt(publicKey.length),
  );
  if (!pubkeyParseResult) throw new Error('Could not parse the public key');
  return secp256k1.secp256k1_ecdsa_verify(
    context,
    parsedSignature,
    messageHash,
    parsedPublicKey,
  );
}

export type XOnlyPubkey = Uint8Array;

export function keypairCreate(secretKey: Uint8Array): Uint8Array {
  assertLength(32, secretKey);
  const keypair = new Uint8Array(96);
  const createResult = secp256k1.secp256k1_keypair_create(
    context,
    keypair,
    secretKey,
  );
  if (!createResult) {
    throw new Error('Could not create a key pair from the secret key');
  }
  return keypair;
}

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
  if (!hashResult) {
    throw new Error('Could not calculate the tagged SHA256 hash');
  }
  return hash;
}

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
  if (!parseResult) {
    throw new Error(
      'Could not convert the serialized public key to x-only public key',
    );
  }
  return xOnlyPublicKey;
}

export function createXOnlyPublicKey(secretKey: Uint8Array): XOnlyPubkey {
  assertLength(32, secretKey);
  const keypair = new Uint8Array(96);
  const createResult = secp256k1.secp256k1_keypair_create(
    context,
    keypair,
    secretKey,
  );
  if (!createResult) {
    throw new Error('Could not create a key pair from the secret key');
  }
  const xOnlyPublicKey = new Uint8Array(64);
  const xOnlyResult = secp256k1.secp256k1_keypair_xonly_pub(
    context,
    xOnlyPublicKey,
    null,
    keypair,
  );
  if (!xOnlyResult) {
    throw new Error('Could not create a key pair from the secret key');
  }
  return xOnlyPublicKey;
}

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
  if (!keypairCreateResult) {
    throw new Error('Could not create a keypair from the secret key');
  }

  const signature = new Uint8Array(64);
  const signResult = secp256k1.secp256k1_schnorrsig_sign32(
    context,
    signature,
    messageHash,
    keypair,
    auxiliaryRandom,
  );
  if (!signResult) throw new Error('Could not sign with Schnorr');
  return signature;
}

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
