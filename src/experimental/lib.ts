import * as secp256k1 from "./ffi.ts";
import { assertLength } from "../assertLength.ts";

const context = secp256k1.secp256k1_context_create(769); // SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY
const randomize = new Uint8Array(32);
crypto.getRandomValues(randomize);
if (!secp256k1.secp256k1_context_randomize(context, randomize)) {
  throw new Error("Could not randomize secp256k1 context");
}

export * from "../lib.ts";

export type XOnlyPubkey = Uint8Array;

export function keypairCreate(secretKey: Uint8Array): Uint8Array {
  assertLength(32, secretKey);
  const keypair = new Uint8Array(96);
  const createResult = secp256k1.secp256k1_keypair_create(
    context,
    keypair,
    secretKey
  );
  if (!createResult) {
    throw new Error("Could not create a key pair from the secret key");
  }
  return keypair;
}

export function taggedSha256(
  message: string | Uint8Array,
  tag: string | Uint8Array
): Uint8Array {
  if (typeof message === "string") {
    message = new Uint8Array(new TextEncoder().encode(message));
  }
  if (typeof tag === "string") {
    tag = new Uint8Array(new TextEncoder().encode(tag));
  }
  const hash = new Uint8Array(32);
  const hashResult = secp256k1.secp256k1_tagged_sha256(
    context,
    hash,
    tag,
    tag.length,
    message,
    message.length
  );
  if (!hashResult) {
    throw new Error("Could not calculate the tagged SHA256 hash");
  }
  return hash;
}

export function convertToXOnlyPublicKey(
  compressedPublicKey: Uint8Array
): XOnlyPubkey {
  assertLength(32, compressedPublicKey);
  const xOnlyPublicKey: XOnlyPubkey = new Uint8Array(64);
  const parseResult = secp256k1.secp256k1_xonly_pubkey_parse(
    context,
    xOnlyPublicKey,
    compressedPublicKey
  );
  if (!parseResult) {
    throw new Error(
      "Could not convert the serialized public key to x-only public key"
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
    secretKey
  );
  if (!createResult) {
    throw new Error("Could not create a key pair from the secret key");
  }
  const xOnlyPublicKey = new Uint8Array(64);
  const xOnlyResult = secp256k1.secp256k1_keypair_xonly_pub(
    context,
    xOnlyPublicKey,
    null,
    keypair
  );
  if (!xOnlyResult) {
    throw new Error("Could not create a key pair from the secret key");
  }
  return xOnlyPublicKey;
}

export function schnorrSign(
  messageHash: Uint8Array,
  secretKey: Uint8Array,
  auxiliaryRandom?: Uint8Array
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
    secretKey
  );
  if (!keypairCreateResult) {
    throw new Error("Could not create a keypair from the secret key");
  }

  const signature = new Uint8Array(64);
  const signResult = secp256k1.secp256k1_schnorrsig_sign32(
    context,
    signature,
    messageHash,
    keypair,
    auxiliaryRandom
  );
  if (!signResult) throw new Error("Could not sign with Schnorr");
  return signature;
}

export function schnorrVerify(
  signature: Uint8Array,
  messageHash: Uint8Array,
  xOnlyPublicKey: XOnlyPubkey
): boolean {
  assertLength(32, messageHash);
  assertLength(64, signature);
  assertLength(64, xOnlyPublicKey);
  return secp256k1.secp256k1_schnorrsig_verify(
    context,
    signature,
    messageHash,
    32,
    xOnlyPublicKey
  );
}
