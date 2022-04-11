import { Context, symbols as stableSymbols } from "../symbols.ts";
import { openLibrary } from "../openLibrary.ts";

const symbols = {
  ...stableSymbols,
  /* Tagged SHA256 */
  secp256k1_tagged_sha256: {
    parameters: [
      "pointer" /* const secp256k1_context* ctx */,
      "pointer" /* unsigned char *hash32 */,
      "pointer" /* const unsigned char *tag */,
      "usize" /* size_t taglen */,
      "pointer" /* const unsigned char *msg */,
      "usize" /* size_t msglen */,
    ],
    result: "i32",
  },
  /* Keypair */
  secp256k1_keypair_create: {
    parameters: [
      "pointer" /* const secp256k1_context* ctx */,
      "pointer" /* secp256k1_keypair *keypair */,
      "pointer" /* const unsigned char *seckey32 */,
    ],
    result: "i32",
  },
  secp256k1_keypair_xonly_pub: {
    parameters: [
      "pointer" /* const secp256k1_context* ctx */,
      "pointer" /* secp256k1_xonly_pubkey *pubkey */,
      "pointer" /* int *pk_parity */,
      "pointer" /* const secp256k1_keypair *keypair */,
    ],
    result: "i32",
  },
  /* Public key */
  secp256k1_xonly_pubkey_parse: {
    parameters: [
      "pointer" /* const secp256k1_context* ctx */,
      "pointer" /* secp256k1_xonly_pubkey *pubkey */,
      "pointer" /* const unsigned char *input32 */,
    ],
    result: "i32",
  },
  /* Schnorr */
  secp256k1_schnorrsig_sign32: {
    parameters: [
      "pointer" /* const secp256k1_context* ctx */,
      "pointer" /* unsigned char *sig64 */,
      "pointer" /* const unsigned char *msg32 */,
      "pointer" /* const secp256k1_keypair *keypair */,
      "pointer" /* const unsigned char *aux_rand32 */,
    ],
    result: "i32",
  },
  secp256k1_schnorrsig_verify: {
    parameters: [
      "pointer" /* const secp256k1_context* ctx */,
      "pointer" /* const unsigned char *sig64 */,
      "pointer" /* const unsigned char *msg */,
      "usize" /* size_t msglen */,
      "pointer" /* const secp256k1_xonly_pubkey *pubkey */,
    ],
    result: "i32",
  },
} as const;

const lib = openLibrary(symbols);

export * from "../ffi.ts";

export function secp256k1_tagged_sha256(
  context: Context,
  hash: Uint8Array,
  tag: Uint8Array,
  tagLength: number,
  message: Uint8Array,
  messageLength: number
): boolean {
  return Boolean(
    lib.symbols.secp256k1_tagged_sha256(
      context,
      hash,
      tag,
      tagLength,
      message,
      messageLength
    )
  );
}

export function secp256k1_keypair_xonly_pub(
  context: Context,
  pubkey: Uint8Array,
  pk_parity: Uint8Array | null,
  keypair: Uint8Array
): boolean {
  return Boolean(
    lib.symbols.secp256k1_keypair_xonly_pub(context, pubkey, pk_parity, keypair)
  );
}

export function secp256k1_xonly_pubkey_parse(
  context: Context,
  pubkey: Uint8Array,
  input: Uint8Array
): boolean {
  return Boolean(
    lib.symbols.secp256k1_xonly_pubkey_parse(context, pubkey, input)
  );
}

export function secp256k1_keypair_create(
  context: Context,
  keypair: Uint8Array,
  secretKey: Uint8Array
): boolean {
  return Boolean(
    lib.symbols.secp256k1_keypair_create(context, keypair, secretKey)
  );
}

export function secp256k1_schnorrsig_sign32(
  context: Context,
  signature: Uint8Array,
  messageHash: Uint8Array,
  keypair: Uint8Array,
  aux_rand32: Uint8Array
): boolean {
  return Boolean(
    lib.symbols.secp256k1_schnorrsig_sign32(
      context,
      signature,
      messageHash,
      keypair,
      aux_rand32
    )
  );
}

export function secp256k1_schnorrsig_verify(
  context: Context,
  signature: Uint8Array,
  messageHash: Uint8Array,
  messageLength: number,
  publickey: Uint8Array
): boolean {
  return Boolean(
    lib.symbols.secp256k1_schnorrsig_verify(
      context,
      signature,
      messageHash,
      messageLength,
      publickey
    )
  );
}
