import { openLibrary } from "./openLibrary.ts";
import { Context, symbols } from "./symbols.ts";

const lib = openLibrary(symbols);

export function secp256k1_context_create(flags: number): Context {
  return lib.symbols.secp256k1_context_create(flags);
}

export function secp256k1_context_destroy(context: Context): void {
  lib.symbols.secp256k1_context_destroy(context);
}

export function secp256k1_context_preallocated_size(flags: number): number {
  return lib.symbols.secp256k1_context_preallocated_size(flags);
}

export function secp256k1_context_randomize(
  context: Context,
  seed: Uint8Array
): boolean {
  return Boolean(lib.symbols.secp256k1_context_randomize(context, seed));
}

export function secp256k1_ec_seckey_verify(
  context: Context,
  seckey: Uint8Array
): boolean {
  return Boolean(lib.symbols.secp256k1_ec_seckey_verify(context, seckey));
}

export function secp256k1_ec_seckey_negate(
  context: Context,
  seckey: Uint8Array
): boolean {
  return Boolean(lib.symbols.secp256k1_ec_seckey_negate(context, seckey));
}

export function secp256k1_ec_seckey_tweak_add(
  context: Context,
  seckey: Uint8Array,
  tweak: Uint8Array
): boolean {
  return Boolean(
    lib.symbols.secp256k1_ec_seckey_tweak_add(context, seckey, tweak)
  );
}

export function secp256k1_ec_seckey_tweak_mul(
  context: Context,
  seckey: Uint8Array,
  tweak: Uint8Array
): boolean {
  return Boolean(
    lib.symbols.secp256k1_ec_seckey_tweak_mul(context, seckey, tweak)
  );
}

export function secp256k1_ec_pubkey_parse(
  context: Context,
  pubkey: Uint8Array,
  input: Uint8Array,
  size: number
) {
  return Boolean(
    lib.symbols.secp256k1_ec_pubkey_parse(context, pubkey, input, size)
  );
}
export function secp256k1_ec_pubkey_negate(
  context: Context,
  pubkey: Uint8Array
) {
  return Boolean(lib.symbols.secp256k1_ec_pubkey_negate(context, pubkey));
}
export function secp256k1_ec_pubkey_combine(
  context: Context,
  pubnonce: Uint8Array,
  pubnonces: BigUint64Array /* array of 64-bit pointers to public keys */,
  size: number
): boolean {
  return Boolean(
    lib.symbols.secp256k1_ec_pubkey_combine(context, pubnonce, pubnonces, size)
  );
}
export function secp256k1_ec_pubkey_tweak_add(
  context: Context,
  pubkey: Uint8Array,
  tweak: Uint8Array
) {
  return lib.symbols.secp256k1_ec_pubkey_tweak_add(context, pubkey, tweak);
}
export function secp256k1_ec_pubkey_tweak_mul(
  context: Context,
  pubkey: Uint8Array,
  tweak: Uint8Array
) {
  return lib.symbols.secp256k1_ec_pubkey_tweak_mul(context, pubkey, tweak);
}

export function secp256k1_ec_pubkey_create(
  context: Context,
  pubkey: Uint8Array,
  seckey: Uint8Array
): boolean {
  return Boolean(
    lib.symbols.secp256k1_ec_pubkey_create(context, pubkey, seckey)
  );
}
export function secp256k1_ec_pubkey_serialize(
  context: Context,
  output: Uint8Array,
  outputlen: number,
  pubkey: Uint8Array,
  flags: number
) {
  return lib.symbols.secp256k1_ec_pubkey_serialize(
    context,
    output,
    new Uint8Array([outputlen]),
    pubkey,
    flags
  );
}

export function secp256k1_ecdsa_signature_normalize(
  context: Context,
  sigout: Uint8Array,
  sigin: Uint8Array
): boolean {
  return Boolean(
    lib.symbols.secp256k1_ecdsa_signature_normalize(context, sigout, sigin)
  );
}
export function secp256k1_ecdsa_signature_serialize_compact(
  context: Context,
  output: Uint8Array,
  sig: Uint8Array
): boolean {
  return Boolean(
    lib.symbols.secp256k1_ecdsa_signature_serialize_compact(
      context,
      output,
      sig
    )
  );
}
export function secp256k1_ecdsa_signature_parse_compact(
  context: Context,
  sigout: Uint8Array,
  sigin: Uint8Array
): boolean {
  return Boolean(
    lib.symbols.secp256k1_ecdsa_signature_parse_compact(context, sigout, sigin)
  );
}

export function secp256k1_ecdsa_signature_parse_der(
  context: Context,
  signature: Uint8Array,
  input: Uint8Array,
  inputlen: number
): boolean {
  return Boolean(
    lib.symbols.secp256k1_ecdsa_signature_parse_der(
      context,
      signature,
      input,
      inputlen
    )
  );
}
export function secp256k1_ecdsa_signature_serialize_der(
  context: Context,
  output: Uint8Array,
  outputlen: BigUint64Array,
  signature: Uint8Array
): boolean {
  return Boolean(
    lib.symbols.secp256k1_ecdsa_signature_serialize_der(
      context,
      output,
      outputlen,
      signature
    )
  );
}

export function secp256k1_ecdsa_recover(
  context: Context,
  pubkey: Uint8Array,
  signature: Uint8Array,
  msghash: Uint8Array
): boolean {
  return Boolean(
    lib.symbols.secp256k1_ecdsa_recover(context, pubkey, signature, msghash)
  );
}
export function secp256k1_ecdsa_recoverable_signature_parse_compact(
  context: Context,
  signature: Uint8Array,
  input: Uint8Array,
  recid: number
): boolean {
  return Boolean(
    lib.symbols.secp256k1_ecdsa_recoverable_signature_parse_compact(
      context,
      signature,
      input,
      recid
    )
  );
}
export function secp256k1_ecdsa_recoverable_signature_serialize_compact(
  context: Context,
  output: Uint8Array,
  recid: Uint8Array,
  signature: Uint8Array
): boolean {
  return Boolean(
    lib.symbols.secp256k1_ecdsa_recoverable_signature_serialize_compact(
      context,
      output,
      recid,
      signature
    )
  );
}
export function secp256k1_ecdsa_sign(
  context: Context,
  signature: Uint8Array,
  msghash: Uint8Array,
  seckey: Uint8Array,
  noncefp: Uint8Array | null,
  noncedata: Uint8Array | null
): boolean {
  return Boolean(
    lib.symbols.secp256k1_ecdsa_sign(
      context,
      signature,
      msghash,
      seckey,
      noncefp,
      noncedata
    )
  );
}

export function secp256k1_ecdsa_sign_recoverable(
  context: Context,
  signature: Uint8Array,
  msghash: Uint8Array,
  seckey: Uint8Array,
  noncefp: Uint8Array,
  noncedata: Uint8Array
): boolean {
  return Boolean(
    lib.symbols.secp256k1_ecdsa_sign_recoverable(
      context,
      signature,
      msghash,
      seckey,
      noncefp,
      noncedata
    )
  );
}

export function secp256k1_ecdsa_verify(
  context: Context,
  signature: Uint8Array,
  msghash: Uint8Array,
  pubkey: Uint8Array
): boolean {
  return Boolean(
    lib.symbols.secp256k1_ecdsa_verify(context, signature, msghash, pubkey)
  );
}
