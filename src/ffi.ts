type Context = Deno.PointerValue;

const symbols = {
  /* Context (precomputed tables etc) */
  secp256k1_context_create: {
    parameters: ['u32'],
    result: 'pointer',
  },
  secp256k1_context_destroy: {
    parameters: ['pointer' /* secp256k1_context* ctx */],
    result: 'void',
  },
  secp256k1_context_preallocated_size: {
    parameters: ['u32' /* unsigned int flags */],
    result: 'usize', /* size_t ret */
  },
  secp256k1_context_randomize: {
    parameters: [
      'pointer', /* secp256k1_context* ctx */
      'buffer', /* const unsigned char *seed32 */
    ],
    result: 'i32', /* int */
  },
  /* Secret key functions */
  secp256k1_ec_seckey_verify: {
    parameters: [
      'pointer', /* const secp256k1_context* ctx */
      'buffer', /* const unsigned char *seckey */
    ],
    result: 'i32', /* int ret */
  },
  secp256k1_ec_seckey_negate: {
    parameters: [
      'pointer', /* const secp256k1_context* ctx */
      'buffer', /* unsigned char *seckey */
    ],
    result: 'i32', /* int */
  },
  secp256k1_ec_seckey_tweak_add: {
    parameters: [
      'pointer', /* const secp256k1_context* ctx */
      'buffer', /* unsigned char *seckey */
      'buffer', /* const unsigned char *tweak32 */
    ],
    result: 'i32', /* int ret */
  },
  secp256k1_ec_seckey_tweak_mul: {
    parameters: [
      'pointer', /* const secp256k1_context* ctx */
      'buffer', /* unsigned char *seckey */
      'buffer', /* const unsigned char *tweak32 */
    ],
    result: 'i32', /* int ret */
  },
  /* Public key functions */
  secp256k1_ec_pubkey_parse: {
    parameters: [
      'pointer', /* const secp256k1_context* ctx */
      'buffer', /* secp256k1_pubkey* pubkey */
      'buffer', /* const unsigned char *input */
      'usize', /* size_t inputlen */
    ],
    result: 'i32', /* int 0 or 1 */
  },
  secp256k1_ec_pubkey_negate: {
    parameters: [
      'pointer', /* const secp256k1_context* ctx */
      'buffer', /* secp256k1_pubkey* pubkey */
    ],
    result: 'i32', /* int ret */
  },
  secp256k1_ec_pubkey_combine: {
    parameters: [
      'pointer', /* const secp256k1_context* ctx */
      'buffer', /* secp256k1_pubkey *pubnonce */
      'buffer', /* const secp256k1_pubkey * const *pubnonces */
      'usize', /* size_t n */
    ],
    result: 'i32', /* int 0 or 1 */
  },
  secp256k1_ec_pubkey_tweak_add: {
    parameters: [
      'pointer', /* const secp256k1_context* ctx */
      'buffer', /* secp256k1_pubkey *pubkey */
      'buffer', /* const unsigned char *tweak32 */
    ],
    result: 'i32', /* int ret */
  },
  secp256k1_ec_pubkey_tweak_mul: {
    parameters: [
      'pointer', /* const secp256k1_context* ctx */
      'buffer', /* secp256k1_pubkey* pubkey */
      'buffer', /* const unsigned char *tweak32 */
    ],
    result: 'i32', /* int ret */
  },
  secp256k1_ec_pubkey_create: {
    parameters: [
      'pointer', /* const secp256k1_context* ctx */
      'buffer', /* secp256k1_pubkey *pubkey */
      'buffer', /* const unsigned char *seckey */
    ],
    result: 'i32', /* int ret */
  },
  secp256k1_ec_pubkey_serialize: {
    parameters: [
      'pointer', /* const secp256k1_context* ctx */
      'buffer', /* unsigned char *output */
      'buffer', /* size_t *outputlen */
      'buffer', /* const secp256k1_pubkey* pubkey */
      'u32', /* unsigned int flags */
    ],
    result: 'i32', /* int ret */
  },
  /* Signature functions */
  secp256k1_ecdsa_signature_normalize: {
    parameters: [
      'pointer', /* const secp256k1_context* ctx */
      'buffer', /* secp256k1_ecdsa_signature *sigout */
      'buffer', /* const secp256k1_ecdsa_signature *sigin */
    ],
    result: 'i32', /* int ret */
  },
  secp256k1_ecdsa_signature_serialize_compact: {
    parameters: [
      'pointer', /* const secp256k1_context* ctx */
      'buffer', /* unsigned char *output64 */
      'buffer', /* const secp256k1_ecdsa_signature* sig */
    ],
    result: 'i32', /* int ret */
  },
  secp256k1_ecdsa_signature_parse_compact: {
    parameters: [
      'pointer', /* const secp256k1_context* ctx */
      'buffer', /* secp256k1_ecdsa_signature *sigout */
      'buffer', /* const secp256k1_ecdsa_signature *sigin */
    ],
    result: 'i32', /* int ret */
  },
  secp256k1_ecdsa_signature_parse_der: {
    parameters: [
      'pointer', /* const secp256k1_context* ctx */
      'buffer', /* secp256k1_ecdsa_signature* sig */
      'buffer', /* const unsigned char *input */
      'usize', /* size_t inputlen */
    ],
    result: 'i32', /* int 0 or 1 */
  },
  secp256k1_ecdsa_signature_serialize_der: {
    parameters: [
      'pointer', /* const secp256k1_context* ctx */
      'buffer', /* unsigned char *output */
      'buffer', /* size_t *outputlen */
      'buffer', /* const secp256k1_ecdsa_signature* sig */
    ],
    result: 'i32', /* int 0 or 1 */
  },
  secp256k1_ecdsa_recover: {
    parameters: [
      'pointer', /* const secp256k1_context* ctx */
      'buffer', /* secp256k1_pubkey *pubkey */
      'buffer', /* const secp256k1_ecdsa_recoverable_signature *signature */
      'buffer', /* const unsigned char *msghash32 */
    ],
    result: 'i32', /* int 0 or 1 */
  },
  secp256k1_ecdsa_recoverable_signature_parse_compact: {
    parameters: [
      'pointer', /* const secp256k1_context* ctx */
      'buffer', /* secp256k1_ecdsa_recoverable_signature* sig */
      'buffer', /* const unsigned char *input64 */
      'i32', /* int recid */
    ],
    result: 'i32', /* int 0 or 1 */
  },
  secp256k1_ecdsa_recoverable_signature_serialize_compact: {
    parameters: [
      'pointer', /* const secp256k1_context* ctx */
      'buffer', /* unsigned char *output64 */
      'buffer', /* int *recid */
      'buffer', /* const secp256k1_ecdsa_recoverable_signature* sig */
    ],
    result: 'i32', /* int 0 or 1 */
  },
  secp256k1_ecdsa_sign_recoverable: {
    parameters: [
      'pointer', /* const secp256k1_context* ctx */
      'buffer', /* secp256k1_ecdsa_recoverable_signature *signature */
      'buffer', /* const unsigned char *msghash32 */
      'buffer', /* const unsigned char *seckey */
      'buffer', /* secp256k1_nonce_function noncefp */
      'buffer', /* const void* noncedata */
    ],
    result: 'i32', /* int ret */
  },
  secp256k1_ecdsa_sign: {
    parameters: [
      'pointer', /* const secp256k1_context* ctx */
      'buffer', /* secp256k1_ecdsa_signature *signature */
      'buffer', /* const unsigned char *msghash32 */
      'buffer', /* const unsigned char *seckey */
      'buffer', /* secp256k1_nonce_function noncefp */
      'buffer', /* const void* noncedata */
    ],
    result: 'i32', /* int ret */
  },
  secp256k1_ecdsa_verify: {
    parameters: [
      'pointer', /* const secp256k1_context* ctx */
      'buffer', /* const secp256k1_ecdsa_signature *sig */
      'buffer', /* const unsigned char *msghash32 */
      'buffer', /* const secp256k1_pubkey *pubkey */
    ],
    result: 'i32', /* int 0 or 1 */
  },
  /* Tagged SHA256 */
  secp256k1_tagged_sha256: {
    parameters: [
      'pointer', /* const secp256k1_context* ctx */
      'buffer', /* unsigned char *hash32 */
      'buffer', /* const unsigned char *tag */
      'usize', /* size_t taglen */
      'buffer', /* const unsigned char *msg */
      'usize', /* size_t msglen */
    ],
    result: 'i32',
  },
  /* Keypair */
  secp256k1_keypair_create: {
    parameters: [
      'pointer', /* const secp256k1_context* ctx */
      'buffer', /* secp256k1_keypair *keypair */
      'buffer', /* const unsigned char *seckey32 */
    ],
    result: 'i32',
  },
  secp256k1_keypair_xonly_pub: {
    parameters: [
      'pointer', /* const secp256k1_context* ctx */
      'buffer', /* secp256k1_xonly_pubkey *pubkey */
      'buffer', /* int *pk_parity */
      'buffer', /* const secp256k1_keypair *keypair */
    ],
    result: 'i32',
  },
  /* Public key */
  secp256k1_xonly_pubkey_parse: {
    parameters: [
      'pointer', /* const secp256k1_context* ctx */
      'buffer', /* secp256k1_xonly_pubkey *pubkey */
      'buffer', /* const unsigned char *input32 */
    ],
    result: 'i32',
  },
  /* Schnorr */
  secp256k1_schnorrsig_sign32: {
    parameters: [
      'pointer', /* const secp256k1_context* ctx */
      'buffer', /* unsigned char *sig64 */
      'buffer', /* const unsigned char *msg32 */
      'buffer', /* const secp256k1_keypair *keypair */
      'buffer', /* const unsigned char *aux_rand32 */
    ],
    result: 'i32',
  },
  secp256k1_schnorrsig_verify: {
    parameters: [
      'pointer', /* const secp256k1_context* ctx */
      'buffer', /* const unsigned char *sig64 */
      'buffer', /* const unsigned char *msg */
      'usize', /* size_t msglen */
      'buffer', /* const secp256k1_xonly_pubkey *pubkey */
    ],
    result: 'i32',
  },
} as const satisfies Deno.ForeignLibraryInterface;

let lib: Deno.DynamicLibrary<typeof symbols>['symbols'];

const envSecp256k1Path = Deno.env.get('DENO_SECP256K1_PATH');
if (envSecp256k1Path !== undefined) {
  lib = Deno.dlopen(envSecp256k1Path, symbols).symbols;
} else {
  try {
    lib = Deno.dlopen(
      Deno.build.os === 'windows'
        ? 'secp256k1.dll'
        : Deno.build.os === 'darwin'
        ? 'libsecp256k1.dylib'
        : 'libsecp256k1.so',
      symbols,
    ).symbols;
  } catch (e) {
    if (e instanceof Deno.errors.PermissionDenied) {
      throw e;
    }

    const error = new Error(
      'Native secp256k1 library was not found, try installing a `libsecp256k1` or `libsecp256k1-0` package.' +
        ' If you have an existing installation, either add it to the LD_LIBRARY_PATH or set the `DENO_SECP256K1_PATH` environment variable.' +
        ' Make sure that libsecp256k1 library was built with Schnorr signatures support.' +
        ' Rebuild it with `--enable-module-schnorrsig --enable-module-recovery` parameters or use a different operating system distribution',
    );
    error.cause = e;
    throw error;
  }
}
export function secp256k1_context_create(flags: number): Context {
  return lib.secp256k1_context_create(flags);
}

export function secp256k1_context_destroy(context: Context): void {
  lib.secp256k1_context_destroy(context);
}

export function secp256k1_context_preallocated_size(
  flags: number,
): number | bigint {
  return lib.secp256k1_context_preallocated_size(flags);
}

export function secp256k1_context_randomize(
  context: Context,
  seed: Uint8Array,
): boolean {
  return Boolean(lib.secp256k1_context_randomize(context, seed));
}

export function secp256k1_ec_seckey_verify(
  context: Context,
  seckey: Uint8Array,
): boolean {
  return Boolean(lib.secp256k1_ec_seckey_verify(context, seckey));
}

export function secp256k1_ec_seckey_negate(
  context: Context,
  seckey: Uint8Array,
): boolean {
  return Boolean(lib.secp256k1_ec_seckey_negate(context, seckey));
}

export function secp256k1_ec_seckey_tweak_add(
  context: Context,
  seckey: Uint8Array,
  tweak: Uint8Array,
): boolean {
  return Boolean(
    lib.secp256k1_ec_seckey_tweak_add(context, seckey, tweak),
  );
}

export function secp256k1_ec_seckey_tweak_mul(
  context: Context,
  seckey: Uint8Array,
  tweak: Uint8Array,
): boolean {
  return Boolean(
    lib.secp256k1_ec_seckey_tweak_mul(context, seckey, tweak),
  );
}

export function secp256k1_ec_pubkey_parse(
  context: Context,
  pubkey: Uint8Array,
  input: Uint8Array,
  size: bigint,
) {
  return Boolean(
    lib.secp256k1_ec_pubkey_parse(context, pubkey, input, size),
  );
}
export function secp256k1_ec_pubkey_negate(
  context: Context,
  pubkey: Uint8Array,
) {
  return Boolean(lib.secp256k1_ec_pubkey_negate(context, pubkey));
}
export function secp256k1_ec_pubkey_combine(
  context: Context,
  pubnonce: Uint8Array,
  pubnonces: BigUint64Array, /* array of 64-bit pointers to public keys */
  size: bigint,
): boolean {
  return Boolean(
    lib.secp256k1_ec_pubkey_combine(
      context,
      pubnonce,
      new Uint8Array(pubnonces.buffer),
      size,
    ),
  );
}
export function secp256k1_ec_pubkey_tweak_add(
  context: Context,
  pubkey: Uint8Array,
  tweak: Uint8Array,
) {
  return lib.secp256k1_ec_pubkey_tweak_add(context, pubkey, tweak);
}
export function secp256k1_ec_pubkey_tweak_mul(
  context: Context,
  pubkey: Uint8Array,
  tweak: Uint8Array,
) {
  return lib.secp256k1_ec_pubkey_tweak_mul(context, pubkey, tweak);
}

export function secp256k1_ec_pubkey_create(
  context: Context,
  pubkey: Uint8Array,
  seckey: Uint8Array,
): boolean {
  return Boolean(
    lib.secp256k1_ec_pubkey_create(context, pubkey, seckey),
  );
}
export function secp256k1_ec_pubkey_serialize(
  context: Context,
  output: Uint8Array,
  outputlen: number,
  pubkey: Uint8Array,
  flags: number,
) {
  return lib.secp256k1_ec_pubkey_serialize(
    context,
    output,
    new BigUint64Array([BigInt(outputlen)]),
    pubkey,
    flags,
  );
}

export function secp256k1_ecdsa_signature_normalize(
  context: Context,
  sigout: Uint8Array,
  sigin: Uint8Array,
): boolean {
  return Boolean(
    lib.secp256k1_ecdsa_signature_normalize(context, sigout, sigin),
  );
}
export function secp256k1_ecdsa_signature_serialize_compact(
  context: Context,
  output: Uint8Array,
  sig: Uint8Array,
): boolean {
  return Boolean(
    lib.secp256k1_ecdsa_signature_serialize_compact(
      context,
      output,
      sig,
    ),
  );
}
export function secp256k1_ecdsa_signature_parse_compact(
  context: Context,
  sigout: Uint8Array,
  sigin: Uint8Array,
): boolean {
  return Boolean(
    lib.secp256k1_ecdsa_signature_parse_compact(context, sigout, sigin),
  );
}

export function secp256k1_ecdsa_signature_parse_der(
  context: Context,
  signature: Uint8Array,
  input: Uint8Array,
  inputlen: number,
): boolean {
  return Boolean(
    lib.secp256k1_ecdsa_signature_parse_der(
      context,
      signature,
      input,
      BigInt(inputlen),
    ),
  );
}
export function secp256k1_ecdsa_signature_serialize_der(
  context: Context,
  output: Uint8Array,
  outputlen: BigUint64Array,
  signature: Uint8Array,
): boolean {
  return Boolean(
    lib.secp256k1_ecdsa_signature_serialize_der(
      context,
      output,
      new Uint8Array(outputlen.buffer),
      signature,
    ),
  );
}

export function secp256k1_ecdsa_recover(
  context: Context,
  pubkey: Uint8Array,
  signature: Uint8Array,
  msghash: Uint8Array,
): boolean {
  return Boolean(
    lib.secp256k1_ecdsa_recover(context, pubkey, signature, msghash),
  );
}
export function secp256k1_ecdsa_recoverable_signature_parse_compact(
  context: Context,
  signature: Uint8Array,
  input: Uint8Array,
  recid: number,
): boolean {
  return Boolean(
    lib.secp256k1_ecdsa_recoverable_signature_parse_compact(
      context,
      signature,
      input,
      recid,
    ),
  );
}
export function secp256k1_ecdsa_recoverable_signature_serialize_compact(
  context: Context,
  output: Uint8Array,
  recid: Uint8Array,
  signature: Uint8Array,
): boolean {
  return Boolean(
    lib.secp256k1_ecdsa_recoverable_signature_serialize_compact(
      context,
      output,
      recid,
      signature,
    ),
  );
}
export function secp256k1_ecdsa_sign(
  context: Context,
  signature: Uint8Array,
  msghash: Uint8Array,
  seckey: Uint8Array,
  noncefp: Uint8Array | null,
  noncedata: Uint8Array | null,
): boolean {
  return Boolean(
    lib.secp256k1_ecdsa_sign(
      context,
      signature,
      msghash,
      seckey,
      noncefp,
      noncedata,
    ),
  );
}

export function secp256k1_ecdsa_sign_recoverable(
  context: Context,
  signature: Uint8Array,
  msghash: Uint8Array,
  seckey: Uint8Array,
  noncefp: Uint8Array,
  noncedata: Uint8Array,
): boolean {
  return Boolean(
    lib.secp256k1_ecdsa_sign_recoverable(
      context,
      signature,
      msghash,
      seckey,
      noncefp,
      noncedata,
    ),
  );
}

export function secp256k1_ecdsa_verify(
  context: Context,
  signature: Uint8Array,
  msghash: Uint8Array,
  pubkey: Uint8Array,
): boolean {
  return Boolean(
    lib.secp256k1_ecdsa_verify(context, signature, msghash, pubkey),
  );
}

export function secp256k1_tagged_sha256(
  context: Context,
  hash: Uint8Array,
  tag: Uint8Array,
  tagLength: bigint,
  message: Uint8Array,
  messageLength: bigint,
): boolean {
  return Boolean(
    lib.secp256k1_tagged_sha256(
      context,
      hash,
      tag,
      tagLength,
      message,
      messageLength,
    ),
  );
}

export function secp256k1_keypair_xonly_pub(
  context: Context,
  pubkey: Uint8Array,
  pk_parity: Uint8Array | null,
  keypair: Uint8Array,
): boolean {
  return Boolean(
    lib.secp256k1_keypair_xonly_pub(
      context,
      pubkey,
      pk_parity,
      keypair,
    ),
  );
}

export function secp256k1_xonly_pubkey_parse(
  context: Context,
  pubkey: Uint8Array,
  input: Uint8Array,
): boolean {
  return Boolean(
    lib.secp256k1_xonly_pubkey_parse(context, pubkey, input),
  );
}

export function secp256k1_keypair_create(
  context: Context,
  keypair: Uint8Array,
  secretKey: Uint8Array,
): boolean {
  return Boolean(
    lib.secp256k1_keypair_create(context, keypair, secretKey),
  );
}

export function secp256k1_schnorrsig_sign32(
  context: Context,
  signature: Uint8Array,
  messageHash: Uint8Array,
  keypair: Uint8Array,
  aux_rand32: Uint8Array,
): boolean {
  return Boolean(
    lib.secp256k1_schnorrsig_sign32(
      context,
      signature,
      messageHash,
      keypair,
      aux_rand32,
    ),
  );
}

export function secp256k1_schnorrsig_verify(
  context: Context,
  signature: Uint8Array,
  messageHash: Uint8Array,
  messageLength: bigint,
  publickey: Uint8Array,
): boolean {
  return Boolean(
    lib.secp256k1_schnorrsig_verify(
      context,
      signature,
      messageHash,
      messageLength,
      publickey,
    ),
  );
}
