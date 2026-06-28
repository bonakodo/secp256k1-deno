type Context = Deno.PointerValue;
type Pointer = Deno.PointerValue;
type Buffer = Uint8Array | null;
type PointerArray = BigUint64Array | Uint8Array;

export const SECP256K1_CONTEXT_NONE = 1;
export const SECP256K1_CONTEXT_VERIFY = 257;
export const SECP256K1_CONTEXT_SIGN = 513;
export const SECP256K1_CONTEXT_DECLASSIFY = 1025;
export const SECP256K1_EC_COMPRESSED = 258;
export const SECP256K1_EC_UNCOMPRESSED = 2;

export const SECP256K1_PUBKEY_SIZE = 64;
export const SECP256K1_ECDSA_SIGNATURE_SIZE = 64;
export const SECP256K1_ECDSA_RECOVERABLE_SIGNATURE_SIZE = 65;
export const SECP256K1_XONLY_PUBKEY_SIZE = 64;
export const SECP256K1_KEYPAIR_SIZE = 96;
export const SECP256K1_MUSIG_KEYAGG_CACHE_SIZE = 197;
export const SECP256K1_MUSIG_SECNONCE_SIZE = 132;
export const SECP256K1_MUSIG_PUBNONCE_SIZE = 132;
export const SECP256K1_MUSIG_AGGNONCE_SIZE = 132;
export const SECP256K1_MUSIG_SESSION_SIZE = 133;
export const SECP256K1_MUSIG_PARTIAL_SIG_SIZE = 36;

export const SECP256K1_SCHNORRSIG_EXTRAPARAMS_MAGIC = new Uint8Array([
  0xda,
  0x6f,
  0xb3,
  0x8c,
]);

export const symbols = {
  /* Public static data */
  secp256k1_context_static: { type: 'pointer' },
  secp256k1_context_no_precomp: { type: 'pointer' },
  secp256k1_nonce_function_rfc6979: { type: 'pointer' },
  secp256k1_nonce_function_default: { type: 'pointer' },
  secp256k1_ecdh_hash_function_sha256: { type: 'pointer' },
  secp256k1_ecdh_hash_function_default: { type: 'pointer' },
  secp256k1_ellswift_xdh_hash_function_prefix: { type: 'pointer' },
  secp256k1_ellswift_xdh_hash_function_bip324: { type: 'pointer' },
  secp256k1_nonce_function_bip340: { type: 'pointer' },

  /* Context */
  secp256k1_selftest: {
    parameters: [],
    result: 'void',
  },
  secp256k1_context_create: {
    parameters: ['u32'],
    result: 'pointer',
  },
  secp256k1_context_clone: {
    parameters: ['pointer'],
    result: 'pointer',
  },
  secp256k1_context_destroy: {
    parameters: ['pointer'],
    result: 'void',
  },
  secp256k1_context_set_illegal_callback: {
    parameters: ['pointer', 'pointer', 'pointer'],
    result: 'void',
  },
  secp256k1_context_set_error_callback: {
    parameters: ['pointer', 'pointer', 'pointer'],
    result: 'void',
  },
  secp256k1_context_set_sha256_compression: {
    parameters: ['pointer', 'pointer'],
    result: 'void',
  },
  secp256k1_context_randomize: {
    parameters: ['pointer', 'buffer'],
    result: 'i32',
  },

  /* Preallocated contexts */
  secp256k1_context_preallocated_size: {
    parameters: ['u32'],
    result: 'usize',
  },
  secp256k1_context_preallocated_create: {
    parameters: ['buffer', 'u32'],
    result: 'pointer',
  },
  secp256k1_context_preallocated_clone_size: {
    parameters: ['pointer'],
    result: 'usize',
  },
  secp256k1_context_preallocated_clone: {
    parameters: ['pointer', 'buffer'],
    result: 'pointer',
  },
  secp256k1_context_preallocated_destroy: {
    parameters: ['pointer'],
    result: 'void',
  },

  /* Secret key functions */
  secp256k1_ec_seckey_verify: {
    parameters: ['pointer', 'buffer'],
    result: 'i32',
  },
  secp256k1_ec_seckey_negate: {
    parameters: ['pointer', 'buffer'],
    result: 'i32',
  },
  secp256k1_ec_seckey_tweak_add: {
    parameters: ['pointer', 'buffer', 'buffer'],
    result: 'i32',
  },
  secp256k1_ec_seckey_tweak_mul: {
    parameters: ['pointer', 'buffer', 'buffer'],
    result: 'i32',
  },

  /* Public key functions */
  secp256k1_ec_pubkey_parse: {
    parameters: ['pointer', 'buffer', 'buffer', 'usize'],
    result: 'i32',
  },
  secp256k1_ec_pubkey_serialize: {
    parameters: ['pointer', 'buffer', 'buffer', 'buffer', 'u32'],
    result: 'i32',
  },
  secp256k1_ec_pubkey_cmp: {
    parameters: ['pointer', 'buffer', 'buffer'],
    result: 'i32',
  },
  secp256k1_ec_pubkey_sort: {
    parameters: ['pointer', 'buffer', 'usize'],
    result: 'i32',
  },
  secp256k1_ec_pubkey_negate: {
    parameters: ['pointer', 'buffer'],
    result: 'i32',
  },
  secp256k1_ec_pubkey_combine: {
    parameters: ['pointer', 'buffer', 'buffer', 'usize'],
    result: 'i32',
  },
  secp256k1_ec_pubkey_tweak_add: {
    parameters: ['pointer', 'buffer', 'buffer'],
    result: 'i32',
  },
  secp256k1_ec_pubkey_tweak_mul: {
    parameters: ['pointer', 'buffer', 'buffer'],
    result: 'i32',
  },
  secp256k1_ec_pubkey_create: {
    parameters: ['pointer', 'buffer', 'buffer'],
    result: 'i32',
  },

  /* Signature functions */
  secp256k1_ecdsa_signature_normalize: {
    parameters: ['pointer', 'buffer', 'buffer'],
    result: 'i32',
  },
  secp256k1_ecdsa_signature_serialize_compact: {
    parameters: ['pointer', 'buffer', 'buffer'],
    result: 'i32',
  },
  secp256k1_ecdsa_signature_parse_compact: {
    parameters: ['pointer', 'buffer', 'buffer'],
    result: 'i32',
  },
  secp256k1_ecdsa_signature_parse_der: {
    parameters: ['pointer', 'buffer', 'buffer', 'usize'],
    result: 'i32',
  },
  secp256k1_ecdsa_signature_serialize_der: {
    parameters: ['pointer', 'buffer', 'buffer', 'buffer'],
    result: 'i32',
  },
  secp256k1_ecdsa_sign: {
    parameters: ['pointer', 'buffer', 'buffer', 'buffer', 'pointer', 'pointer'],
    result: 'i32',
  },
  secp256k1_ecdsa_verify: {
    parameters: ['pointer', 'buffer', 'buffer', 'buffer'],
    result: 'i32',
  },

  /* Recovery */
  secp256k1_ecdsa_recoverable_signature_parse_compact: {
    parameters: ['pointer', 'buffer', 'buffer', 'i32'],
    result: 'i32',
  },
  secp256k1_ecdsa_recoverable_signature_convert: {
    parameters: ['pointer', 'buffer', 'buffer'],
    result: 'i32',
  },
  secp256k1_ecdsa_recoverable_signature_serialize_compact: {
    parameters: ['pointer', 'buffer', 'buffer', 'buffer'],
    result: 'i32',
  },
  secp256k1_ecdsa_sign_recoverable: {
    parameters: ['pointer', 'buffer', 'buffer', 'buffer', 'pointer', 'pointer'],
    result: 'i32',
  },
  secp256k1_ecdsa_recover: {
    parameters: ['pointer', 'buffer', 'buffer', 'buffer'],
    result: 'i32',
  },

  /* Tagged SHA256 */
  secp256k1_tagged_sha256: {
    parameters: ['pointer', 'buffer', 'buffer', 'usize', 'buffer', 'usize'],
    result: 'i32',
  },

  /* ECDH */
  secp256k1_ecdh: {
    parameters: ['pointer', 'buffer', 'buffer', 'buffer', 'pointer', 'pointer'],
    result: 'i32',
  },

  /* ElligatorSwift */
  secp256k1_ellswift_encode: {
    parameters: ['pointer', 'buffer', 'buffer', 'buffer'],
    result: 'i32',
  },
  secp256k1_ellswift_decode: {
    parameters: ['pointer', 'buffer', 'buffer'],
    result: 'i32',
  },
  secp256k1_ellswift_create: {
    parameters: ['pointer', 'buffer', 'buffer', 'buffer'],
    result: 'i32',
  },
  secp256k1_ellswift_xdh: {
    parameters: [
      'pointer',
      'buffer',
      'buffer',
      'buffer',
      'buffer',
      'i32',
      'pointer',
      'pointer',
    ],
    result: 'i32',
  },

  /* Extra keys */
  secp256k1_xonly_pubkey_parse: {
    parameters: ['pointer', 'buffer', 'buffer'],
    result: 'i32',
  },
  secp256k1_xonly_pubkey_serialize: {
    parameters: ['pointer', 'buffer', 'buffer'],
    result: 'i32',
  },
  secp256k1_xonly_pubkey_cmp: {
    parameters: ['pointer', 'buffer', 'buffer'],
    result: 'i32',
  },
  secp256k1_xonly_pubkey_from_pubkey: {
    parameters: ['pointer', 'buffer', 'buffer', 'buffer'],
    result: 'i32',
  },
  secp256k1_xonly_pubkey_tweak_add: {
    parameters: ['pointer', 'buffer', 'buffer', 'buffer'],
    result: 'i32',
  },
  secp256k1_xonly_pubkey_tweak_add_check: {
    parameters: ['pointer', 'buffer', 'i32', 'buffer', 'buffer'],
    result: 'i32',
  },
  secp256k1_keypair_create: {
    parameters: ['pointer', 'buffer', 'buffer'],
    result: 'i32',
  },
  secp256k1_keypair_sec: {
    parameters: ['pointer', 'buffer', 'buffer'],
    result: 'i32',
  },
  secp256k1_keypair_pub: {
    parameters: ['pointer', 'buffer', 'buffer'],
    result: 'i32',
  },
  secp256k1_keypair_xonly_pub: {
    parameters: ['pointer', 'buffer', 'buffer', 'buffer'],
    result: 'i32',
  },
  secp256k1_keypair_xonly_tweak_add: {
    parameters: ['pointer', 'buffer', 'buffer'],
    result: 'i32',
  },

  /* Schnorr */
  secp256k1_schnorrsig_sign32: {
    parameters: ['pointer', 'buffer', 'buffer', 'buffer', 'buffer'],
    result: 'i32',
  },
  secp256k1_schnorrsig_sign: {
    parameters: ['pointer', 'buffer', 'buffer', 'buffer', 'buffer'],
    result: 'i32',
  },
  secp256k1_schnorrsig_sign_custom: {
    parameters: ['pointer', 'buffer', 'buffer', 'usize', 'buffer', 'buffer'],
    result: 'i32',
  },
  secp256k1_schnorrsig_verify: {
    parameters: ['pointer', 'buffer', 'buffer', 'usize', 'buffer'],
    result: 'i32',
  },

  /* MuSig */
  secp256k1_musig_pubnonce_parse: {
    parameters: ['pointer', 'buffer', 'buffer'],
    result: 'i32',
  },
  secp256k1_musig_pubnonce_serialize: {
    parameters: ['pointer', 'buffer', 'buffer'],
    result: 'i32',
  },
  secp256k1_musig_aggnonce_parse: {
    parameters: ['pointer', 'buffer', 'buffer'],
    result: 'i32',
  },
  secp256k1_musig_aggnonce_serialize: {
    parameters: ['pointer', 'buffer', 'buffer'],
    result: 'i32',
  },
  secp256k1_musig_partial_sig_parse: {
    parameters: ['pointer', 'buffer', 'buffer'],
    result: 'i32',
  },
  secp256k1_musig_partial_sig_serialize: {
    parameters: ['pointer', 'buffer', 'buffer'],
    result: 'i32',
  },
  secp256k1_musig_pubkey_agg: {
    parameters: ['pointer', 'buffer', 'buffer', 'buffer', 'usize'],
    result: 'i32',
  },
  secp256k1_musig_pubkey_get: {
    parameters: ['pointer', 'buffer', 'buffer'],
    result: 'i32',
  },
  secp256k1_musig_pubkey_ec_tweak_add: {
    parameters: ['pointer', 'buffer', 'buffer', 'buffer'],
    result: 'i32',
  },
  secp256k1_musig_pubkey_xonly_tweak_add: {
    parameters: ['pointer', 'buffer', 'buffer', 'buffer'],
    result: 'i32',
  },
  secp256k1_musig_nonce_gen: {
    parameters: [
      'pointer',
      'buffer',
      'buffer',
      'buffer',
      'buffer',
      'buffer',
      'buffer',
      'buffer',
      'buffer',
    ],
    result: 'i32',
  },
  secp256k1_musig_nonce_gen_counter: {
    parameters: [
      'pointer',
      'buffer',
      'buffer',
      'u64',
      'buffer',
      'buffer',
      'buffer',
      'buffer',
    ],
    result: 'i32',
  },
  secp256k1_musig_nonce_agg: {
    parameters: ['pointer', 'buffer', 'buffer', 'usize'],
    result: 'i32',
  },
  secp256k1_musig_nonce_process: {
    parameters: ['pointer', 'buffer', 'buffer', 'buffer', 'buffer'],
    result: 'i32',
  },
  secp256k1_musig_partial_sign: {
    parameters: ['pointer', 'buffer', 'buffer', 'buffer', 'buffer', 'buffer'],
    result: 'i32',
  },
  secp256k1_musig_partial_sig_verify: {
    parameters: ['pointer', 'buffer', 'buffer', 'buffer', 'buffer', 'buffer'],
    result: 'i32',
  },
  secp256k1_musig_partial_sig_agg: {
    parameters: ['pointer', 'buffer', 'buffer', 'buffer', 'usize'],
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
        ' Make sure that libsecp256k1 library was built with all public modules enabled.' +
        ' Rebuild it with `-DSECP256K1_ENABLE_MODULE_RECOVERY=ON -DSECP256K1_ENABLE_MODULE_ECDH=ON -DSECP256K1_ENABLE_MODULE_EXTRAKEYS=ON -DSECP256K1_ENABLE_MODULE_SCHNORRSIG=ON -DSECP256K1_ENABLE_MODULE_ELLSWIFT=ON -DSECP256K1_ENABLE_MODULE_MUSIG=ON` or use a distribution package that includes those modules.',
    );
    error.cause = e;
    throw error;
  }
}

function bool(result: number): boolean {
  return Boolean(result);
}

function asUsize(size: number | bigint): bigint {
  return BigInt(size);
}

function asPointerBytes(pointers: PointerArray): Uint8Array {
  return pointers instanceof Uint8Array
    ? pointers
    : new Uint8Array(pointers.buffer);
}

function dereferenceStaticPointer(pointer: Pointer): Pointer {
  if (pointer === null) return null;
  return new Deno.UnsafePointerView(pointer).getPointer(0);
}

export const secp256k1_context_static = dereferenceStaticPointer(
  lib.secp256k1_context_static,
);
export const secp256k1_context_no_precomp = dereferenceStaticPointer(
  lib.secp256k1_context_no_precomp,
);
export const secp256k1_nonce_function_rfc6979 = dereferenceStaticPointer(
  lib.secp256k1_nonce_function_rfc6979,
);
export const secp256k1_nonce_function_default = dereferenceStaticPointer(
  lib.secp256k1_nonce_function_default,
);
export const secp256k1_ecdh_hash_function_sha256 = dereferenceStaticPointer(
  lib.secp256k1_ecdh_hash_function_sha256,
);
export const secp256k1_ecdh_hash_function_default = dereferenceStaticPointer(
  lib.secp256k1_ecdh_hash_function_default,
);
export const secp256k1_ellswift_xdh_hash_function_prefix =
  dereferenceStaticPointer(lib.secp256k1_ellswift_xdh_hash_function_prefix);
export const secp256k1_ellswift_xdh_hash_function_bip324 =
  dereferenceStaticPointer(lib.secp256k1_ellswift_xdh_hash_function_bip324);
export const secp256k1_nonce_function_bip340 = dereferenceStaticPointer(
  lib.secp256k1_nonce_function_bip340,
);

export function pointerArray(buffers: Uint8Array[]): BigUint64Array {
  return new BigUint64Array(
    buffers.map((buffer) =>
      BigInt(Deno.UnsafePointer.value(Deno.UnsafePointer.of(buffer)))
    ),
  );
}

export function secp256k1_selftest(): void {
  lib.secp256k1_selftest();
}

export function secp256k1_context_create(flags: number): Context {
  return lib.secp256k1_context_create(flags);
}

export function secp256k1_context_clone(context: Context): Context {
  return lib.secp256k1_context_clone(context);
}

export function secp256k1_context_destroy(context: Context): void {
  lib.secp256k1_context_destroy(context);
}

export function secp256k1_context_set_illegal_callback(
  context: Context,
  callback: Pointer,
  data: Pointer,
): void {
  lib.secp256k1_context_set_illegal_callback(context, callback, data);
}

export function secp256k1_context_set_error_callback(
  context: Context,
  callback: Pointer,
  data: Pointer,
): void {
  lib.secp256k1_context_set_error_callback(context, callback, data);
}

export function secp256k1_context_set_sha256_compression(
  context: Context,
  compression: Pointer,
): void {
  lib.secp256k1_context_set_sha256_compression(context, compression);
}

export function secp256k1_context_preallocated_size(
  flags: number,
): number | bigint {
  return lib.secp256k1_context_preallocated_size(flags);
}

export function secp256k1_context_preallocated_create(
  prealloc: Uint8Array,
  flags: number,
): Context {
  return lib.secp256k1_context_preallocated_create(prealloc, flags);
}

export function secp256k1_context_preallocated_clone_size(
  context: Context,
): number | bigint {
  return lib.secp256k1_context_preallocated_clone_size(context);
}

export function secp256k1_context_preallocated_clone(
  context: Context,
  prealloc: Uint8Array,
): Context {
  return lib.secp256k1_context_preallocated_clone(context, prealloc);
}

export function secp256k1_context_preallocated_destroy(
  context: Context,
): void {
  lib.secp256k1_context_preallocated_destroy(context);
}

export function secp256k1_context_randomize(
  context: Context,
  seed: Buffer,
): boolean {
  return bool(lib.secp256k1_context_randomize(context, seed));
}

export function secp256k1_ec_seckey_verify(
  context: Context,
  seckey: Uint8Array,
): boolean {
  return bool(lib.secp256k1_ec_seckey_verify(context, seckey));
}

export function secp256k1_ec_seckey_negate(
  context: Context,
  seckey: Uint8Array,
): boolean {
  return bool(lib.secp256k1_ec_seckey_negate(context, seckey));
}

export function secp256k1_ec_seckey_tweak_add(
  context: Context,
  seckey: Uint8Array,
  tweak: Uint8Array,
): boolean {
  return bool(lib.secp256k1_ec_seckey_tweak_add(context, seckey, tweak));
}

export function secp256k1_ec_seckey_tweak_mul(
  context: Context,
  seckey: Uint8Array,
  tweak: Uint8Array,
): boolean {
  return bool(lib.secp256k1_ec_seckey_tweak_mul(context, seckey, tweak));
}

export function secp256k1_ec_pubkey_parse(
  context: Context,
  pubkey: Uint8Array,
  input: Uint8Array,
  size: number | bigint,
): boolean {
  return bool(
    lib.secp256k1_ec_pubkey_parse(context, pubkey, input, asUsize(size)),
  );
}

export function secp256k1_ec_pubkey_serialize(
  context: Context,
  output: Uint8Array,
  outputlen: number | BigUint64Array,
  pubkey: Uint8Array,
  flags: number,
): boolean {
  const outputLength = typeof outputlen === 'number'
    ? new BigUint64Array([BigInt(outputlen)])
    : outputlen;
  return bool(
    lib.secp256k1_ec_pubkey_serialize(
      context,
      output,
      new Uint8Array(outputLength.buffer),
      pubkey,
      flags,
    ),
  );
}

export function secp256k1_ec_pubkey_cmp(
  context: Context,
  pubkey1: Uint8Array,
  pubkey2: Uint8Array,
): number {
  return lib.secp256k1_ec_pubkey_cmp(context, pubkey1, pubkey2);
}

export function secp256k1_ec_pubkey_sort(
  context: Context,
  pubkeys: PointerArray,
  size: number | bigint,
): boolean {
  return bool(
    lib.secp256k1_ec_pubkey_sort(
      context,
      asPointerBytes(pubkeys),
      asUsize(size),
    ),
  );
}

export function secp256k1_ec_pubkey_negate(
  context: Context,
  pubkey: Uint8Array,
): boolean {
  return bool(lib.secp256k1_ec_pubkey_negate(context, pubkey));
}

export function secp256k1_ec_pubkey_combine(
  context: Context,
  pubnonce: Uint8Array,
  pubnonces: PointerArray,
  size: number | bigint,
): boolean {
  return bool(
    lib.secp256k1_ec_pubkey_combine(
      context,
      pubnonce,
      asPointerBytes(pubnonces),
      asUsize(size),
    ),
  );
}

export function secp256k1_ec_pubkey_tweak_add(
  context: Context,
  pubkey: Uint8Array,
  tweak: Uint8Array,
): boolean {
  return bool(lib.secp256k1_ec_pubkey_tweak_add(context, pubkey, tweak));
}

export function secp256k1_ec_pubkey_tweak_mul(
  context: Context,
  pubkey: Uint8Array,
  tweak: Uint8Array,
): boolean {
  return bool(lib.secp256k1_ec_pubkey_tweak_mul(context, pubkey, tweak));
}

export function secp256k1_ec_pubkey_create(
  context: Context,
  pubkey: Uint8Array,
  seckey: Uint8Array,
): boolean {
  return bool(lib.secp256k1_ec_pubkey_create(context, pubkey, seckey));
}

export function secp256k1_ecdsa_signature_normalize(
  context: Context,
  sigout: Uint8Array | null,
  sigin: Uint8Array,
): boolean {
  return bool(
    lib.secp256k1_ecdsa_signature_normalize(context, sigout, sigin),
  );
}

export function secp256k1_ecdsa_signature_serialize_compact(
  context: Context,
  output: Uint8Array,
  sig: Uint8Array,
): boolean {
  return bool(
    lib.secp256k1_ecdsa_signature_serialize_compact(context, output, sig),
  );
}

export function secp256k1_ecdsa_signature_parse_compact(
  context: Context,
  sigout: Uint8Array,
  sigin: Uint8Array,
): boolean {
  return bool(
    lib.secp256k1_ecdsa_signature_parse_compact(context, sigout, sigin),
  );
}

export function secp256k1_ecdsa_signature_parse_der(
  context: Context,
  signature: Uint8Array,
  input: Uint8Array,
  inputlen: number | bigint,
): boolean {
  return bool(
    lib.secp256k1_ecdsa_signature_parse_der(
      context,
      signature,
      input,
      asUsize(inputlen),
    ),
  );
}

export function secp256k1_ecdsa_signature_serialize_der(
  context: Context,
  output: Uint8Array,
  outputlen: BigUint64Array,
  signature: Uint8Array,
): boolean {
  return bool(
    lib.secp256k1_ecdsa_signature_serialize_der(
      context,
      output,
      new Uint8Array(outputlen.buffer),
      signature,
    ),
  );
}

export function secp256k1_ecdsa_sign(
  context: Context,
  signature: Uint8Array,
  msghash: Uint8Array,
  seckey: Uint8Array,
  noncefp: Pointer,
  noncedata: Pointer,
): boolean {
  return bool(
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

export function secp256k1_ecdsa_verify(
  context: Context,
  signature: Uint8Array,
  msghash: Uint8Array,
  pubkey: Uint8Array,
): boolean {
  return bool(lib.secp256k1_ecdsa_verify(context, signature, msghash, pubkey));
}

export function secp256k1_ecdsa_recoverable_signature_parse_compact(
  context: Context,
  signature: Uint8Array,
  input: Uint8Array,
  recid: number,
): boolean {
  return bool(
    lib.secp256k1_ecdsa_recoverable_signature_parse_compact(
      context,
      signature,
      input,
      recid,
    ),
  );
}

export function secp256k1_ecdsa_recoverable_signature_convert(
  context: Context,
  signature: Uint8Array,
  recoverableSignature: Uint8Array,
): boolean {
  return bool(
    lib.secp256k1_ecdsa_recoverable_signature_convert(
      context,
      signature,
      recoverableSignature,
    ),
  );
}

export function secp256k1_ecdsa_recoverable_signature_serialize_compact(
  context: Context,
  output: Uint8Array,
  recid: Uint8Array,
  signature: Uint8Array,
): boolean {
  return bool(
    lib.secp256k1_ecdsa_recoverable_signature_serialize_compact(
      context,
      output,
      recid,
      signature,
    ),
  );
}

export function secp256k1_ecdsa_sign_recoverable(
  context: Context,
  signature: Uint8Array,
  msghash: Uint8Array,
  seckey: Uint8Array,
  noncefp: Pointer,
  noncedata: Pointer,
): boolean {
  return bool(
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

export function secp256k1_ecdsa_recover(
  context: Context,
  pubkey: Uint8Array,
  signature: Uint8Array,
  msghash: Uint8Array,
): boolean {
  return bool(lib.secp256k1_ecdsa_recover(context, pubkey, signature, msghash));
}

export function secp256k1_tagged_sha256(
  context: Context,
  hash: Uint8Array,
  tag: Uint8Array,
  tagLength: number | bigint,
  message: Uint8Array,
  messageLength: number | bigint,
): boolean {
  return bool(
    lib.secp256k1_tagged_sha256(
      context,
      hash,
      tag,
      asUsize(tagLength),
      message,
      asUsize(messageLength),
    ),
  );
}

export function secp256k1_ecdh(
  context: Context,
  output: Uint8Array,
  pubkey: Uint8Array,
  seckey: Uint8Array,
  hashfp: Pointer,
  data: Pointer,
): boolean {
  return bool(
    lib.secp256k1_ecdh(context, output, pubkey, seckey, hashfp, data),
  );
}

export function secp256k1_ellswift_encode(
  context: Context,
  output: Uint8Array,
  pubkey: Uint8Array,
  randomness: Uint8Array,
): boolean {
  return bool(
    lib.secp256k1_ellswift_encode(context, output, pubkey, randomness),
  );
}

export function secp256k1_ellswift_decode(
  context: Context,
  pubkey: Uint8Array,
  input: Uint8Array,
): boolean {
  return bool(lib.secp256k1_ellswift_decode(context, pubkey, input));
}

export function secp256k1_ellswift_create(
  context: Context,
  output: Uint8Array,
  seckey: Uint8Array,
  auxrnd: Uint8Array | null,
): boolean {
  return bool(lib.secp256k1_ellswift_create(context, output, seckey, auxrnd));
}

export function secp256k1_ellswift_xdh(
  context: Context,
  output: Uint8Array,
  ellA: Uint8Array,
  ellB: Uint8Array,
  seckey: Uint8Array,
  party: number,
  hashfp: Pointer,
  data: Pointer,
): boolean {
  return bool(
    lib.secp256k1_ellswift_xdh(
      context,
      output,
      ellA,
      ellB,
      seckey,
      party,
      hashfp,
      data,
    ),
  );
}

export function secp256k1_xonly_pubkey_parse(
  context: Context,
  pubkey: Uint8Array,
  input: Uint8Array,
): boolean {
  return bool(lib.secp256k1_xonly_pubkey_parse(context, pubkey, input));
}

export function secp256k1_xonly_pubkey_serialize(
  context: Context,
  output: Uint8Array,
  pubkey: Uint8Array,
): boolean {
  return bool(lib.secp256k1_xonly_pubkey_serialize(context, output, pubkey));
}

export function secp256k1_xonly_pubkey_cmp(
  context: Context,
  pubkey1: Uint8Array,
  pubkey2: Uint8Array,
): number {
  return lib.secp256k1_xonly_pubkey_cmp(context, pubkey1, pubkey2);
}

export function secp256k1_xonly_pubkey_from_pubkey(
  context: Context,
  xonlyPubkey: Uint8Array,
  parity: Uint8Array | null,
  pubkey: Uint8Array,
): boolean {
  return bool(
    lib.secp256k1_xonly_pubkey_from_pubkey(
      context,
      xonlyPubkey,
      parity,
      pubkey,
    ),
  );
}

export function secp256k1_xonly_pubkey_tweak_add(
  context: Context,
  outputPubkey: Uint8Array,
  internalPubkey: Uint8Array,
  tweak: Uint8Array,
): boolean {
  return bool(
    lib.secp256k1_xonly_pubkey_tweak_add(
      context,
      outputPubkey,
      internalPubkey,
      tweak,
    ),
  );
}

export function secp256k1_xonly_pubkey_tweak_add_check(
  context: Context,
  tweakedPubkey: Uint8Array,
  tweakedParity: number,
  internalPubkey: Uint8Array,
  tweak: Uint8Array,
): boolean {
  return bool(
    lib.secp256k1_xonly_pubkey_tweak_add_check(
      context,
      tweakedPubkey,
      tweakedParity,
      internalPubkey,
      tweak,
    ),
  );
}

export function secp256k1_keypair_create(
  context: Context,
  keypair: Uint8Array,
  secretKey: Uint8Array,
): boolean {
  return bool(lib.secp256k1_keypair_create(context, keypair, secretKey));
}

export function secp256k1_keypair_sec(
  context: Context,
  seckey: Uint8Array,
  keypair: Uint8Array,
): boolean {
  return bool(lib.secp256k1_keypair_sec(context, seckey, keypair));
}

export function secp256k1_keypair_pub(
  context: Context,
  pubkey: Uint8Array,
  keypair: Uint8Array,
): boolean {
  return bool(lib.secp256k1_keypair_pub(context, pubkey, keypair));
}

export function secp256k1_keypair_xonly_pub(
  context: Context,
  pubkey: Uint8Array,
  pk_parity: Uint8Array | null,
  keypair: Uint8Array,
): boolean {
  return bool(
    lib.secp256k1_keypair_xonly_pub(context, pubkey, pk_parity, keypair),
  );
}

export function secp256k1_keypair_xonly_tweak_add(
  context: Context,
  keypair: Uint8Array,
  tweak: Uint8Array,
): boolean {
  return bool(lib.secp256k1_keypair_xonly_tweak_add(context, keypair, tweak));
}

export function secp256k1_schnorrsig_sign32(
  context: Context,
  signature: Uint8Array,
  messageHash: Uint8Array,
  keypair: Uint8Array,
  aux_rand32: Uint8Array | null,
): boolean {
  return bool(
    lib.secp256k1_schnorrsig_sign32(
      context,
      signature,
      messageHash,
      keypair,
      aux_rand32,
    ),
  );
}

export function secp256k1_schnorrsig_sign(
  context: Context,
  signature: Uint8Array,
  messageHash: Uint8Array,
  keypair: Uint8Array,
  aux_rand32: Uint8Array | null,
): boolean {
  return bool(
    lib.secp256k1_schnorrsig_sign(
      context,
      signature,
      messageHash,
      keypair,
      aux_rand32,
    ),
  );
}

export function secp256k1_schnorrsig_sign_custom(
  context: Context,
  signature: Uint8Array,
  message: Uint8Array | null,
  messageLength: number | bigint,
  keypair: Uint8Array,
  extraParams: Uint8Array | null,
): boolean {
  return bool(
    lib.secp256k1_schnorrsig_sign_custom(
      context,
      signature,
      message,
      asUsize(messageLength),
      keypair,
      extraParams,
    ),
  );
}

export function secp256k1_schnorrsig_verify(
  context: Context,
  signature: Uint8Array,
  messageHash: Uint8Array | null,
  messageLength: number | bigint,
  publickey: Uint8Array,
): boolean {
  return bool(
    lib.secp256k1_schnorrsig_verify(
      context,
      signature,
      messageHash,
      asUsize(messageLength),
      publickey,
    ),
  );
}

export function secp256k1_musig_pubnonce_parse(
  context: Context,
  nonce: Uint8Array,
  input: Uint8Array,
): boolean {
  return bool(lib.secp256k1_musig_pubnonce_parse(context, nonce, input));
}

export function secp256k1_musig_pubnonce_serialize(
  context: Context,
  output: Uint8Array,
  nonce: Uint8Array,
): boolean {
  return bool(lib.secp256k1_musig_pubnonce_serialize(context, output, nonce));
}

export function secp256k1_musig_aggnonce_parse(
  context: Context,
  nonce: Uint8Array,
  input: Uint8Array,
): boolean {
  return bool(lib.secp256k1_musig_aggnonce_parse(context, nonce, input));
}

export function secp256k1_musig_aggnonce_serialize(
  context: Context,
  output: Uint8Array,
  nonce: Uint8Array,
): boolean {
  return bool(lib.secp256k1_musig_aggnonce_serialize(context, output, nonce));
}

export function secp256k1_musig_partial_sig_parse(
  context: Context,
  signature: Uint8Array,
  input: Uint8Array,
): boolean {
  return bool(lib.secp256k1_musig_partial_sig_parse(context, signature, input));
}

export function secp256k1_musig_partial_sig_serialize(
  context: Context,
  output: Uint8Array,
  signature: Uint8Array,
): boolean {
  return bool(
    lib.secp256k1_musig_partial_sig_serialize(context, output, signature),
  );
}

export function secp256k1_musig_pubkey_agg(
  context: Context,
  aggPubkey: Uint8Array | null,
  keyaggCache: Uint8Array | null,
  pubkeys: PointerArray,
  size: number | bigint,
): boolean {
  return bool(
    lib.secp256k1_musig_pubkey_agg(
      context,
      aggPubkey,
      keyaggCache,
      asPointerBytes(pubkeys),
      asUsize(size),
    ),
  );
}

export function secp256k1_musig_pubkey_get(
  context: Context,
  aggPubkey: Uint8Array,
  keyaggCache: Uint8Array,
): boolean {
  return bool(lib.secp256k1_musig_pubkey_get(context, aggPubkey, keyaggCache));
}

export function secp256k1_musig_pubkey_ec_tweak_add(
  context: Context,
  outputPubkey: Uint8Array | null,
  keyaggCache: Uint8Array,
  tweak: Uint8Array,
): boolean {
  return bool(
    lib.secp256k1_musig_pubkey_ec_tweak_add(
      context,
      outputPubkey,
      keyaggCache,
      tweak,
    ),
  );
}

export function secp256k1_musig_pubkey_xonly_tweak_add(
  context: Context,
  outputPubkey: Uint8Array | null,
  keyaggCache: Uint8Array,
  tweak: Uint8Array,
): boolean {
  return bool(
    lib.secp256k1_musig_pubkey_xonly_tweak_add(
      context,
      outputPubkey,
      keyaggCache,
      tweak,
    ),
  );
}

export function secp256k1_musig_nonce_gen(
  context: Context,
  secnonce: Uint8Array,
  pubnonce: Uint8Array,
  sessionSecretRandom: Uint8Array,
  seckey: Uint8Array | null,
  pubkey: Uint8Array,
  message: Uint8Array | null,
  keyaggCache: Uint8Array | null,
  extraInput: Uint8Array | null,
): boolean {
  return bool(
    lib.secp256k1_musig_nonce_gen(
      context,
      secnonce,
      pubnonce,
      sessionSecretRandom,
      seckey,
      pubkey,
      message,
      keyaggCache,
      extraInput,
    ),
  );
}

export function secp256k1_musig_nonce_gen_counter(
  context: Context,
  secnonce: Uint8Array,
  pubnonce: Uint8Array,
  nonrepeatingCounter: bigint,
  keypair: Uint8Array,
  message: Uint8Array | null,
  keyaggCache: Uint8Array | null,
  extraInput: Uint8Array | null,
): boolean {
  return bool(
    lib.secp256k1_musig_nonce_gen_counter(
      context,
      secnonce,
      pubnonce,
      nonrepeatingCounter,
      keypair,
      message,
      keyaggCache,
      extraInput,
    ),
  );
}

export function secp256k1_musig_nonce_agg(
  context: Context,
  aggnonce: Uint8Array,
  pubnonces: PointerArray,
  size: number | bigint,
): boolean {
  return bool(
    lib.secp256k1_musig_nonce_agg(
      context,
      aggnonce,
      asPointerBytes(pubnonces),
      asUsize(size),
    ),
  );
}

export function secp256k1_musig_nonce_process(
  context: Context,
  session: Uint8Array,
  aggnonce: Uint8Array,
  message: Uint8Array,
  keyaggCache: Uint8Array,
): boolean {
  return bool(
    lib.secp256k1_musig_nonce_process(
      context,
      session,
      aggnonce,
      message,
      keyaggCache,
    ),
  );
}

export function secp256k1_musig_partial_sign(
  context: Context,
  partialSignature: Uint8Array,
  secnonce: Uint8Array,
  keypair: Uint8Array,
  keyaggCache: Uint8Array,
  session: Uint8Array,
): boolean {
  return bool(
    lib.secp256k1_musig_partial_sign(
      context,
      partialSignature,
      secnonce,
      keypair,
      keyaggCache,
      session,
    ),
  );
}

export function secp256k1_musig_partial_sig_verify(
  context: Context,
  partialSignature: Uint8Array,
  pubnonce: Uint8Array,
  pubkey: Uint8Array,
  keyaggCache: Uint8Array,
  session: Uint8Array,
): boolean {
  return bool(
    lib.secp256k1_musig_partial_sig_verify(
      context,
      partialSignature,
      pubnonce,
      pubkey,
      keyaggCache,
      session,
    ),
  );
}

export function secp256k1_musig_partial_sig_agg(
  context: Context,
  signature: Uint8Array,
  session: Uint8Array,
  partialSignatures: PointerArray,
  size: number | bigint,
): boolean {
  return bool(
    lib.secp256k1_musig_partial_sig_agg(
      context,
      signature,
      session,
      asPointerBytes(partialSignatures),
      asUsize(size),
    ),
  );
}
