/**
 * Optional Deno FFI descriptors for the libsecp256k1 ABI used by the Bitcoin
 * API. Core compatibility targets ABI 6, but availability is established only
 * from symbols; no library-version string is parsed.
 */

/** Documented compatible libsecp256k1 core ABI. */
export const SUPPORTED_CORE_ABI = 6;

/**
 * Native symbol descriptors. Every entry is optional so a library can be
 * opened before core completeness and module capabilities are validated.
 */
export const nativeSymbolDefinitions = {
  /** Address of the exported static verification context pointer. */
  secp256k1_context_static: { type: 'pointer', optional: true },

  /** Runs libsecp256k1's built-in self-test. */
  secp256k1_selftest: {
    parameters: [],
    result: 'void',
    optional: true,
  },
  /** Creates a mutable context using `SECP256K1_CONTEXT_NONE`. */
  secp256k1_context_create: {
    parameters: ['u32'],
    result: 'pointer',
    optional: true,
  },
  /** Destroys a mutable context. */
  secp256k1_context_destroy: {
    parameters: ['pointer'],
    result: 'void',
    optional: true,
  },
  /** Randomizes a mutable context with a 32-byte seed. */
  secp256k1_context_randomize: {
    parameters: ['pointer', 'buffer'],
    result: 'i32',
    optional: true,
  },

  /** Validates a secret key scalar. */
  secp256k1_ec_seckey_verify: {
    parameters: ['pointer', 'buffer'],
    result: 'i32',
    optional: true,
  },
  /** Negates a secret key scalar in place. */
  secp256k1_ec_seckey_negate: {
    parameters: ['pointer', 'buffer'],
    result: 'i32',
    optional: true,
  },
  /** Adds a tweak to a secret key scalar in place. */
  secp256k1_ec_seckey_tweak_add: {
    parameters: ['pointer', 'buffer', 'buffer'],
    result: 'i32',
    optional: true,
  },

  /** Parses a serialized public key. */
  secp256k1_ec_pubkey_parse: {
    parameters: ['pointer', 'buffer', 'buffer', 'usize'],
    result: 'i32',
    optional: true,
  },
  /** Serializes an internal public key. */
  secp256k1_ec_pubkey_serialize: {
    parameters: ['pointer', 'buffer', 'buffer', 'buffer', 'u32'],
    result: 'i32',
    optional: true,
  },
  /** Creates a public key from a secret key. */
  secp256k1_ec_pubkey_create: {
    parameters: ['pointer', 'buffer', 'buffer'],
    result: 'i32',
    optional: true,
  },
  /** Negates an internal public key in place. */
  secp256k1_ec_pubkey_negate: {
    parameters: ['pointer', 'buffer'],
    result: 'i32',
    optional: true,
  },
  /** Combines an array of internal public-key pointers. */
  secp256k1_ec_pubkey_combine: {
    parameters: ['pointer', 'buffer', 'buffer', 'usize'],
    result: 'i32',
    optional: true,
  },
  /** Adds a tweak to an internal public key in place. */
  secp256k1_ec_pubkey_tweak_add: {
    parameters: ['pointer', 'buffer', 'buffer'],
    result: 'i32',
    optional: true,
  },

  /** Parses a compact ECDSA signature. */
  secp256k1_ecdsa_signature_parse_compact: {
    parameters: ['pointer', 'buffer', 'buffer'],
    result: 'i32',
    optional: true,
  },
  /** Serializes a compact ECDSA signature. */
  secp256k1_ecdsa_signature_serialize_compact: {
    parameters: ['pointer', 'buffer', 'buffer'],
    result: 'i32',
    optional: true,
  },
  /** Parses a DER-encoded ECDSA signature. */
  secp256k1_ecdsa_signature_parse_der: {
    parameters: ['pointer', 'buffer', 'buffer', 'usize'],
    result: 'i32',
    optional: true,
  },
  /** Serializes a DER-encoded ECDSA signature. */
  secp256k1_ecdsa_signature_serialize_der: {
    parameters: ['pointer', 'buffer', 'buffer', 'buffer'],
    result: 'i32',
    optional: true,
  },
  /** Normalizes an ECDSA signature to low-S form. */
  secp256k1_ecdsa_signature_normalize: {
    parameters: ['pointer', 'buffer', 'buffer'],
    result: 'i32',
    optional: true,
  },
  /** Creates a deterministic ECDSA signature. */
  secp256k1_ecdsa_sign: {
    parameters: ['pointer', 'buffer', 'buffer', 'buffer', 'pointer', 'pointer'],
    result: 'i32',
    optional: true,
  },
  /** Verifies an ECDSA signature. */
  secp256k1_ecdsa_verify: {
    parameters: ['pointer', 'buffer', 'buffer', 'buffer'],
    result: 'i32',
    optional: true,
  },
  /** Computes a BIP340-style tagged SHA-256 hash. */
  secp256k1_tagged_sha256: {
    parameters: ['pointer', 'buffer', 'buffer', 'usize', 'buffer', 'usize'],
    result: 'i32',
    optional: true,
  },

  /** Parses a 32-byte x-only public key. */
  secp256k1_xonly_pubkey_parse: {
    parameters: ['pointer', 'buffer', 'buffer'],
    result: 'i32',
    optional: true,
  },
  /** Serializes an x-only public key. */
  secp256k1_xonly_pubkey_serialize: {
    parameters: ['pointer', 'buffer', 'buffer'],
    result: 'i32',
    optional: true,
  },
  /** Compares two x-only public keys. */
  secp256k1_xonly_pubkey_cmp: {
    parameters: ['pointer', 'buffer', 'buffer'],
    result: 'i32',
    optional: true,
  },
  /** Converts a full public key to x-only form and parity. */
  secp256k1_xonly_pubkey_from_pubkey: {
    parameters: ['pointer', 'buffer', 'buffer', 'buffer'],
    result: 'i32',
    optional: true,
  },
  /** Adds a tweak to an x-only public key. */
  secp256k1_xonly_pubkey_tweak_add: {
    parameters: ['pointer', 'buffer', 'buffer', 'buffer'],
    result: 'i32',
    optional: true,
  },
  /** Checks an x-only public-key tweak result. */
  secp256k1_xonly_pubkey_tweak_add_check: {
    parameters: ['pointer', 'buffer', 'i32', 'buffer', 'buffer'],
    result: 'i32',
    optional: true,
  },
  /** Creates a keypair from a secret key. */
  secp256k1_keypair_create: {
    parameters: ['pointer', 'buffer', 'buffer'],
    result: 'i32',
    optional: true,
  },
  /** Extracts a secret key from a keypair. */
  secp256k1_keypair_sec: {
    parameters: ['pointer', 'buffer', 'buffer'],
    result: 'i32',
    optional: true,
  },
  /** Extracts a full public key from a keypair. */
  secp256k1_keypair_pub: {
    parameters: ['pointer', 'buffer', 'buffer'],
    result: 'i32',
    optional: true,
  },
  /** Extracts an x-only public key and parity from a keypair. */
  secp256k1_keypair_xonly_pub: {
    parameters: ['pointer', 'buffer', 'buffer', 'buffer'],
    result: 'i32',
    optional: true,
  },
  /** Applies an x-only tweak to a keypair in place. */
  secp256k1_keypair_xonly_tweak_add: {
    parameters: ['pointer', 'buffer', 'buffer'],
    result: 'i32',
    optional: true,
  },

  /** Signs a 32-byte message with BIP340 Schnorr. */
  secp256k1_schnorrsig_sign32: {
    parameters: ['pointer', 'buffer', 'buffer', 'buffer', 'buffer'],
    result: 'i32',
    optional: true,
  },
  /** Verifies a Schnorr signature. */
  secp256k1_schnorrsig_verify: {
    parameters: ['pointer', 'buffer', 'buffer', 'usize', 'buffer'],
    result: 'i32',
    optional: true,
  },

  /** Creates a BIP324 ElligatorSwift encoding from a secret key. */
  secp256k1_ellswift_create: {
    parameters: ['pointer', 'buffer', 'buffer', 'buffer'],
    result: 'i32',
    optional: true,
  },
  /** Computes ElligatorSwift XDH with a caller-selected hash function. */
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
    optional: true,
  },
  /** Address of the exported BIP324 ElligatorSwift XDH hash pointer. */
  secp256k1_ellswift_xdh_hash_function_bip324: {
    type: 'pointer',
    optional: true,
  },

  /** Parses a serialized MuSig public nonce. */
  secp256k1_musig_pubnonce_parse: {
    parameters: ['pointer', 'buffer', 'buffer'],
    result: 'i32',
    optional: true,
  },
  /** Serializes a MuSig public nonce. */
  secp256k1_musig_pubnonce_serialize: {
    parameters: ['pointer', 'buffer', 'buffer'],
    result: 'i32',
    optional: true,
  },
  /** Parses a serialized MuSig aggregate nonce. */
  secp256k1_musig_aggnonce_parse: {
    parameters: ['pointer', 'buffer', 'buffer'],
    result: 'i32',
    optional: true,
  },
  /** Serializes a MuSig aggregate nonce. */
  secp256k1_musig_aggnonce_serialize: {
    parameters: ['pointer', 'buffer', 'buffer'],
    result: 'i32',
    optional: true,
  },
  /** Parses a serialized MuSig partial signature. */
  secp256k1_musig_partial_sig_parse: {
    parameters: ['pointer', 'buffer', 'buffer'],
    result: 'i32',
    optional: true,
  },
  /** Serializes a MuSig partial signature. */
  secp256k1_musig_partial_sig_serialize: {
    parameters: ['pointer', 'buffer', 'buffer'],
    result: 'i32',
    optional: true,
  },
  /** Aggregates MuSig participant public keys. */
  secp256k1_musig_pubkey_agg: {
    parameters: ['pointer', 'buffer', 'buffer', 'buffer', 'usize'],
    result: 'i32',
    optional: true,
  },
  /** Extracts the full public key from a MuSig key-aggregation cache. */
  secp256k1_musig_pubkey_get: {
    parameters: ['pointer', 'buffer', 'buffer'],
    result: 'i32',
    optional: true,
  },
  /** Applies an ordinary EC tweak to a MuSig aggregate public key. */
  secp256k1_musig_pubkey_ec_tweak_add: {
    parameters: ['pointer', 'buffer', 'buffer', 'buffer'],
    result: 'i32',
    optional: true,
  },
  /** Applies an x-only tweak to a MuSig aggregate public key. */
  secp256k1_musig_pubkey_xonly_tweak_add: {
    parameters: ['pointer', 'buffer', 'buffer', 'buffer'],
    result: 'i32',
    optional: true,
  },
  /** Generates a MuSig secret/public nonce pair from session randomness. */
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
    optional: true,
  },
  /** Generates a MuSig secret/public nonce pair from a counter. */
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
    optional: true,
  },
  /** Aggregates MuSig public nonces. */
  secp256k1_musig_nonce_agg: {
    parameters: ['pointer', 'buffer', 'buffer', 'usize'],
    result: 'i32',
    optional: true,
  },
  /** Initializes a MuSig signing session from an aggregate nonce. */
  secp256k1_musig_nonce_process: {
    parameters: ['pointer', 'buffer', 'buffer', 'buffer', 'buffer'],
    result: 'i32',
    optional: true,
  },
  /** Creates a MuSig partial signature and consumes its secret nonce. */
  secp256k1_musig_partial_sign: {
    parameters: ['pointer', 'buffer', 'buffer', 'buffer', 'buffer', 'buffer'],
    result: 'i32',
    optional: true,
  },
  /** Verifies a MuSig participant's partial signature. */
  secp256k1_musig_partial_sig_verify: {
    parameters: ['pointer', 'buffer', 'buffer', 'buffer', 'buffer', 'buffer'],
    result: 'i32',
    optional: true,
  },
  /** Aggregates MuSig partial signatures into a Schnorr signature. */
  secp256k1_musig_partial_sig_agg: {
    parameters: ['pointer', 'buffer', 'buffer', 'buffer', 'usize'],
    result: 'i32',
    optional: true,
  },
} as const satisfies Deno.ForeignLibraryInterface;

/** Raw, nullable symbol values returned by the all-optional FFI interface. */
export type NativeSymbols = Deno.DynamicLibrary<
  typeof nativeSymbolDefinitions
>['symbols'];

/**
 * Names an independently detected native feature group.
 *
 * @since 1.0.0
 */
export type NativeCapability =
  | 'core'
  | 'extrakeys'
  | 'schnorrsig'
  | 'ellswift'
  | 'musig';

/** Exact symbols used to establish each independent native capability. */
export const CAPABILITY_SYMBOLS = {
  core: [
    'secp256k1_selftest',
    'secp256k1_context_create',
    'secp256k1_context_destroy',
    'secp256k1_context_randomize',
    'secp256k1_ec_seckey_verify',
    'secp256k1_ec_seckey_negate',
    'secp256k1_ec_seckey_tweak_add',
    'secp256k1_ec_pubkey_parse',
    'secp256k1_ec_pubkey_serialize',
    'secp256k1_ec_pubkey_create',
    'secp256k1_ec_pubkey_negate',
    'secp256k1_ec_pubkey_combine',
    'secp256k1_ec_pubkey_tweak_add',
    'secp256k1_ecdsa_signature_parse_compact',
    'secp256k1_ecdsa_signature_serialize_compact',
    'secp256k1_ecdsa_signature_parse_der',
    'secp256k1_ecdsa_signature_serialize_der',
    'secp256k1_ecdsa_signature_normalize',
    'secp256k1_ecdsa_sign',
    'secp256k1_ecdsa_verify',
    'secp256k1_tagged_sha256',
  ],
  extrakeys: [
    'secp256k1_xonly_pubkey_parse',
    'secp256k1_xonly_pubkey_serialize',
    'secp256k1_xonly_pubkey_cmp',
    'secp256k1_xonly_pubkey_from_pubkey',
    'secp256k1_xonly_pubkey_tweak_add',
    'secp256k1_xonly_pubkey_tweak_add_check',
    'secp256k1_keypair_create',
    'secp256k1_keypair_sec',
    'secp256k1_keypair_pub',
    'secp256k1_keypair_xonly_pub',
    'secp256k1_keypair_xonly_tweak_add',
  ],
  schnorrsig: [
    'secp256k1_schnorrsig_sign32',
    'secp256k1_schnorrsig_verify',
  ],
  ellswift: [
    'secp256k1_ellswift_create',
    'secp256k1_ellswift_xdh',
    'secp256k1_ellswift_xdh_hash_function_bip324',
  ],
  musig: [
    'secp256k1_musig_pubnonce_parse',
    'secp256k1_musig_pubnonce_serialize',
    'secp256k1_musig_aggnonce_parse',
    'secp256k1_musig_aggnonce_serialize',
    'secp256k1_musig_partial_sig_parse',
    'secp256k1_musig_partial_sig_serialize',
    'secp256k1_musig_pubkey_agg',
    'secp256k1_musig_pubkey_get',
    'secp256k1_musig_pubkey_ec_tweak_add',
    'secp256k1_musig_pubkey_xonly_tweak_add',
    'secp256k1_musig_nonce_gen',
    'secp256k1_musig_nonce_gen_counter',
    'secp256k1_musig_nonce_agg',
    'secp256k1_musig_nonce_process',
    'secp256k1_musig_partial_sign',
    'secp256k1_musig_partial_sig_verify',
    'secp256k1_musig_partial_sig_agg',
  ],
} as const satisfies Record<
  NativeCapability,
  readonly (keyof NativeSymbols)[]
>;

/**
 * Availability classification for a native feature group.
 *
 * @since 1.0.0
 */
export type NativeCapabilityState =
  | 'available'
  | 'unavailable'
  | 'incompatible';

/**
 * Structured availability details for one native feature group.
 *
 * @since 1.0.0
 */
export interface NativeCapabilityStatus {
  /**
   * Classification derived only from symbol presence.
   *
   * @since 1.0.0
   */
  readonly state: NativeCapabilityState;
  /**
   * Required symbols not exported by the selected library.
   *
   * @since 1.0.0
   */
  readonly missingSymbols: readonly string[];
}

/**
 * Availability details for every native feature group.
 *
 * @since 1.0.0
 */
export type NativeCapabilityStatuses = Readonly<
  Record<NativeCapability, NativeCapabilityStatus>
>;

type CapabilitySymbolName<C extends NativeCapability> =
  (typeof CAPABILITY_SYMBOLS)[C][number];

/** Raw symbols with the requested capability groups narrowed to non-null. */
export type NativeSymbolsWith<C extends NativeCapability> =
  & NativeSymbols
  & {
    [K in CapabilitySymbolName<C>]-?: NonNullable<NativeSymbols[K]>;
  };

/** Raw symbols after successful core validation. */
export type LoadedCoreSymbols = NativeSymbolsWith<'core'>;

/** Raw symbols after successful core and requested-capability validation. */
export type LoadedCapabilitySymbols<C extends NativeCapability> =
  NativeSymbolsWith<'core' | C>;

/** Internal reader for a non-null exported static-symbol address. */
export type NativeStaticPointerReader = (
  address: NonNullable<Deno.PointerValue>,
) => Deno.PointerValue;

/**
 * Dereferences an exported pointer static such as the static context or the
 * BIP324 EllSwift hash callback. `ForeignStatic` exposes the variable address,
 * not the pointer value stored in that variable. This is intentionally absent
 * from core API paths because Deno currently requires unscoped FFI permission
 * for `UnsafePointerView` memory access.
 */
export function dereferenceStaticPointer(
  address: Deno.PointerValue,
  read: NativeStaticPointerReader = (pointer) =>
    new Deno.UnsafePointerView(pointer).getPointer(0),
): Deno.PointerValue {
  return address === null ? null : read(address);
}
