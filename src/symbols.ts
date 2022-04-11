export type Context = Deno.UnsafePointer;

export const symbols = {
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
      'pointer', /* const unsigned char *seed32 */
    ],
    result: 'i32', /* int */
  },
  /* Secret key functions */
  secp256k1_ec_seckey_verify: {
    parameters: [
      'pointer', /* const secp256k1_context* ctx */
      'pointer', /* const unsigned char *seckey */
    ],
    result: 'i32', /* int ret */
  },
  secp256k1_ec_seckey_negate: {
    parameters: [
      'pointer', /* const secp256k1_context* ctx */
      'pointer', /* unsigned char *seckey */
    ],
    result: 'i32', /* int */
  },
  secp256k1_ec_seckey_tweak_add: {
    parameters: [
      'pointer', /* const secp256k1_context* ctx */
      'pointer', /* unsigned char *seckey */
      'pointer', /* const unsigned char *tweak32 */
    ],
    result: 'i32', /* int ret */
  },
  secp256k1_ec_seckey_tweak_mul: {
    parameters: [
      'pointer', /* const secp256k1_context* ctx */
      'pointer', /* unsigned char *seckey */
      'pointer', /* const unsigned char *tweak32 */
    ],
    result: 'i32', /* int ret */
  },
  /* Public key functions */
  secp256k1_ec_pubkey_parse: {
    parameters: [
      'pointer', /* const secp256k1_context* ctx */
      'pointer', /* secp256k1_pubkey* pubkey */
      'pointer', /* const unsigned char *input */
      'usize', /* size_t inputlen */
    ],
    result: 'i32', /* int 0 or 1 */
  },
  secp256k1_ec_pubkey_negate: {
    parameters: [
      'pointer', /* const secp256k1_context* ctx */
      'pointer', /* secp256k1_pubkey* pubkey */
    ],
    result: 'i32', /* int ret */
  },
  secp256k1_ec_pubkey_combine: {
    parameters: [
      'pointer', /* const secp256k1_context* ctx */
      'pointer', /* secp256k1_pubkey *pubnonce */
      'pointer', /* const secp256k1_pubkey * const *pubnonces */
      'usize', /* size_t n */
    ],
    result: 'i32', /* int 0 or 1 */
  },
  secp256k1_ec_pubkey_tweak_add: {
    parameters: [
      'pointer', /* const secp256k1_context* ctx */
      'pointer', /* secp256k1_pubkey *pubkey */
      'pointer', /* const unsigned char *tweak32 */
    ],
    result: 'i32', /* int ret */
  },
  secp256k1_ec_pubkey_tweak_mul: {
    parameters: [
      'pointer', /* const secp256k1_context* ctx */
      'pointer', /* secp256k1_pubkey* pubkey */
      'pointer', /* const unsigned char *tweak32 */
    ],
    result: 'i32', /* int ret */
  },
  secp256k1_ec_pubkey_create: {
    parameters: [
      'pointer', /* const secp256k1_context* ctx */
      'pointer', /* secp256k1_pubkey *pubkey */
      'pointer', /* const unsigned char *seckey */
    ],
    result: 'i32', /* int ret */
  },
  secp256k1_ec_pubkey_serialize: {
    parameters: [
      'pointer', /* const secp256k1_context* ctx */
      'pointer', /* unsigned char *output */
      'pointer', /* size_t *outputlen */
      'pointer', /* const secp256k1_pubkey* pubkey */
      'u32', /* unsigned int flags */
    ],
    result: 'i32', /* int ret */
  },
  /* Signature functions */
  secp256k1_ecdsa_signature_normalize: {
    parameters: [
      'pointer', /* const secp256k1_context* ctx */
      'pointer', /* secp256k1_ecdsa_signature *sigout */
      'pointer', /* const secp256k1_ecdsa_signature *sigin */
    ],
    result: 'i32', /* int ret */
  },
  secp256k1_ecdsa_signature_serialize_compact: {
    parameters: [
      'pointer', /* const secp256k1_context* ctx */
      'pointer', /* unsigned char *output64 */
      'pointer', /* const secp256k1_ecdsa_signature* sig */
    ],
    result: 'i32', /* int ret */
  },
  secp256k1_ecdsa_signature_parse_compact: {
    parameters: [
      'pointer', /* const secp256k1_context* ctx */
      'pointer', /* secp256k1_ecdsa_signature *sigout */
      'pointer', /* const secp256k1_ecdsa_signature *sigin */
    ],
    result: 'i32', /* int ret */
  },
  secp256k1_ecdsa_signature_parse_der: {
    parameters: [
      'pointer', /* const secp256k1_context* ctx */
      'pointer', /* secp256k1_ecdsa_signature* sig */
      'pointer', /* const unsigned char *input */
      'usize', /* size_t inputlen */
    ],
    result: 'i32', /* int 0 or 1 */
  },
  secp256k1_ecdsa_signature_serialize_der: {
    parameters: [
      'pointer', /* const secp256k1_context* ctx */
      'pointer', /* unsigned char *output */
      'pointer', /* size_t *outputlen */
      'pointer', /* const secp256k1_ecdsa_signature* sig */
    ],
    result: 'i32', /* int 0 or 1 */
  },
  secp256k1_ecdsa_recover: {
    parameters: [
      'pointer', /* const secp256k1_context* ctx */
      'pointer', /* secp256k1_pubkey *pubkey */
      'pointer', /* const secp256k1_ecdsa_recoverable_signature *signature */
      'pointer', /* const unsigned char *msghash32 */
    ],
    result: 'i32', /* int 0 or 1 */
  },
  secp256k1_ecdsa_recoverable_signature_parse_compact: {
    parameters: [
      'pointer', /* const secp256k1_context* ctx */
      'pointer', /* secp256k1_ecdsa_recoverable_signature* sig */
      'pointer', /* const unsigned char *input64 */
      'i32', /* int recid */
    ],
    result: 'i32', /* int 0 or 1 */
  },
  secp256k1_ecdsa_recoverable_signature_serialize_compact: {
    parameters: [
      'pointer', /* const secp256k1_context* ctx */
      'pointer', /* unsigned char *output64 */
      'pointer', /* int *recid */
      'pointer', /* const secp256k1_ecdsa_recoverable_signature* sig */
    ],
    result: 'i32', /* int 0 or 1 */
  },
  secp256k1_ecdsa_sign_recoverable: {
    parameters: [
      'pointer', /* const secp256k1_context* ctx */
      'pointer', /* secp256k1_ecdsa_recoverable_signature *signature */
      'pointer', /* const unsigned char *msghash32 */
      'pointer', /* const unsigned char *seckey */
      'pointer', /* secp256k1_nonce_function noncefp */
      'pointer', /* const void* noncedata */
    ],
    result: 'i32', /* int ret */
  },
  secp256k1_ecdsa_sign: {
    parameters: [
      'pointer', /* const secp256k1_context* ctx */
      'pointer', /* secp256k1_ecdsa_signature *signature */
      'pointer', /* const unsigned char *msghash32 */
      'pointer', /* const unsigned char *seckey */
      'pointer', /* secp256k1_nonce_function noncefp */
      'pointer', /* const void* noncedata */
    ],
    result: 'i32', /* int ret */
  },
  secp256k1_ecdsa_verify: {
    parameters: [
      'pointer', /* const secp256k1_context* ctx */
      'pointer', /* const secp256k1_ecdsa_signature *sig */
      'pointer', /* const unsigned char *msghash32 */
      'pointer', /* const secp256k1_pubkey *pubkey */
    ],
    result: 'i32', /* int 0 or 1 */
  },
} as const;
