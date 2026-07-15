import { withStaticContext } from '../native/context.ts';
import { getNativeSymbols } from '../native/loader.ts';

/**
 * Reports that Web Crypto returned an invalid secp256k1 secret scalar.
 *
 * @since 1.0.3
 */
export class SecretKeyRandomError extends Error {
  /**
   * Creates a fail-closed secret-key randomness error.
   *
   * @since 1.0.3
   */
  constructor() {
    super('Web Crypto returned an invalid secp256k1 secret scalar');
    this.name = 'SecretKeyRandomError';
  }
}

/** Fills and validates one secret-scalar sample without retrying. */
export function fillRandomSecretKey(candidate: Uint8Array): void {
  crypto.getRandomValues(candidate);
  if (!isValidSecretKey(candidate)) {
    throw new SecretKeyRandomError();
  }
}

/** Validates a secret scalar with libsecp256k1. */
export function isValidSecretKey(bytes: Uint8Array): boolean {
  const symbols = getNativeSymbols();
  return withStaticContext((context) =>
    symbols.secp256k1_ec_seckey_verify(context, bytes) === 1
  );
}
