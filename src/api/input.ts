/** Programmer-facing input errors for trusted parsing APIs. */

/**
 * Reports malformed bytes passed to a throwing public value constructor.
 *
 * Network-facing code should prefer the corresponding `tryFromBytes` or
 * `tryParse` method, which returns `null` for malformed peer input. Native
 * configuration and loading failures are never converted to this error.
 *
 * @since 1.0.0
 */
export class Secp256k1InputError extends TypeError {
  /**
   * A stable name for the value that failed validation.
   *
   * @since 1.0.0
   */
  readonly inputName: string;

  /**
   * Creates an input error for a trusted parsing API.
   *
   * @param inputName Name of the rejected value.
   * @param message Human-readable validation failure.
   * @since 1.0.0
   */
  constructor(inputName: string, message: string) {
    super(`${inputName}: ${message}`);
    this.name = 'Secp256k1InputError';
    this.inputName = inputName;
  }
}

/** Returns a detached copy when `bytes` has exactly `length` bytes. */
export function copyExact(
  bytes: Uint8Array,
  length: number,
): Uint8Array | null {
  return bytes.length === length ? bytes.slice() : null;
}

/** Throws the public trusted-input error used by throwing constructors. */
export function invalidInput(inputName: string, message: string): never {
  throw new Secp256k1InputError(inputName, message);
}
