/**
 * Validates if values are {length} bytes long
 * @param length length of bytes
 */
export function assertLength(length: number, ...values: Uint8Array[]): void {
  for (const value of values) {
    if (value.length !== length) {
      throw new Error(`The argument must be ${length} bytes long`);
    }
  }
}
export function assert3365(...values: Uint8Array[]): void {
  try {
    assertLength(33, ...values);
  } catch (_e) {
    assertLength(65, ...values);
  }
}
