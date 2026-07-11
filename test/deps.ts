export {
  assert,
  assertEquals,
  assertNotEquals,
  assertThrows,
} from 'jsr:@std/assert@1';

export const ONE = () => new Uint8Array(32).fill(1, 31, 32);
// deno-fmt-ignore
export const N = () => new Uint8Array([
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    254, 186, 174, 220, 230, 175, 72, 160, 59, 191, 210, 94, 140, 208, 54, 65,
    65,
  ]);

export const N_BIGINT = BigInt(
  '0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',
);

export const FIELD_P = () =>
  hexToBytes(
    'fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f',
  );

export const HALF_N = () => scalarFromBigInt(N_BIGINT / 2n);

export const HALF_N_PLUS_ONE = () => scalarFromBigInt(N_BIGINT / 2n + 1n);

export function hexToBytes(hex: string) {
  if (hex.length % 2 !== 0) throw new Error('hex length must be even');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function scalarFromBigInt(value: bigint) {
  const out = new Uint8Array(32);
  let remaining = value;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return out;
}
