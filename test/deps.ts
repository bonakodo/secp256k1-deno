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
