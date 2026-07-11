import { assertEquals, assertThrows, N } from './deps.ts';
import { Secp256k1InputError } from '../src/api/input.ts';
import {
  addTweakToPublicKey,
  addTweakToSecretKey,
  KeyTweakError,
  Tweak32,
} from '../src/key_tweaks.ts';
import { SecretKey } from '../src/signing.ts';

const TWO_G = hex(
  '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5',
);

Deno.test('Tweak32 copies exact scalars from zero through n-1', () => {
  const zero = new Uint8Array(32);
  const tweak = Tweak32.fromBytes(zero);
  zero.fill(1);
  assertEquals(tweak.toBytes(), new Uint8Array(32));
  assertEquals(Tweak32.tryFromBytes(N()), null);
  assertEquals(Tweak32.tryFromBytes(new Uint8Array(31)), null);
  assertThrows(() => Tweak32.fromBytes(N()), Secp256k1InputError);
});

Deno.test('additive secret and public tweaks agree and do not mutate', () => {
  using original = SecretKey.fromBytes(scalar(1));
  const originalPublic = original.publicKey();
  const tweak = Tweak32.fromBytes(scalar(1));
  using tweakedSecret = addTweakToSecretKey(original, tweak);
  const tweakedPublic = addTweakToPublicKey(originalPublic, tweak);

  assertEquals(tweakedSecret.exportBytes(), scalar(2));
  assertEquals(tweakedSecret.publicKey().toCompressedBytes(), TWO_G);
  assertEquals(tweakedPublic.toCompressedBytes(), TWO_G);
  assertEquals(original.exportBytes(), scalar(1));
});

Deno.test('zero tweak returns independent key values', () => {
  using original = SecretKey.fromBytes(scalar(1));
  const zero = Tweak32.fromBytes(new Uint8Array(32));
  using copied = addTweakToSecretKey(original, zero);
  assertEquals(copied.exportBytes(), original.exportBytes());
  copied.destroy();
  assertEquals(original.exportBytes(), scalar(1));
  assertEquals(
    addTweakToPublicKey(original.publicKey(), zero).toCompressedBytes(),
    original.publicKey().toCompressedBytes(),
  );
});

Deno.test('additive cancellation has typed zero and infinity errors', () => {
  using key = SecretKey.fromBytes(scalar(1));
  const minusOne = N();
  minusOne[31] -= 1;
  const tweak = Tweak32.fromBytes(minusOne);
  const secretError = assertThrows(
    () => addTweakToSecretKey(key, tweak),
    KeyTweakError,
  );
  assertEquals(secretError.code, 'secret-key-zero');
  const publicError = assertThrows(
    () => addTweakToPublicKey(key.publicKey(), tweak),
    KeyTweakError,
  );
  assertEquals(publicError.code, 'public-key-infinity');
});

function scalar(value: number): Uint8Array {
  const bytes = new Uint8Array(32);
  bytes[31] = value;
  return bytes;
}

function hex(value: string): Uint8Array {
  const bytes = new Uint8Array(value.length / 2);
  for (let index = 0; index < bytes.length; index++) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}
