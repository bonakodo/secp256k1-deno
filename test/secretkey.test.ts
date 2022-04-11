import { assertEquals, assertNotEquals, assertThrows, N, ONE } from './deps.ts';
import * as secp256k1 from '../src/lib.ts';

Deno.test('secretKeyVerify', () => {
  let secretKey = new Uint8Array(32);
  assertEquals(
    false,
    secp256k1.secretKeyVerify(secretKey),
    'All zeroes secret key should fail',
  );
  // deno-fmt-ignore
  secretKey = new Uint8Array([
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
    0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
  ]);
  assertEquals(
    false,
    secp256k1.secretKeyVerify(secretKey),
    'A secret key of order N should fail',
  );
  secretKey = new Uint8Array(32);
  crypto.getRandomValues(secretKey);
  assertEquals(
    true,
    secp256k1.secretKeyVerify(secretKey),
    'Random key should pass (most of the time)',
  );
});

Deno.test('secretKeyNegate', () => {
  let secretKey = new Uint8Array(32);
  crypto.getRandomValues(secretKey);
  let secretKeyTmp = new Uint8Array(secretKey);
  secp256k1.secretKeyNegate(secretKey);
  assertNotEquals(
    secretKey,
    secretKeyTmp,
    'The key should not be equal to its negated value',
  );
  secp256k1.secretKeyNegate(secretKey);
  assertEquals(
    secretKey,
    secretKeyTmp,
    'The key should be equal to its double negated value',
  );
  secretKey = new Uint8Array(32);
  secretKeyTmp = new Uint8Array(secretKey);
  assertEquals(
    false,
    secp256k1.secretKeyNegate(secretKey),
    'Negation should fail for all zeroes secret key',
  );
  assertEquals(
    secretKey,
    secretKeyTmp,
    'The secret key should not be modified if negation fails',
  );

  /* Negating an overflowing seckey fails and the seckey is zeroed. In this
   * test, the seckey has 16 random bytes to ensure that ec_seckey_negate
   * doesn't just set seckey to a constant value in case of failure. */
  secretKey = new Uint8Array(32);
  crypto.getRandomValues(secretKey);
  secretKey.fill(0xff, 0, 16);
  assertEquals(
    false,
    secp256k1.secretKeyNegate(secretKey),
    'Negating an overflowing secret key should fail',
  );
  assertEquals(
    secretKey,
    new Uint8Array(32),
    'Negating an overflowing secret should set it to all zeroes',
  );
});

Deno.test('secretKeyTweakAdd', () => {
  let secretKey = new Uint8Array(32);
  crypto.getRandomValues(secretKey);
  let tweak = new Uint8Array(31);
  crypto.getRandomValues(tweak);
  assertThrows(
    () => secp256k1.secretKeyTweakAdd(secretKey, tweak),
    Error,
    'The argument must be 32 bytes long',
  );
  // deno-fmt-ignore
  secretKey = new Uint8Array([
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    254, 186, 174, 220, 230, 175, 72, 160, 59, 191, 210, 94, 140, 208, 54, 65,
    64,
  ]);
  tweak = ONE(); // 1
  assertEquals(false, secp256k1.secretKeyTweakAdd(secretKey, tweak));
  assertEquals(secretKey, new Uint8Array(32), 'Secret key should be zeroes');
  secretKey = ONE();
  secp256k1.secretKeyTweakAdd(secretKey, tweak);
  assertEquals(
    secretKey,
    new Uint8Array(32).fill(2, 31, 32),
    'One plus one should equal two',
  );
});

Deno.test('secretKeyTweakMul', () => {
  let secretKey = ONE();
  let tweak = ONE();
  secp256k1.secretKeyTweakMul(secretKey, tweak);
  assertEquals(secretKey, ONE(), 'One times one should equal one');
  secretKey = new Uint8Array(32);
  crypto.getRandomValues(secretKey);
  tweak = N();
  assertEquals(
    false,
    secp256k1.secretKeyTweakMul(secretKey, tweak),
    'Should fail when tweak equals N',
  );
  assertEquals(
    secretKey,
    new Uint8Array(32),
    'Secret key should be zeroed out after failure',
  );
  crypto.getRandomValues(secretKey);
  assertEquals(
    false,
    secp256k1.secretKeyTweakMul(secretKey, new Uint8Array(32)),
    'Should fail when tweak equals zero',
  );
});
