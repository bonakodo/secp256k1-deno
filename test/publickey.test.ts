import { assertEquals, assertThrows, N } from './deps.ts';
import * as secp256k1 from '../src/lib.ts';

Deno.test('publicKeyCreate', () => {
  let secretKey = new Uint8Array(31);
  crypto.getRandomValues(secretKey);
  assertThrows(
    () => secp256k1.publicKeyCreate(secretKey),
    Error,
    'The argument must be 32 bytes long',
  );
  secretKey = new Uint8Array(32);
  crypto.getRandomValues(secretKey);
  let publicKey = secp256k1.publicKeyCreate(secretKey);
  assertEquals(
    publicKey.length,
    33,
    'Public key length should be 33 when `compressed` is omitted',
  );
  publicKey = secp256k1.publicKeyCreate(secretKey, false);
  assertEquals(
    publicKey.length,
    65,
    'Public key length should be 65 when `compressed` is set to false',
  );

  // deno-fmt-ignore
  secretKey = new Uint8Array([
    0xf8, 0x5d, 0x4b, 0xd8, 0xa0, 0x3c, 0xa1, 0x06, 0xc9, 0xde, 0xb4, 0x7b,
    0x79, 0x18, 0x03, 0xda, 0xc7, 0xf0, 0x33, 0x38, 0x09, 0xe3, 0xf1, 0xdd,
    0x04, 0xd1, 0x82, 0xe0, 0xab, 0xa6, 0xe5, 0x53,
  ]);
  publicKey = secp256k1.publicKeyCreate(secretKey);
  // deno-fmt-ignore
  assertEquals(
    publicKey,
    new Uint8Array([
      0x03, 0x76, 0xea, 0x9e, 0x36, 0xa7, 0x5d, 0x2e, 0xcf, 0x9c, 0x93, 0xa0,
      0xbe, 0x76, 0x88, 0x5e, 0x36, 0xf8, 0x22, 0x52, 0x9d, 0xb2, 0x2a, 0xcf,
      0xdc, 0x76, 0x1c, 0x9b, 0x5b, 0x45, 0x44, 0xf5, 0xc5,
    ]),
    "The public key should be equal to the fixture"
  );
});

Deno.test('publicKeyVerify', () => {
  const secretKey = new Uint8Array(32);
  crypto.getRandomValues(secretKey);
  const publicKey = secp256k1.publicKeyCreate(secretKey);
  assertEquals(
    true,
    secp256k1.publicKeyVerify(publicKey),
    'Should return true for generated public key',
  );
  assertEquals(
    false,
    secp256k1.publicKeyVerify(publicKey.slice(1)),
    'Should return false for a 32-byte public key',
  );
  publicKey[0] = 0xff;
  assertEquals(
    false,
    secp256k1.publicKeyVerify(publicKey),
    'Should return false for a malformed first byte',
  );
});

Deno.test('publicKeyCombine', () => {
  const secretKey1 = new Uint8Array(32);
  crypto.getRandomValues(secretKey1);
  const publicKey1 = secp256k1.publicKeyCreate(secretKey1);

  const secretKey2 = new Uint8Array(32);
  crypto.getRandomValues(secretKey2);
  const publicKey2 = secp256k1.publicKeyCreate(secretKey2);

  const result = secp256k1.publicKeyCombine([publicKey1, publicKey2]);
  assertEquals(result.length, 33, 'Result must be a 33 byte array');
});

Deno.test('publicKeyTweakAdd', () => {
  const secretKey = new Uint8Array(32);
  crypto.getRandomValues(secretKey);
  const publicKey = secp256k1.publicKeyCreate(secretKey);
  /* If pubkey_tweak_add is called with an overflowing tweak, the pubkey is zeroized. */
  const tweak = N();
  assertThrows(
    () => {
      secp256k1.publicKeyTweakAdd(publicKey, tweak);
    },
    Error,
    'Could not add the tweak to the public key',
  );

  /* If the resulting key in secp256k1_ec_seckey_tweak_add and
   * secp256k1_ec_pubkey_tweak_add is 0 the functions fail and in the latter
   * case the pubkey is zeroized. */
});
Deno.test('publicKeyTweakMul', () => {
  /* If pubkey_tweak_mul is called with an overflowing tweak, the pubkey is zeroized. */
  const secretKey = new Uint8Array(32);
  crypto.getRandomValues(secretKey);
  const publicKey = secp256k1.publicKeyCreate(secretKey);
  /* If pubkey_tweak_add is called with an overflowing tweak, the pubkey is zeroized. */
  const tweak = N();
  assertThrows(
    () => {
      secp256k1.publicKeyTweakMul(publicKey, tweak);
    },
    Error,
    'Could not multiply the public key by the tweak',
  );
});
