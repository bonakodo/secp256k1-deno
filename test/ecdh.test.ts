import { assertEquals, assertThrows, N } from './deps.ts';
import * as secp256k1 from '../src/lib.ts';

Deno.test('ecdh', () => {
  const secretKey1 = new Uint8Array(32);
  secretKey1[31] = 3;
  const secretKey2 = new Uint8Array(32);
  secretKey2[31] = 4;
  const publicKey1 = secp256k1.publicKeyCreate(secretKey1);
  const publicKey2 = secp256k1.publicKeyCreate(secretKey2);
  const publicKey2Uncompressed = secp256k1.publicKeyCreate(secretKey2, false);

  const shared1 = secp256k1.ecdh(publicKey1, secretKey2);
  const shared2 = secp256k1.ecdh(publicKey2, secretKey1);
  const shared2Uncompressed = secp256k1.ecdh(
    publicKey2Uncompressed,
    secretKey1,
  );

  assertEquals(shared1.length, 32);
  assertEquals(shared1, shared2);
  assertEquals(shared2, shared2Uncompressed);

  assertThrows(
    () => secp256k1.ecdh(publicKey1.slice(1), secretKey2),
    Error,
    'The argument must be 65 bytes long',
  );

  const invalidPublicKey = publicKey1.slice();
  invalidPublicKey[0] = 0x01;
  assertThrows(
    () => secp256k1.ecdh(invalidPublicKey, secretKey2),
    Error,
    'Invalid public key format',
  );

  assertThrows(
    () => secp256k1.ecdh(publicKey1, new Uint8Array(32)),
    Error,
    'Could not compute the ECDH shared secret',
  );
  assertThrows(
    () => secp256k1.ecdh(publicKey1, N()),
    Error,
    'Could not compute the ECDH shared secret',
  );
});
