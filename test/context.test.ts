import { assert, assertThrows } from './deps.ts';
import * as secp256k1 from '../src/lib.ts';

Deno.test('contextRandomize', () => {
  assertThrows(
    () => secp256k1.contextRandomize(new Uint8Array(31)),
    Error,
    'The argument must be 32 bytes long',
  );

  secp256k1.contextRandomize(new Uint8Array(32).fill(1));
  secp256k1.contextRandomize(null);

  const secretKey = new Uint8Array(32);
  secretKey[31] = 1;
  const message = new Uint8Array(32).fill(2);
  const signature = secp256k1.ecdsaSign(message, secretKey);
  const publicKey = secp256k1.publicKeyCreate(secretKey);
  assert(secp256k1.ecdsaVerify(signature, message, publicKey));
});
