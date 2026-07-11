import { assertEquals, assertThrows, hexToBytes, N } from './deps.ts';
import * as secp256k1 from '../src/lib.ts';

async function bip340TaggedHash(
  message: Uint8Array,
  tag: Uint8Array,
): Promise<Uint8Array> {
  const tagHash = new Uint8Array(
    await crypto.subtle.digest('SHA-256', Uint8Array.from(tag)),
  );
  return new Uint8Array(
    await crypto.subtle.digest(
      'SHA-256',
      Uint8Array.from([...tagHash, ...tagHash, ...message]),
    ),
  );
}

Deno.test('taggedSha256 accepts strings and bytes', async () => {
  const message = new TextEncoder().encode('message');
  const tag = new TextEncoder().encode('tag');

  assertEquals(
    secp256k1.taggedSha256('message', 'tag'),
    await bip340TaggedHash(message, tag),
  );
  assertEquals(
    secp256k1.taggedSha256(message, tag),
    await bip340TaggedHash(message, tag),
  );
});

Deno.test('hexToBytes rejects odd-length hex', () => {
  assertThrows(() => hexToBytes('0'), Error, 'hex length must be even');
});

Deno.test('keypair and x-only public key validation failures', () => {
  const secretKey = new Uint8Array(32);
  secretKey[31] = 11;
  assertEquals(secp256k1.keypairCreate(secretKey).length, 96);

  assertThrows(
    () => secp256k1.keypairCreate(N()),
    Error,
    'Could not create a key pair from the secret key',
  );
  assertThrows(
    () => secp256k1.createXOnlyPublicKey(N()),
    Error,
    'Could not create a key pair from the secret key',
  );
});

Deno.test('ecdsa validation error branches', () => {
  const secretKey = new Uint8Array(32);
  secretKey[31] = 12;
  const message = new Uint8Array(32).fill(13);
  const publicKey = secp256k1.publicKeyCreate(secretKey);
  const { signature, recid } = secp256k1.ecdsaSignRecoverable(
    message,
    secretKey,
  );

  assertThrows(
    () => secp256k1.ecdsaSignRecoverable(message, N()),
    Error,
    'Could not sign the message',
  );

  assertThrows(
    () => {
      secp256k1.ecdsaVerify(
        Uint8Array.from([...N(), ...message]),
        message,
        publicKey,
      );
    },
    Error,
    'Could not parse compact signature',
  );

  const invalidPublicKey = publicKey.slice();
  invalidPublicKey[0] = 0x01;
  assertThrows(
    () => secp256k1.ecdsaVerify(signature, message, invalidPublicKey),
    Error,
    'Could not parse the public key',
  );

  assertThrows(
    () =>
      secp256k1.ecdsaRecover(
        Uint8Array.from([...N(), ...message]),
        recid,
        message,
      ),
    Error,
    'Could not parse the recoverable signature',
  );
});

Deno.test('publicKeyCombine rejects unsupported 32-bit architectures', () => {
  const originalBuild = Deno.build;
  try {
    Object.defineProperty(Deno, 'build', {
      configurable: true,
      value: { ...originalBuild, arch: 'x86' },
    });
    assertThrows(
      () => secp256k1.publicKeyCombine([]),
      Error,
      '32 bit architectures are not currently supported',
    );
  } finally {
    Object.defineProperty(Deno, 'build', {
      configurable: true,
      value: originalBuild,
    });
  }
});

Deno.test('schnorrSign default randomness and validation failures', () => {
  const secretKey = new Uint8Array(32);
  secretKey[31] = 9;
  const message = new Uint8Array(32).fill(10);
  const publicKey = secp256k1.createXOnlyPublicKey(secretKey);
  const signature = secp256k1.schnorrSign(message, secretKey);

  assertEquals(signature.length, 64);
  assertEquals(secp256k1.schnorrVerify(signature, message, publicKey), true);

  assertThrows(
    () => secp256k1.schnorrSign(message, N()),
    Error,
    'Could not create a keypair from the secret key',
  );
  assertThrows(
    () => secp256k1.schnorrVerify(signature.slice(1), message, publicKey),
    Error,
    'The argument must be 64 bytes long',
  );
});
