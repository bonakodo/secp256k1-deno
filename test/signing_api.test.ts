import { assert, assertEquals, assertNotEquals, assertThrows } from './deps.ts';
import { Digest32 } from '../src/api/digest.ts';
import { verifyEcdsa, verifyTaprootSignature } from '../src/api/verify.ts';
import {
  EcdsaSigningError,
  SecretKey,
  SecretKeyDestroyedError,
  signEcdsa,
  signTaprootSignature,
} from '../src/signing.ts';

const GENERATOR = hex(
  '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
);

Deno.test('SecretKey copies, derives keys, and destroys deterministically', () => {
  const input = scalar(1);
  const key = SecretKey.fromBytes(input);
  input.fill(9);
  assertEquals(key.exportBytes(), scalar(1));
  assertEquals(key.publicKey().toCompressedBytes(), GENERATOR);
  assertEquals(key.xOnlyPublicKey().key.toBytes(), GENERATOR.slice(1));
  assertEquals(key.xOnlyPublicKey().parity, 0);
  assertEquals(JSON.stringify(key), '{}');
  assertEquals(String(key).includes(bytesToHex(scalar(1))), false);

  const exported = key.exportBytes();
  exported.fill(8);
  assertEquals(key.exportBytes(), scalar(1));

  key.destroy();
  assert(key.destroyed);
  key.destroy();
  assertThrows(() => key.exportBytes(), SecretKeyDestroyedError);
  assertThrows(() => key.publicKey(), SecretKeyDestroyedError);
});

Deno.test('SecretKey.generate returns independently disposable valid keys', () => {
  using first = SecretKey.generate();
  using second = SecretKey.generate();
  assertEquals(first.exportBytes().length, 32);
  assertEquals(second.exportBytes().length, 32);
  assertNotEquals(first.exportBytes(), new Uint8Array(32));
});

Deno.test('signEcdsa is deterministic, low-S, and verifies', () => {
  using key = SecretKey.fromBytes(scalar(1));
  const digest = Digest32.fromBytes(new Uint8Array(32).fill(0x42));
  const first = signEcdsa(digest, key);
  const second = signEcdsa(digest, key);
  assert(first.isLowS());
  assertEquals(first.toCompact(), second.toCompact());
  assert(verifyEcdsa(first, digest, key.publicKey()));

  const error = new EcdsaSigningError('post-verification-failed', {
    cause: 'fault',
  });
  assertEquals(error.code, 'post-verification-failed');
  assertEquals(error.cause, 'fault');
});

Deno.test('signTaprootSignature post-verifies BIP340 signatures', () => {
  using key = SecretKey.fromBytes(scalar(3));
  assertEquals(
    key.xOnlyPublicKey().key.toBytes(),
    hex('f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9'),
  );
  const digest = Digest32.fromBytes(
    hex('0000000000000000000000000000000000000000000000000000000000000000'),
  );
  const signature = signTaprootSignature(digest, key);
  assert(
    verifyTaprootSignature(signature, digest, key.xOnlyPublicKey().key),
  );
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

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join(
    '',
  );
}
