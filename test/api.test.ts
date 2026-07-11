import { assert, assertEquals, assertNotEquals, assertThrows } from './deps.ts';
import {
  CompressedPublicKey,
  Digest32,
  EcdsaCompactSignature,
  EcdsaDerSignature,
  PublicKey,
  SchnorrSignature,
  Secp256k1InputError,
  verifyEcdsa,
  verifyEcdsaDer,
  verifyTaprootSignature,
  XOnlyPublicKey,
} from '../src/mod.ts';

const GENERATOR_COMPRESSED = hex(
  '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
);
const GENERATOR_UNCOMPRESSED = hex(
  '0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798' +
    '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8',
);
const ECDSA_DIGEST = hex(
  'dade12e06a5bbf5e1116f9bc44998b876813e948e10707dcb48008a1daf3512d',
);
const ECDSA_PUBLIC_KEY = hex(
  '0376ea9e36a75d2ecf9c93a0be76885e36f822529db22acfdc761c9b5b4544f5c5',
);
const ECDSA_COMPACT = hex(
  'ab4c6d9ba51da83072615c33a9887b756478e6f9de381085f5183c97603fc6ff' +
    '29722188bd937f54c861582ca6fc685b8da2b40d05f06b368374d35e4af2b764',
);
const ECDSA_HIGH_S = hex(
  'ab4c6d9ba51da83072615c33a9887b756478e6f9de381085f5183c97603fc6ff' +
    'd68dde77426c80ab379ea7d3590397a32d0c28d9a95835053c5d8b2e854389dd',
);
const ECDSA_DER = hex(
  '3045022100ab4c6d9ba51da83072615c33a9887b756478e6f9de381085f5183c' +
    '97603fc6ff022029722188bd937f54c861582ca6fc685b8da2b40d05f06b3683' +
    '74d35e4af2b764',
);
const GROUP_ORDER = hex(
  'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',
);

Deno.test('Digest32 copies input and output and rejects other lengths', () => {
  const input = new Uint8Array(32).fill(7);
  const digest = Digest32.fromBytes(input);
  input[0] = 9;
  assertEquals(digest.toBytes()[0], 7);

  const output = digest.toBytes();
  output[1] = 9;
  assertEquals(digest.toBytes()[1], 7);
  assertEquals(Digest32.tryFromBytes(new Uint8Array(31)), null);
  assertThrows(
    () => Digest32.fromBytes(new Uint8Array(33)),
    Secp256k1InputError,
  );
});

Deno.test('PublicKey accepts compressed, uncompressed, and hybrid SEC', () => {
  const compressed = PublicKey.parse(GENERATOR_COMPRESSED);
  assertEquals(compressed.sourceEncoding, 'compressed');
  assertEquals(compressed.toCompressedBytes(), GENERATOR_COMPRESSED);
  assertEquals(compressed.toUncompressedBytes(), GENERATOR_UNCOMPRESSED);

  const uncompressed = PublicKey.parse(GENERATOR_UNCOMPRESSED);
  assertEquals(uncompressed.sourceEncoding, 'uncompressed');
  assertEquals(uncompressed.toCompressedBytes(), GENERATOR_COMPRESSED);

  const hybrid = GENERATOR_UNCOMPRESSED.slice();
  hybrid[0] = 0x06; // Generator Y is even.
  const parsedHybrid = PublicKey.parse(hybrid);
  assertEquals(parsedHybrid.sourceEncoding, 'hybrid');
  assertEquals(parsedHybrid.toCompressedBytes(), GENERATOR_COMPRESSED);
  assertEquals(parsedHybrid.toUncompressedBytes(), GENERATOR_UNCOMPRESSED);

  hybrid[0] = 0x07;
  assertEquals(PublicKey.tryParse(hybrid), null);
  assertEquals(PublicKey.tryParse(new Uint8Array(32)), null);
});

Deno.test('PublicKey and CompressedPublicKey isolate mutable buffers', () => {
  const input = GENERATOR_COMPRESSED.slice();
  const key = PublicKey.parse(input);
  input.fill(0);
  assertEquals(key.toCompressedBytes(), GENERATOR_COMPRESSED);

  const output = key.toCompressedBytes();
  output.fill(0);
  assertEquals(key.toCompressedBytes(), GENERATOR_COMPRESSED);

  const compressed = key.toCompressed();
  assert(compressed instanceof CompressedPublicKey);
  const compressedOutput = compressed.toBytes();
  compressedOutput.fill(0);
  assertEquals(compressed.toBytes(), GENERATOR_COMPRESSED);
  assertEquals(
    compressed.toPublicKey().toCompressedBytes(),
    GENERATOR_COMPRESSED,
  );
  assertEquals(CompressedPublicKey.tryParse(GENERATOR_UNCOMPRESSED), null);
});

Deno.test('PublicKey toXOnly reports Y parity and validates x-only keys', () => {
  const even = PublicKey.parse(GENERATOR_COMPRESSED).toXOnly();
  assertEquals(even.parity, 0);
  assertEquals(even.key.toBytes(), GENERATOR_COMPRESSED.slice(1));

  const oddEncoding = GENERATOR_COMPRESSED.slice();
  oddEncoding[0] = 0x03;
  const odd = PublicKey.parse(oddEncoding).toXOnly();
  assertEquals(odd.parity, 1);
  assertEquals(odd.key.toBytes(), even.key.toBytes());

  const input = even.key.toBytes();
  const xOnly = XOnlyPublicKey.parse(input);
  input.fill(0);
  assertEquals(xOnly.toBytes(), GENERATOR_COMPRESSED.slice(1));
  const output = xOnly.toBytes();
  output.fill(0);
  assertEquals(xOnly.toBytes(), GENERATOR_COMPRESSED.slice(1));

  assertEquals(XOnlyPublicKey.tryParse(new Uint8Array(31)), null);
  assertEquals(
    XOnlyPublicKey.tryParse(
      hex('fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f'),
    ),
    null,
  );
});

Deno.test('ECDSA candidates separate syntax, length, and scalar validity', () => {
  const der = EcdsaDerSignature.fromBytes(ECDSA_DER);
  assertEquals(der.toBytes(), ECDSA_DER);
  assertEquals(der.decode()?.toCompact(), ECDSA_COMPACT);

  const compact = EcdsaCompactSignature.fromBytes(ECDSA_COMPACT);
  assertEquals(compact.decode()?.toDer(), ECDSA_DER);
  assertEquals(EcdsaCompactSignature.tryFromBytes(new Uint8Array(63)), null);

  const zeroDer = EcdsaDerSignature.fromBytes(hex('3006020100020101'));
  assertEquals(zeroDer.decode(), null);
  const orderDer = strictDer(GROUP_ORDER, hex('01'));
  assert(EcdsaDerSignature.tryFromBytes(orderDer) !== null);
  assertEquals(EcdsaDerSignature.fromBytes(orderDer).decode(), null);

  const zeroCompact = new Uint8Array(64);
  zeroCompact[63] = 1;
  assertEquals(EcdsaCompactSignature.fromBytes(zeroCompact).decode(), null);
  assertEquals(
    EcdsaCompactSignature.fromBytes(
      Uint8Array.from([...GROUP_ORDER, ...new Uint8Array(31), 1]),
    ).decode(),
    null,
  );
});

Deno.test('strict DER candidate rejects malformed encodings', () => {
  assertEquals(EcdsaDerSignature.tryFromBytes(hex('3005020101020101')), null);
  assertEquals(
    EcdsaDerSignature.tryFromBytes(hex('300702020001020101')),
    null,
  );
  assertEquals(
    EcdsaDerSignature.tryFromBytes(hex('3006020180020101')),
    null,
  );
  assertEquals(
    EcdsaDerSignature.tryFromBytes(hex('300602010102010100')),
    null,
  );
  assertThrows(
    () => EcdsaDerSignature.fromBytes(new Uint8Array()),
    Secp256k1InputError,
  );
});

Deno.test('ECDSA values are immutable and normalize high-S', () => {
  const low = EcdsaCompactSignature.fromBytes(ECDSA_COMPACT).decode();
  const high = EcdsaCompactSignature.fromBytes(ECDSA_HIGH_S).decode();
  assert(low !== null && high !== null);
  assert(low.isLowS());
  assertEquals(high.isLowS(), false);
  assertEquals(high.normalize().toCompact(), ECDSA_COMPACT);
  assertEquals(high.toCompact(), ECDSA_HIGH_S);

  const output = low.toCompact();
  output.fill(0);
  assertEquals(low.toCompact(), ECDSA_COMPACT);
});

Deno.test('known ECDSA vector verifies in compact and strict DER forms', () => {
  const digest = Digest32.fromBytes(ECDSA_DIGEST);
  const publicKey = PublicKey.parse(ECDSA_PUBLIC_KEY);
  const low = EcdsaCompactSignature.fromBytes(ECDSA_COMPACT).decode();
  const high = EcdsaCompactSignature.fromBytes(ECDSA_HIGH_S).decode();
  assert(low !== null && high !== null);

  assert(verifyEcdsa(low, digest, publicKey));
  assert(verifyEcdsa(high, digest, publicKey));
  assert(
    verifyEcdsaDer(EcdsaDerSignature.fromBytes(ECDSA_DER), digest, publicKey),
  );

  const changed = ECDSA_DIGEST.slice();
  changed[0] ^= 1;
  assertEquals(verifyEcdsa(low, Digest32.fromBytes(changed), publicKey), false);
  const invalid = EcdsaDerSignature.fromBytes(hex('3006020100020101'));
  assertEquals(verifyEcdsaDer(invalid, digest, publicKey), false);
});

Deno.test('known BIP340 vector verifies and candidates check length only', () => {
  const publicKeyBytes = hex(
    'd69c3509bb99e412e68b0fe8544e72837dfa30746d8be2aa65975f29d22dc7b9',
  );
  const digestBytes = hex(
    '4df3c3f68fcc83b27e9d42c90431a72499f17875c81a599b566c9889b9696703',
  );
  const signatureBytes = hex(
    '00000000000000000000003b78ce563f89a0ed9414f5aa28ad0d96d6795f9c63' +
      '76afb1548af603b3eb45c9f8207dee1060cb71c04e80f593060b07d28308d7f4',
  );
  assertEquals(signatureBytes.length, 64);

  const signature = SchnorrSignature.fromBytes(signatureBytes);
  const publicKey = XOnlyPublicKey.parse(publicKeyBytes);
  const digest = Digest32.fromBytes(digestBytes);
  assert(verifyTaprootSignature(signature, digest, publicKey));

  const allZero = SchnorrSignature.fromBytes(new Uint8Array(64));
  assertEquals(verifyTaprootSignature(allZero, digest, publicKey), false);
  assertEquals(SchnorrSignature.tryFromBytes(new Uint8Array(63)), null);

  const input = signatureBytes.slice();
  const isolated = SchnorrSignature.fromBytes(input);
  input.fill(0);
  assertNotEquals(isolated.toBytes(), input);
  const output = isolated.toBytes();
  output.fill(0);
  assertEquals(isolated.toBytes(), signatureBytes);
});

function hex(value: string): Uint8Array {
  const result = new Uint8Array(value.length / 2);
  for (let index = 0; index < result.length; index++) {
    result[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return result;
}

function strictDer(r: Uint8Array, s: Uint8Array): Uint8Array {
  const positiveR = (r[0] & 0x80) === 0 ? r : Uint8Array.from([0, ...r]);
  const positiveS = (s[0] & 0x80) === 0 ? s : Uint8Array.from([0, ...s]);
  return Uint8Array.from([
    0x30,
    positiveR.length + positiveS.length + 4,
    0x02,
    positiveR.length,
    ...positiveR,
    0x02,
    positiveS.length,
    ...positiveS,
  ]);
}
