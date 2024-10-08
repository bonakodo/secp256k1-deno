import { assertEquals, assertThrows, N, ONE } from './deps.ts';
import * as secp256k1 from '../src/lib.ts';

// fixtures from https://github.com/bitjson/libauth/blob/d04d353019f4710de43f3a527d2d1089a23adb21/src/lib/crypto/secp256k1.spec.ts#L38

// deno-fmt-ignore
const signatureCompact = new Uint8Array([
  0xab, 0x4c, 0x6d, 0x9b, 0xa5, 0x1d, 0xa8, 0x30, 0x72, 0x61, 0x5c, 0x33, 0xa9,
  0x88, 0x7b, 0x75, 0x64, 0x78, 0xe6, 0xf9, 0xde, 0x38, 0x10, 0x85, 0xf5, 0x18,
  0x3c, 0x97, 0x60, 0x3f, 0xc6, 0xff, 0x29, 0x72, 0x21, 0x88, 0xbd, 0x93, 0x7f,
  0x54, 0xc8, 0x61, 0x58, 0x2c, 0xa6, 0xfc, 0x68, 0x5b, 0x8d, 0xa2, 0xb4, 0x0d,
  0x05, 0xf0, 0x6b, 0x36, 0x83, 0x74, 0xd3, 0x5e, 0x4a, 0xf2, 0xb7, 0x64,
]);

// deno-fmt-ignore
const signatureDER = new Uint8Array([
  0x30, 0x45, 0x02, 0x21, 0x00, 0xab, 0x4c, 0x6d, 0x9b, 0xa5, 0x1d, 0xa8, 0x30,
  0x72, 0x61, 0x5c, 0x33, 0xa9, 0x88, 0x7b, 0x75, 0x64, 0x78, 0xe6, 0xf9, 0xde,
  0x38, 0x10, 0x85, 0xf5, 0x18, 0x3c, 0x97, 0x60, 0x3f, 0xc6, 0xff, 0x02, 0x20,
  0x29, 0x72, 0x21, 0x88, 0xbd, 0x93, 0x7f, 0x54, 0xc8, 0x61, 0x58, 0x2c, 0xa6,
  0xfc, 0x68, 0x5b, 0x8d, 0xa2, 0xb4, 0x0d, 0x05, 0xf0, 0x6b, 0x36, 0x83, 0x74,
  0xd3, 0x5e, 0x4a, 0xf2, 0xb7, 0x64,
]);

// const signatureDERHighS = new Uint8Array([
//   0x30, 0x46, 0x02, 0x21, 0x00, 0xab, 0x4c, 0x6d, 0x9b, 0xa5, 0x1d, 0xa8, 0x30,
//   0x72, 0x61, 0x5c, 0x33, 0xa9, 0x88, 0x7b, 0x75, 0x64, 0x78, 0xe6, 0xf9, 0xde,
//   0x38, 0x10, 0x85, 0xf5, 0x18, 0x3c, 0x97, 0x60, 0x3f, 0xc6, 0xff, 0x02, 0x21,
//   0x00, 0xd6, 0x8d, 0xde, 0x77, 0x42, 0x6c, 0x80, 0xab, 0x37, 0x9e, 0xa7, 0xd3,
//   0x59, 0x03, 0x97, 0xa3, 0x2d, 0x0c, 0x28, 0xd9, 0xa9, 0x58, 0x35, 0x05, 0x3c,
//   0x5d, 0x8b, 0x2e, 0x85, 0x43, 0x89, 0xdd,
// ]);

// deno-fmt-ignore
const signatureCompactHighS = new Uint8Array([
  0xab, 0x4c, 0x6d, 0x9b, 0xa5, 0x1d, 0xa8, 0x30, 0x72, 0x61, 0x5c, 0x33, 0xa9,
  0x88, 0x7b, 0x75, 0x64, 0x78, 0xe6, 0xf9, 0xde, 0x38, 0x10, 0x85, 0xf5, 0x18,
  0x3c, 0x97, 0x60, 0x3f, 0xc6, 0xff, 0xd6, 0x8d, 0xde, 0x77, 0x42, 0x6c, 0x80,
  0xab, 0x37, 0x9e, 0xa7, 0xd3, 0x59, 0x03, 0x97, 0xa3, 0x2d, 0x0c, 0x28, 0xd9,
  0xa9, 0x58, 0x35, 0x05, 0x3c, 0x5d, 0x8b, 0x2e, 0x85, 0x43, 0x89, 0xdd,
]);

Deno.test('signatureImport', () => {
  /* Invalid signature */
  let signature = new Uint8Array(1);
  assertThrows(
    () => {
      secp256k1.signatureImport(signature);
    },
    Error,
    'Could not parse the signature in DER format',
  );
  /* Valid DER */
  signature = new Uint8Array([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]);
  let compactSignature = secp256k1.signatureImport(signature);
  assertEquals(
    64,
    compactSignature.length,
    'Resulting signature length must be 64 bytes',
  );
  for (let i = 0; i < 64; i++) {
    assertEquals(compactSignature[i], i == 31 || i == 63 ? 1 : 0);
  }

  compactSignature = secp256k1.signatureImport(signatureDER);
  assertEquals(
    compactSignature,
    signatureCompact,
    'Imported compact signature should must the fixture',
  );
});

Deno.test('signatureExport', () => {
  const invalidSignature = Uint8Array.from([...N(), ...ONE()]);
  assertThrows(
    () => {
      secp256k1.signatureExport(invalidSignature);
    },
    Error,
    'Could not parse the signature',
    'Should throw error for signature with r equal to N',
  );
  const exported = secp256k1.signatureExport(signatureCompact);
  assertEquals(
    exported,
    signatureDER,
    'Exported signature should match the fixture',
  );
});

Deno.test('signatureNormalize', () => {
  const normalized = secp256k1.signatureNormalize(
    Uint8Array.from([...signatureCompactHighS]),
  );
  assertEquals(normalized, signatureCompact);
});

Deno.test('export/import', () => {
  const secretKey = new Uint8Array(32);
  crypto.getRandomValues(secretKey);
  const message = new Uint8Array(32);
  crypto.getRandomValues(message);
  const signature = secp256k1.ecdsaSign(message, secretKey);
  const exported = secp256k1.signatureExport(signature);
  const imported = secp256k1.signatureImport(exported);
  assertEquals(
    imported,
    signature,
    'Signature has to remain the same after export / import',
  );
});
