import { assert, assertEquals, assertThrows, N } from "./deps.ts";
import * as secp256k1 from "../src/lib.ts";

Deno.test("ecdsaSign", () => {
  const messageHash = new Uint8Array(32);
  const secretKey = new Uint8Array(32);
  assertThrows(
    () => {
      secp256k1.ecdsaSign(messageHash.slice(1), secretKey);
    },
    Error,
    "The argument must be 32 bytes long",
    "Should fail with the message hash of invalid length"
  );
  assertThrows(
    () => {
      secp256k1.ecdsaSign(messageHash, secretKey.slice(1));
    },
    Error,
    "The argument must be 32 bytes long",
    "Should fail with the secret key of invalid length"
  );

  assertThrows(
    () => {
      secp256k1.ecdsaSign(messageHash, N());
    },
    Error,
    "Could not sign the message",
    "Should fail with the secret key equal to N"
  );

  assertThrows(
    () => {
      secp256k1.ecdsaSign(messageHash, new Uint8Array(32));
    },
    Error,
    "Could not sign the message",
    "Should fail with all zeroes secret key"
  );
});

Deno.test("ecdsaVerify", () => {
  const secretKey = new Uint8Array(32);
  let messageHash = new Uint8Array(32);
  crypto.getRandomValues(secretKey);
  crypto.getRandomValues(messageHash);
  let signature = secp256k1.ecdsaSign(messageHash, secretKey);
  let publicKey = secp256k1.publicKeyCreate(secretKey);

  assertEquals(
    false,
    secp256k1.ecdsaVerify(signature.slice(1), messageHash, publicKey),
    "Should return false with a shorter signature"
  );

  messageHash = new Uint8Array([
    0xda, 0xde, 0x12, 0xe0, 0x6a, 0x5b, 0xbf, 0x5e, 0x11, 0x16, 0xf9, 0xbc,
    0x44, 0x99, 0x8b, 0x87, 0x68, 0x13, 0xe9, 0x48, 0xe1, 0x07, 0x07, 0xdc,
    0xb4, 0x80, 0x08, 0xa1, 0xda, 0xf3, 0x51, 0x2d,
  ]);
  publicKey = new Uint8Array([
    0x03, 0x76, 0xea, 0x9e, 0x36, 0xa7, 0x5d, 0x2e, 0xcf, 0x9c, 0x93, 0xa0,
    0xbe, 0x76, 0x88, 0x5e, 0x36, 0xf8, 0x22, 0x52, 0x9d, 0xb2, 0x2a, 0xcf,
    0xdc, 0x76, 0x1c, 0x9b, 0x5b, 0x45, 0x44, 0xf5, 0xc5,
  ]);
  signature = new Uint8Array([
    0xab, 0x4c, 0x6d, 0x9b, 0xa5, 0x1d, 0xa8, 0x30, 0x72, 0x61, 0x5c, 0x33,
    0xa9, 0x88, 0x7b, 0x75, 0x64, 0x78, 0xe6, 0xf9, 0xde, 0x38, 0x10, 0x85,
    0xf5, 0x18, 0x3c, 0x97, 0x60, 0x3f, 0xc6, 0xff, 0x29, 0x72, 0x21, 0x88,
    0xbd, 0x93, 0x7f, 0x54, 0xc8, 0x61, 0x58, 0x2c, 0xa6, 0xfc, 0x68, 0x5b,
    0x8d, 0xa2, 0xb4, 0x0d, 0x05, 0xf0, 0x6b, 0x36, 0x83, 0x74, 0xd3, 0x5e,
    0x4a, 0xf2, 0xb7, 0x64,
  ]);
  assert(secp256k1.ecdsaVerify(signature, messageHash, publicKey));
});

Deno.test("sign/verify", () => {
  const secretKey = new Uint8Array(32);
  const messageHash = new Uint8Array(32);
  crypto.getRandomValues(secretKey);
  crypto.getRandomValues(messageHash);
  const signature = secp256k1.ecdsaSign(messageHash, secretKey);
  const publicKey = secp256k1.publicKeyCreate(secretKey);
  assert(
    secp256k1.ecdsaVerify(signature, messageHash, publicKey),
    "Should successfully verify signature"
  );
});
