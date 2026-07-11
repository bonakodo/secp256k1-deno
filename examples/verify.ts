#!/usr/bin/env -S deno run --no-lock --import-map=doc.import-map.json --allow-env=DENO_SECP256K1_PATH --allow-ffi
// deno-lint-ignore-file no-import-prefix

import {
  Digest32,
  EcdsaCompactSignature,
  PublicKey,
  verifyEcdsa,
} from 'jsr:@bonakodo/secp256k1@1';

const hex = (value: string): Uint8Array =>
  Uint8Array.from(value.match(/../g) ?? [], (byte) => parseInt(byte, 16));

const digest = Digest32.fromBytes(
  hex('dade12e06a5bbf5e1116f9bc44998b876813e948e10707dcb48008a1daf3512d'),
);
const publicKey = PublicKey.parse(
  hex('0376ea9e36a75d2ecf9c93a0be76885e36f822529db22acfdc761c9b5b4544f5c5'),
);
const signature = EcdsaCompactSignature.fromBytes(
  hex(
    'ab4c6d9ba51da83072615c33a9887b756478e6f9de381085f5183c97603fc6ff' +
      '29722188bd937f54c861582ca6fc685b8da2b40d05f06b368374d35e4af2b764',
  ),
).decode();

if (signature === null || !verifyEcdsa(signature, digest, publicKey)) {
  throw new Error('valid ECDSA fixture did not verify');
}
