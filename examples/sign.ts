#!/usr/bin/env -S deno run --no-lock --import-map=doc.import-map.json --allow-env=DENO_SECP256K1_PATH --allow-ffi
// deno-lint-ignore-file no-import-prefix

import { Digest32, verifyEcdsa } from 'jsr:@bonakodo/secp256k1@1';
import { SecretKey, signEcdsa } from 'jsr:@bonakodo/secp256k1@1/signing.ts';

const secretBytes = new Uint8Array(32);
secretBytes[31] = 1;
using secretKey = SecretKey.fromBytes(secretBytes);
const digest = Digest32.fromBytes(new Uint8Array(32));
const signature = signEcdsa(digest, secretKey);

if (!verifyEcdsa(signature, digest, secretKey.publicKey())) {
  throw new Error('fresh ECDSA signature did not verify');
}
