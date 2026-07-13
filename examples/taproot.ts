#!/usr/bin/env -S deno run --no-lock --import-map=doc.import-map.json --allow-env=DENO_SECP256K1_PATH --allow-ffi
// deno-lint-ignore-file no-import-prefix

import {
  checkTaprootTweak,
  taprootTweakPublicKey,
  XOnlyPublicKey,
} from 'jsr:@bonakodo/secp256k1@1/taproot.ts';

const internalKey = XOnlyPublicKey.parse(
  Uint8Array.from(
    '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
      .match(/../g) ?? [],
    (byte) => parseInt(byte, 16),
  ),
);
const output = taprootTweakPublicKey({ internalKey, merkleRoot: null });

if (
  !checkTaprootTweak({
    internalKey,
    merkleRoot: null,
    outputKey: output.outputKey,
    outputKeyParity: output.outputKeyParity,
  })
) {
  throw new Error('Taproot output key did not pass its tweak check');
}
