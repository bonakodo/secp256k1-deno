#!/usr/bin/env -S deno run --no-lock --import-map=doc.import-map.json --allow-env=DENO_SECP256K1_PATH --allow-ffi
// deno-lint-ignore-file no-import-prefix

import { verifyTaprootSignature } from 'jsr:@bonakodo/secp256k1@1';
import {
  Digest32,
  MuSigAggregateNonce,
  MuSigKeyAggregation,
  MuSigSecretNonce,
  MuSigSession,
} from 'jsr:@bonakodo/secp256k1@1/musig2';
import { SecretKey } from 'jsr:@bonakodo/secp256k1@1/signing';

const scalar = (value: number): Uint8Array => {
  const bytes = new Uint8Array(32);
  bytes[31] = value;
  return bytes;
};

using firstKey = SecretKey.fromBytes(scalar(1));
using secondKey = SecretKey.fromBytes(scalar(2));
const signingKeys = [firstKey, secondKey] as const;
const aggregation = MuSigKeyAggregation.fromOrderedPublicKeys(
  signingKeys.map((key) => key.publicKey().toCompressed()),
);
const digest = Digest32.fromBytes(new Uint8Array(32).fill(42));
const secretNonces = signingKeys.map((secretKey, participantIndex) =>
  MuSigSecretNonce.generate({
    participantIndex,
    secretKey,
    digest,
    keyAggregation: aggregation,
  })
);
const publicNonces = secretNonces.map((nonce) => nonce.indexedPublicNonce());
const aggregateNonce = MuSigAggregateNonce.aggregate(
  aggregation,
  publicNonces,
);
const session = MuSigSession.create({
  aggregateNonce,
  publicNonces,
  digest,
  keyAggregation: aggregation,
});
const partials = secretNonces.map((secretNonce, index) =>
  session.signPartial({ secretNonce, secretKey: signingKeys[index] })
);
const signature = session.aggregatePartials(partials);

if (
  signature === null ||
  !verifyTaprootSignature(
    signature,
    digest,
    aggregation.aggregateXOnlyPublicKey(),
  )
) {
  throw new Error('MuSig2 aggregate signature did not verify');
}
