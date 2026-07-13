#!/usr/bin/env -S deno run --no-lock --import-map=doc.import-map.json --allow-env=DENO_SECP256K1_PATH --allow-ffi
// deno-lint-ignore-file no-import-prefix

import { Bip324KeyExchange } from 'jsr:@bonakodo/secp256k1@1/bip324.ts';

using initiator = Bip324KeyExchange.initiator();
using responder = Bip324KeyExchange.responder();
using initiatorSecret = initiator.deriveSharedSecret(responder.encoding);
using responderSecret = responder.deriveSharedSecret(initiator.encoding);
const left = initiatorSecret.consumeBytes();
const right = responderSecret.consumeBytes();

try {
  if (!left.every((byte, index) => byte === right[index])) {
    throw new Error('BIP324 peers derived different shared secrets');
  }
} finally {
  left.fill(0);
  right.fill(0);
}
