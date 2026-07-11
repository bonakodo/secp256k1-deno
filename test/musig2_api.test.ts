import { assert, assertEquals, assertNotEquals, assertThrows } from './deps.ts';
import { Digest32 } from '../src/api/digest.ts';
import { CompressedPublicKey } from '../src/api/keys.ts';
import { verifyTaprootSignature } from '../src/api/verify.ts';
import {
  type IndexedMuSigPartialSignature,
  type IndexedMuSigPublicNonce,
  MuSigAggregateNonce,
  MuSigKeyAggregation,
  MuSigPartialSignature,
  MuSigPublicNonce,
  MuSigSecretNonce,
  MuSigSession,
  type MuSigSigningKey,
  MuSigStateError,
  sortMuSigPublicKeys,
} from '../src/musig2.ts';

const G = hex(
  '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
);
const TWO_G = hex(
  '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5',
);

class TestSigningKey implements MuSigSigningKey {
  readonly #bytes: Uint8Array;

  constructor(value: number) {
    this.#bytes = new Uint8Array(32);
    this.#bytes[31] = value;
  }

  exportBytes(): Uint8Array {
    return this.#bytes.slice();
  }
}

interface Flow {
  readonly aggregation: MuSigKeyAggregation;
  readonly digest: Digest32;
  readonly secretNonces: readonly MuSigSecretNonce[];
  readonly publicNonces: readonly IndexedMuSigPublicNonce[];
  readonly aggregateNonce: MuSigAggregateNonce;
  readonly session: MuSigSession;
}

function twoPartyFlow(
  aggregation = MuSigKeyAggregation.fromOrderedPublicKeys([
    CompressedPublicKey.parse(G),
    CompressedPublicKey.parse(TWO_G),
  ]),
  digest = Digest32.fromBytes(new Uint8Array(32).fill(42)),
): Flow {
  const secrets = [new TestSigningKey(1), new TestSigningKey(2)];
  const secretNonces = secrets.map((secretKey, participantIndex) =>
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
  return {
    aggregation,
    digest,
    secretNonces,
    publicNonces,
    aggregateNonce,
    session,
  };
}

function signFlow(
  flow: Flow,
  secrets: readonly MuSigSigningKey[] = [
    new TestSigningKey(1),
    new TestSigningKey(2),
  ],
): readonly IndexedMuSigPartialSignature[] {
  return flow.secretNonces.map((secretNonce, index) =>
    flow.session.signPartial({ secretNonce, secretKey: secrets[index] })
  );
}

Deno.test('MuSig2 completes a verified two-party signing flow', () => {
  const flow = twoPartyFlow();
  const partials = signFlow(flow);

  for (let index = 0; index < partials.length; index++) {
    assert(
      flow.session.verifyPartial({
        participantIndex: index,
        publicNonce: flow.publicNonces[index].publicNonce,
        partialSignature: partials[index].partialSignature,
      }),
    );
    assert(flow.secretNonces[index].consumed);
  }

  const signature = flow.session.aggregatePartials(partials);
  assert(signature !== null);
  assert(
    verifyTaprootSignature(
      signature,
      flow.digest,
      flow.aggregation.aggregateXOnlyPublicKey(),
    ),
  );
});

Deno.test('MuSig2 supports duplicate keys through distinct participant indexes', () => {
  const key = CompressedPublicKey.parse(G);
  const aggregation = MuSigKeyAggregation.fromOrderedPublicKeys([key, key]);
  const digest = Digest32.fromBytes(new Uint8Array(32).fill(7));
  const secrets = [new TestSigningKey(1), new TestSigningKey(1)];
  const secretNonces = secrets.map((secretKey, participantIndex) =>
    MuSigSecretNonce.generate({
      participantIndex,
      secretKey,
      digest,
      keyAggregation: aggregation,
    })
  );
  assertEquals(secretNonces[0].participantIndex, 0);
  assertEquals(secretNonces[1].participantIndex, 1);
  assertNotEquals(
    toHex(secretNonces[0].publicNonce.toBytes()),
    toHex(secretNonces[1].publicNonce.toBytes()),
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
    session.signPartial({ secretNonce, secretKey: secrets[index] })
  );
  assert(session.aggregatePartials(partials) !== null);
});

Deno.test('MuSig2 preserves key order and sorts only on explicit request', () => {
  const first = CompressedPublicKey.parse(G);
  const second = CompressedPublicKey.parse(TWO_G);
  const forward = MuSigKeyAggregation.fromOrderedPublicKeys([first, second]);
  const reverse = MuSigKeyAggregation.fromOrderedPublicKeys([second, first]);

  assertNotEquals(
    toHex(forward.aggregateXOnlyPublicKey().toBytes()),
    toHex(reverse.aggregateXOnlyPublicKey().toBytes()),
  );
  assertEquals(forward.participantPublicKey(0).toBytes(), G);
  assertEquals(reverse.participantPublicKey(0).toBytes(), TWO_G);

  const sorted = sortMuSigPublicKeys([second, first, first]);
  assertEquals(sorted.map((key) => key.toBytes()), [G, G, TWO_G]);
});

Deno.test('MuSig2 applies a BIP341 tweak before nonce generation', () => {
  const base = MuSigKeyAggregation.fromOrderedPublicKeys([
    CompressedPublicKey.parse(G),
    CompressedPublicKey.parse(TWO_G),
  ]);
  const tweaked = base.taprootTweak(null);
  assertEquals(
    tweaked.outputKey.toBytes(),
    tweaked.keyAggregation.aggregateXOnlyPublicKey().toBytes(),
  );
  assert(
    tweaked.outputKeyParity === 0 || tweaked.outputKeyParity === 1,
  );

  const flow = twoPartyFlow(tweaked.keyAggregation);
  const signature = flow.session.aggregatePartials(signFlow(flow));
  assert(signature !== null);
  assert(verifyTaprootSignature(signature, flow.digest, tweaked.outputKey));

  const untweakedFlow = twoPartyFlow(base);
  assertThrows(
    () => base.taprootTweak(null),
    MuSigStateError,
    'before MuSig2 nonce generation',
  );
  assert(untweakedFlow.secretNonces.length === 2);

  const root = { toBytes: () => new Uint8Array(32).fill(9) };
  const scriptTweaked = MuSigKeyAggregation.fromOrderedPublicKeys([
    CompressedPublicKey.parse(G),
    CompressedPublicKey.parse(TWO_G),
  ]).taprootTweak(root);
  assertNotEquals(
    toHex(scriptTweaked.outputKey.toBytes()),
    toHex(tweaked.outputKey.toBytes()),
  );
  assertThrows(
    () => scriptTweaked.keyAggregation.taprootTweak(null),
    MuSigStateError,
    'only one BIP341 TapTweak',
  );
});

Deno.test('MuSig2 consumes a nonce before wrong-key and reuse failures', () => {
  const flow = twoPartyFlow();
  const first = flow.secretNonces[0];
  const error = assertThrows(
    () =>
      flow.session.signPartial({
        secretNonce: first,
        secretKey: new TestSigningKey(2),
      }),
    MuSigStateError,
  );
  assertEquals(error.code, 'secret-key-mismatch');
  assert(first.consumed);

  const reuse = assertThrows(
    () =>
      flow.session.signPartial({
        secretNonce: first,
        secretKey: new TestSigningKey(1),
      }),
    MuSigStateError,
  );
  assertEquals(reuse.code, 'nonce-already-consumed');
});

Deno.test('MuSig2 secret nonces dispose idempotently without hiding public state', () => {
  const flow = twoPartyFlow();
  const nonce = flow.secretNonces[0];
  const expectedPublicNonce = nonce.publicNonce.toBytes();
  const detached = nonce.publicNonce.toBytes();
  detached.fill(0);

  assertEquals(nonce.consumed, false);
  nonce.destroy();
  assertEquals(nonce.consumed, true);
  assertEquals(nonce.participantIndex, 0);
  assertEquals(nonce.publicNonce.toBytes(), expectedPublicNonce);
  assertEquals(
    nonce.indexedPublicNonce().publicNonce.toBytes(),
    expectedPublicNonce,
  );

  nonce.destroy();
  nonce[Symbol.dispose]();
  const error = assertThrows(
    () =>
      flow.session.signPartial({
        secretNonce: nonce,
        secretKey: new TestSigningKey(1),
      }),
    MuSigStateError,
  );
  assertEquals(error.code, 'nonce-already-consumed');
});

Deno.test('MuSig2 secret nonces support using disposal', () => {
  const flow = twoPartyFlow();
  const nonce = flow.secretNonces[0];
  {
    using scoped = nonce;
    assertEquals(scoped.consumed, false);
  }
  assertEquals(nonce.consumed, true);
});

Deno.test('MuSig2 consumes a nonce before wrong aggregation binding fails', () => {
  const flow = twoPartyFlow();
  const otherAggregation = MuSigKeyAggregation.fromOrderedPublicKeys([
    CompressedPublicKey.parse(G),
    CompressedPublicKey.parse(TWO_G),
  ]);
  const otherAggregateNonce = MuSigAggregateNonce.aggregate(
    otherAggregation,
    flow.publicNonces,
  );
  const otherSession = MuSigSession.create({
    aggregateNonce: otherAggregateNonce,
    publicNonces: flow.publicNonces,
    digest: flow.digest,
    keyAggregation: otherAggregation,
  });

  const error = assertThrows(
    () =>
      otherSession.signPartial({
        secretNonce: flow.secretNonces[0],
        secretKey: new TestSigningKey(1),
      }),
    MuSigStateError,
  );
  assertEquals(error.code, 'nonce-binding-mismatch');
  assert(flow.secretNonces[0].consumed);
});

Deno.test('MuSig2 wire parsing handles malformed peer values without throwing', () => {
  assertEquals(MuSigPublicNonce.tryFromBytes(new Uint8Array(65)), null);
  assertEquals(MuSigPublicNonce.tryFromBytes(new Uint8Array(66)), null);
  assertEquals(MuSigAggregateNonce.tryFromBytes(new Uint8Array(65)), null);
  const invalidAggregateNonce = new Uint8Array(66);
  invalidAggregateNonce[0] = 4;
  assertEquals(MuSigAggregateNonce.tryFromBytes(invalidAggregateNonce), null);
  assertEquals(MuSigPartialSignature.tryFromBytes(new Uint8Array(31)), null);
  assertEquals(
    MuSigPartialSignature.tryFromBytes(new Uint8Array(32).fill(0xff)),
    null,
  );

  const first = twoPartyFlow();
  const second = twoPartyFlow(first.aggregation, first.digest);
  assertEquals(
    MuSigSession.tryCreate({
      aggregateNonce: second.aggregateNonce,
      publicNonces: first.publicNonces,
      digest: first.digest,
      keyAggregation: first.aggregation,
    }),
    null,
  );
});

Deno.test('MuSig2 rejects incomplete, duplicate, extra, and empty participant sets', () => {
  const aggregation = MuSigKeyAggregation.fromOrderedPublicKeys([
    CompressedPublicKey.parse(G),
    CompressedPublicKey.parse(TWO_G),
  ]);
  const digest = Digest32.fromBytes(new Uint8Array(32).fill(8));
  const nonce0 = MuSigSecretNonce.generate({
    participantIndex: 0,
    secretKey: new TestSigningKey(1),
    digest,
    keyAggregation: aggregation,
  }).indexedPublicNonce();

  assertStateCode(
    () => MuSigAggregateNonce.aggregate(aggregation, []),
    'empty-participants',
  );
  assertStateCode(
    () => MuSigAggregateNonce.aggregate(aggregation, [nonce0]),
    'missing-participant-index',
  );
  assertStateCode(
    () =>
      MuSigAggregateNonce.aggregate(aggregation, [
        nonce0,
        { participantIndex: 0, publicNonce: nonce0.publicNonce },
      ]),
    'duplicate-participant-index',
  );
  assertStateCode(
    () =>
      MuSigAggregateNonce.aggregate(aggregation, [
        nonce0,
        { participantIndex: 2, publicNonce: nonce0.publicNonce },
      ]),
    'extra-participant-index',
  );

  const flow = twoPartyFlow();
  const partials = signFlow(flow);
  assertStateCode(
    () => flow.session.aggregatePartials([]),
    'empty-participants',
  );
  assertStateCode(
    () => flow.session.aggregatePartials([partials[0]]),
    'missing-participant-index',
  );
  assertStateCode(
    () => flow.session.aggregatePartials([partials[0], partials[0]]),
    'duplicate-participant-index',
  );
  assertStateCode(
    () =>
      flow.session.aggregatePartials([
        partials[0],
        { participantIndex: 2, partialSignature: partials[1].partialSignature },
      ]),
    'extra-participant-index',
  );
});

Deno.test('MuSig2 rejects wrong partial bindings and invalid final inputs', () => {
  const flow = twoPartyFlow();
  const partials = signFlow(flow);
  assertEquals(
    flow.session.verifyPartial({
      participantIndex: 0,
      publicNonce: flow.publicNonces[1].publicNonce,
      partialSignature: partials[0].partialSignature,
    }),
    false,
  );
  assertEquals(
    flow.session.verifyPartial({
      participantIndex: 2,
      publicNonce: flow.publicNonces[0].publicNonce,
      partialSignature: partials[0].partialSignature,
    }),
    false,
  );

  const invalid = MuSigPartialSignature.fromBytes(new Uint8Array(32));
  assertEquals(
    flow.session.verifyPartial({
      participantIndex: 0,
      publicNonce: flow.publicNonces[0].publicNonce,
      partialSignature: invalid,
    }),
    false,
  );
  assertEquals(
    flow.session.aggregatePartials([
      { participantIndex: 0, partialSignature: invalid },
      partials[1],
    ]),
    null,
  );
});

Deno.test('MuSig2 wire values isolate mutable input and output buffers', () => {
  const flow = twoPartyFlow();
  const partial = signFlow(flow)[0].partialSignature;
  const values = [
    [flow.publicNonces[0].publicNonce, 66],
    [flow.aggregateNonce, 66],
    [partial, 32],
  ] as const;

  for (const [value, length] of values) {
    const original = value.toBytes();
    const input = original.slice();
    const parsed = length === 32
      ? MuSigPartialSignature.fromBytes(input)
      : length === 66 && original[0] === flow.aggregateNonce.toBytes()[0] &&
          toHex(original) === toHex(flow.aggregateNonce.toBytes())
      ? MuSigAggregateNonce.fromBytes(input)
      : MuSigPublicNonce.fromBytes(input);
    input.fill(0);
    assertEquals(parsed.toBytes(), original);
    const output = parsed.toBytes();
    output.fill(0);
    assertEquals(parsed.toBytes(), original);
  }

  const ordered = flow.aggregation.orderedPublicKeys();
  const bytes = ordered[0].toBytes();
  bytes.fill(0);
  assertEquals(flow.aggregation.participantPublicKey(0).toBytes(), G);
});

function assertStateCode(
  operation: () => unknown,
  code: MuSigStateError['code'],
): void {
  const error = assertThrows(operation, MuSigStateError);
  assertEquals(error.code, code);
}

function hex(value: string): Uint8Array {
  const output = new Uint8Array(value.length / 2);
  for (let index = 0; index < output.length; index++) {
    output[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return output;
}

function toHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join(
    '',
  );
}
