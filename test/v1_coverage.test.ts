import { assert, assertEquals, assertThrows, ffiTest, N } from './deps.ts';
import {
  CompressedPublicKey,
  PublicKey,
  XOnlyPublicKey,
} from '../src/api/keys.ts';
import {
  EcdsaCompactSignature,
  EcdsaDerSignature,
  SchnorrSignature,
} from '../src/api/signatures.ts';
import { Digest32 } from '../src/api/digest.ts';
import { Secp256k1InputError } from '../src/api/input.ts';
import { verifyHistoricalEcdsa } from '../src/historical.ts';
import {
  MuSigAggregateNonce,
  MuSigKeyAggregation,
  MuSigNativeError,
  MuSigRandomError,
  MuSigSecretNonce,
  MuSigSession,
  type MuSigSigningKey,
  MuSigStateError,
} from '../src/musig2.ts';
import {
  SecretKey,
  SecretKeyDestroyedError,
  signEcdsa,
  signTaprootSignature,
} from '../src/signing.ts';
import {
  checkTaprootTweak,
  TapMerkleRoot,
  TaprootTweakError,
  taprootTweakPublicKey,
} from '../src/taproot.ts';
import {
  Bip324NativeError,
  type Bip324NativeErrorCode,
} from '../src/bip324.ts';

const G = hex(
  '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
);
const TWO_G = hex(
  '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5',
);

ffiTest(
  'v1 key and signature parsers cover every public rejection shape',
  () => {
    assertThrows(() => PublicKey.parse(new Uint8Array()), Secp256k1InputError);
    assertThrows(
      () => CompressedPublicKey.parse(new Uint8Array(33)),
      Secp256k1InputError,
    );
    assertEquals(XOnlyPublicKey.tryParse(new Uint8Array(31)), null);
    assertEquals(XOnlyPublicKey.tryParse(new Uint8Array(32).fill(0xff)), null);
    assertThrows(
      () => XOnlyPublicKey.parse(new Uint8Array(31)),
      Secp256k1InputError,
    );

    const compressed = CompressedPublicKey.parse(G);
    assertEquals(compressed.toPublicKey().toCompressedBytes(), G);
    assertEquals(compressed.toPublicKey().toXOnly().key.toBytes(), G.slice(1));

    const compactBytes = new Uint8Array(64);
    compactBytes[31] = 1;
    compactBytes[63] = 1;
    const compact = EcdsaCompactSignature.fromBytes(compactBytes);
    assertEquals(compact.toBytes(), compactBytes);
    assertThrows(
      () => EcdsaCompactSignature.fromBytes(new Uint8Array(63)),
      Secp256k1InputError,
    );
    assertThrows(
      () => SchnorrSignature.fromBytes(new Uint8Array(63)),
      Secp256k1InputError,
    );

    for (
      const malformed of [
        '3006030101020101',
        '3006020002020101',
        '3006020301020101',
        '3006020101030101',
        '3006020101020000',
        '3006020101020180',
        '300702010102020001',
      ]
    ) {
      assertEquals(EcdsaDerSignature.tryFromBytes(hex(malformed)), null);
    }
  },
);

ffiTest(
  'v1 secret handles reject invalid scalars and all destroyed uses',
  () => {
    for (const invalid of [new Uint8Array(31), new Uint8Array(32), N()]) {
      assertThrows(() => SecretKey.fromBytes(invalid), Secp256k1InputError);
    }

    const key = SecretKey.fromBytes(scalar(1));
    key[Symbol.dispose]();
    const digest = Digest32.fromBytes(new Uint8Array(32));
    for (
      const operation of [
        () => key.xOnlyPublicKey(),
        () => signEcdsa(digest, key),
        () => signTaprootSignature(digest, key),
      ]
    ) {
      assertThrows(operation, SecretKeyDestroyedError);
    }
  },
);

ffiTest('Taproot value errors and mismatch paths are explicit', () => {
  assertThrows(
    () => TapMerkleRoot.fromBytes(new Uint8Array(31)),
    Secp256k1InputError,
  );
  for (
    const code of [
      'invalid-tweak',
      'public-key-infinity',
      'secret-key-zero',
    ] as const
  ) {
    const error = new TaprootTweakError(code);
    assertEquals(error.code, code);
    assert(error.message.length > 0);
  }

  const internalKey = XOnlyPublicKey.parse(G.slice(1));
  const result = taprootTweakPublicKey({ internalKey, merkleRoot: null });
  const otherOutput = XOnlyPublicKey.parse(TWO_G.slice(1));
  assertEquals(
    checkTaprootTweak({
      internalKey,
      merkleRoot: null,
      outputKey: otherOutput,
      outputKeyParity: result.outputKeyParity,
    }),
    false,
  );
});

Deno.test('historical parser rejects every truncated and oversized form', () => {
  const digest = Digest32.fromBytes(new Uint8Array(32));
  const malformed = [
    [0x30, 0x82, 0x00],
    [0x30, 0x00, 0x03],
    [0x30, 0x00, 0x02],
    [0x30, 0x00, 0x02, 0x82, 0x01],
    [0x30, 0x00, 0x02, 0x02, 0x01],
    [0x30, 0x00, 0x02, 0x00],
    [0x30, 0x00, 0x02, 0x00, 0x03],
    [0x30, 0x00, 0x02, 0x00, 0x02],
    [0x30, 0x00, 0x02, 0x00, 0x02, 0x82, 0x01],
    [0x30, 0x00, 0x02, 0x00, 0x02, 0x02, 0x01],
    [0x30, 0x00, 0x02, 0x88, 1, 0, 0, 0, 0, 0, 0, 0],
    [0x30, 0x00, 0x02, 0x82, 0, 1, 1, 0x02, 1, 1],
    [0x30, 0x00, 0x02, 0x21, ...new Uint8Array(33).fill(1), 0x02, 0],
    [0x30, 0x00, 0x02, 0, 0x02, 0x21, ...new Uint8Array(33).fill(1)],
  ].map((bytes) => Uint8Array.from(bytes));

  for (const signature of malformed) {
    assertEquals(verifyHistoricalEcdsa(signature, digest, G), false);
  }
});

Deno.test('BIP324 native errors expose every stable operation code', () => {
  for (
    const code of [
      'ellswift-create-failed',
      'hash-callback-unavailable',
      'ellswift-xdh-failed',
    ] satisfies Bip324NativeErrorCode[]
  ) {
    const cause = new Error('fault');
    const error = new Bip324NativeError(code, { cause });
    assertEquals(error.code, code);
    assertEquals(error.cause, cause);
    assert(error.message.length > 0);
  }
});

ffiTest(
  'MuSig2 validates public state, participant indexes, and signing keys',
  () => {
    assertThrows(
      () => MuSigKeyAggregation.fromOrderedPublicKeys([]),
      MuSigStateError,
    );
    const aggregation = MuSigKeyAggregation.fromOrderedPublicKeys([
      CompressedPublicKey.parse(G),
      CompressedPublicKey.parse(TWO_G),
    ]);
    assertEquals(aggregation.participantCount, 2);
    assertEquals(aggregation.aggregatePublicKey().toBytes().length, 33);
    assertThrows(() => aggregation.participantPublicKey(-1), MuSigStateError);
    assertThrows(() => aggregation.participantPublicKey(2), MuSigStateError);
    assertThrows(
      () => aggregation.taprootTweak({ toBytes: () => new Uint8Array(31) }),
      Secp256k1InputError,
    );

    const digest = Digest32.fromBytes(new Uint8Array(32));
    const invalidKeys: MuSigSigningKey[] = [
      { exportBytes: () => new Uint8Array(31) },
      { exportBytes: () => new Uint8Array(32) },
      { exportBytes: () => N() },
      {
        exportBytes: () => {
          throw new Error('destroyed');
        },
      },
    ];
    for (const secretKey of invalidKeys) {
      assertThrows(
        () =>
          MuSigSecretNonce.generate({
            participantIndex: 0,
            secretKey,
            digest,
            keyAggregation: aggregation,
          }),
        MuSigStateError,
      );
    }
    assertThrows(
      () =>
        MuSigSecretNonce.generate({
          participantIndex: Number.NaN,
          secretKey: { exportBytes: () => scalar(1) },
          digest,
          keyAggregation: aggregation,
        }),
      MuSigStateError,
    );

    assertEquals(new MuSigNativeError('test').operation, 'test');
    assertEquals(new MuSigRandomError({ cause: 'test' }).cause, 'test');
  },
);

ffiTest(
  'MuSig2 rejects generation key, index, and aggregate bindings',
  () => {
    const aggregation = MuSigKeyAggregation.fromOrderedPublicKeys([
      CompressedPublicKey.parse(G),
      CompressedPublicKey.parse(TWO_G),
    ]);
    const digest = Digest32.fromBytes(new Uint8Array(32));
    assertThrows(
      () =>
        MuSigSecretNonce.generate({
          participantIndex: 0,
          secretKey: { exportBytes: () => scalar(2) },
          digest,
          keyAggregation: aggregation,
        }),
      MuSigStateError,
    );

    const nonce = MuSigSecretNonce.generate({
      participantIndex: 0,
      secretKey: { exportBytes: () => scalar(1) },
      digest,
      keyAggregation: aggregation,
    });
    assertThrows(
      () =>
        MuSigAggregateNonce.aggregate(aggregation, [
          { participantIndex: Number.NaN, publicNonce: nonce.publicNonce },
        ]),
      MuSigStateError,
    );

    const second = MuSigSecretNonce.generate({
      participantIndex: 1,
      secretKey: { exportBytes: () => scalar(2) },
      digest,
      keyAggregation: aggregation,
    });
    const publicNonces = [
      nonce.indexedPublicNonce(),
      second.indexedPublicNonce(),
    ];
    assertEquals(
      MuSigSession.tryCreate({
        aggregateNonce: {
          toBytes: () => new Uint8Array(1),
        } as never,
        publicNonces,
        digest,
        keyAggregation: aggregation,
      }),
      null,
    );
  },
);

ffiTest('MuSig2 wraps Web Crypto randomness failure', () => {
  const aggregation = MuSigKeyAggregation.fromOrderedPublicKeys([
    CompressedPublicKey.parse(G),
  ]);
  const descriptor = Object.getOwnPropertyDescriptor(crypto, 'getRandomValues');
  const original = crypto.getRandomValues.bind(crypto);
  let calls = 0;
  Object.defineProperty(crypto, 'getRandomValues', {
    configurable: true,
    value(array: Uint8Array): Uint8Array {
      calls++;
      if (calls === 2) throw new Error('randomness unavailable');
      return original(array);
    },
  });
  try {
    assertThrows(
      () =>
        MuSigSecretNonce.generate({
          participantIndex: 0,
          secretKey: { exportBytes: () => scalar(1) },
          digest: Digest32.fromBytes(new Uint8Array(32)),
          keyAggregation: aggregation,
        }),
      MuSigRandomError,
    );
  } finally {
    if (descriptor === undefined) {
      delete (crypto as unknown as Record<string, unknown>).getRandomValues;
    } else {
      Object.defineProperty(crypto, 'getRandomValues', descriptor);
    }
  }
});

ffiTest('MuSig2 fails closed when an FFI buffer has no pointer', () => {
  const descriptor = Object.getOwnPropertyDescriptor(Deno.UnsafePointer, 'of')!;
  Object.defineProperty(Deno.UnsafePointer, 'of', {
    configurable: true,
    value: () => null,
  });
  try {
    assertThrows(
      () =>
        MuSigKeyAggregation.fromOrderedPublicKeys([
          CompressedPublicKey.parse(G),
        ]),
      MuSigNativeError,
    );
  } finally {
    Object.defineProperty(Deno.UnsafePointer, 'of', descriptor);
  }
});

ffiTest('MuSig2 rejects prototype-polluted session identity storage', () => {
  const aggregation = MuSigKeyAggregation.fromOrderedPublicKeys([
    CompressedPublicKey.parse(G),
  ]);
  const digest = Digest32.fromBytes(new Uint8Array(32));
  const secretNonce = MuSigSecretNonce.generate({
    participantIndex: 0,
    secretKey: { exportBytes: () => scalar(1) },
    digest,
    keyAggregation: aggregation,
  });
  const publicNonces = [secretNonce.indexedPublicNonce()];
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

  const descriptor = Object.getOwnPropertyDescriptor(
    Object.prototype,
    'sessionIdentity',
  );
  let pollutedIdentity: object | undefined;
  Object.defineProperty(Object.prototype, 'sessionIdentity', {
    configurable: true,
    get: () => pollutedIdentity,
    set: () => {
      pollutedIdentity = {};
    },
  });
  try {
    assertThrows(
      () =>
        session.signPartial({
          secretNonce,
          secretKey: { exportBytes: () => scalar(1) },
        }),
      MuSigStateError,
    );
    assert(secretNonce.consumed);
  } finally {
    if (descriptor === undefined) {
      delete (Object.prototype as Record<string, unknown>).sessionIdentity;
    } else {
      Object.defineProperty(Object.prototype, 'sessionIdentity', descriptor);
    }
  }
});

Deno.test('MuSig2 rejects forged class receivers', () => {
  const participantCount = Object.getOwnPropertyDescriptor(
    MuSigKeyAggregation.prototype,
    'participantCount',
  )!.get!;
  const nonceConsumed = Object.getOwnPropertyDescriptor(
    MuSigSecretNonce.prototype,
    'consumed',
  )!.get!;
  assertThrows(() => participantCount.call({}), TypeError);
  assertThrows(() => nonceConsumed.call({}), TypeError);
  assertThrows(
    () => MuSigSession.prototype.verifyPartial.call({}, {} as never),
    TypeError,
  );
});

function scalar(value: number): Uint8Array {
  const bytes = new Uint8Array(32);
  bytes[31] = value;
  return bytes;
}

function hex(value: string): Uint8Array {
  const output = new Uint8Array(value.length / 2);
  for (let index = 0; index < output.length; index++) {
    output[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return output;
}
