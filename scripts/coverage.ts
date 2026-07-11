const root = new URL('../', import.meta.url).pathname;
const coverageDir = await Deno.makeTempDir({
  prefix: 'secp256k1-deno-coverage.',
});
const scriptDir = await Deno.makeTempDir({
  prefix: 'secp256k1-deno-coverage-scripts.',
});
const libraryDir = `${root}secp256k1/build-deno/lib`;

async function findNativeLibrary(): Promise<string> {
  const patterns: Partial<Record<typeof Deno.build.os, RegExp>> = {
    darwin: /^libsecp256k1\.6\.dylib$/,
    linux: /^libsecp256k1\.so\.6(?:\..*)?$/,
    windows: /^(?:lib)?secp256k1(?:-6)?\.dll$/i,
  };
  const pattern = patterns[Deno.build.os];
  if (pattern === undefined) {
    throw new Error(`Unsupported coverage host: ${Deno.build.os}`);
  }

  const candidates: string[] = [];
  for await (const entry of Deno.readDir(libraryDir)) {
    if ((entry.isFile || entry.isSymlink) && pattern.test(entry.name)) {
      candidates.push(entry.name);
    }
  }
  candidates.sort();
  const selected = candidates[0];
  if (selected === undefined) {
    throw new Error(
      `No ABI-6 libsecp256k1 library found in ${libraryDir}`,
    );
  }
  return `${libraryDir}/${selected}`;
}

const libraryPath = await findNativeLibrary();

async function writeScript(name: string, source: string): Promise<string> {
  const path = `${scriptDir}/${name}`;
  await Deno.writeTextFile(path, source);
  return path;
}

async function runDeno(
  args: string[],
  options: {
    env?: Record<string, string>;
    clearEnv?: boolean;
    printOutput?: boolean;
  } = {},
): Promise<void> {
  const command = new Deno.Command(Deno.execPath(), {
    args,
    cwd: root,
    env: options.env,
    clearEnv: options.clearEnv,
  });
  const output = await command.output();
  if (output.success) {
    if (options.printOutput) {
      await Deno.stdout.write(output.stdout);
      await Deno.stderr.write(output.stderr);
    }
    return;
  }

  const decoder = new TextDecoder();
  await Deno.stderr.write(output.stderr);
  await Deno.stdout.write(output.stdout);
  throw new Error(
    `Command failed: deno ${args.join(' ')}\n${decoder.decode(output.stderr)}`,
  );
}

async function compileFaultLibrary(
  name: string,
  defines: readonly string[],
): Promise<string> {
  if (Deno.build.os !== 'darwin' && Deno.build.os !== 'linux') {
    throw new Error(`Native fault coverage is unsupported on ${Deno.build.os}`);
  }
  const extension = Deno.build.os === 'darwin' ? 'dylib' : 'so';
  const output = `${scriptDir}/${name}.${extension}`;
  const fixture = `${root}test/fixtures/native_fault.c`;
  const platformArgs = Deno.build.os === 'darwin'
    ? [
      '-dynamiclib',
      `-Wl,-reexport_library,${libraryPath}`,
      `-Wl,-rpath,${libraryDir}`,
    ]
    : [
      '-shared',
      '-fPIC',
      '-Wl,--no-as-needed',
      libraryPath,
      `-Wl,-rpath,${libraryDir}`,
    ];
  const command = new Deno.Command('clang', {
    args: [
      ...platformArgs,
      ...defines.map((define) => `-D${define}`),
      fixture,
      '-o',
      output,
    ],
    cwd: root,
  });
  const result = await command.output();
  if (!result.success) {
    await Deno.stderr.write(result.stderr);
    throw new Error(`Unable to compile native fault library ${name}`);
  }
  return output;
}

interface NativeFaultScenario {
  readonly name: string;
  readonly defines: readonly string[];
  readonly body: string;
}

const faultPrelude = `
import {
  CompressedPublicKey,
  nativeXOnlyPublicKey,
  PublicKey,
  XOnlyPublicKey,
} from '${root}src/api/keys.ts';
import {
  EcdsaDerSignature,
  EcdsaSignature,
} from '${root}src/api/signatures.ts';
import { Digest32 } from '${root}src/api/digest.ts';
import { verifyHistoricalEcdsa } from '${root}src/historical.ts';
import { addTweakToPublicKey, Tweak32 } from '${root}src/key_tweaks.ts';
import {
  MuSigAggregateNonce,
  MuSigKeyAggregation,
  MuSigSecretNonce,
  MuSigSession,
} from '${root}src/musig2.ts';
import {
  SecretKey,
  signEcdsa,
  signTaprootSignature,
} from '${root}src/signing.ts';
import {
  checkTaprootTweak,
  taprootTweakPublicKey,
  taprootTweakSecretKey,
} from '${root}src/taproot.ts';
import { Bip324KeyExchange } from '${root}src/bip324.ts';

const G = hex(
  '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
);
const ECDSA_COMPACT = hex(
  'ab4c6d9ba51da83072615c33a9887b756478e6f9de381085f5183c97603fc6ff' +
  '29722188bd937f54c861582ca6fc685b8da2b40d05f06b368374d35e4af2b764',
);
const ECDSA_DER = hex(
  '3045022100ab4c6d9ba51da83072615c33a9887b756478e6f9de381085f5183c' +
  '97603fc6ff022029722188bd937f54c861582ca6fc685b8da2b40d05f06b3683' +
  '74d35e4af2b764',
);

function hex(value: string): Uint8Array {
  return Uint8Array.from(value.match(/../g)!, (byte) => parseInt(byte, 16));
}
function scalar(value: number): Uint8Array {
  const bytes = new Uint8Array(32);
  bytes[31] = value;
  return bytes;
}
function expectError(operation: () => unknown, message: string): void {
  try {
    operation();
  } catch (error) {
    if (error instanceof Error && error.message.includes(message)) return;
    throw error;
  }
  throw new Error('Expected error containing: ' + message);
}
function assert(value: unknown, message = 'Assertion failed'): asserts value {
  if (!value) throw new Error(message);
}
class SigningKey {
  exportBytes(): Uint8Array {
    return scalar(1);
  }
}
function aggregation(): MuSigKeyAggregation {
  return MuSigKeyAggregation.fromOrderedPublicKeys([
    CompressedPublicKey.parse(G),
  ]);
}
function nonceFor(keyAggregation: MuSigKeyAggregation): MuSigSecretNonce {
  return MuSigSecretNonce.generate({
    participantIndex: 0,
    secretKey: new SigningKey(),
    digest: Digest32.fromBytes(new Uint8Array(32).fill(7)),
    keyAggregation,
  });
}
function flow() {
  const keyAggregation = aggregation();
  const digest = Digest32.fromBytes(new Uint8Array(32).fill(7));
  const secretNonce = MuSigSecretNonce.generate({
    participantIndex: 0,
    secretKey: new SigningKey(),
    digest,
    keyAggregation,
  });
  const publicNonces = [secretNonce.indexedPublicNonce()];
  const aggregateNonce = MuSigAggregateNonce.aggregate(
    keyAggregation,
    publicNonces,
  );
  const session = MuSigSession.create({
    aggregateNonce,
    publicNonces,
    digest,
    keyAggregation,
  });
  return { keyAggregation, digest, secretNonce, publicNonces, session };
}
`;

const nativeFaultScenarios: readonly NativeFaultScenario[] = [
  {
    name: 'api-xonly-convert',
    defines: ['FAULT_SYMBOL=secp256k1_xonly_pubkey_from_pubkey'],
    body:
      `expectError(() => PublicKey.parse(G).toXOnly(), 'conversion failed');`,
  },
  {
    name: 'api-xonly-serialize',
    defines: ['FAULT_SYMBOL=secp256k1_xonly_pubkey_serialize'],
    body:
      `expectError(() => PublicKey.parse(G).toXOnly(), 'serialization failed');`,
  },
  {
    name: 'api-xonly-reparse',
    defines: [
      'FAULT_SYMBOL=secp256k1_xonly_pubkey_parse',
      'FAIL_CALL=2',
    ],
    body: `
const key = XOnlyPublicKey.parse(G.slice(1));
expectError(() => nativeXOnlyPublicKey(key), 'reparse failed');`,
  },
  {
    name: 'api-public-reparse',
    defines: ['FAULT_SYMBOL=secp256k1_ec_pubkey_parse', 'FAIL_CALL=2'],
    body: `
const key = PublicKey.parse(G);
expectError(() => key.toUncompressedBytes(), 'reparse failed');`,
  },
  {
    name: 'api-public-serialize',
    defines: ['FAULT_SYMBOL=secp256k1_ec_pubkey_serialize'],
    body: `expectError(() => PublicKey.parse(G), 'serialization failed');`,
  },
  {
    name: 'der-parse',
    defines: ['FAULT_SYMBOL=secp256k1_ecdsa_signature_parse_der'],
    body: `assert(EcdsaDerSignature.fromBytes(ECDSA_DER).decode() === null);`,
  },
  {
    name: 'ecdsa-normalize',
    defines: ['FAULT_SYMBOL=secp256k1_ecdsa_signature_normalize'],
    body: `
const signature = EcdsaSignature.fromBytes(ECDSA_COMPACT)!;
expectError(() => signature.normalize(), 'normalization produced invalid');`,
  },
  {
    name: 'der-serialize',
    defines: ['FAULT_SYMBOL=secp256k1_ecdsa_signature_serialize_der'],
    body: `
const signature = EcdsaSignature.fromBytes(ECDSA_COMPACT)!;
expectError(() => signature.toDer(), 'DER signature serialization failed');`,
  },
  {
    name: 'ecdsa-reparse',
    defines: [
      'FAULT_SYMBOL=secp256k1_ecdsa_signature_parse_compact',
      'FAIL_CALL=2',
    ],
    body: `
const signature = EcdsaSignature.fromBytes(ECDSA_COMPACT)!;
expectError(() => signature.isLowS(), 'signature reparse failed');`,
  },
  {
    name: 'ecdsa-compact-serialize',
    defines: ['FAULT_SYMBOL=secp256k1_ecdsa_signature_serialize_compact'],
    body: `
expectError(
  () => EcdsaDerSignature.fromBytes(ECDSA_DER).decode(),
  'compact signature serialization failed',
);`,
  },
  {
    name: 'historical-compact-parse',
    defines: ['FAULT_SYMBOL=secp256k1_ecdsa_signature_parse_compact'],
    body: `
assert(!verifyHistoricalEcdsa(
  ECDSA_DER,
  Digest32.fromBytes(new Uint8Array(32)),
  G,
));`,
  },
  {
    name: 'key-tweak-serialize',
    defines: ['FAULT_SYMBOL=secp256k1_ec_pubkey_serialize', 'FAIL_CALL=3'],
    body: `
using secret = SecretKey.fromBytes(scalar(1));
const key = secret.publicKey();
expectError(
  () => addTweakToPublicKey(key, Tweak32.fromBytes(scalar(1))),
  'tweaked public-key serialization failed',
);`,
  },
  {
    name: 'sign-public-create',
    defines: ['FAULT_SYMBOL=secp256k1_ec_pubkey_create'],
    body: `
using key = SecretKey.fromBytes(scalar(1));
expectError(() => key.publicKey(), 'public-key derivation failed');`,
  },
  {
    name: 'sign-public-serialize',
    defines: ['FAULT_SYMBOL=secp256k1_ec_pubkey_serialize'],
    body: `
using key = SecretKey.fromBytes(scalar(1));
expectError(() => key.publicKey(), 'public-key serialization failed');`,
  },
  {
    name: 'sign-xonly-create',
    defines: ['FAULT_SYMBOL=secp256k1_keypair_create'],
    body: `
using key = SecretKey.fromBytes(scalar(1));
expectError(() => key.xOnlyPublicKey(), 'keypair creation failed');`,
  },
  {
    name: 'sign-xonly-derive',
    defines: ['FAULT_SYMBOL=secp256k1_keypair_xonly_pub'],
    body: `
using key = SecretKey.fromBytes(scalar(1));
expectError(() => key.xOnlyPublicKey(), 'x-only public-key derivation failed');`,
  },
  {
    name: 'sign-xonly-serialize',
    defines: ['FAULT_SYMBOL=secp256k1_xonly_pubkey_serialize'],
    body: `
using key = SecretKey.fromBytes(scalar(1));
expectError(() => key.xOnlyPublicKey(), 'x-only public-key serialization failed');`,
  },
  {
    name: 'sign-ecdsa',
    defines: ['FAULT_SYMBOL=secp256k1_ecdsa_sign'],
    body: `
using key = SecretKey.fromBytes(scalar(1));
expectError(
  () => signEcdsa(Digest32.fromBytes(new Uint8Array(32)), key),
  'ECDSA signing failed',
);`,
  },
  {
    name: 'sign-ecdsa-serialize',
    defines: ['FAULT_SYMBOL=secp256k1_ecdsa_signature_serialize_compact'],
    body: `
using key = SecretKey.fromBytes(scalar(1));
expectError(
  () => signEcdsa(Digest32.fromBytes(new Uint8Array(32)), key),
  'ECDSA signature serialization failed',
);`,
  },
  {
    name: 'sign-ecdsa-invalid',
    defines: [
      'FAULT_SYMBOL=secp256k1_ecdsa_signature_serialize_compact',
      'ZERO_SECOND_OUTPUT',
    ],
    body: `
using key = SecretKey.fromBytes(scalar(1));
expectError(
  () => signEcdsa(Digest32.fromBytes(new Uint8Array(32)), key),
  'signing produced an invalid signature',
);`,
  },
  {
    name: 'sign-schnorr-keypair',
    defines: ['FAULT_SYMBOL=secp256k1_keypair_create'],
    body: `
using key = SecretKey.fromBytes(scalar(1));
expectError(
  () => signTaprootSignature(Digest32.fromBytes(new Uint8Array(32)), key),
  'keypair creation failed',
);`,
  },
  {
    name: 'sign-schnorr-xonly',
    defines: ['FAULT_SYMBOL=secp256k1_keypair_xonly_pub'],
    body: `
using key = SecretKey.fromBytes(scalar(1));
expectError(
  () => signTaprootSignature(Digest32.fromBytes(new Uint8Array(32)), key),
  'x-only public-key derivation failed',
);`,
  },
  {
    name: 'sign-schnorr',
    defines: ['FAULT_SYMBOL=secp256k1_schnorrsig_sign32'],
    body: `
using key = SecretKey.fromBytes(scalar(1));
expectError(
  () => signTaprootSignature(Digest32.fromBytes(new Uint8Array(32)), key),
  'Taproot signing failed',
);`,
  },
  {
    name: 'sign-schnorr-verify',
    defines: ['FAULT_SYMBOL=secp256k1_schnorrsig_verify'],
    body: `
using key = SecretKey.fromBytes(scalar(1));
expectError(
  () => signTaprootSignature(Digest32.fromBytes(new Uint8Array(32)), key),
  'post-verification failed',
);`,
  },
  {
    name: 'taproot-hash',
    defines: ['FAULT_SYMBOL=secp256k1_tagged_sha256'],
    body: `
expectError(
  () => taprootTweakPublicKey({
    internalKey: XOnlyPublicKey.parse(G.slice(1)),
    merkleRoot: null,
  }),
  'TapTweak tagged hash failed',
);`,
  },
  {
    name: 'taproot-order',
    defines: ['TAGGED_HASH_ORDER'],
    body: `
const internalKey = XOnlyPublicKey.parse(G.slice(1));
expectError(
  () => taprootTweakPublicKey({ internalKey, merkleRoot: null }),
  'not a valid curve scalar',
);
using secret = SecretKey.fromBytes(scalar(1));
expectError(
  () => taprootTweakSecretKey({ internalKey: secret, merkleRoot: null }),
  'not a valid curve scalar',
);
assert(!checkTaprootTweak({
  internalKey,
  merkleRoot: null,
  outputKey: internalKey,
  outputKeyParity: 0,
}));`,
  },
  {
    name: 'taproot-over-order',
    defines: ['TAGGED_HASH_OVER_ORDER'],
    body: `
expectError(
  () => taprootTweakPublicKey({
    internalKey: XOnlyPublicKey.parse(G.slice(1)),
    merkleRoot: null,
  }),
  'not a valid curve scalar',
);`,
  },
  {
    name: 'taproot-public-tweak',
    defines: ['FAULT_SYMBOL=secp256k1_xonly_pubkey_tweak_add'],
    body: `
expectError(
  () => taprootTweakPublicKey({
    internalKey: XOnlyPublicKey.parse(G.slice(1)),
    merkleRoot: null,
  }),
  'produced infinity',
);`,
  },
  {
    name: 'taproot-public-convert',
    defines: ['FAULT_SYMBOL=secp256k1_xonly_pubkey_from_pubkey'],
    body: `
expectError(
  () => taprootTweakPublicKey({
    internalKey: XOnlyPublicKey.parse(G.slice(1)),
    merkleRoot: null,
  }),
  'output-key conversion failed',
);`,
  },
  {
    name: 'taproot-public-serialize',
    defines: ['FAULT_SYMBOL=secp256k1_xonly_pubkey_serialize'],
    body: `
expectError(
  () => taprootTweakPublicKey({
    internalKey: XOnlyPublicKey.parse(G.slice(1)),
    merkleRoot: null,
  }),
  'output-key serialization failed',
);`,
  },
  {
    name: 'taproot-secret-keypair',
    defines: ['FAULT_SYMBOL=secp256k1_keypair_create', 'FAIL_CALL=2'],
    body: `
using key = SecretKey.fromBytes(scalar(1));
expectError(
  () => taprootTweakSecretKey({ internalKey: key, merkleRoot: null }),
  'keypair creation failed',
);`,
  },
  {
    name: 'taproot-secret-tweak',
    defines: ['FAULT_SYMBOL=secp256k1_keypair_xonly_tweak_add'],
    body: `
using key = SecretKey.fromBytes(scalar(1));
expectError(
  () => taprootTweakSecretKey({ internalKey: key, merkleRoot: null }),
  'produced zero',
);`,
  },
  {
    name: 'taproot-secret-extract',
    defines: ['FAULT_SYMBOL=secp256k1_keypair_sec'],
    body: `
using key = SecretKey.fromBytes(scalar(1));
expectError(
  () => taprootTweakSecretKey({ internalKey: key, merkleRoot: null }),
  'secret-key extraction failed',
);`,
  },
  {
    name: 'taproot-secret-public',
    defines: ['FAULT_SYMBOL=secp256k1_keypair_xonly_pub', 'FAIL_CALL=2'],
    body: `
using key = SecretKey.fromBytes(scalar(1));
expectError(
  () => taprootTweakSecretKey({ internalKey: key, merkleRoot: null }),
  'public-key extraction failed',
);`,
  },
  {
    name: 'bip324-create',
    defines: ['FAULT_SYMBOL=secp256k1_ellswift_create'],
    body:
      `expectError(() => Bip324KeyExchange.initiator(), 'generation failed');`,
  },
  {
    name: 'bip324-xdh',
    defines: ['FAULT_SYMBOL=secp256k1_ellswift_xdh'],
    body: `
using initiator = Bip324KeyExchange.initiator();
using responder = Bip324KeyExchange.responder();
expectError(
  () => initiator.deriveSharedSecret(responder.encoding),
  'XDH failed',
);`,
  },
  {
    name: 'bip324-null-callback',
    defines: [
      'NULL_POINTER_SYMBOL=secp256k1_ellswift_xdh_hash_function_bip324',
    ],
    body: `
using initiator = Bip324KeyExchange.initiator();
using responder = Bip324KeyExchange.responder();
expectError(
  () => initiator.deriveSharedSecret(responder.encoding),
  'hash callback is unavailable',
);`,
  },
  {
    name: 'musig-key-aggregate',
    defines: ['FAULT_SYMBOL=secp256k1_musig_pubkey_agg'],
    body: `expectError(() => aggregation(), 'public-key-aggregate');`,
  },
  {
    name: 'musig-key-get',
    defines: ['FAULT_SYMBOL=secp256k1_musig_pubkey_get'],
    body: `expectError(() => aggregation(), 'aggregate-public-key-get');`,
  },
  {
    name: 'musig-key-serialize',
    defines: ['FAULT_SYMBOL=secp256k1_ec_pubkey_serialize', 'FAIL_CALL=4'],
    body: `expectError(() => aggregation(), 'public-key-serialize');`,
  },
  {
    name: 'musig-xonly-serialize',
    defines: ['FAULT_SYMBOL=secp256k1_xonly_pubkey_serialize'],
    body: `expectError(() => aggregation(), 'x-only-public-key-serialize');`,
  },
  {
    name: 'musig-taproot-tweak',
    defines: ['FAULT_SYMBOL=secp256k1_musig_pubkey_xonly_tweak_add'],
    body:
      `expectError(() => aggregation().taprootTweak(null), 'taproot-tweak');`,
  },
  {
    name: 'musig-taproot-convert',
    defines: ['FAULT_SYMBOL=secp256k1_xonly_pubkey_from_pubkey'],
    body: `
expectError(
  () => aggregation().taprootTweak(null),
  'taproot-output-key-convert',
);`,
  },
  {
    name: 'musig-keypair-create',
    defines: ['FAULT_SYMBOL=secp256k1_keypair_create'],
    body: `
const keyAggregation = aggregation();
expectError(() => nonceFor(keyAggregation), 'keypair-create');`,
  },
  {
    name: 'musig-keypair-public',
    defines: ['FAULT_SYMBOL=secp256k1_keypair_pub'],
    body: `
const keyAggregation = aggregation();
expectError(() => nonceFor(keyAggregation), 'keypair-create');`,
  },
  {
    name: 'musig-tagged-hash',
    defines: ['FAULT_SYMBOL=secp256k1_tagged_sha256'],
    body: `
const keyAggregation = aggregation();
expectError(() => nonceFor(keyAggregation), 'tagged-hash');`,
  },
  {
    name: 'musig-nonce-generate',
    defines: ['FAULT_SYMBOL=secp256k1_musig_nonce_gen'],
    body: `
const keyAggregation = aggregation();
expectError(() => nonceFor(keyAggregation), 'nonce-generate');`,
  },
  {
    name: 'musig-public-nonce-serialize',
    defines: ['FAULT_SYMBOL=secp256k1_musig_pubnonce_serialize'],
    body: `
const keyAggregation = aggregation();
expectError(() => nonceFor(keyAggregation), 'public-nonce-serialize');`,
  },
  {
    name: 'musig-public-nonce-reparse',
    defines: [
      'FAULT_SYMBOL=secp256k1_musig_pubnonce_parse',
      'FAIL_CALL=3',
    ],
    body: `
const keyAggregation = aggregation();
const nonce = nonceFor(keyAggregation);
expectError(
  () => MuSigAggregateNonce.aggregate(
    keyAggregation,
    [nonce.indexedPublicNonce()],
  ),
  'public-nonce-reparse',
);`,
  },
  {
    name: 'musig-nonce-aggregate',
    defines: ['FAULT_SYMBOL=secp256k1_musig_nonce_agg'],
    body: `
const keyAggregation = aggregation();
const nonce = nonceFor(keyAggregation);
expectError(
  () => MuSigAggregateNonce.aggregate(
    keyAggregation,
    [nonce.indexedPublicNonce()],
  ),
  'nonce-aggregate',
);`,
  },
  {
    name: 'musig-aggregate-nonce-serialize',
    defines: ['FAULT_SYMBOL=secp256k1_musig_aggnonce_serialize'],
    body: `
const keyAggregation = aggregation();
const nonce = nonceFor(keyAggregation);
expectError(
  () => MuSigAggregateNonce.aggregate(
    keyAggregation,
    [nonce.indexedPublicNonce()],
  ),
  'aggregate-nonce-serialize',
);`,
  },
  {
    name: 'musig-aggregate-nonce-reparse',
    defines: ['FAULT_SYMBOL=secp256k1_musig_aggnonce_parse'],
    body: `expectError(() => flow(), 'aggregate-nonce-reparse');`,
  },
  {
    name: 'musig-nonce-process',
    defines: ['FAULT_SYMBOL=secp256k1_musig_nonce_process'],
    body: `
const keyAggregation = aggregation();
const digest = Digest32.fromBytes(new Uint8Array(32).fill(7));
const nonce = nonceFor(keyAggregation);
const publicNonces = [nonce.indexedPublicNonce()];
const aggregateNonce = MuSigAggregateNonce.aggregate(
  keyAggregation,
  publicNonces,
);
assert(MuSigSession.tryCreate({
  aggregateNonce,
  publicNonces,
  digest,
  keyAggregation,
}) === null);`,
  },
  {
    name: 'musig-partial-sign',
    defines: ['FAULT_SYMBOL=secp256k1_musig_partial_sign'],
    body: `
const state = flow();
expectError(
  () => state.session.signPartial({
    secretNonce: state.secretNonce,
    secretKey: new SigningKey(),
  }),
  'partial-sign',
);`,
  },
  {
    name: 'musig-local-partial-verify',
    defines: ['FAULT_SYMBOL=secp256k1_musig_partial_sig_verify'],
    body: `
const state = flow();
expectError(
  () => state.session.signPartial({
    secretNonce: state.secretNonce,
    secretKey: new SigningKey(),
  }),
  'local-partial-verification',
);`,
  },
  {
    name: 'musig-partial-serialize',
    defines: ['FAULT_SYMBOL=secp256k1_musig_partial_sig_serialize'],
    body: `
const state = flow();
expectError(
  () => state.session.signPartial({
    secretNonce: state.secretNonce,
    secretKey: new SigningKey(),
  }),
  'partial-signature-serialize',
);`,
  },
  {
    name: 'musig-partial-parse-verify',
    defines: [
      'FAULT_SYMBOL=secp256k1_musig_partial_sig_parse',
      'FAIL_CALL=2',
    ],
    body: `
const state = flow();
const partial = state.session.signPartial({
  secretNonce: state.secretNonce,
  secretKey: new SigningKey(),
});
assert(!state.session.verifyPartial({
  participantIndex: 0,
  publicNonce: state.publicNonces[0].publicNonce,
  partialSignature: partial.partialSignature,
}));`,
  },
  {
    name: 'musig-partial-parse-aggregate',
    defines: [
      'FAULT_SYMBOL=secp256k1_musig_partial_sig_parse',
      'FAIL_CALL=3',
    ],
    body: `
const state = flow();
const partial = state.session.signPartial({
  secretNonce: state.secretNonce,
  secretKey: new SigningKey(),
});
assert(state.session.aggregatePartials([partial]) === null);`,
  },
  {
    name: 'musig-partial-aggregate',
    defines: ['FAULT_SYMBOL=secp256k1_musig_partial_sig_agg'],
    body: `
const state = flow();
const partial = state.session.signPartial({
  secretNonce: state.secretNonce,
  secretKey: new SigningKey(),
});
expectError(
  () => state.session.aggregatePartials([partial]),
  'partial-signature-aggregate',
);`,
  },
];

async function runNativeFaultScenario(
  scenario: NativeFaultScenario,
): Promise<void> {
  const library = await compileFaultLibrary(scenario.name, scenario.defines);
  const script = await writeScript(
    `${scenario.name}.test.ts`,
    `${faultPrelude}\n${scenario.body}\n`,
  );
  await runDeno(
    [
      'run',
      '--no-lock',
      `--coverage=${coverageDir}`,
      '--allow-env=DENO_SECP256K1_PATH',
      '--allow-ffi',
      '--allow-read=.',
      script,
    ],
    { env: { DENO_SECP256K1_PATH: library } },
  );
}

const fallbackSuccess = await writeScript(
  'fallback-success.test.ts',
  `
import * as ffi from '${root}src/ffi.ts';
ffi.secp256k1_selftest();
`,
);

const fallbackError = await writeScript(
  'fallback-error.test.ts',
  `
try {
  await import('${root}src/ffi.ts');
  throw new Error('expected import to fail without all-module library');
} catch (error) {
  if (!(error instanceof Error)) throw error;
  if (!error.message.includes('Native secp256k1 library was not found')) {
    throw error;
  }
}
`,
);

const fallbackPermission = await writeScript(
  'fallback-permission.test.ts',
  `
try {
  await import('${root}src/ffi.ts');
  throw new Error('expected import to fail without ffi permission');
} catch (error) {
  if (!(error instanceof Deno.errors.NotCapable)) throw error;
}
`,
);

await runDeno(
  [
    'test',
    '--no-lock',
    `--coverage=${coverageDir}`,
    '--allow-ffi',
    '--allow-env=DENO_SECP256K1_PATH',
    '--allow-read=.',
    '--allow-run',
  ],
  { env: { DENO_SECP256K1_PATH: libraryPath } },
);

for (const scenario of nativeFaultScenarios) {
  await runNativeFaultScenario(scenario);
}

const scopedBip324Failure = await writeScript(
  'bip324-scoped-callback.test.ts',
  `
import {
  Bip324KeyExchange,
  Bip324NativeError,
} from '${root}src/bip324.ts';

using initiator = Bip324KeyExchange.initiator();
using responder = Bip324KeyExchange.responder();
try {
  initiator.deriveSharedSecret(responder.encoding);
  throw new Error('expected callback dereference to require unscoped FFI');
} catch (error) {
  if (
    !(error instanceof Bip324NativeError) ||
    error.code !== 'hash-callback-unavailable' ||
    error.cause === undefined
  ) throw error;
}
`,
);
await runDeno(
  [
    'run',
    '--no-lock',
    `--coverage=${coverageDir}`,
    '--allow-env=DENO_SECP256K1_PATH',
    `--allow-ffi=${libraryPath}`,
    '--allow-read=.',
    scopedBip324Failure,
  ],
  { env: { DENO_SECP256K1_PATH: libraryPath } },
);

await runDeno(
  [
    'run',
    '--no-lock',
    `--coverage=${coverageDir}`,
    '--allow-ffi',
    '--allow-env=DENO_SECP256K1_PATH',
    fallbackSuccess,
  ],
  {
    clearEnv: true,
    env: { DYLD_LIBRARY_PATH: libraryDir },
  },
);

await runDeno(
  [
    'run',
    '--no-lock',
    `--coverage=${coverageDir}`,
    '--allow-ffi',
    '--allow-env=DENO_SECP256K1_PATH',
    fallbackError,
  ],
  { clearEnv: true },
);

await runDeno(
  [
    'run',
    '--no-lock',
    `--coverage=${coverageDir}`,
    '--allow-env=DENO_SECP256K1_PATH',
    fallbackPermission,
  ],
  {
    clearEnv: true,
    env: { DYLD_LIBRARY_PATH: libraryDir },
  },
);

const coverageInclude = `${root}(src|test/deps)`;
await runDeno([
  'coverage',
  coverageDir,
  `--include=${coverageInclude}`,
], { printOutput: true });

const lcovResult = await new Deno.Command(Deno.execPath(), {
  args: [
    'coverage',
    coverageDir,
    `--include=${coverageInclude}`,
    '--lcov',
  ],
  cwd: root,
}).output();
if (!lcovResult.success) {
  await Deno.stderr.write(lcovResult.stderr);
  throw new Error('Unable to generate the combined LCOV report');
}
const lcov = new TextDecoder().decode(lcovResult.stdout);
const linesFound = sumLcovMetric(lcov, 'LF');
const linesHit = sumLcovMetric(lcov, 'LH');
if (linesFound === 0 || linesHit !== linesFound) {
  const percent = linesFound === 0 ? 0 : (linesHit / linesFound) * 100;
  throw new Error(
    `Line coverage ${percent.toFixed(2)}% is below the 100.00% threshold`,
  );
}
console.log(`Line coverage threshold: 100.0% (${linesHit}/${linesFound})`);

console.log(`Coverage profile: ${coverageDir}`);

function sumLcovMetric(lcov: string, metric: 'LF' | 'LH'): number {
  let total = 0;
  for (const line of lcov.split('\n')) {
    if (line.startsWith(`${metric}:`)) {
      total += Number.parseInt(line.slice(3), 10);
    }
  }
  return total;
}
