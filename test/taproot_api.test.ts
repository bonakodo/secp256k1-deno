import { assert, assertEquals, assertNotEquals } from './deps.ts';
import { XOnlyPublicKey } from '../src/api/keys.ts';
import { SecretKey } from '../src/signing.ts';
import {
  checkTaprootTweak,
  TapMerkleRoot,
  taprootTweakPublicKey,
  taprootTweakSecretKey,
} from '../src/taproot.ts';

Deno.test('BIP341 no-tree wallet vector derives the expected output key', () => {
  const internalKey = XOnlyPublicKey.parse(
    hex('d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d'),
  );
  const result = taprootTweakPublicKey({ internalKey, merkleRoot: null });
  assertEquals(
    result.outputKey.toBytes(),
    hex('53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343'),
  );
  assert(checkTaprootTweak({ internalKey, merkleRoot: null, ...result }));
});

Deno.test('BIP341 script-tree wallet vector derives key and parity', () => {
  const internalKey = XOnlyPublicKey.parse(
    hex('187791b6f712a8ea41c8ecdd0ee77fab3e85263b37e1ec18a3651926b3a6cf27'),
  );
  const merkleRoot = TapMerkleRoot.fromBytes(
    hex('5b75adecf53548f3ec6ad7d78383bf84cc57b55a3127c72b9a2481752dd88b21'),
  );
  const result = taprootTweakPublicKey({ internalKey, merkleRoot });
  assertEquals(
    result.outputKey.toBytes(),
    hex('147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3'),
  );
  assertEquals(result.outputKeyParity, 1);
  assert(checkTaprootTweak({ internalKey, merkleRoot, ...result }));
  assertEquals(
    checkTaprootTweak({
      internalKey,
      merkleRoot,
      outputKey: result.outputKey,
      outputKeyParity: 0,
    }),
    false,
  );
});

Deno.test('null tree is distinct from an all-zero Merkle root', () => {
  const internalKey = XOnlyPublicKey.parse(
    hex('d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d'),
  );
  const noTree = taprootTweakPublicKey({ internalKey, merkleRoot: null });
  const zeroRoot = TapMerkleRoot.fromBytes(new Uint8Array(32));
  const withZeroRoot = taprootTweakPublicKey({
    internalKey,
    merkleRoot: zeroRoot,
  });
  assertNotEquals(noTree.outputKey.toBytes(), withZeroRoot.outputKey.toBytes());
  assertEquals(
    checkTaprootTweak({
      internalKey,
      merkleRoot: zeroRoot,
      ...noTree,
    }),
    false,
  );
});

Deno.test('secret tweaking normalizes an odd-Y internal key', () => {
  using internalSecret = SecretKey.fromBytes(scalar(6));
  const original = internalSecret.exportBytes();
  const internalPublic = internalSecret.xOnlyPublicKey();
  assertEquals(internalPublic.parity, 1);

  const publicResult = taprootTweakPublicKey({
    internalKey: internalPublic.key,
    merkleRoot: null,
  });
  const secretResult = taprootTweakSecretKey({
    internalKey: internalSecret,
    merkleRoot: null,
  });
  using outputSecret = secretResult.secretKey;

  assertEquals(
    outputSecret.xOnlyPublicKey().key.toBytes(),
    publicResult.outputKey.toBytes(),
  );
  assertEquals(secretResult.outputKeyParity, publicResult.outputKeyParity);
  assertEquals(internalSecret.exportBytes(), original);
  outputSecret.destroy();
  assertEquals(internalSecret.exportBytes(), original);
});

Deno.test('TapMerkleRoot isolates input and output mutation', () => {
  const input = new Uint8Array(32).fill(7);
  const root = TapMerkleRoot.fromBytes(input);
  input.fill(8);
  assertEquals(root.toBytes(), new Uint8Array(32).fill(7));
  const output = root.toBytes();
  output.fill(9);
  assertEquals(root.toBytes(), new Uint8Array(32).fill(7));
  assertEquals(TapMerkleRoot.tryFromBytes(new Uint8Array(31)), null);
});

function scalar(value: number): Uint8Array {
  const bytes = new Uint8Array(32);
  bytes[31] = value;
  return bytes;
}

function hex(value: string): Uint8Array {
  const bytes = new Uint8Array(value.length / 2);
  for (let index = 0; index < bytes.length; index++) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}
