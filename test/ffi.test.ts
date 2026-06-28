import { assert, assertEquals, assertNotEquals } from './deps.ts';
import * as ffi from '../src/ffi.ts';

const CONTEXT_FLAGS = ffi.SECP256K1_CONTEXT_NONE;

function u8(size: number, fill = 0): Uint8Array {
  return new Uint8Array(size).fill(fill);
}

function scalar(value: number): Uint8Array {
  const out = new Uint8Array(32);
  out[31] = value;
  return out;
}

function i32Buffer(value = 0): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setInt32(0, value, true);
  return out;
}

function readI32(buffer: Uint8Array): number {
  return new DataView(buffer.buffer, buffer.byteOffset, 4).getInt32(0, true);
}

function createContext(): Deno.PointerValue {
  const ctx = ffi.secp256k1_context_create(CONTEXT_FLAGS);
  assert(ctx !== null);
  const seed = new Uint8Array(32).fill(7);
  assert(ffi.secp256k1_context_randomize(ctx, seed));
  return ctx;
}

function withContext(fn: (ctx: Deno.PointerValue) => void): void {
  const ctx = createContext();
  try {
    fn(ctx);
  } finally {
    ffi.secp256k1_context_destroy(ctx);
  }
}

function publicKey(ctx: Deno.PointerValue, seckey: Uint8Array): Uint8Array {
  const pubkey = u8(ffi.SECP256K1_PUBKEY_SIZE);
  assert(ffi.secp256k1_ec_pubkey_create(ctx, pubkey, seckey));
  return pubkey;
}

function serializePublicKey(
  ctx: Deno.PointerValue,
  pubkey: Uint8Array,
  compressed = true,
): Uint8Array {
  const out = u8(compressed ? 33 : 65);
  const outLen = new BigUint64Array([BigInt(out.length)]);
  assert(
    ffi.secp256k1_ec_pubkey_serialize(
      ctx,
      out,
      outLen,
      pubkey,
      compressed ? ffi.SECP256K1_EC_COMPRESSED : ffi.SECP256K1_EC_UNCOMPRESSED,
    ),
  );
  return out.slice(0, Number(outLen[0]));
}

function keypair(ctx: Deno.PointerValue, seckey: Uint8Array): Uint8Array {
  const keypair = u8(ffi.SECP256K1_KEYPAIR_SIZE);
  assert(ffi.secp256k1_keypair_create(ctx, keypair, seckey));
  return keypair;
}

function xonlyFromPubkey(
  ctx: Deno.PointerValue,
  pubkey: Uint8Array,
): { pubkey: Uint8Array; parity: number } {
  const xonly = u8(ffi.SECP256K1_XONLY_PUBKEY_SIZE);
  const parity = i32Buffer();
  assert(ffi.secp256k1_xonly_pubkey_from_pubkey(ctx, xonly, parity, pubkey));
  return { pubkey: xonly, parity: readI32(parity) };
}

function pointerValue(buffer: Uint8Array): bigint {
  return BigInt(Deno.UnsafePointer.value(Deno.UnsafePointer.of(buffer)));
}

function schnorrExtraParams(
  nonceFunction: Deno.PointerValue,
  data: Uint8Array | null,
): Uint8Array {
  const pointerSize = Deno.build.arch === 'x86_64' ||
      Deno.build.arch === 'aarch64'
    ? 8
    : 4;
  const firstPointerOffset = pointerSize;
  const out = u8(firstPointerOffset + pointerSize * 2);
  out.set(ffi.SECP256K1_SCHNORRSIG_EXTRAPARAMS_MAGIC);
  const view = new DataView(out.buffer);
  const writePointer = (offset: number, pointer: Deno.PointerValue) => {
    const value = pointer === null
      ? 0n
      : BigInt(Deno.UnsafePointer.value(pointer));
    if (pointerSize === 8) {
      view.setBigUint64(offset, value, true);
    } else {
      view.setUint32(offset, Number(value), true);
    }
  };
  writePointer(firstPointerOffset, nonceFunction);
  writePointer(
    firstPointerOffset + pointerSize,
    data === null ? null : Deno.UnsafePointer.of(data),
  );
  return out;
}

function publicApiSymbolsFromHeaders(): Set<string> {
  const names = new Set<string>();
  for (const entry of Deno.readDirSync('secp256k1/include')) {
    if (!entry.isFile || !entry.name.endsWith('.h')) continue;
    const source = Deno.readTextFileSync(`secp256k1/include/${entry.name}`)
      .replaceAll(/\/\*[\s\S]*?\*\//g, ' ')
      .replaceAll(/\\\n/g, ' ');
    const declarations = source.match(/SECP256K1_API[\s\S]*?;/g) ?? [];
    for (const declaration of declarations) {
      const functionMatch = declaration.match(
        /\b(secp256k1_[A-Za-z0-9_]+)\s*\(/,
      );
      if (functionMatch) {
        names.add(functionMatch[1]);
        continue;
      }
      const staticMatch = declaration.match(
        /\b(secp256k1_[A-Za-z0-9_]+)\s*(?:SECP256K1_DEPRECATED\([^)]*\))?\s*;/,
      );
      if (staticMatch) names.add(staticMatch[1]);
    }
  }
  return names;
}

Deno.test('raw FFI symbol table covers upstream public headers', () => {
  // Ported from the public declarations in secp256k1/include/*.h.
  const headerSymbols = [...publicApiSymbolsFromHeaders()].sort();
  const ffiSymbols = new Set(Object.keys(ffi.symbols));
  const missing = headerSymbols.filter((name) => !ffiSymbols.has(name));
  assertEquals(missing, []);
});

Deno.test('runtime library exports the raw FFI symbol table', () => {
  const path = Deno.env.get('DENO_SECP256K1_PATH');
  assert(path, 'DENO_SECP256K1_PATH must point at the all-module build');
  const lib = Deno.dlopen(path, ffi.symbols);
  lib.close();
});

Deno.test('context, callback reset, selftest, and preallocated APIs', () => {
  // Covers secp256k1.h and secp256k1_preallocated.h non-aborting API cases.
  ffi.secp256k1_selftest();
  assert(ffi.secp256k1_context_static !== null);
  assert(ffi.secp256k1_context_no_precomp !== null);
  assert(ffi.secp256k1_nonce_function_default !== null);
  assert(ffi.secp256k1_nonce_function_rfc6979 !== null);

  const ctx = createContext();
  const cloned = ffi.secp256k1_context_clone(ctx);
  assert(cloned !== null);
  ffi.secp256k1_context_set_illegal_callback(ctx, null, null);
  ffi.secp256k1_context_set_error_callback(ctx, null, null);
  ffi.secp256k1_context_set_sha256_compression(ctx, null);
  ffi.secp256k1_context_destroy(cloned);
  ffi.secp256k1_context_destroy(ctx);

  const size = Number(ffi.secp256k1_context_preallocated_size(CONTEXT_FLAGS));
  assert(size > 0);
  const prealloc = u8(size);
  const preallocatedCtx = ffi.secp256k1_context_preallocated_create(
    prealloc,
    CONTEXT_FLAGS,
  );
  assert(preallocatedCtx !== null);
  const cloneSize = Number(
    ffi.secp256k1_context_preallocated_clone_size(preallocatedCtx),
  );
  assert(cloneSize > 0);
  const clonePrealloc = u8(cloneSize);
  const preallocatedClone = ffi.secp256k1_context_preallocated_clone(
    preallocatedCtx,
    clonePrealloc,
  );
  assert(preallocatedClone !== null);
  ffi.secp256k1_context_preallocated_destroy(preallocatedClone);
  ffi.secp256k1_context_preallocated_destroy(preallocatedCtx);
});

Deno.test('public key compare, sort, and combine raw APIs', () => {
  // Ported from public key comparison/sort/combine coverage in src/tests.c.
  withContext((ctx) => {
    const pk1 = publicKey(ctx, scalar(1));
    const pk2 = publicKey(ctx, scalar(2));
    assertNotEquals(ffi.secp256k1_ec_pubkey_cmp(ctx, pk1, pk2), 0);

    const pointers = ffi.pointerArray([pk2, pk1]);
    const expectedFirst = ffi.secp256k1_ec_pubkey_cmp(ctx, pk1, pk2) < 0
      ? pointerValue(pk1)
      : pointerValue(pk2);
    assert(ffi.secp256k1_ec_pubkey_sort(ctx, pointers, 2n));
    assert(
      ffi.secp256k1_ec_pubkey_sort(ctx, new Uint8Array(pointers.buffer), 2n),
    );
    assertEquals(pointers[0], expectedFirst);

    const combined = u8(ffi.SECP256K1_PUBKEY_SIZE);
    assert(ffi.secp256k1_ec_pubkey_combine(ctx, combined, pointers, 2n));
    assertEquals(serializePublicKey(ctx, combined).length, 33);
  });
});

Deno.test('recovery sign, serialize, convert, and recover', () => {
  // Ported from src/modules/recovery/tests_impl.h happy-path coverage.
  withContext((ctx) => {
    const seckey = scalar(3);
    const message = new Uint8Array(32).fill(9);
    const recoverable = u8(ffi.SECP256K1_ECDSA_RECOVERABLE_SIGNATURE_SIZE);
    assert(
      ffi.secp256k1_ecdsa_sign_recoverable(
        ctx,
        recoverable,
        message,
        seckey,
        null,
        null,
      ),
    );

    const compact = u8(64);
    const recid = i32Buffer();
    assert(
      ffi.secp256k1_ecdsa_recoverable_signature_serialize_compact(
        ctx,
        compact,
        recid,
        recoverable,
      ),
    );
    assert(readI32(recid) >= 0);

    const parsed = u8(ffi.SECP256K1_ECDSA_RECOVERABLE_SIGNATURE_SIZE);
    assert(
      ffi.secp256k1_ecdsa_recoverable_signature_parse_compact(
        ctx,
        parsed,
        compact,
        readI32(recid),
      ),
    );

    const regular = u8(ffi.SECP256K1_ECDSA_SIGNATURE_SIZE);
    assert(
      ffi.secp256k1_ecdsa_recoverable_signature_convert(ctx, regular, parsed),
    );
    assert(
      ffi.secp256k1_ecdsa_verify(ctx, regular, message, publicKey(ctx, seckey)),
    );

    const recovered = u8(ffi.SECP256K1_PUBKEY_SIZE);
    assert(ffi.secp256k1_ecdsa_recover(ctx, recovered, parsed, message));
    assertEquals(
      serializePublicKey(ctx, recovered),
      serializePublicKey(ctx, publicKey(ctx, seckey)),
    );
  });
});

Deno.test('extrakeys xonly/keypair roundtrips and tweaks', () => {
  // Ported from src/modules/extrakeys/tests_impl.h xonly/keypair paths.
  withContext((ctx) => {
    const seckey = scalar(4);
    const pair = keypair(ctx, seckey);
    const extractedSecret = u8(32);
    assert(ffi.secp256k1_keypair_sec(ctx, extractedSecret, pair));
    assertEquals(extractedSecret, seckey);

    const pairPubkey = u8(ffi.SECP256K1_PUBKEY_SIZE);
    assert(ffi.secp256k1_keypair_pub(ctx, pairPubkey, pair));
    assertEquals(
      serializePublicKey(ctx, pairPubkey),
      serializePublicKey(ctx, publicKey(ctx, seckey)),
    );

    const xonly = u8(ffi.SECP256K1_XONLY_PUBKEY_SIZE);
    const parity = i32Buffer();
    assert(ffi.secp256k1_keypair_xonly_pub(ctx, xonly, parity, pair));
    const serialized = u8(32);
    assert(ffi.secp256k1_xonly_pubkey_serialize(ctx, serialized, xonly));
    const parsed = u8(ffi.SECP256K1_XONLY_PUBKEY_SIZE);
    assert(ffi.secp256k1_xonly_pubkey_parse(ctx, parsed, serialized));
    assertEquals(ffi.secp256k1_xonly_pubkey_cmp(ctx, xonly, parsed), 0);

    const tweak = scalar(1);
    const tweakedPubkey = u8(ffi.SECP256K1_PUBKEY_SIZE);
    assert(
      ffi.secp256k1_xonly_pubkey_tweak_add(ctx, tweakedPubkey, xonly, tweak),
    );
    const { pubkey: tweakedXonly, parity: tweakedParity } = xonlyFromPubkey(
      ctx,
      tweakedPubkey,
    );
    const tweakedSerialized = u8(32);
    assert(
      ffi.secp256k1_xonly_pubkey_serialize(
        ctx,
        tweakedSerialized,
        tweakedXonly,
      ),
    );
    assert(
      ffi.secp256k1_xonly_pubkey_tweak_add_check(
        ctx,
        tweakedSerialized,
        tweakedParity,
        xonly,
        tweak,
      ),
    );

    const tweakedPair = pair.slice();
    assert(ffi.secp256k1_keypair_xonly_tweak_add(ctx, tweakedPair, tweak));
    const tweakedPairPubkey = u8(ffi.SECP256K1_PUBKEY_SIZE);
    assert(ffi.secp256k1_keypair_pub(ctx, tweakedPairPubkey, tweakedPair));
    assertEquals(
      serializePublicKey(ctx, tweakedPairPubkey),
      serializePublicKey(ctx, tweakedPubkey),
    );
  });
});

Deno.test('ECDH default and explicit hash function pointers', () => {
  // Ported from src/modules/ecdh/tests_impl.h default hash coverage.
  withContext((ctx) => {
    assert(ffi.secp256k1_ecdh_hash_function_sha256 !== null);
    assert(ffi.secp256k1_ecdh_hash_function_default !== null);
    const pubkey = publicKey(ctx, scalar(5));
    const seckey = scalar(6);
    const implicitDefault = u8(32);
    const explicitDefault = u8(32);
    assert(
      ffi.secp256k1_ecdh(ctx, implicitDefault, pubkey, seckey, null, null),
    );
    assert(
      ffi.secp256k1_ecdh(
        ctx,
        explicitDefault,
        pubkey,
        seckey,
        ffi.secp256k1_ecdh_hash_function_default,
        null,
      ),
    );
    assertEquals(explicitDefault, implicitDefault);
  });
});

Deno.test('EllSwift create, encode, decode, and XDH', () => {
  // Ported from src/modules/ellswift/tests_impl.h roundtrip-style coverage.
  withContext((ctx) => {
    assert(ffi.secp256k1_ellswift_xdh_hash_function_bip324 !== null);
    const seckeyA = scalar(7);
    const seckeyB = scalar(8);
    const ellA = u8(64);
    const ellB = u8(64);
    assert(ffi.secp256k1_ellswift_create(ctx, ellA, seckeyA, u8(32, 1)));
    assert(ffi.secp256k1_ellswift_create(ctx, ellB, seckeyB, null));

    const decoded = u8(ffi.SECP256K1_PUBKEY_SIZE);
    assert(ffi.secp256k1_ellswift_decode(ctx, decoded, ellA));
    const encoded = u8(64);
    assert(ffi.secp256k1_ellswift_encode(ctx, encoded, decoded, u8(32, 2)));
    const decodedAgain = u8(ffi.SECP256K1_PUBKEY_SIZE);
    assert(ffi.secp256k1_ellswift_decode(ctx, decodedAgain, encoded));
    assertEquals(
      serializePublicKey(ctx, decodedAgain),
      serializePublicKey(ctx, decoded),
    );

    const secretA = u8(32);
    const secretB = u8(32);
    assert(
      ffi.secp256k1_ellswift_xdh(
        ctx,
        secretA,
        ellA,
        ellB,
        seckeyA,
        0,
        ffi.secp256k1_ellswift_xdh_hash_function_bip324,
        null,
      ),
    );
    assert(
      ffi.secp256k1_ellswift_xdh(
        ctx,
        secretB,
        ellA,
        ellB,
        seckeyB,
        1,
        ffi.secp256k1_ellswift_xdh_hash_function_bip324,
        null,
      ),
    );
    assertEquals(secretA, secretB);
  });
});

Deno.test('Schnorr aliases and custom signing extraparams', () => {
  // Ported from src/modules/schnorrsig/tests_impl.h sign32/sign/sign_custom.
  withContext((ctx) => {
    assert(ffi.secp256k1_nonce_function_bip340 !== null);
    const pair = keypair(ctx, scalar(9));
    const xonly = u8(ffi.SECP256K1_XONLY_PUBKEY_SIZE);
    assert(ffi.secp256k1_keypair_xonly_pub(ctx, xonly, null, pair));
    const msg32 = new Uint8Array(32).fill(10);
    const aux = new Uint8Array(32).fill(11);
    const sign32 = u8(64);
    const deprecatedSign = u8(64);
    const custom = u8(64);
    assert(ffi.secp256k1_schnorrsig_sign32(ctx, sign32, msg32, pair, aux));
    assert(
      ffi.secp256k1_schnorrsig_sign(ctx, deprecatedSign, msg32, pair, aux),
    );
    const extraParams = schnorrExtraParams(null, aux);
    assert(
      ffi.secp256k1_schnorrsig_sign_custom(
        ctx,
        custom,
        msg32,
        msg32.length,
        pair,
        extraParams,
      ),
    );
    assertEquals(deprecatedSign, sign32);
    assertEquals(custom, sign32);
    assert(
      ffi.secp256k1_schnorrsig_verify(ctx, custom, msg32, msg32.length, xonly),
    );

    const variableMessage = new TextEncoder().encode('secp256k1-deno');
    const variableSig = u8(64);
    assert(
      ffi.secp256k1_schnorrsig_sign_custom(
        ctx,
        variableSig,
        variableMessage,
        variableMessage.length,
        pair,
        null,
      ),
    );
    assert(
      ffi.secp256k1_schnorrsig_verify(
        ctx,
        variableSig,
        variableMessage,
        variableMessage.length,
        xonly,
      ),
    );
  });
});

Deno.test('MuSig nonce, partial signature, and aggregate signature flow', () => {
  // Ported from examples/musig.c and src/modules/musig/tests_impl.h.
  withContext((ctx) => {
    const msg = new Uint8Array(32).fill(12);
    const seckeys = [scalar(13), scalar(14)];
    const keypairs = seckeys.map((secret) => keypair(ctx, secret));
    const pubkeys = keypairs.map((pair) => {
      const pubkey = u8(ffi.SECP256K1_PUBKEY_SIZE);
      assert(ffi.secp256k1_keypair_pub(ctx, pubkey, pair));
      return pubkey;
    });

    const keyaggCache = u8(ffi.SECP256K1_MUSIG_KEYAGG_CACHE_SIZE);
    const aggXonly = u8(ffi.SECP256K1_XONLY_PUBKEY_SIZE);
    assert(
      ffi.secp256k1_musig_pubkey_agg(
        ctx,
        aggXonly,
        keyaggCache,
        ffi.pointerArray(pubkeys),
        pubkeys.length,
      ),
    );
    const aggFull = u8(ffi.SECP256K1_PUBKEY_SIZE);
    assert(ffi.secp256k1_musig_pubkey_get(ctx, aggFull, keyaggCache));

    const ecTweakedCache = keyaggCache.slice();
    const ecTweakedPubkey = u8(ffi.SECP256K1_PUBKEY_SIZE);
    assert(
      ffi.secp256k1_musig_pubkey_ec_tweak_add(
        ctx,
        ecTweakedPubkey,
        ecTweakedCache,
        scalar(1),
      ),
    );
    const xonlyTweakedCache = keyaggCache.slice();
    const xonlyTweakedPubkey = u8(ffi.SECP256K1_PUBKEY_SIZE);
    assert(
      ffi.secp256k1_musig_pubkey_xonly_tweak_add(
        ctx,
        xonlyTweakedPubkey,
        xonlyTweakedCache,
        scalar(2),
      ),
    );

    const counterSecnonce = u8(ffi.SECP256K1_MUSIG_SECNONCE_SIZE);
    const counterPubnonce = u8(ffi.SECP256K1_MUSIG_PUBNONCE_SIZE);
    assert(
      ffi.secp256k1_musig_nonce_gen_counter(
        ctx,
        counterSecnonce,
        counterPubnonce,
        1n,
        keypairs[0],
        msg,
        keyaggCache,
        null,
      ),
    );

    const secnonces = [u8(ffi.SECP256K1_MUSIG_SECNONCE_SIZE), u8(132)];
    const pubnonces = [u8(ffi.SECP256K1_MUSIG_PUBNONCE_SIZE), u8(132)];
    for (let i = 0; i < 2; i++) {
      const sessionRandom = new Uint8Array(32).fill(20 + i);
      assert(
        ffi.secp256k1_musig_nonce_gen(
          ctx,
          secnonces[i],
          pubnonces[i],
          sessionRandom,
          seckeys[i],
          pubkeys[i],
          msg,
          keyaggCache,
          null,
        ),
      );
      const serializedPubnonce = u8(66);
      assert(
        ffi.secp256k1_musig_pubnonce_serialize(
          ctx,
          serializedPubnonce,
          pubnonces[i],
        ),
      );
      const parsedPubnonce = u8(ffi.SECP256K1_MUSIG_PUBNONCE_SIZE);
      assert(
        ffi.secp256k1_musig_pubnonce_parse(
          ctx,
          parsedPubnonce,
          serializedPubnonce,
        ),
      );
      assertEquals(parsedPubnonce, pubnonces[i]);
    }

    const badPubnonce = u8(ffi.SECP256K1_MUSIG_PUBNONCE_SIZE);
    assertEquals(
      ffi.secp256k1_musig_pubnonce_parse(ctx, badPubnonce, u8(66)),
      false,
    );

    const aggnonce = u8(ffi.SECP256K1_MUSIG_AGGNONCE_SIZE);
    assert(
      ffi.secp256k1_musig_nonce_agg(
        ctx,
        aggnonce,
        ffi.pointerArray(pubnonces),
        pubnonces.length,
      ),
    );
    const serializedAggnonce = u8(66);
    assert(
      ffi.secp256k1_musig_aggnonce_serialize(ctx, serializedAggnonce, aggnonce),
    );
    const parsedAggnonce = u8(ffi.SECP256K1_MUSIG_AGGNONCE_SIZE);
    assert(
      ffi.secp256k1_musig_aggnonce_parse(
        ctx,
        parsedAggnonce,
        serializedAggnonce,
      ),
    );
    assertEquals(parsedAggnonce, aggnonce);

    const session = u8(ffi.SECP256K1_MUSIG_SESSION_SIZE);
    assert(
      ffi.secp256k1_musig_nonce_process(
        ctx,
        session,
        aggnonce,
        msg,
        keyaggCache,
      ),
    );

    const partials = [
      u8(ffi.SECP256K1_MUSIG_PARTIAL_SIG_SIZE),
      u8(ffi.SECP256K1_MUSIG_PARTIAL_SIG_SIZE),
    ];
    for (let i = 0; i < 2; i++) {
      assert(
        ffi.secp256k1_musig_partial_sign(
          ctx,
          partials[i],
          secnonces[i],
          keypairs[i],
          keyaggCache,
          session,
        ),
      );
      assert(
        ffi.secp256k1_musig_partial_sig_verify(
          ctx,
          partials[i],
          pubnonces[i],
          pubkeys[i],
          keyaggCache,
          session,
        ),
      );

      const serializedPartial = u8(32);
      assert(
        ffi.secp256k1_musig_partial_sig_serialize(
          ctx,
          serializedPartial,
          partials[i],
        ),
      );
      const parsedPartial = u8(ffi.SECP256K1_MUSIG_PARTIAL_SIG_SIZE);
      assert(
        ffi.secp256k1_musig_partial_sig_parse(
          ctx,
          parsedPartial,
          serializedPartial,
        ),
      );
      assertEquals(parsedPartial, partials[i]);
    }

    assertEquals(
      ffi.secp256k1_musig_partial_sig_verify(
        ctx,
        partials[0],
        pubnonces[1],
        pubkeys[0],
        keyaggCache,
        session,
      ),
      false,
    );

    const finalSig = u8(64);
    assert(
      ffi.secp256k1_musig_partial_sig_agg(
        ctx,
        finalSig,
        session,
        ffi.pointerArray(partials),
        partials.length,
      ),
    );
    assert(
      ffi.secp256k1_schnorrsig_verify(ctx, finalSig, msg, msg.length, aggXonly),
    );
  });
});
