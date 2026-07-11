import { assert, assertEquals, assertThrows } from './deps.ts';
import {
  nativeLibraryCandidates,
  type NativeTarget,
  parseNativeLibraryConfig,
} from '../src/native/config.ts';
import { NativeConfigError } from '../src/native/errors.ts';
import {
  classifyNativeCapabilities,
  createNativeLoader,
  type NativeLibraryHandle,
  type NativeLoaderRuntime,
} from '../src/native/loader.ts';
import {
  CAPABILITY_SYMBOLS,
  type NativeCapability,
  nativeSymbolDefinitions,
  type NativeSymbols,
} from '../src/native/symbols.ts';
import {
  NativeCapabilityError,
  NativeContextError,
  NativeCoreCompatibilityError,
  NativeLoadError,
} from '../src/native/errors.ts';
import {
  createNativeContextHelpers,
  type NativeContextRuntime,
  SECP256K1_CONTEXT_NONE,
} from '../src/native/context.ts';

const LINUX_X64: NativeTarget = { os: 'linux', arch: 'x86_64' };
const LINUX_ARM64: NativeTarget = { os: 'linux', arch: 'aarch64' };
const MACOS_X64: NativeTarget = { os: 'darwin', arch: 'x86_64' };
const MACOS_ARM64: NativeTarget = { os: 'darwin', arch: 'aarch64' };

Deno.test('native config requires an exact auto value or absolute path', () => {
  for (
    const [value, code] of [
      [undefined, 'missing'],
      ['', 'empty'],
      ['relative/libsecp256k1.so.6', 'not-absolute'],
      [' auto ', 'not-absolute'],
      ['AUTO', 'not-absolute'],
    ] as const
  ) {
    const error = assertThrows(
      () => parseNativeLibraryConfig(value, LINUX_X64),
      NativeConfigError,
    );
    assertEquals(error.code, code);
    assertEquals(error.value, value);
  }

  assertEquals(parseNativeLibraryConfig('auto', LINUX_X64), {
    mode: 'auto',
  });
  assertEquals(parseNativeLibraryConfig('/custom/libsecp.dylib', MACOS_ARM64), {
    mode: 'path',
    path: '/custom/libsecp.dylib',
  });
  assertEquals(
    parseNativeLibraryConfig('C:\\lib\\secp256k1.dll', {
      os: 'windows',
      arch: 'x86_64',
    }),
    { mode: 'path', path: 'C:\\lib\\secp256k1.dll' },
  );
  assertEquals(
    parseNativeLibraryConfig('\\\\server\\share\\secp256k1.dll', {
      os: 'windows',
      arch: 'x86_64',
    }),
    { mode: 'path', path: '\\\\server\\share\\secp256k1.dll' },
  );
  assertEquals(
    parseNativeLibraryConfig('//server/share/secp256k1.dll', {
      os: 'windows',
      arch: 'x86_64',
    }),
    { mode: 'path', path: '//server/share/secp256k1.dll' },
  );
});

Deno.test('native candidates are deterministic and architecture-specific', () => {
  assertEquals(nativeLibraryCandidates('auto', LINUX_X64), [
    'libsecp256k1.so.6',
  ]);
  assertEquals(nativeLibraryCandidates('auto', LINUX_ARM64), [
    'libsecp256k1.so.6',
  ]);
  assertEquals(nativeLibraryCandidates('auto', MACOS_X64), [
    'libsecp256k1.6.dylib',
    '/usr/local/lib/libsecp256k1.6.dylib',
  ]);
  assertEquals(nativeLibraryCandidates('auto', MACOS_ARM64), [
    'libsecp256k1.6.dylib',
    '/opt/homebrew/lib/libsecp256k1.6.dylib',
  ]);

  const exact = '/tmp/../custom/libsecp256k1.6.dylib';
  assertEquals(nativeLibraryCandidates(exact, MACOS_ARM64), [exact]);
});

Deno.test('native auto candidates reject unsupported targets', () => {
  for (
    const target of [
      { os: 'windows', arch: 'x86_64' },
      { os: 'linux', arch: 'riscv64' },
      { os: 'freebsd', arch: 'x86_64' },
    ]
  ) {
    const error = assertThrows(
      () => nativeLibraryCandidates('auto', target),
      NativeConfigError,
    );
    assertEquals(error.code, 'unsupported-auto');
    assertEquals(error.target, target);
  }
});

Deno.test('native config errors preserve their structured cause', () => {
  const cause = new Error('environment denied');
  const error = new NativeConfigError(
    'environment-unavailable',
    undefined,
    LINUX_X64,
    { cause },
  );

  assert(error.cause === cause);
  assertEquals(error.name, 'NativeConfigError');
  assertEquals(error.code, 'environment-unavailable');
});

const EXPECTED_CAPABILITY_SYMBOLS = {
  core: [
    'secp256k1_context_static',
    'secp256k1_selftest',
    'secp256k1_context_create',
    'secp256k1_context_destroy',
    'secp256k1_context_randomize',
    'secp256k1_ec_seckey_verify',
    'secp256k1_ec_seckey_negate',
    'secp256k1_ec_seckey_tweak_add',
    'secp256k1_ec_pubkey_parse',
    'secp256k1_ec_pubkey_serialize',
    'secp256k1_ec_pubkey_create',
    'secp256k1_ec_pubkey_negate',
    'secp256k1_ec_pubkey_combine',
    'secp256k1_ec_pubkey_tweak_add',
    'secp256k1_ecdsa_signature_parse_compact',
    'secp256k1_ecdsa_signature_serialize_compact',
    'secp256k1_ecdsa_signature_parse_der',
    'secp256k1_ecdsa_signature_serialize_der',
    'secp256k1_ecdsa_signature_normalize',
    'secp256k1_ecdsa_sign',
    'secp256k1_ecdsa_verify',
    'secp256k1_tagged_sha256',
  ],
  extrakeys: [
    'secp256k1_xonly_pubkey_parse',
    'secp256k1_xonly_pubkey_serialize',
    'secp256k1_xonly_pubkey_cmp',
    'secp256k1_xonly_pubkey_from_pubkey',
    'secp256k1_xonly_pubkey_tweak_add',
    'secp256k1_xonly_pubkey_tweak_add_check',
    'secp256k1_keypair_create',
    'secp256k1_keypair_sec',
    'secp256k1_keypair_pub',
    'secp256k1_keypair_xonly_pub',
    'secp256k1_keypair_xonly_tweak_add',
  ],
  schnorrsig: [
    'secp256k1_schnorrsig_sign32',
    'secp256k1_schnorrsig_verify',
  ],
  ellswift: [
    'secp256k1_ellswift_create',
    'secp256k1_ellswift_xdh',
    'secp256k1_ellswift_xdh_hash_function_bip324',
  ],
  musig: [
    'secp256k1_musig_pubnonce_parse',
    'secp256k1_musig_pubnonce_serialize',
    'secp256k1_musig_aggnonce_parse',
    'secp256k1_musig_aggnonce_serialize',
    'secp256k1_musig_partial_sig_parse',
    'secp256k1_musig_partial_sig_serialize',
    'secp256k1_musig_pubkey_agg',
    'secp256k1_musig_pubkey_get',
    'secp256k1_musig_pubkey_ec_tweak_add',
    'secp256k1_musig_pubkey_xonly_tweak_add',
    'secp256k1_musig_nonce_gen',
    'secp256k1_musig_nonce_gen_counter',
    'secp256k1_musig_nonce_agg',
    'secp256k1_musig_nonce_process',
    'secp256k1_musig_partial_sign',
    'secp256k1_musig_partial_sig_verify',
    'secp256k1_musig_partial_sig_agg',
  ],
} as const;

const ALL_SYMBOL_NAMES = Object.keys(
  nativeSymbolDefinitions,
) as (keyof NativeSymbols)[];

function fakeSymbols(
  present: readonly (keyof NativeSymbols)[],
): NativeSymbols {
  const presentSet = new Set<keyof NativeSymbols>(present);
  return Object.fromEntries(
    ALL_SYMBOL_NAMES.map((name) => {
      if (!presentSet.has(name)) return [name, null];
      const descriptor = nativeSymbolDefinitions[name];
      return [name, 'type' in descriptor ? {} : () => 1];
    }),
  ) as NativeSymbols;
}

interface FakeHandle extends NativeLibraryHandle {
  closeCount: number;
}

function fakeHandle(symbols: NativeSymbols): FakeHandle {
  return {
    symbols,
    closeCount: 0,
    close(): void {
      this.closeCount++;
    },
  };
}

function fakeRuntime(
  value: string | undefined,
  open: (candidate: string) => NativeLibraryHandle,
  target: NativeTarget = LINUX_X64,
): NativeLoaderRuntime {
  return {
    target,
    readPath(): string | undefined {
      return value;
    },
    open,
  };
}

Deno.test('native ABI inventory is exact and every descriptor is optional', () => {
  assertEquals(CAPABILITY_SYMBOLS, EXPECTED_CAPABILITY_SYMBOLS);
  for (const descriptor of Object.values(nativeSymbolDefinitions)) {
    assertEquals(descriptor.optional, true);
  }

  for (
    const excluded of [
      'secp256k1_ecdh',
      'secp256k1_ecdsa_recover',
      'secp256k1_ecdsa_sign_recoverable',
      'secp256k1_ec_seckey_tweak_mul',
      'secp256k1_schnorrsig_sign_custom',
      'secp256k1_ellswift_encode',
    ]
  ) {
    assert(!(excluded in nativeSymbolDefinitions));
  }
});

Deno.test('capabilities classify none, all, and partial independently', () => {
  for (
    const capability of Object.keys(
      CAPABILITY_SYMBOLS,
    ) as NativeCapability[]
  ) {
    const names = CAPABILITY_SYMBOLS[capability];
    const unavailable = classifyNativeCapabilities(fakeSymbols([]));
    assertEquals(unavailable[capability].state, 'unavailable');
    assertEquals(unavailable[capability].missingSymbols, names);

    const available = classifyNativeCapabilities(fakeSymbols(names));
    assertEquals(available[capability], {
      state: 'available',
      missingSymbols: [],
    });

    const incompatible = classifyNativeCapabilities(
      fakeSymbols(names.slice(0, -1)),
    );
    assertEquals(incompatible[capability].state, 'incompatible');
    assertEquals(incompatible[capability].missingSymbols, [
      names[names.length - 1],
    ]);
  }
});

Deno.test('auto continues after open and core failures and closes rejections', () => {
  const openCause = new Error('first candidate did not open');
  const selected = fakeHandle(fakeSymbols(ALL_SYMBOL_NAMES));
  const opened: string[] = [];
  const afterOpenFailure = createNativeLoader(fakeRuntime(
    'auto',
    (candidate) => {
      opened.push(candidate);
      if (opened.length === 1) throw openCause;
      return selected;
    },
    MACOS_ARM64,
  ));

  assertEquals(
    afterOpenFailure.initialize().selectedCandidate,
    '/opt/homebrew/lib/libsecp256k1.6.dylib',
  );
  assertEquals(selected.closeCount, 0);

  const rejected = fakeHandle(fakeSymbols([]));
  const accepted = fakeHandle(fakeSymbols(ALL_SYMBOL_NAMES));
  let calls = 0;
  const afterCoreFailure = createNativeLoader(fakeRuntime(
    'auto',
    () => ++calls === 1 ? rejected : accepted,
    MACOS_X64,
  ));

  assertEquals(
    afterCoreFailure.initialize().selectedCandidate,
    '/usr/local/lib/libsecp256k1.6.dylib',
  );
  assertEquals(rejected.closeCount, 1);
  assertEquals(accepted.closeCount, 0);
});

Deno.test('terminal load failure is structured and cached after valid config', () => {
  const cause = new Error('dlopen failed');
  let reads = 0;
  let opens = 0;
  const loader = createNativeLoader({
    target: LINUX_X64,
    readPath(): string {
      reads++;
      return '/absolute/libsecp256k1.so.6';
    },
    open(candidate): NativeLibraryHandle {
      opens++;
      assertEquals(candidate, '/absolute/libsecp256k1.so.6');
      throw cause;
    },
  });

  const first = assertThrows(() => loader.initialize(), NativeLoadError);
  const second = assertThrows(() => loader.initialize(), NativeLoadError);
  assert(first === second);
  assert(first.attempts[0].cause === cause);
  assertEquals(first.attempts[0].candidate, '/absolute/libsecp256k1.so.6');
  assertEquals(reads, 1);
  assertEquals(opens, 1);
  assertEquals(loader.status().state, 'failed');
  assertEquals(loader.status().selectedCandidate, null);
});

Deno.test('core incompatibility reports missing symbols and closes the handle', () => {
  const symbols = fakeSymbols(CAPABILITY_SYMBOLS.core.slice(0, -1));
  const handle = fakeHandle(symbols);
  const loader = createNativeLoader(fakeRuntime(
    '/absolute/libsecp256k1.so.6',
    () => handle,
  ));

  const error = assertThrows(() => loader.initialize(), NativeLoadError);
  assert(error.attempts[0].cause instanceof NativeCoreCompatibilityError);
  assertEquals(error.attempts[0].cause.missingSymbols, [
    CAPABILITY_SYMBOLS.core[CAPABILITY_SYMBOLS.core.length - 1],
  ]);
  assertEquals(handle.closeCount, 1);
});

Deno.test('config errors stay uninitialized and can be retried', () => {
  let reads = 0;
  const handle = fakeHandle(fakeSymbols(ALL_SYMBOL_NAMES));
  const loader = createNativeLoader({
    target: LINUX_X64,
    readPath(): string | undefined {
      reads++;
      return reads === 1 ? undefined : '/absolute/libsecp256k1.so.6';
    },
    open(): NativeLibraryHandle {
      return handle;
    },
  });

  assertThrows(() => loader.initialize(), NativeConfigError);
  assertEquals(loader.status().state, 'uninitialized');
  assertEquals(loader.initialize().state, 'loaded');
  assertEquals(reads, 2);
});

Deno.test('status has no loader side effects and exposes no handle', () => {
  let reads = 0;
  let opens = 0;
  const loader = createNativeLoader({
    target: LINUX_X64,
    readPath(): string {
      reads++;
      return '/tmp/../absolute/libsecp256k1.so.6';
    },
    open(): NativeLibraryHandle {
      opens++;
      return fakeHandle(fakeSymbols(ALL_SYMBOL_NAMES));
    },
  });

  assertEquals(loader.status().state, 'uninitialized');
  assertEquals(reads, 0);
  assertEquals(opens, 0);

  const status = loader.initialize();
  assertEquals(status.selectedCandidate, '/tmp/../absolute/libsecp256k1.so.6');
  assertEquals(Object.keys(status).sort(), [
    'capabilities',
    'error',
    'selectedCandidate',
    'state',
  ]);
  assert(!('handle' in status));
  assert(!('symbols' in status));
});

Deno.test('capability failures do not poison a loaded core', () => {
  const handle = fakeHandle(fakeSymbols(CAPABILITY_SYMBOLS.core));
  const loader = createNativeLoader(fakeRuntime(
    '/absolute/libsecp256k1.so.6',
    () => handle,
  ));

  assertThrows(
    () => loader.initialize({ require: ['schnorrsig'] }),
    NativeCapabilityError,
  );
  assertEquals(loader.status().state, 'loaded');
  assert(loader.getNativeSymbols().secp256k1_selftest !== null);
  assertThrows(
    () => loader.requireCapability('extrakeys'),
    NativeCapabilityError,
  );
  assert(loader.requireCapability('core').secp256k1_context_create !== null);
  assertEquals(handle.closeCount, 0);
});

function coreSymbols(
  overrides: Partial<NativeSymbols> = {},
): NativeSymbols {
  return Object.assign(
    fakeSymbols(CAPABILITY_SYMBOLS.core),
    overrides,
  );
}

function contextRuntime(
  events: string[],
  staticContext: Deno.PointerValue,
): NativeContextRuntime {
  return {
    dereferenceStatic(): Deno.PointerValue {
      events.push('dereference');
      return staticContext;
    },
    randomFill(seed): void {
      events.push(`random:${seed.length}`);
      seed.fill(7);
    },
  };
}

Deno.test('static context self-tests once before first use', () => {
  const events: string[] = [];
  const staticAddress = {} as Deno.PointerValue;
  const staticContext = {} as Deno.PointerValue;
  const symbols = coreSymbols({
    secp256k1_context_static: staticAddress,
    secp256k1_selftest: () => events.push('selftest'),
  }) as import('../src/native/symbols.ts').LoadedCoreSymbols;
  const helpers = createNativeContextHelpers(
    symbols,
    contextRuntime(events, staticContext),
  );

  helpers.withStaticContext((context) => {
    assert(context === staticContext);
    events.push('callback:1');
  });
  helpers.withStaticContext(() => events.push('callback:2'));

  assertEquals(events, [
    'selftest',
    'dereference',
    'callback:1',
    'dereference',
    'callback:2',
  ]);
});

Deno.test('signing context uses NONE, randomizes, calls back, and destroys', () => {
  const events: string[] = [];
  const mutableContext = {} as Deno.PointerValue;
  const symbols = coreSymbols({
    secp256k1_context_create: (flags) => {
      events.push(`create:${flags}`);
      return mutableContext;
    },
    secp256k1_context_randomize: (context, seed) => {
      assert(context === mutableContext);
      assert(seed instanceof Uint8Array);
      events.push(`randomize:${seed[0]}`);
      return 1;
    },
    secp256k1_context_destroy: (context) => {
      assert(context === mutableContext);
      events.push('destroy');
    },
  }) as import('../src/native/symbols.ts').LoadedCoreSymbols;
  const helpers = createNativeContextHelpers(
    symbols,
    contextRuntime(events, null),
  );

  const result = helpers.withSigningContext((context) => {
    assert(context === mutableContext);
    events.push('callback');
    return 42;
  });

  assertEquals(result, 42);
  assertEquals(events, [
    `create:${SECP256K1_CONTEXT_NONE}`,
    'random:32',
    'randomize:7',
    'callback',
    'destroy',
  ]);
});

Deno.test('signing context destroys after callback throws', () => {
  const events: string[] = [];
  const callbackCause = new Error('callback failed');
  const context = {} as Deno.PointerValue;
  const symbols = coreSymbols({
    secp256k1_context_create: () => context,
    secp256k1_context_randomize: () => 1,
    secp256k1_context_destroy: () => events.push('destroy'),
  }) as import('../src/native/symbols.ts').LoadedCoreSymbols;
  const helpers = createNativeContextHelpers(
    symbols,
    contextRuntime(events, null),
  );

  const thrown = assertThrows(() =>
    helpers.withSigningContext(() => {
      events.push('callback');
      throw callbackCause;
    })
  );

  assert(thrown === callbackCause);
  assertEquals(events, ['random:32', 'callback', 'destroy']);
});

Deno.test('signing context destroys without callback after RNG failure', () => {
  const events: string[] = [];
  const rngCause = new Error('rng failed');
  const symbols = coreSymbols({
    secp256k1_context_create: () => ({} as Deno.PointerValue),
    secp256k1_context_randomize: () => {
      events.push('randomize');
      return 1;
    },
    secp256k1_context_destroy: () => events.push('destroy'),
  }) as import('../src/native/symbols.ts').LoadedCoreSymbols;
  const runtime: NativeContextRuntime = {
    dereferenceStatic: () => null,
    randomFill(): void {
      events.push('random');
      throw rngCause;
    },
  };
  const helpers = createNativeContextHelpers(symbols, runtime);

  const thrown = assertThrows(() =>
    helpers.withSigningContext(() => events.push('callback'))
  );
  assert(thrown === rngCause);
  assertEquals(events, ['random', 'destroy']);
});

Deno.test('signing context destroys after randomize failure', () => {
  const events: string[] = [];
  const symbols = coreSymbols({
    secp256k1_context_create: () => ({} as Deno.PointerValue),
    secp256k1_context_randomize: () => {
      events.push('randomize');
      return 0;
    },
    secp256k1_context_destroy: () => events.push('destroy'),
  }) as import('../src/native/symbols.ts').LoadedCoreSymbols;
  const helpers = createNativeContextHelpers(
    symbols,
    contextRuntime(events, null),
  );

  const error = assertThrows(
    () => helpers.withSigningContext(() => events.push('callback')),
    NativeContextError,
  );
  assertEquals(error.code, 'context-randomize-failed');
  assertEquals(events, ['random:32', 'randomize', 'destroy']);
});

Deno.test('real native initialization and contexts run only in a subprocess', async () => {
  const path = Deno.env.get('DENO_SECP256K1_PATH');
  assert(path, 'DENO_SECP256K1_PATH must select the integration library');
  const moduleUrl = new URL('../src/native/mod.ts', import.meta.url).href;
  const contextUrl = new URL('../src/native/context.ts', import.meta.url).href;
  const script = `
    import { initializeNative, nativeStatus } from ${JSON.stringify(moduleUrl)};
    import { withSigningContext, withStaticContext } from ${
    JSON.stringify(contextUrl)
  };
    if (nativeStatus().state !== 'uninitialized') throw new Error('eager load');
    const status = initializeNative({
      require: ['extrakeys', 'schnorrsig', 'ellswift', 'musig'],
    });
    withStaticContext((context) => {
      if (context === null) throw new Error('null static context');
    });
    withSigningContext((context) => {
      if (context === null) throw new Error('null signing context');
    });
    console.log(JSON.stringify(status));
  `;
  const output = await new Deno.Command(Deno.execPath(), {
    args: ['eval', script],
    env: { DENO_SECP256K1_PATH: path },
    stdout: 'piped',
    stderr: 'piped',
  }).output();

  assertEquals(
    output.code,
    0,
    new TextDecoder().decode(output.stderr),
  );
  const status = JSON.parse(new TextDecoder().decode(output.stdout)) as {
    state: string;
    selectedCandidate: string;
    capabilities: Record<string, { state: string }>;
  };
  assertEquals(status.state, 'loaded');
  assertEquals(status.selectedCandidate, path);
  for (const capability of Object.values(status.capabilities)) {
    assertEquals(capability.state, 'available');
  }
});
