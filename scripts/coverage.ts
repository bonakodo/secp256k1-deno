const root = new URL('../', import.meta.url).pathname;
const coverageDir = await Deno.makeTempDir({
  prefix: 'secp256k1-deno-coverage.',
});
const scriptDir = await Deno.makeTempDir({
  prefix: 'secp256k1-deno-coverage-scripts.',
});
const libraryPath = `${root}secp256k1/build-deno/lib/libsecp256k1.dylib`;

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
    `--coverage=${coverageDir}`,
    '--allow-ffi',
    '--allow-env=DENO_SECP256K1_PATH',
    '--allow-read=secp256k1/include',
  ],
  { env: { DENO_SECP256K1_PATH: libraryPath } },
);

await runDeno(
  [
    'run',
    `--coverage=${coverageDir}`,
    '--allow-ffi',
    '--allow-env=DENO_SECP256K1_PATH',
    fallbackSuccess,
  ],
  {
    clearEnv: true,
    env: { DYLD_LIBRARY_PATH: `${root}secp256k1/build-deno/lib` },
  },
);

await runDeno(
  [
    'run',
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
    `--coverage=${coverageDir}`,
    '--allow-env=DENO_SECP256K1_PATH',
    fallbackPermission,
  ],
  {
    clearEnv: true,
    env: { DYLD_LIBRARY_PATH: `${root}secp256k1/build-deno/lib` },
  },
);

await runDeno([
  'coverage',
  coverageDir,
  `--include=${root}(src|test/deps)`,
  '--threshold=100',
], { printOutput: true });

console.log(`Coverage profile: ${coverageDir}`);
