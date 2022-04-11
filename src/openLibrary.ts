export function openLibrary<S extends Deno.ForeignLibraryInterface>(
  symbols: S,
): Deno.DynamicLibrary<S> {
  let lib: Deno.DynamicLibrary<S>;
  const envSecp256k1Path = Deno.env.get('DENO_SECP256K1_PATH');
  if (envSecp256k1Path !== undefined) {
    lib = Deno.dlopen(envSecp256k1Path, symbols);
  } else {
    try {
      lib = Deno.dlopen(
        Deno.build.os === 'windows'
          ? 'secp256k1.dll'
          : Deno.build.os === 'darwin'
          ? 'libsecp256k1.dylib'
          : 'libsecp256k1.so',
        symbols,
      );
    } catch (e) {
      if (e instanceof Deno.errors.PermissionDenied) {
        throw e;
      }

      const error = new Error(
        'Native secp256k1 library was not found, try installing a `libsecp256k1` or `libsecp256k1-0` package.' +
          ' If you have an existing installation, either add it to the LD_LIBRARY_PATH or set the `DENO_SECP256K1_PATH` environment variable.' +
          ' If you import experimental module then make sure that libsecp256k1 library was built with Schnorr signatures support.' +
          ' Rebuild it with `--enable-module-schnorrsig --enable-module-recovery` parameters or use a different operating system distribution',
      );
      error.cause = e;
      throw error;
    }
  }
  return lib;
}
