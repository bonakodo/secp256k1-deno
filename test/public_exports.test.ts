import { assert } from './deps.ts';
import * as digest from '../src/api/digest.ts';
import * as keys from '../src/api/keys.ts';
import * as signatures from '../src/api/signatures.ts';
import * as historical from '../src/historical.ts';
import * as tweaks from '../src/key_tweaks.ts';
import * as musig from '../src/musig2.ts';
import * as errors from '../src/native/errors.ts';
import * as loader from '../src/native/loader.ts';
import * as diagnostics from '../src/native/mod.ts';
import * as signing from '../src/signing.ts';
import * as taproot from '../src/taproot.ts';

Deno.test('documented public aliases preserve source binding identity', () => {
  const aliases: ReadonlyArray<readonly [string, unknown, unknown]> = [
    ['signing.Digest32', signing.Digest32, digest.Digest32],
    [
      'signing.CompressedPublicKey',
      signing.CompressedPublicKey,
      keys.CompressedPublicKey,
    ],
    ['signing.PublicKey', signing.PublicKey, keys.PublicKey],
    ['signing.XOnlyPublicKey', signing.XOnlyPublicKey, keys.XOnlyPublicKey],
    [
      'signing.EcdsaSignature',
      signing.EcdsaSignature,
      signatures.EcdsaSignature,
    ],
    [
      'signing.SchnorrSignature',
      signing.SchnorrSignature,
      signatures.SchnorrSignature,
    ],
    ['taproot.XOnlyPublicKey', taproot.XOnlyPublicKey, keys.XOnlyPublicKey],
    ['historical.Digest32', historical.Digest32, digest.Digest32],
    [
      'historical.CompressedPublicKey',
      historical.CompressedPublicKey,
      keys.CompressedPublicKey,
    ],
    ['historical.PublicKey', historical.PublicKey, keys.PublicKey],
    [
      'tweaks.CompressedPublicKey',
      tweaks.CompressedPublicKey,
      keys.CompressedPublicKey,
    ],
    ['tweaks.PublicKey', tweaks.PublicKey, keys.PublicKey],
    [
      'musig.CompressedPublicKey',
      musig.CompressedPublicKey,
      keys.CompressedPublicKey,
    ],
    ['musig.Digest32', musig.Digest32, digest.Digest32],
    ['musig.PublicKey', musig.PublicKey, keys.PublicKey],
    [
      'musig.SchnorrSignature',
      musig.SchnorrSignature,
      signatures.SchnorrSignature,
    ],
    ['musig.XOnlyPublicKey', musig.XOnlyPublicKey, keys.XOnlyPublicKey],
    [
      'diagnostics.initializeNative',
      diagnostics.initializeNative,
      loader.initializeNative,
    ],
    ['diagnostics.nativeStatus', diagnostics.nativeStatus, loader.nativeStatus],
    [
      'diagnostics.NativeCapabilityError',
      diagnostics.NativeCapabilityError,
      errors.NativeCapabilityError,
    ],
    [
      'diagnostics.NativeConfigError',
      diagnostics.NativeConfigError,
      errors.NativeConfigError,
    ],
    [
      'diagnostics.NativeContextError',
      diagnostics.NativeContextError,
      errors.NativeContextError,
    ],
    [
      'diagnostics.NativeCoreCompatibilityError',
      diagnostics.NativeCoreCompatibilityError,
      errors.NativeCoreCompatibilityError,
    ],
    [
      'diagnostics.NativeLoadError',
      diagnostics.NativeLoadError,
      errors.NativeLoadError,
    ],
  ];

  for (const [name, alias, source] of aliases) {
    assert(alias === source, `${name} must preserve source binding identity`);
  }
});
