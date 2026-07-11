/** Pure parsing and candidate selection for user-installed libsecp256k1. */

import { NativeConfigError } from './errors.ts';

/** Platform inputs used by deterministic native-library candidate selection. */
export interface NativeTarget {
  /** Deno operating-system identifier. */
  readonly os: string;
  /** Deno CPU-architecture identifier. */
  readonly arch: string;
}

/** Validated native-library selection. */
export type NativeLibraryConfig =
  | { readonly mode: 'auto' }
  | { readonly mode: 'path'; readonly path: string };

/**
 * Validates the mandatory native-library environment value without accessing
 * process state or the filesystem.
 */
export function parseNativeLibraryConfig(
  value: string | undefined,
  target: NativeTarget,
): NativeLibraryConfig {
  if (value === undefined) {
    throw new NativeConfigError('missing', value, target);
  }
  if (value.length === 0) {
    throw new NativeConfigError('empty', value, target);
  }
  if (value === 'auto') return { mode: 'auto' };
  if (!isAbsoluteNativePath(value, target.os)) {
    throw new NativeConfigError('not-absolute', value, target);
  }
  return { mode: 'path', path: value };
}

/**
 * Returns the exact ordered candidates for a validated environment value.
 * Exact paths are never normalized and never gain fallback candidates.
 */
export function nativeLibraryCandidates(
  value: string | undefined,
  target: NativeTarget,
): readonly string[] {
  const config = parseNativeLibraryConfig(value, target);
  if (config.mode === 'path') return [config.path];

  if (
    target.os === 'linux' &&
    (target.arch === 'x86_64' || target.arch === 'aarch64')
  ) {
    return ['libsecp256k1.so.6'];
  }
  if (target.os === 'darwin' && target.arch === 'x86_64') {
    return [
      'libsecp256k1.6.dylib',
      '/usr/local/lib/libsecp256k1.6.dylib',
    ];
  }
  if (target.os === 'darwin' && target.arch === 'aarch64') {
    return [
      'libsecp256k1.6.dylib',
      '/opt/homebrew/lib/libsecp256k1.6.dylib',
    ];
  }
  throw new NativeConfigError('unsupported-auto', value, target);
}

function isAbsoluteNativePath(path: string, os: string): boolean {
  if (os !== 'windows') return path.startsWith('/');
  return /^[A-Za-z]:[\\/]/.test(path) || /^[\\/]{2}[^\\/]/.test(path);
}
