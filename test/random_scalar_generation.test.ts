import { assertEquals, assertThrows, ffiTest } from './deps.ts';
import {
  Bip324KeyExchange,
  SecretKeyRandomError as Bip324SecretKeyRandomError,
} from '../src/bip324.ts';
import {
  SecretKey,
  SecretKeyRandomError as SigningSecretKeyRandomError,
} from '../src/signing.ts';

class UnexpectedRetryError extends Error {}

ffiTest(
  'SecretKey.generate rejects an invalid random scalar without retrying',
  () => {
    warmVerificationContext();
    const descriptor = Object.getOwnPropertyDescriptor(
      crypto,
      'getRandomValues',
    );
    let calls = 0;
    Object.defineProperty(crypto, 'getRandomValues', {
      configurable: true,
      value(candidate: Uint8Array): Uint8Array {
        calls++;
        if (calls > 1) throw new UnexpectedRetryError();
        candidate.fill(0);
        return candidate;
      },
    });
    try {
      assertThrows(() => SecretKey.generate(), SigningSecretKeyRandomError);
      assertEquals(calls, 1);
    } finally {
      restoreRandomValues(descriptor);
    }
  },
);

ffiTest('BIP324 rejects an invalid random scalar without retrying', () => {
  warmVerificationContext();
  const descriptor = Object.getOwnPropertyDescriptor(crypto, 'getRandomValues');
  let calls = 0;
  Object.defineProperty(crypto, 'getRandomValues', {
    configurable: true,
    value(candidate: Uint8Array): Uint8Array {
      calls++;
      if (calls > 1) throw new UnexpectedRetryError();
      candidate.fill(0);
      return candidate;
    },
  });
  try {
    assertThrows(
      () => Bip324KeyExchange.initiator(),
      Bip324SecretKeyRandomError,
    );
    assertEquals(calls, 1);
  } finally {
    restoreRandomValues(descriptor);
  }
});

Deno.test('signing and BIP324 export the same random-scalar error', () => {
  assertEquals(Bip324SecretKeyRandomError, SigningSecretKeyRandomError);
});

function restoreRandomValues(
  descriptor: PropertyDescriptor | undefined,
): void {
  if (descriptor === undefined) {
    delete (crypto as unknown as Record<string, unknown>).getRandomValues;
  } else {
    Object.defineProperty(crypto, 'getRandomValues', descriptor);
  }
}

function warmVerificationContext(): void {
  const scalar = new Uint8Array(32);
  scalar[31] = 1;
  SecretKey.fromBytes(scalar).destroy();
}
