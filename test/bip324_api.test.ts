import { assert, assertEquals, assertThrows } from './deps.ts';
import {
  Bip324InputError,
  Bip324KeyExchange,
  Bip324StateError,
  EllSwiftEncoding,
} from '../src/bip324.ts';
import { withSigningContext } from '../src/native/context.ts';
import { requireEllSwift } from '../src/native/loader.ts';

Deno.test('EllSwiftEncoding validates only length and copies bytes', () => {
  const input = new Uint8Array(64).fill(7);
  const encoding = EllSwiftEncoding.fromBytes(input);
  input[0] = 9;
  assertEquals(encoding.toBytes()[0], 7);

  const output = encoding.toBytes();
  output[1] = 9;
  assertEquals(encoding.toBytes()[1], 7);
  assert(encoding.toBytes() !== encoding.toBytes());

  assert(EllSwiftEncoding.tryFromBytes(new Uint8Array(64)) !== null);
  assertEquals(EllSwiftEncoding.tryFromBytes(new Uint8Array(63)), null);
  assertEquals(EllSwiftEncoding.tryFromBytes(new Uint8Array(65)), null);
  const error = assertThrows(
    () => EllSwiftEncoding.fromBytes(new Uint8Array(0)),
    Bip324InputError,
  );
  assertEquals(error.code, 'invalid-ellswift-length');
});

Deno.test('role-bound exchanges derive the same BIP324 shared secret', () => {
  using initiator = Bip324KeyExchange.initiator();
  using responder = Bip324KeyExchange.responder();
  const initiatorEncoding = initiator.encoding;
  const responderEncoding = responder.encoding;

  using leftSecret = initiator.deriveSharedSecret(responderEncoding);
  using rightSecret = responder.deriveSharedSecret(initiatorEncoding);
  const left = leftSecret.consumeBytes();
  const right = rightSecret.consumeBytes();
  try {
    assertEquals(left.length, 32);
    assertEquals(left, right);
  } finally {
    left.fill(0);
    right.fill(0);
  }
});

Deno.test('exchange encoding getters and outputs are mutation-isolated', () => {
  using exchange = Bip324KeyExchange.initiator();
  const first = exchange.encoding;
  const expected = first.toBytes();
  const mutated = first.toBytes();
  mutated.fill(0);

  assert(first !== exchange.encoding);
  assertEquals(first.toBytes(), expected);
  assertEquals(exchange.encoding.toBytes(), expected);
});

Deno.test('exchange is consumed after successful derivation', () => {
  using initiator = Bip324KeyExchange.initiator();
  using responder = Bip324KeyExchange.responder();
  const responderEncoding = responder.encoding;
  using _secret = initiator.deriveSharedSecret(responderEncoding);

  const error = assertThrows(
    () => initiator.deriveSharedSecret(responderEncoding),
    Bip324StateError,
  );
  assertEquals(error.code, 'exchange-consumed');
});

Deno.test('exchange remains consumed after derivation input failure', () => {
  using exchange = Bip324KeyExchange.initiator();
  const inputError = assertThrows(
    () =>
      exchange.deriveSharedSecret(
        null as unknown as EllSwiftEncoding,
      ),
    Bip324InputError,
  );
  assertEquals(inputError.code, 'invalid-peer-encoding');

  const stateError = assertThrows(
    () =>
      exchange.deriveSharedSecret(
        EllSwiftEncoding.fromBytes(new Uint8Array(64)),
      ),
    Bip324StateError,
  );
  assertEquals(stateError.code, 'exchange-consumed');
});

Deno.test('destroy consumes an exchange without hiding its encoding', () => {
  using exchange = Bip324KeyExchange.responder();
  const encoding = exchange.encoding.toBytes();
  exchange.destroy();
  exchange.destroy();
  assertEquals(exchange.encoding.toBytes(), encoding);

  const error = assertThrows(
    () =>
      exchange.deriveSharedSecret(
        EllSwiftEncoding.fromBytes(new Uint8Array(64)),
      ),
    Bip324StateError,
  );
  assertEquals(error.code, 'exchange-consumed');
});

Deno.test('shared secrets are one-shot, disposable, and mutation-isolated', () => {
  using initiator = Bip324KeyExchange.initiator();
  using responder = Bip324KeyExchange.responder();
  const initiatorEncoding = initiator.encoding;
  const responderEncoding = responder.encoding;
  using first = initiator.deriveSharedSecret(responderEncoding);
  using second = responder.deriveSharedSecret(initiatorEncoding);

  const exposed = first.consumeBytes();
  const expected = second.consumeBytes();
  try {
    exposed[0] ^= 0xff;
    assert(exposed.some((byte, index) => byte !== expected[index]));
    const error = assertThrows(() => first.consumeBytes(), Bip324StateError);
    assertEquals(error.code, 'shared-secret-consumed');
  } finally {
    exposed.fill(0);
    expected.fill(0);
  }

  using disposableInitiator = Bip324KeyExchange.initiator();
  using disposableResponder = Bip324KeyExchange.responder();
  using disposable = disposableInitiator.deriveSharedSecret(
    disposableResponder.encoding,
  );
  disposable.destroy();
  disposable.destroy();
  const destroyed = assertThrows(
    () => disposable.consumeBytes(),
    Bip324StateError,
  );
  assertEquals(destroyed.code, 'shared-secret-consumed');
  assert(!('toJSON' in disposable));
});

Deno.test('native callback matches an upstream BIP324 XDH vector', () => {
  // First vector from secp256k1/src/modules/ellswift/tests_impl.h.
  const secretKey = hex(
    '61062ea5071d800bbfd59e2e8b53d47d194b095ae5a4df04936b49772ef0d4d7',
  );
  const initiatorEncoding = hex(
    'ec0adff257bbfe500c188c80b4fdd640f6b45a482bbc15fc7cef5931deff0aa1' +
      '86f6eb9bba7b85dc4dcc28b28722de1e3d9108b985e2967045668f66098e475b',
  );
  const responderEncoding = hex(
    'a4a94dfce69b4a2a0a099313d10f9f7e7d649d60501c9e1d274c300e0d89aafa' +
      'ffffffffffffffffffffffffffffffffffffffffffffffffffffffff8faf88d5',
  );
  const expected = hex(
    'c6992a117f5edbea70c3f511d32d26b9798be4b81a62eaee1a5acaa8459a3592',
  );
  const output = new Uint8Array(32);
  const { symbols, bip324HashCallback } = requireEllSwift();

  try {
    const succeeded = withSigningContext((context) =>
      symbols.secp256k1_ellswift_xdh(
        context,
        output,
        initiatorEncoding,
        responderEncoding,
        secretKey,
        0,
        bip324HashCallback,
        null,
      ) === 1
    );
    assert(succeeded);
    assertEquals(output, expected);
  } finally {
    secretKey.fill(0);
    output.fill(0);
  }
});

function hex(value: string): Uint8Array {
  const output = new Uint8Array(value.length / 2);
  for (let index = 0; index < output.length; index++) {
    output[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return output;
}
