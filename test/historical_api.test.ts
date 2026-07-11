import { assert, assertEquals, ffiTest } from './deps.ts';
import { Digest32 } from '../src/api/digest.ts';
import { PublicKey } from '../src/api/keys.ts';
import { verifyHistoricalEcdsa } from '../src/historical.ts';

const DIGEST = hex(
  'dade12e06a5bbf5e1116f9bc44998b876813e948e10707dcb48008a1daf3512d',
);
const PUBLIC_KEY = hex(
  '0376ea9e36a75d2ecf9c93a0be76885e36f822529db22acfdc761c9b5b4544f5c5',
);
const R = hex(
  'ab4c6d9ba51da83072615c33a9887b756478e6f9de381085f5183c97603fc6ff',
);
const LOW_S = hex(
  '29722188bd937f54c861582ca6fc685b8da2b40d05f06b368374d35e4af2b764',
);
const HIGH_S = hex(
  'd68dde77426c80ab379ea7d3590397a32d0c28d9a95835053c5d8b2e854389dd',
);

ffiTest('historical verifier accepts strict and high-S DER', () => {
  const digest = Digest32.fromBytes(DIGEST);
  assert(verifyHistoricalEcdsa(strictDer(R, LOW_S), digest, PUBLIC_KEY));
  assert(verifyHistoricalEcdsa(strictDer(R, HIGH_S), digest, PUBLIC_KEY));
});

ffiTest('historical verifier accepts pre-BIP66 lax DER forms', () => {
  const digest = Digest32.fromBytes(DIGEST);
  const wrongSequenceLength = strictDer(R, LOW_S);
  wrongSequenceLength[1] = 0;
  assert(verifyHistoricalEcdsa(wrongSequenceLength, digest, PUBLIC_KEY));

  const negativeR = Uint8Array.from([
    0x30,
    0x44,
    0x02,
    0x20,
    ...R,
    0x02,
    0x20,
    ...LOW_S,
  ]);
  assert(verifyHistoricalEcdsa(negativeR, digest, PUBLIC_KEY));

  const longLengths = Uint8Array.from([
    0x30,
    0x80,
    0x02,
    0x81,
    0x20,
    ...R,
    0x02,
    0x81,
    0x20,
    ...LOW_S,
    0xaa,
  ]);
  assert(verifyHistoricalEcdsa(longLengths, digest, PUBLIC_KEY));
});

ffiTest('historical verifier accepts hybrid public keys', () => {
  const publicKey = PublicKey.parse(PUBLIC_KEY);
  const hybrid = publicKey.toUncompressedBytes();
  hybrid[0] = (hybrid[64] & 1) === 0 ? 0x06 : 0x07;
  assert(
    verifyHistoricalEcdsa(
      strictDer(R, LOW_S),
      Digest32.fromBytes(DIGEST),
      hybrid,
    ),
  );
});

ffiTest(
  'historical verifier returns false for attacker-controlled input',
  () => {
    const digest = Digest32.fromBytes(DIGEST);
    const malformed = [
      new Uint8Array(),
      Uint8Array.of(0x30),
      Uint8Array.of(0x31, 0, 2, 0, 2, 0),
      Uint8Array.of(0x30, 0, 2, 0),
      Uint8Array.of(0x30, 0, 2, 0, 2, 0),
      Uint8Array.of(0x30, 0, 2, 0x88),
    ];
    for (const signature of malformed) {
      assertEquals(
        verifyHistoricalEcdsa(signature, digest, PUBLIC_KEY),
        false,
      );
    }
    assertEquals(
      verifyHistoricalEcdsa(strictDer(R, LOW_S), digest, new Uint8Array()),
      false,
    );
    const changedDigest = DIGEST.slice();
    changedDigest[0] ^= 1;
    assertEquals(
      verifyHistoricalEcdsa(
        strictDer(R, LOW_S),
        Digest32.fromBytes(changedDigest),
        PUBLIC_KEY,
      ),
      false,
    );
  },
);

function strictDer(r: Uint8Array, s: Uint8Array): Uint8Array {
  const positiveR = (r[0] & 0x80) === 0 ? r : Uint8Array.from([0, ...r]);
  const positiveS = (s[0] & 0x80) === 0 ? s : Uint8Array.from([0, ...s]);
  return Uint8Array.from([
    0x30,
    positiveR.length + positiveS.length + 4,
    0x02,
    positiveR.length,
    ...positiveR,
    0x02,
    positiveS.length,
    ...positiveS,
  ]);
}

function hex(value: string): Uint8Array {
  const bytes = new Uint8Array(value.length / 2);
  for (let index = 0; index < bytes.length; index++) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}
