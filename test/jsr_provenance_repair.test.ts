import {
  assertEquals,
  assertRejects,
  assertStringIncludes,
  assertThrows,
} from '@std/assert';

import {
  assertRecentPublication,
  buildJsrAudience,
  buildStatement,
  derBase64ToPem,
  REPAIR_PACKAGE,
  type RepairPackage,
  requestGithubOidcToken,
  type SerializedSigstoreBundle,
  sha256Hex,
  submitJsrProvenance,
  toJsrBundle,
} from '../scripts/repair_jsr_provenance.ts';

const packageVersion: RepairPackage = {
  scope: 'bonakodo',
  name: 'secp256k1',
  version: '1.0.1',
};

Deno.test('targets the replacement provenance release', () => {
  assertEquals(REPAIR_PACKAGE, {
    scope: 'bonakodo',
    name: 'secp256k1',
    version: '1.0.2',
  });
});

Deno.test("enforces JSR's two-minute provenance window", () => {
  const now = Date.parse('2026-07-14T09:00:00Z');
  assertRecentPublication('2026-07-14T08:59:30Z', now);
  assertThrows(
    () => assertRecentPublication('2026-07-14T08:58:00Z', now),
    Error,
    'outside the provenance attachment window',
  );
});

Deno.test('builds a tarball-bound SLSA statement', () => {
  const statement = buildStatement(packageVersion, 'abc123', {
    GITHUB_EVENT_NAME: 'workflow_dispatch',
    GITHUB_REF: 'refs/heads/master',
    GITHUB_REPOSITORY: 'bonakodo/secp256k1-deno',
    GITHUB_REPOSITORY_ID: '480268412',
    GITHUB_REPOSITORY_OWNER_ID: '85427468',
    GITHUB_RUN_ATTEMPT: '1',
    GITHUB_RUN_ID: '29320000000',
    GITHUB_SERVER_URL: 'https://github.com',
    GITHUB_SHA: '73420f6',
    GITHUB_WORKFLOW_REF:
      'bonakodo/secp256k1-deno/.github/workflows/repair-provenance.yml@refs/heads/master',
    RUNNER_ENVIRONMENT: 'github-hosted',
  });

  assertEquals(statement.subject, [{
    name: 'pkg:jsr/@bonakodo/secp256k1@1.0.1',
    digest: { sha256: 'abc123' },
  }]);
  assertEquals(
    statement.predicate.buildDefinition.externalParameters.workflow,
    {
      ref: 'refs/heads/master',
      repository: 'https://github.com/bonakodo/secp256k1-deno',
      path: '.github/workflows/repair-provenance.yml',
    },
  );
});

Deno.test('builds a JSR package-publish OIDC audience', () => {
  assertEquals(JSON.parse(buildJsrAudience(packageVersion, 'abc123')), {
    permissions: [{
      permission: 'package/publish',
      scope: 'bonakodo',
      package: 'secp256k1',
      version: '1.0.1',
      tarballHash: 'sha256-abc123',
    }],
  });
});

Deno.test('hashes the immutable tarball bytes', async () => {
  assertEquals(
    await sha256Hex(new TextEncoder().encode('abc')),
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
  );
});

Deno.test('converts base64 DER certificates to PEM', () => {
  assertEquals(
    derBase64ToPem('Y2VydGlmaWNhdGU='),
    '-----BEGIN CERTIFICATE-----\nY2VydGlmaWNhdGU=\n-----END CERTIFICATE-----',
  );
});

Deno.test("converts a legacy Sigstore bundle to JSR's wire shape", () => {
  const converted = toJsrBundle({
    mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.1',
    dsseEnvelope: {
      payload: 'cGF5bG9hZA==',
      payloadType: 'application/vnd.in-toto+json',
      signatures: [{ keyid: '', sig: 'c2lnbmF0dXJl' }],
    },
    verificationMaterial: {
      x509CertificateChain: {
        certificates: [{ rawBytes: 'Y2VydGlmaWNhdGU=' }],
      },
      tlogEntries: [{ logIndex: '2167000000' }],
    },
  });

  assertEquals(converted.content.$case, 'dsseSignature');
  assertEquals(converted.content.dsseEnvelope.signatures.length, 1);
  assertEquals(
    converted.verificationMaterial.content.x509CertificateChain
      .certificates[0].rawBytes,
    '-----BEGIN CERTIFICATE-----\nY2VydGlmaWNhdGU=\n-----END CERTIFICATE-----',
  );
  assertEquals(converted.verificationMaterial.tlogEntries, [{
    logIndex: 2167000000,
  }]);
});

Deno.test("restores Sigstore's omitted default key id for JSR", () => {
  const serialized = {
    mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.1',
    dsseEnvelope: {
      payload: 'cGF5bG9hZA==',
      payloadType: 'application/vnd.in-toto+json',
      signatures: [{ sig: 'c2lnbmF0dXJl' }],
    },
    verificationMaterial: {
      x509CertificateChain: {
        certificates: [{ rawBytes: 'Y2VydGlmaWNhdGU=' }],
      },
      tlogEntries: [{ logIndex: '2167000000' }],
    },
  } as unknown as SerializedSigstoreBundle;

  assertEquals(
    toJsrBundle(serialized).content.dsseEnvelope.signatures[0].keyid,
    '',
  );
});

Deno.test('rejects malformed Sigstore bundles', () => {
  assertThrows(
    () =>
      toJsrBundle({
        mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.1',
        dsseEnvelope: {
          payload: 'cGF5bG9hZA==',
          payloadType: 'application/vnd.in-toto+json',
          signatures: [],
        },
        verificationMaterial: {
          x509CertificateChain: {
            certificates: [{ rawBytes: 'Y2VydGlmaWNhdGU=' }],
          },
          tlogEntries: [{ logIndex: '2167000000' }],
        },
      }),
    Error,
    'exactly one DSSE signature',
  );
});

Deno.test('requests a GitHub OIDC token for the exact audience', async () => {
  let requestedUrl = '';
  let authorization = '';
  const token = await requestGithubOidcToken(
    'sigstore',
    {
      ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'request-token',
      ACTIONS_ID_TOKEN_REQUEST_URL: 'https://example.test/oidc?api-version=1',
    },
    (input, init) => {
      requestedUrl = String(input);
      authorization = new Headers(init?.headers).get('authorization') ?? '';
      return Promise.resolve(Response.json({ value: 'identity-token' }));
    },
  );

  assertEquals(token, 'identity-token');
  assertEquals(new URL(requestedUrl).searchParams.get('audience'), 'sigstore');
  assertEquals(authorization, 'Bearer request-token');
});

Deno.test('fails closed when JSR rejects the provenance bundle', async () => {
  const bundle = toJsrBundle({
    mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.1',
    dsseEnvelope: {
      payload: 'cGF5bG9hZA==',
      payloadType: 'application/vnd.in-toto+json',
      signatures: [{ keyid: '', sig: 'c2lnbmF0dXJl' }],
    },
    verificationMaterial: {
      x509CertificateChain: {
        certificates: [{ rawBytes: 'Y2VydGlmaWNhdGU=' }],
      },
      tlogEntries: [{ logIndex: '2167000000' }],
    },
  });

  const error = await assertRejects(
    () =>
      submitJsrProvenance(
        packageVersion,
        bundle,
        'jsr-token',
        () =>
          Promise.resolve(
            new Response('invalid subject digest', {
              status: 400,
            }),
          ),
      ),
    Error,
  );
  assertStringIncludes(error.message, '400');
  assertStringIncludes(error.message, 'invalid subject digest');
});
