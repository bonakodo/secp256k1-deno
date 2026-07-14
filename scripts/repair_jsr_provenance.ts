import { Buffer } from 'node:buffer';

export interface RepairPackage {
  readonly scope: string;
  readonly name: string;
  readonly version: string;
}

export type RepairEnvironment = Record<string, string | undefined>;

export type Fetcher = (
  input: string | URL | Request,
  init?: RequestInit,
) => Promise<Response>;

export interface SerializedSigstoreBundle {
  readonly mediaType: string;
  readonly dsseEnvelope?: {
    readonly payload: string;
    readonly payloadType: string;
    readonly signatures: readonly {
      readonly keyid?: string;
      readonly sig: string;
    }[];
  };
  readonly verificationMaterial: {
    readonly x509CertificateChain?: {
      readonly certificates: readonly { readonly rawBytes: string }[];
    };
    readonly tlogEntries: readonly { readonly logIndex: string }[];
  };
}

export interface JsrProvenanceBundle {
  readonly mediaType: 'application/vnd.in-toto+json';
  readonly content: {
    readonly $case: 'dsseSignature';
    readonly dsseEnvelope: {
      readonly payload: string;
      readonly payloadType: string;
      readonly signatures: readonly [{
        readonly keyid: string;
        readonly sig: string;
      }];
    };
  };
  readonly verificationMaterial: {
    readonly content: {
      readonly $case: 'x509CertificateChain';
      readonly x509CertificateChain: {
        readonly certificates: readonly [{ readonly rawBytes: string }];
      };
    };
    readonly tlogEntries: readonly [{ readonly logIndex: number }];
  };
}

export const REPAIR_PACKAGE: RepairPackage = {
  scope: 'bonakodo',
  name: 'secp256k1',
  version: '1.0.2',
};

const INTOTO_PAYLOAD_TYPE = 'application/vnd.in-toto+json';
const SLSA_BUILD_TYPE =
  'https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1';
const SLSA_PREDICATE_TYPE = 'https://slsa.dev/provenance/v1';
const INTOTO_STATEMENT_TYPE = 'https://in-toto.io/Statement/v1';

function required(environment: RepairEnvironment, name: string): string {
  const value = environment[name];
  if (!value) throw new Error(`Required environment variable ${name} is unset`);
  return value;
}

export function buildStatement(
  packageVersion: RepairPackage,
  tarballDigest: string,
  environment: RepairEnvironment,
) {
  const repository = required(environment, 'GITHUB_REPOSITORY');
  const workflowRef = required(environment, 'GITHUB_WORKFLOW_REF');
  const relativeWorkflowRef = workflowRef.startsWith(`${repository}/`)
    ? workflowRef.slice(repository.length + 1)
    : workflowRef;
  const delimiter = relativeWorkflowRef.lastIndexOf('@');
  if (delimiter < 1 || delimiter === relativeWorkflowRef.length - 1) {
    throw new Error(`Invalid GITHUB_WORKFLOW_REF: ${workflowRef}`);
  }
  const workflowPath = relativeWorkflowRef.slice(0, delimiter);
  const workflowGitRef = relativeWorkflowRef.slice(delimiter + 1);
  const serverUrl = required(environment, 'GITHUB_SERVER_URL');
  const githubRef = required(environment, 'GITHUB_REF');
  const githubSha = required(environment, 'GITHUB_SHA');
  const runId = required(environment, 'GITHUB_RUN_ID');
  const runAttempt = required(environment, 'GITHUB_RUN_ATTEMPT');

  return {
    _type: INTOTO_STATEMENT_TYPE,
    subject: [{
      name:
        `pkg:jsr/@${packageVersion.scope}/${packageVersion.name}@${packageVersion.version}`,
      digest: { sha256: tarballDigest },
    }],
    predicateType: SLSA_PREDICATE_TYPE,
    predicate: {
      buildDefinition: {
        buildType: SLSA_BUILD_TYPE,
        externalParameters: {
          workflow: {
            ref: workflowGitRef,
            repository: `${serverUrl}/${repository}`,
            path: workflowPath,
          },
        },
        internalParameters: {
          github: {
            eventName: required(environment, 'GITHUB_EVENT_NAME'),
            repositoryId: required(environment, 'GITHUB_REPOSITORY_ID'),
            repositoryOwnerId: required(
              environment,
              'GITHUB_REPOSITORY_OWNER_ID',
            ),
          },
        },
        resolvedDependencies: [{
          uri: `git+${serverUrl}/${repository}@${githubRef}`,
          digest: { gitCommit: githubSha },
        }],
      },
      runDetails: {
        builder: {
          id: `https://github.com/actions/runner/${
            required(environment, 'RUNNER_ENVIRONMENT')
          }`,
        },
        metadata: {
          invocationId:
            `${serverUrl}/${repository}/actions/runs/${runId}/attempts/${runAttempt}`,
        },
      },
    },
  };
}

export function buildJsrAudience(
  packageVersion: RepairPackage,
  tarballDigest: string,
): string {
  return JSON.stringify({
    permissions: [{
      permission: 'package/publish',
      scope: packageVersion.scope,
      package: packageVersion.name,
      version: packageVersion.version,
      tarballHash: `sha256-${tarballDigest}`,
    }],
  });
}

export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new Uint8Array(bytes));
  return Array.from(
    new Uint8Array(digest),
    (byte) => byte.toString(16).padStart(2, '0'),
  ).join('');
}

export function assertRecentPublication(
  createdAt: string,
  now = Date.now(),
): void {
  const createdAtMilliseconds = Date.parse(createdAt);
  const age = now - createdAtMilliseconds;
  if (
    !Number.isFinite(createdAtMilliseconds) || age < -30_000 || age >= 90_000
  ) {
    throw new Error(
      `Package version is outside the provenance attachment window (age ${age}ms)`,
    );
  }
}

export function derBase64ToPem(rawBytes: string): string {
  const normalized = Buffer.from(rawBytes, 'base64').toString('base64');
  if (!normalized) throw new Error('Sigstore certificate is empty');
  const lines = normalized.match(/.{1,64}/g);
  if (!lines) throw new Error('Sigstore certificate is invalid');
  return [
    '-----BEGIN CERTIFICATE-----',
    ...lines,
    '-----END CERTIFICATE-----',
  ].join('\n');
}

export function toJsrBundle(
  bundle: SerializedSigstoreBundle,
): JsrProvenanceBundle {
  const envelope = bundle.dsseEnvelope;
  if (!envelope || envelope.signatures.length !== 1) {
    throw new Error('Sigstore bundle must contain exactly one DSSE signature');
  }
  const certificates = bundle.verificationMaterial.x509CertificateChain
    ?.certificates;
  if (!certificates || certificates.length !== 1) {
    throw new Error('Sigstore bundle must contain exactly one certificate');
  }
  const entries = bundle.verificationMaterial.tlogEntries;
  if (entries.length !== 1) {
    throw new Error('Sigstore bundle must contain exactly one Rekor entry');
  }
  const logIndexBigInt = BigInt(entries[0].logIndex);
  if (logIndexBigInt < 0n || logIndexBigInt > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error(
      "Rekor log index is outside JavaScript's safe integer range",
    );
  }

  return {
    mediaType: INTOTO_PAYLOAD_TYPE,
    content: {
      $case: 'dsseSignature',
      dsseEnvelope: {
        payload: envelope.payload,
        payloadType: envelope.payloadType,
        signatures: [{
          keyid: envelope.signatures[0].keyid ?? '',
          sig: envelope.signatures[0].sig,
        }],
      },
    },
    verificationMaterial: {
      content: {
        $case: 'x509CertificateChain',
        x509CertificateChain: {
          certificates: [{
            rawBytes: derBase64ToPem(certificates[0].rawBytes),
          }],
        },
      },
      tlogEntries: [{ logIndex: Number(logIndexBigInt) }],
    },
  };
}

export async function requestGithubOidcToken(
  audience: string,
  environment: RepairEnvironment,
  fetcher: Fetcher = fetch,
): Promise<string> {
  const url = new URL(required(environment, 'ACTIONS_ID_TOKEN_REQUEST_URL'));
  url.searchParams.set('audience', audience);
  const response = await fetcher(url, {
    headers: {
      authorization: `Bearer ${
        required(environment, 'ACTIONS_ID_TOKEN_REQUEST_TOKEN')
      }`,
    },
  });
  if (!response.ok) {
    throw new Error(
      `GitHub OIDC request failed (${response.status}): ${await response
        .text()}`,
    );
  }
  const body: unknown = await response.json();
  if (
    typeof body !== 'object' || body === null || !('value' in body) ||
    typeof body.value !== 'string' || !body.value
  ) {
    throw new Error('GitHub OIDC response did not contain a token');
  }
  return body.value;
}

function versionApiUrl(packageVersion: RepairPackage): string {
  return `https://api.jsr.io/scopes/${packageVersion.scope}/packages/${packageVersion.name}/versions/${packageVersion.version}`;
}

export async function submitJsrProvenance(
  packageVersion: RepairPackage,
  bundle: JsrProvenanceBundle,
  jsrOidcToken: string,
  fetcher: Fetcher = fetch,
): Promise<void> {
  const response = await fetcher(
    `${versionApiUrl(packageVersion)}/provenance`,
    {
      method: 'POST',
      headers: {
        authorization: `githuboidc ${jsrOidcToken}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({ bundle }),
    },
  );
  if (!response.ok) {
    throw new Error(
      `JSR provenance submission failed (${response.status}): ${await response
        .text()}`,
    );
  }
}

async function downloadTarball(
  packageVersion: RepairPackage,
  fetcher: Fetcher,
): Promise<Uint8Array> {
  const response = await fetcher(`${versionApiUrl(packageVersion)}/tarball`);
  if (!response.ok) {
    throw new Error(
      `JSR tarball download failed (${response.status}): ${await response
        .text()}`,
    );
  }
  return new Uint8Array(await response.arrayBuffer());
}

async function readPublicationCreatedAt(
  packageVersion: RepairPackage,
  fetcher: Fetcher,
): Promise<string> {
  const response = await fetcher(
    `${versionApiUrl(packageVersion)}?created=${crypto.randomUUID()}`,
  );
  if (!response.ok) {
    throw new Error(
      `JSR version readback failed (${response.status}): ${await response
        .text()}`,
    );
  }
  const body: unknown = await response.json();
  if (
    typeof body !== 'object' || body === null || !('createdAt' in body) ||
    typeof body.createdAt !== 'string'
  ) {
    throw new Error('JSR version response has an invalid createdAt');
  }
  return body.createdAt;
}

export async function repairProvenance(
  environment: RepairEnvironment = Deno.env.toObject(),
  fetcher: Fetcher = fetch,
): Promise<number> {
  const createdAt = await readPublicationCreatedAt(REPAIR_PACKAGE, fetcher);
  assertRecentPublication(createdAt);
  const tarball = await downloadTarball(REPAIR_PACKAGE, fetcher);
  const tarballDigest = await sha256Hex(tarball);
  const statement = buildStatement(
    REPAIR_PACKAGE,
    tarballDigest,
    environment,
  );

  const sigstoreToken = await requestGithubOidcToken(
    'sigstore',
    environment,
    fetcher,
  );
  // deno-lint-ignore no-import-prefix -- one-time tool uses an isolated lockfile
  const { attest } = await import('npm:sigstore@5.0.0');
  const serialized = await attest(
    Buffer.from(JSON.stringify(statement)),
    INTOTO_PAYLOAD_TYPE,
    {
      identityToken: sigstoreToken,
      legacyCompatibility: true,
      tlogUpload: true,
    },
  ) as SerializedSigstoreBundle;
  const bundle = toJsrBundle(serialized);

  const jsrToken = await requestGithubOidcToken(
    buildJsrAudience(REPAIR_PACKAGE, tarballDigest),
    environment,
    fetcher,
  );
  await submitJsrProvenance(REPAIR_PACKAGE, bundle, jsrToken, fetcher);
  return bundle.verificationMaterial.tlogEntries[0].logIndex;
}

if (import.meta.main) {
  const logIndex = await repairProvenance();
  console.log(
    `Attached @bonakodo/secp256k1@1.0.2 provenance at Rekor log index ${logIndex}`,
  );
}
