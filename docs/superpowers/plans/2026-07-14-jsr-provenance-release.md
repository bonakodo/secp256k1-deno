# JSR Provenance Release Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (- [ ]) syntax for tracking.

**Goal:** Publish @bonakodo/secp256k1@1.0.1 from its matching Git tag through GitHub Actions so JSR records and credits public provenance.

**Architecture:** Keep the existing OIDC-enabled publish job and add a fail-closed tag/version check before its dry run. Bump only the package patch version, publish from v1.0.1, then verify the workflow, Rekor entry, and JSR score.

**Tech Stack:** Deno 2, GitHub Actions, JSR OIDC publishing, Sigstore Rekor, Git

---

### Task 1: Guard tag and package-version alignment

**Files:**

- Modify: deno.jsonc:3
- Modify: .github/workflows/publish.yml:21-28

- [ ] **Step 1: Run a failing desired-state assertion**

Run:

```bash
test "$(deno eval 'console.log(JSON.parse(await Deno.readTextFile("deno.jsonc")).version)')" = "1.0.1" && \
  rg -q '^      - name: Verify release tag$' .github/workflows/publish.yml
```

Expected: exit status 1 because deno.jsonc still declares 1.0.0 and the workflow has no release-tag guard.

- [ ] **Step 2: Bump the package version**

Change the package metadata to:

```json
"version": "1.0.1",
```

- [ ] **Step 3: Add the fail-closed release-tag guard**

Insert this step after denoland/setup-deno and before the dry run:

```yaml
- name: Verify release tag
  shell: bash
  run: |
    version="$(deno eval 'console.log(JSON.parse(await Deno.readTextFile("deno.jsonc")).version)')"
    expected="v${version}"
    if [[ "$GITHUB_REF_NAME" != "$expected" ]]; then
      echo "::error::Release tag '$GITHUB_REF_NAME' does not match package version '$version' (expected '$expected')."
      exit 1
    fi
```

- [ ] **Step 4: Re-run the desired-state assertion**

Run:

```bash
test "$(deno eval 'console.log(JSON.parse(await Deno.readTextFile("deno.jsonc")).version)')" = "1.0.1" && \
  rg -q '^      - name: Verify release tag$' .github/workflows/publish.yml
```

Expected: exit status 0.

- [ ] **Step 5: Exercise both guard outcomes locally**

Run the guard with GITHUB_REF_NAME=v1.0.1 and expect exit status 0:

```bash
GITHUB_REF_NAME=v1.0.1 bash -eu -o pipefail -c '
version="$(deno eval '\''console.log(JSON.parse(await Deno.readTextFile("deno.jsonc")).version)'\'')"
expected="v${version}"
if [[ "$GITHUB_REF_NAME" != "$expected" ]]; then
  echo "::error::Release tag '\''$GITHUB_REF_NAME'\'' does not match package version '\''$version'\'' (expected '\''$expected'\'')."
  exit 1
fi
'
```

Run the guard with the mismatching tag:

```bash
GITHUB_REF_NAME=v0.1.0 bash -eu -o pipefail -c '
version="$(deno eval '\''console.log(JSON.parse(await Deno.readTextFile("deno.jsonc")).version)'\'')"
expected="v${version}"
if [[ "$GITHUB_REF_NAME" != "$expected" ]]; then
  echo "::error::Release tag '\''$GITHUB_REF_NAME'\'' does not match package version '\''$version'\'' (expected '\''$expected'\'')."
  exit 1
fi
'
```

Expected: exit status 1 and an error naming actual tag v0.1.0, package version 1.0.1, and expected tag v1.0.1.

### Task 2: Validate and commit the release change

**Files:**

- Verify: deno.jsonc
- Verify: .github/workflows/publish.yml

- [ ] **Step 1: Run local package gates**

```bash
deno fmt --check --config deno.jsonc
deno lint --config deno.jsonc
deno publish --dry-run --allow-dirty
```

Expected: all commands exit 0; the dirty-tree dry run identifies @bonakodo/secp256k1@1.0.1 without publishing it.

- [ ] **Step 2: Inspect the exact release diff**

```bash
git diff --check
git diff -- .github/workflows/publish.yml deno.jsonc
git status --short
```

Expected: no whitespace errors; only .github/workflows/publish.yml and deno.jsonc are uncommitted.

- [ ] **Step 3: Commit the implementation**

```bash
git add .github/workflows/publish.yml deno.jsonc
git commit -m '🔒 ci: enforce provenance release tags'
```

Expected: one Conventional Commit with gitmoji containing exactly the workflow guard and patch-version bump.

- [ ] **Step 4: Verify the committed package from a clean tree**

```bash
deno publish --dry-run
```

Expected: exit status 0 and a simulated publication of @bonakodo/secp256k1@1.0.1 from a clean Git tree.

### Task 3: Publish and verify the provenance release

**Files:**

- No local file changes

- [ ] **Step 1: Integrate the release commit onto master**

From the primary worktree, merge the isolated implementation branch:

```bash
git switch master
git merge --no-ff --no-gpg-sign codex/jsr-provenance \
  -m '🔀 chore: merge JSR provenance release'
git log -4 --oneline
```

Expected: master contains the design, plan, version bump, and workflow guard commits.

- [ ] **Step 2: Push the release commit**

```bash
git push origin master
```

Expected: origin/master advances to the local release commit.

- [ ] **Step 3: Create and push the matching release tag**

```bash
git tag -a v1.0.1 -m 'v1.0.1'
git push origin v1.0.1
```

Expected: the annotated v1.0.1 tag is created on the release commit and the Publish workflow starts for refs/tags/v1.0.1.

- [ ] **Step 4: Wait for GitHub Actions**

```bash
run_id="$(gh run list --workflow publish.yml --branch v1.0.1 --limit 1 --json databaseId --jq '.[0].databaseId')"
test -n "$run_id"
gh run watch "$run_id" --exit-status
```

Expected: all matrix tests and the publish job succeed.

- [ ] **Step 5: Extract and verify the public Rekor entry**

```bash
log_index="$(gh run view "$run_id" --log | sed -n 's#.*search.sigstore.dev/?logIndex=\([0-9][0-9]*\).*#\1#p' | tail -1)"
test -n "$log_index"
curl -fsSL "https://rekor.sigstore.dev/api/v1/log/entries?logIndex=$log_index" | \
  jq -e --argjson index "$log_index" 'to_entries[0].value.logIndex == $index'
```

Expected: the workflow log contains a log index and Rekor returns that exact public entry.

- [ ] **Step 6: Verify JSR credits provenance**

Poll JSR for up to two minutes:

```bash
for attempt in {1..12}; do
  overview="$(curl -fsSL "https://jsr.io/@bonakodo/secp256k1?refresh=$(date +%s)")"
  score="$(curl -fsSL "https://jsr.io/@bonakodo/secp256k1/score?refresh=$(date +%s)")"
  provenance_status="$(printf '%s' "$score" | sed 's/></>\n</g' | awk '/<span class="sr-only">/{status=$0} /Has provenance/{print status; exit}')"
  if [[ "$overview" == *'@1.0.1'* ]] && \
     [[ "$provenance_status" == *'Complete score'* ]]; then
    exit 0
  fi
  sleep 10
done
exit 1
```

Expected: exit status 0 after JSR lists 1.0.1 as latest and marks “Has provenance” as “Complete score.”
