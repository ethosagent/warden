# Releasing Warden

Warden ships as a **single static Go binary** and a **multi-arch container image**, both produced and signed by CI. A release is **driven entirely by a git tag** — there is no `VERSION` file to maintain.

## Version source of truth

The **git tag is the version.** `scripts/build.sh` stamps the binary's `warden version` output from `git describe` at build time, so the tag a release is cut from *is* the version — nothing else to keep in sync.

```
tag v1.2.3  ->  binary reports "warden 1.2.3"  ->  image ethosagent/warden:1.2.3
```

Tags are `vX.Y.Z` (semver, `v`-prefixed). Pushing a `v*` tag is what triggers the release workflow.

## What a release produces

Pushing a `v*` tag runs [`.github/workflows/release.yml`](.github/workflows/release.yml), which publishes:

**A GitHub Release** with:
- `warden-{linux,darwin}-{amd64,arm64}` — reproducible static binaries (`scripts/build.sh`)
- `checksums.txt` + `checksums.txt.sig` + `checksums.txt.pem` — keyless **cosign** signature over the checksums
- `warden-sbom.cyclonedx.json` — a **CycloneDX SBOM** (syft); its hash is inside the signed `checksums.txt`
- **SLSA build-provenance** attestations for every artifact

**A multi-arch container image** at `ethosagent/warden:<version>` and `:latest` (Docker Hub):
- `linux/amd64` + `linux/arm64`
- SBOM + SLSA provenance attached to the image digest
- the digest **signed by keyless cosign** (one signature covers both arches)

All signing is **keyless Sigstore** (GitHub OIDC) — no signing keys to manage; cosign + attestations use the workflow's OIDC identity. The only registry credential is a Docker Hub access token (`DOCKERHUB_TOKEN`) for the image push.

## Prerequisites — first time only

- **Docker Hub credentials.** Add two GitHub repo secrets (Settings -> Secrets and variables -> Actions):
  - `DOCKERHUB_USERNAME` — a Docker Hub account with **write** access to `ethosagent/warden`.
  - `DOCKERHUB_TOKEN` — a Docker Hub **Access Token** (Account Settings -> Security -> New Access Token, scope **Read & Write**). Not the account password.
- **Docker Hub repo.** Ensure `ethosagent/warden` exists on Docker Hub and is public if releases should be publicly pullable.

## Cutting a release

From a clean `main` that is pushed to origin and green:

```bash
make release VERSION=1.2.3
```

`make release` runs these gates, then tags and pushes:
1. working tree is clean,
2. `HEAD == origin/main` (release only from pushed main),
3. tag `v1.2.3` does not already exist (local or remote),
4. full gate `scripts/check.sh` (fmt, vet, lint, govulncheck, build, race tests, coverage),
5. `git tag -a v1.2.3`,
6. `git push origin v1.2.3` — which triggers the release workflow.

Preview without side effects:

```bash
make release-dry VERSION=1.2.3
```

Or by hand:

```bash
git checkout main && git pull origin main
git status            # clean
scripts/check.sh      # green
git tag -a v1.2.3 -m "Release v1.2.3"
git push origin v1.2.3
```

## What the CI workflow does

[`.github/workflows/release.yml`](.github/workflows/release.yml) runs on `push: tags: 'v*'`. Two jobs run in parallel:

| Job | Steps | Produces |
|---|---|---|
| **release** | build cross-platform binaries -> SBOM (syft) -> SLSA provenance -> checksums -> cosign sign-blob -> `gh release create` | the signed GitHub Release + SBOM + provenance |
| **image** | buildx multi-arch build + push to Docker Hub (SBOM + provenance on the digest) -> cosign sign the digest | the signed multi-arch image |

Release notes are auto-generated from Conventional-Commit PR titles since the previous tag (`--generate-notes`) — that is the de-facto changelog; there is no `CHANGELOG.md`.

## Verify a release

**Binaries:**
```bash
gh release download v1.2.3 -p 'checksums.txt*' -p 'warden-linux-amd64'
cosign verify-blob \
  --certificate checksums.txt.pem --signature checksums.txt.sig \
  --certificate-identity-regexp 'https://github.com/ethosagent/warden/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
sha256sum --check --ignore-missing checksums.txt     # now trusted
gh attestation verify warden-linux-amd64 --repo ethosagent/warden
```

**Image:**
```bash
cosign verify ethosagent/warden:1.2.3 \
  --certificate-identity-regexp 'https://github.com/ethosagent/warden/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
docker buildx imagetools inspect ethosagent/warden:1.2.3   # shows both arches
```

> **Always pass `--certificate-identity*` and `--certificate-oidc-issuer`.** A bare `cosign verify` only checks that *some* valid Sigstore signature exists — pinning the identity + issuer is what proves it is *this* repo's release workflow.

**Reproducibility:** `make repro` (or `scripts/repro-verify.sh`) rebuilds the binary twice and asserts an identical SHA-256 from the same commit.

## Recovery runbook

| Failure | Symptom | Recovery |
|---|---|---|
| Pre-flight failed | `make release` exits before tagging | Fix (clean tree, push main, fix tests); re-run. Nothing was tagged or published. |
| Tag pushed but workflow failed | Tag exists; no/partial Release | Fix the cause, then delete + re-push the tag: `git tag -d v1.2.3 && git push origin :refs/tags/v1.2.3`, then `make release VERSION=1.2.3` again. |
| Re-run only | Workflow flaked | Actions -> the release run -> **Re-run jobs**. Steps are idempotent except `gh release create` — if the Release was already created, delete it first: `gh release delete v1.2.3`. |
| Bad release shipped | Broken binary/image | Cut a fixed patch: `make release VERSION=1.2.4`. Optionally mark the bad GitHub Release as a draft/pre-release with a note. |

## Quick reference

```bash
make version                    # what the current commit builds as (git describe)
make release-dry VERSION=1.2.3  # preview, no side effects
make release VERSION=1.2.3      # gate -> tag -> push -> CI publishes & signs
make repro                      # verify the binary builds reproducibly
gh release view v1.2.3          # inspect a published release
```
