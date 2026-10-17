# Maintainer setup: gates, labels and branch protection

One-time GitHub admin steps for the risk map, protected paths and
gates-not-weakened check (#354). Nothing in the repo can do these for you: the
workflows only *use* the labels and the required checks. Run the `gh` commands
below as a repository **admin** (replace `OWNER/REPO`). Do them **before**
merging the PR that adds the workflows, except where a step says otherwise.

How the pieces fit:

| Piece | Where | What it does |
|---|---|---|
| Risk map | `.agents/risk.yaml` | tiers by path glob; the `gates` tier is the protected-path list |
| `risk` workflow | `.github/workflows/risk.yml` | labels each PR `risk:<tier>`; `e2e-required` job for `critical` |
| `gates` workflow | `.github/workflows/gates.yml` | runs `tools/gatecheck weakened` and `tools/gatecheck protected-paths` |
| Approval | label `gates-change-approved` | a maintainer's confirmation of a gate change or an intended weakening |

## 1. Create the labels

```sh
gh label create risk:critical --repo OWNER/REPO --color B60205 --description "touches the egress path or its isolation: needs L2 e2e and the security lens"
gh label create risk:gates    --repo OWNER/REPO --color D93F0B --description "touches a protected gate path (.agents/risk.yaml): human review"
gh label create risk:normal   --repo OWNER/REPO --color FBCA04 --description "code or tests"
gh label create risk:low      --repo OWNER/REPO --color 0E8A16 --description "docs only"
gh label create gates-change-approved --repo OWNER/REPO --color 5319E7 \
  --description "maintainer approves a gate change or weakening; add it after the last push"
```

The `risk` workflow fails to label a PR if a `risk:*` label does not exist.

## 2. Bot and agent account rules

- The agent opens PRs from its **own** GitHub account or GitHub App, never from
  the maintainer's account or token.
- Give it the **Write** role at most. It must not be `maintain` or `admin`, must
  not be on any ruleset or branch-protection **bypass** list, and its token must
  not carry repository-administration or "bypass" permissions.
- A GitHub App/Bot account is recognised automatically (type `Bot`, or a login
  ending in `[bot]`). A bot that uses an ordinary user account: add its login to
  `agent-accounts` in `.agents/risk.yaml` (a change to a gate file, so a
  maintainer makes it).
- Such an account can never approve: the verification rejects a
  `gates-change-approved` label added by a bot or listed agent, whatever its
  permission.

## 3. Branch protection on `main`

Require a PR; require the `check` and `gates` status checks; block force pushes
and deletion; no bypass for the agent. With a single maintainer, require 0
approving reviews (approval of a gate change is the label, not a review).

```sh
gh api -X PUT repos/OWNER/REPO/branches/main/protection --input - <<'JSON'
{
  "required_status_checks": { "strict": true, "contexts": ["check", "gates"] },
  "enforce_admins": true,
  "required_pull_request_reviews": { "required_approving_review_count": 0 },
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "required_linear_history": false
}
JSON
```

`contexts` are job names: `check` is the job in `ci.yml`, `gates` the job in
`gates.yml`. Add each only after it has run once on a PR (GitHub lists a check
only after its first run).

`enforce_admins: true` makes the rules bind the admin too; set it to `false`
only if the maintainer must be able to push straight to `main`.

### Make the e2e job required for `risk:critical` (after #351)

The `e2e-required` job in `risk.yml` passes at once for every tier except
`critical`; for `critical` it waits for a check run named `e2e` on the head
commit. It is safe to require for every PR:

```sh
gh api -X PATCH repos/OWNER/REPO/branches/main/protection/required_status_checks \
  -F strict=true -f 'contexts[]=check' -f 'contexts[]=gates' -f 'contexts[]=e2e-required'
```

Do this **only once** the L2 e2e workflow (#351) exists and its job is named
`e2e`: until then a `risk:critical` PR stays red on `e2e-required` (fail
closed). Until the L2 job exists, leave `e2e-required` out of `contexts`.

## 4. Token permissions

The workflows declare read-only permissions (`contents`, `pull-requests`,
`issues`, `checks`) plus `pull-requests: write` / `issues: write` in `risk.yml`
only, to set the risk label. In Settings, Actions, General, leave the default
`GITHUB_TOKEN` permission at **read**.

The approval check calls `GET /repos/{repo}/collaborators/{user}/permission`.
This could not be exercised from the implementation environment. If the first
run reports `HTTP 403` for it, create a fine-grained read-only token
(repository Metadata: read, Pull requests: read) and store it as the repository
secret `GATES_TOKEN`. `gates.yml` already prefers it
(`secrets.GATES_TOKEN || github.token`) in both gatecheck steps; with no secret
it uses the default token. Any API failure fails the check (fail closed).

The `gates` job never runs code from the PR: `tools/gatecheck` is built from the
base branch and only reads the head checkout as text (it parses
`scripts/check.sh`; it does not execute it). This is what keeps a token-holding
`pull_request_target` job safe. Do not add a step that runs anything from
`head/`.

The two `gates` checks need the base branch to contain `tools/gatecheck`: until
the PR that adds it is merged, the job warns and skips instead of running the
PR's own copy.

## 5. How a gate change is approved

1. The agent stops and asks (see `AGENTS.md`): it never edits a path of the
   `gates` tier on its own.
2. A human maintainer (role `maintain` or `admin`, not a bot) makes the change,
   or reviews the agent's PR.
3. After the **last push**, the maintainer adds `gates-change-approved`. The
   `gates` check re-runs on the label event and passes with warnings.
4. Any later push invalidates the approval (the label then predates the push);
   remove and re-add the label, or add it for the first time after the push.

A label added by the bot itself, by someone without `maintain`/`admin`, or
before the latest push is rejected, and the check says why.

## 6. Verify the setup

On a throwaway branch, as the agent account, open a PR that edits
`scripts/check.sh`:

- `gates` fails with `protected-paths/touched` until a maintainer labels it.
- A label added by the agent account itself keeps it red.
- A label added by a maintainer, then a new push, makes it red again.
- Lowering `COVERAGE_MIN` in a maintainer PR fails `gates` with a
  `gates/coverage-lowered` finding until the label is added; raising it passes.

## Bootstrap note

`gates.yml` and `risk.yml` run the tools from the **base** branch. In the PR
that introduces them there is no base copy yet, so both skip with a warning.
They take effect from the first PR after the merge.
