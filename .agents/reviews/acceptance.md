# Acceptance (`ACC-*`)

Does the PR do what its issue asked for, all of it, and nothing else? Most
Warden work comes from roadmap tickets (`docs/roadmap/tickets.json`, synced
to GitHub), which have requirements, an implementation plan and acceptance
criteria. This lens checks the diff against them.

## Inputs

- The linked issue (`Closes #N`), its acceptance criteria and its
  requirements.
- For roadmap tickets: the ticket key (for example `W-P1-VRFY-02`) and the
  feature page in `docs/roadmap/features/`.
- The PR's test results (`scripts/check.sh`, and its JSON report once #353
  lands).

## Already covered by CI

The checks pass or fail on their own. This lens is about whether the *right*
behaviour was built and proven.

## Checks

**ACC-1 Every acceptance criterion has evidence.**
For each criterion, name the test, scenario or command output that proves it.
A criterion with no evidence is unmet, even if the code looks right.

**ACC-2 The evidence actually tests the criterion.**
The named test must fail if the behaviour were missing. A test that only
checks "no error" or a status code, when the criterion is about content, an
event or a deny reason, is not evidence. See `TEST-*`.

**ACC-3 Every requirement is met.**
Check the issue's requirements list item by item: config keys and defaults,
error codes, metrics and audit records, limits.

**ACC-4 Nothing outside the scope.**
Changes the issue didn't ask for (refactors, new options, unrelated fixes)
belong in their own PR. Flag them, even if they look good.

**ACC-5 Out-of-scope items stayed out.**
If the issue lists "out of scope", none of it should appear in the diff.

**ACC-6 The roadmap definition of done holds.**
From `docs/roadmap/conventions.md`:
- one PR, mergeable on its own, with `main` green;
- new behaviour ships behind a flag or default-off config;
- `scripts/check.sh` passes;
- no secret, token or full body in logs or test output;
- default-deny and the core invariant are not weakened.

**ACC-7 Dependencies were done first.**
The ticket's "Depends on" items are merged. If the PR works around a missing
dependency, the workaround must be called out and tracked.

**ACC-8 Docs and config examples match.**
New config keys appear in `configs/config.example.yaml` and the relevant
`docs/` page, with the default. Changed behaviour updates the docs that
describe it. For roadmap work, the ticket text stays true, or the PR updates
`tickets.json`.

**ACC-9 The PR says what it did.**
The description lists each acceptance criterion with its evidence, notes
anything not done and why, and links follow-up issues.

## Out of scope for this lens

Code quality and design. Those belong to the other lenses.
