---
name: add-config-key
description: Add a new configuration key or block to Warden's YAML config. Use when new behaviour needs an operator setting, default or validation.
---

# Add a config key

Rules live in [`AGENTS.md`](../../../AGENTS.md); checks in
[`security-invariants`](../../reviews/security-invariants.md) (`SEC-9`, `SEC-12`),
[`architecture`](../../reviews/architecture.md) (`ARCH-6`), [`acceptance`](../../reviews/acceptance.md)
(`ACC-8`) and [`test-quality`](../../reviews/test-quality.md) (`TEST-7`).

## Steps

1. **Test first**: a config test for the default, a valid value and each invalid value
   (`internal/config/*_test.go`).
2. **Field and default.** Add the typed field to the config struct in `internal/config`, and the raw
   `yaml` mirror (`rawXxx`). Parsing uses `KnownFields(true)`, so an unregistered key fails to parse.
   Apply the default in a `parseXxx` func and as a named constant.
3. **Default off.** New behaviour is disabled when the block is absent, and an absent block must be
   byte-identical to before (`SEC-12`).
4. **Validate at startup.** Add `validateXxx` and call it from `validate` in `internal/config/config.go`.
   Reject unknown enum values with an error that names the key. Never fall back to "allow".
5. **Decide where it travels.** A value only the control plane may hold or edit (secrets, credentials,
   local wiring) gets `json:"-"` on the `Policy` field so it is never sent to workers (`SEC-9`).
   A value workers must receive goes through `SettingsWire` in `internal/config/settings.go`, with no
   secret in it. A Go-native check for the `json:"-"` rule is planned (#349, rule X2); until then
   check by hand.
6. **Document it.** Add a commented block to `configs/config.example.yaml` (default value, what off
   means) and mention it in the relevant doc under `docs/` (`ACC-8`).
7. Run `scripts/check.sh`.

## Worked example: `dlp:`

- Field: `Policy.DLP DLPConfig \`json:"-"\`` in `internal/config/config.go`; raw mirror `rawDLP` and
  `parseDLP` in `internal/config/dlp.go`; default `defaultDLPMode = DLPModeOff`.
- Validation: `validateDLP`, called from `validate` in `config.go`.
- Distribution: workers get the operator-relevant parts through `DLPSettings` in `settings.go`.
- Consumed by: `p.dlp() == nil` makes `dlpScan` a no-op.
- A simpler one to copy: `responseScan:` in `configs/config.example.yaml`.
- Known gap, do not copy: `dlp:` has no block in `configs/config.example.yaml`. New keys must add one
  (step 6); `responseScan:` shows the expected form.
