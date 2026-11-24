# Runbook: admin audit signing key

The control plane signs every admin audit entry with one Ed25519 key
(`--admin-audit-key-file`, default `<state-dir>/cp-audit.key`). This runbook covers
checking the chain offline, rotating the signing key with `admin-audit rotate-key`
(W-P2-KEYS-06), and the `--admin-audit-new-segment` recovery for a lost key.

## Check the chain offline

Both commands open `<state-dir>/warden-cp.db` read-only, take every public key from
the chain itself (the `audit.genesis`, `audit.segment_start` and `audit.key_rotated`
entries), never load the signing key and write no audit row. They work with the
control plane stopped or running, and after a key change without any key file.

```sh
warden control-plane admin-audit verify --state-dir /data
# {"ok":true,"checked":1234,"firstBadSeq":0,"headSeq":1234,"headHash":"9f2c…","lastVerifiedSeq":1234}
```

- Exit 0: the chain verifies. Exit 1: it does not; `firstBadSeq` is the first entry
  that fails and `reason` names the check (`entry_hash`, `prev_hash`, `seq_gap`,
  `signature`, `key_change`, `anchor_missing`, ...). Exit 2: a usage or I/O error
  (missing `--state-dir`, no database, a bad flag).
- `--from-seq N` starts at seq N and trusts the rows before it (for a quick check
  after an earlier full run).
- `--anchor seq:hash` also checks a head you saw earlier (`headSeq:headHash` from an
  earlier run, or a shipped log line; the hash is hex). Deleting the newest rows passes
  a plain verify but fails against the anchor. Keep the last `headSeq:headHash`
  off-host.
- A `key_id` change is legal only as the take-up of a signed `audit.key_rotated`
  entry: the old key may not sign past its own handover. Anything else fails with
  `key_change` at that seq.

```sh
warden control-plane admin-audit export --state-dir /data --out /backup/admin-audit-2026-10-27.jsonl
# {"keys":2,"entries":1234,"headSeq":1234,"identity":false}
```

- The file is JSONL: one `keys` record (every `key_id` in the rotation history with
  its base64 public key and first seq) and then one line per entry in seq order. It
  is created with mode 0600 and an existing file is never overwritten.
- The plaintext actor sub and email are left out; entries carry only the HMAC
  `actor_id`. Add `--include-identity` to include them (personal data: store the file
  accordingly).
- An auditor verifies the file with no database and no key file through
  `adminaudit.VerifyExport`, which runs the same checks as `verify` and also checks
  that the `keys` record matches the keys the entries declare. The same list is
  served by `GET /dashboard/api/admin-audit/pubkey` (admin session), so every key in
  the rotation history stays checkable.

The control plane also checks the newest 1000 rows and the head signature at every
start. A failure logs `admin audit chain verification failed` at ERROR with
`first_bad_seq` and raises an `admin_audit_verify_failed` alert (reason `verify_error`
when the chain could not be read at all), but the control plane keeps serving policy. When that happens, run a full `verify` and investigate before
any key change.

## Rotate the signing key (supported path)

`rotate-key` does the whole rotation offline in one step: it generates the new key,
appends one `audit.key_rotated` entry signed by the old key (linked to the head,
carrying `old_key_id`, `new_key_id` and the new public key), then swaps the key
files — the new key replaces `--admin-audit-key-file`, and the old key is kept
beside it as `<key>.<old_key_id>.key.retired` (mode 0600). The HMAC key
(`cp-audit-hmac.key`) does not change. The next control-plane start accepts the new
key because the chain itself names it; the old key stops signing.

1. **Stop the control plane.** `rotate-key` takes the state-dir lock; with the
   control plane running it exits 1 with `control plane is running` and changes
   nothing.

2. **Verify the chain.** Do not rotate on exit 1:

   ```sh
   warden control-plane admin-audit verify --state-dir /data
   ```

3. **Archive the chain** and keep the export and the public keys off-host (they are
   in the export's `keys` record and in the `admin audit enabled` startup log line):

   ```sh
   warden control-plane admin-audit export --state-dir /data --out /backup/admin-audit-before-rotation.jsonl
   ```

4. **Rotate**:

   ```sh
   warden control-plane admin-audit rotate-key --state-dir /data
   # {"oldKeyID":"3f9c…","newKeyID":"91ab…","seq":1235,"retiredPath":"/data/cp-audit.3f9c….key.retired","recovered":false}
   ```

   Pass `--admin-audit-key-file` only when the key is not at the default path. Check
   the output: `seq` is the handover entry's seq (one past the head of step 2),
   `retiredPath` is where the old key now lives. Keep the retired file until the next
   backup set that was taken before the rotation has itself been rotated past, and
   never ship it off the secret mount.

5. **Start the control plane.** It loads the new key; the startup log's
   `admin audit enabled` line shows the new `key_id` and public key.

6. **Verify again**, with the old head as anchor:

   ```sh
   warden control-plane admin-audit verify --state-dir /data --anchor <old headSeq>:<old headHash>
   ```

   It must exit 0 with `headSeq` at least the `seq` from step 4. Also check the
   dashboard's admin audit key list (or `GET /dashboard/api/admin-audit/pubkey`)
   shows both keys.

**Restores across a rotation.** A backup taken before a rotation carries the old
key's fingerprint in its manifest. The restore check accepts any key the state
dir's chain declares in its rotation history, so such a backup restores without
`--new-audit-key`; put the retired key back at `--admin-audit-key-file` (or point
the flag at the retired file) before starting, because the restored chain's head is
signed with it.

**Interrupted rotations.** The entry and the file swap are two steps. If the run
died in between, the head is a `key_rotated` entry naming the new key while the key
file still holds the old one; if it died between the two renames of the swap
itself, there is no key file at all and the old key sits at the retired path.
Re-running `rotate-key` completes the swap from the parked new key in either
state (the output says `"recovered":true`). Without the parked new key it fails
closed naming the pending `key_id`; restore the parked
`<key>.rotate-<new_key_id>.tmp` file (or re-generate the rotation) from your
secret store, or recover with a new segment (below).

## Lost key recovery (new segment)

`--admin-audit-new-segment` exists for the cases `rotate-key` cannot cover: a key
the chain is waiting on is lost or destroyed — the old signing key before its
handover was signed (no one can sign the rotation), or the parked new key of a
committed rotation entry (the handover names a key nobody holds). It starts a new
chain segment with an `audit.segment_start` entry signed by the new key that links
to the old head and names the previous `key_id`; the old key keeps verifying its
segment, and every later row carries the new `key_id`. The control plane logs a
WARN on such a start naming `admin-audit rotate-key` as the supported path. The
step-by-step procedure:

1. **Stop the control plane** and generate the new key, mode 0600, and its
   `key_id` (hex of the first 8 bytes of sha256 of the raw public key):

   ```sh
   (umask 077; openssl genpkey -algorithm ed25519 -out /secrets/cp-audit-new.key)
   openssl pkey -in /secrets/cp-audit-new.key -pubout -outform DER | tail -c 32 | sha256sum | cut -c1-16
   ```

2. **Verify and export the chain** as in steps 2 and 3 above, and confirm with the
   last off-host anchor that the chain is intact. Do not continue on exit 1.

3. **Install the new key** at `--admin-audit-key-file`, with the existing
   `cp-audit-hmac.key` beside it. Starting without the next flag fails with an error
   that names the new key's `key_id`.

4. **Start once with the new segment flag**:

   ```sh
   warden control-plane --config /etc/warden/config.yaml --state-dir /data \
     --admin-audit-key-file /secrets/cp-audit-new.key \
     --admin-audit-new-segment=<new key_id>
   ```

   The flag must equal the loaded key's `key_id`; anything else stops startup. It is
   a no-op once the head is on that key, so leaving it set can never rotate twice.

5. **Verify again** with the old head as anchor, as in step 6 above.

## If something goes wrong

- **Startup fails with a key_id mismatch**: the key at `--admin-audit-key-file` is
  not the key the chain head expects. When the head is a `key_rotated` entry the
  error names the key_id it hands the chain to — point the flag at that key. After
  restoring a pre-rotation backup, put the retired key back. Otherwise point the
  flag at the key for the named key_id, or do the recovery procedure above.
- **Startup fails with a missing key file**: restore the key (and
  `cp-audit-hmac.key`) from backup; the retired file beside the key file may be the
  one you need. The control plane never mints a replacement while rows exist.
- **`verify` exits 1**: do not rotate. Compare with the last off-host export and
  anchor to find what changed, and restore `warden-cp.db` from a backup that
  verifies.
- **`rotate-key` exits 1 with `control plane is running`**: the state-dir lock is
  held. Stop the control plane and run it again; nothing was changed.
- **`rotate-key` exits 2 naming a pending key_id**: a previous run committed the
  handover but died before swapping the key files. Restore the parked
  `<key>.rotate-<key_id>.tmp` file it names and re-run `rotate-key`.
