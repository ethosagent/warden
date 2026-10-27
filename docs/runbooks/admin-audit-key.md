# Runbook: admin audit signing key

The control plane signs every admin audit entry with one Ed25519 key
(`--admin-audit-key-file`, default `<state-dir>/cp-audit.key`). This runbook covers
checking the chain offline and the manual key change.

**P1 ships one key and no rotation command.** The procedure below is the supported way
to move to a new key until W-P2-KEYS-06 replaces it with `warden control-plane
admin-audit rotate-key`, which writes an old-key-signed handoff entry instead.

## Check the chain offline

Both commands open `<state-dir>/warden-cp.db` read-only, take every public key from
the chain itself (the `audit.genesis` and `audit.segment_start` entries), never load
the signing key and write no audit row. They work with the control plane stopped or
running, and after a key change without any key file.

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

```sh
warden control-plane admin-audit export --state-dir /data --out /backup/admin-audit-2026-10-27.jsonl
# {"keys":1,"entries":1234,"headSeq":1234,"identity":false}
```

- The file is JSONL: one `keys` record (every `key_id` with its base64 public key and
  first seq) and then one line per entry in seq order. It is created with mode 0600
  and an existing file is never overwritten.
- The plaintext actor sub and email are left out; entries carry only the HMAC
  `actor_id`. Add `--include-identity` to include them (personal data: store the file
  accordingly).
- An auditor verifies the file with no database and no key file through
  `adminaudit.VerifyExport`, which runs the same checks as `verify` and also checks
  that the `keys` record matches the keys the entries declare.

The control plane also checks the newest 1000 rows and the head signature at every
start. A failure logs `admin audit chain verification failed` at ERROR with
`first_bad_seq` and raises an `admin_audit_verify_failed` alert, but the control plane
keeps serving policy. When that happens, run a full `verify` and investigate before
any key change.

## Manual key change (new segment)

The old key keeps verifying its segment: the new segment starts with an
`audit.segment_start` entry signed by the new key that links to the old head and names
the previous `key_id`. The HMAC key (`cp-audit-hmac.key`, beside the signing key) does
not change.

1. **Stop the control plane.** Nothing else may append while you rotate.

2. **Verify the chain.** It must verify before you start a new segment:

   ```sh
   warden control-plane admin-audit verify --state-dir /data
   ```

   Note `headSeq` and `headHash`. Do not continue on exit 1.

3. **Export the old segment** and keep the export and the old public key off-host
   (the public key is in the export's `keys` record and in the `admin audit enabled`
   startup log line):

   ```sh
   warden control-plane admin-audit export --state-dir /data --out /backup/admin-audit-before-rotation.jsonl
   ```

4. **Install the new key** at `--admin-audit-key-file`, with the existing
   `cp-audit-hmac.key` beside it. Keep the old key file until step 6 succeeds. The key
   is an Ed25519 PKCS#8 PEM file, mode 0600; its `key_id` is the hex of the first 8
   bytes of sha256 of the raw public key:

   ```sh
   (umask 077; openssl genpkey -algorithm ed25519 -out /secrets/cp-audit-new.key)
   openssl pkey -in /secrets/cp-audit-new.key -pubout -outform DER | tail -c 32 | sha256sum | cut -c1-16
   ```

   Starting the control plane on the new key without the next flag also fails with an
   error that names the new key's `key_id`.

5. **Start once with the new segment flag**, with `--admin-audit-key-file` pointing at
   the new key:

   ```sh
   warden control-plane --config /etc/warden/config.yaml --state-dir /data \
     --admin-audit-key-file /secrets/cp-audit-new.key \
     --admin-audit-new-segment=<new key_id>
   ```

   The flag must equal the loaded key's `key_id`; anything else stops startup. It is a
   no-op once the head is on that key, so leaving it set can never rotate twice. The
   startup log's `admin audit enabled` line shows the new `key_id` and public key.

6. **Verify again**, with the old head as anchor:

   ```sh
   warden control-plane admin-audit verify --state-dir /data --anchor <old headSeq>:<old headHash>
   ```

   It must exit 0 with `headSeq` one past the old head (the `audit.segment_start`
   entry) or later. Then retire the old private key; its public key stays in the chain.

## If something goes wrong

- **Startup fails with a key_id mismatch**: the key at `--admin-audit-key-file` is not
  the key the chain head is signed with. Point the flag at the right key, or do steps
  1 to 6 to start a new segment.
- **Startup fails with a missing key file**: restore the key (and `cp-audit-hmac.key`)
  from backup. The control plane never mints a replacement while rows exist.
- **`verify` exits 1**: do not rotate. Compare with the last off-host export and
  anchor to find what changed, and restore `warden-cp.db` from a backup that verifies.
