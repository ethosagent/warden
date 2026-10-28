package auditlog

import (
	"encoding/json"
	"errors"
	"time"
)

// Schema identifiers of the control plane's admin stream.
const (
	SchemaAdminV1 = "warden.admin.v1"
	// AdminSchemaRev is the revision within warden.admin.v1.
	AdminSchemaRev = 1

	// ActionCheckpoint is the action of the periodic chain-head record. It is
	// not a stored admin_audit row: chain_seq, entry_hash and key_id carry the
	// head the checkpoint anchors.
	ActionCheckpoint = "admin_audit.checkpoint"
)

// errAdminLineTooLong is returned by AdminRecord.MarshalLine for a record
// that still exceeds MaxLineBytes after its fields were bounded.
var errAdminLineTooLong = errors.New("auditlog: admin record exceeds the line limit")

// AdminActor is the plaintext actor of an admin line. Sub and Email come from
// the side table (the signed row holds only an HMAC of the sub); both are empty
// for rows the store writes itself and for checkpoints.
type AdminActor struct {
	Sub   string `json:"sub,omitempty"`
	Email string `json:"email,omitempty"`
	Role  string `json:"role"`
}

// AdminRecord is one warden.admin.v1 line: the closed projection of a stored
// admin_audit row (or of a chain-head checkpoint). Field order here is the key
// order on the wire. It has no field a request body, header, token or cookie
// could land in. Consumers must sort by ts, never by line order; seq and
// boot_id order lines within one boot, and a gap in seq means dropped lines.
// chain_seq, entry_hash, prev_hash and key_id are copied from the stored row,
// so a shipped copy anchors the chain off host.
type AdminRecord struct {
	Schema     string     `json:"schema"`
	SchemaRev  int        `json:"schema_rev"`
	TS         string     `json:"ts"`
	CPID       string     `json:"cp_id"`
	BootID     string     `json:"boot_id"`
	Seq        uint64     `json:"seq"`
	Actor      AdminActor `json:"actor"`
	AuthMethod string     `json:"auth_method"`
	Action     string     `json:"action"`
	Target     string     `json:"target"`
	TargetRef  string     `json:"target_ref"`
	Outcome    string     `json:"outcome"`
	BeforeHash string     `json:"before_hash"`
	AfterHash  string     `json:"after_hash"`
	RequestID  string     `json:"request_id"`
	ChainSeq   int64      `json:"chain_seq"`
	EntryHash  string     `json:"entry_hash"`
	PrevHash   string     `json:"prev_hash"`
	KeyID      string     `json:"key_id"`
}

// FormatTS renders t the way every line's ts is written: UTC, RFC 3339 with
// nanoseconds.
func FormatTS(t time.Time) string { return t.UTC().Format(tsLayout) }

// bounded stamps the stream fields the caller does not own (schema, schema_rev,
// cp_id, boot_id) and caps and cleans every caller-supplied string, so one line
// is bounded whatever the row held. Seq is assigned by the sink.
func (r AdminRecord) bounded(m Meta) AdminRecord {
	field := func(s string) string { return cut(stripControl(s), maxFieldBytes) }
	r.Schema, r.SchemaRev = SchemaAdminV1, AdminSchemaRev
	r.CPID, r.BootID = field(m.ProxyID), field(m.BootID)
	r.Actor = AdminActor{Sub: field(r.Actor.Sub), Email: field(r.Actor.Email), Role: field(r.Actor.Role)}
	r.AuthMethod, r.Action = field(r.AuthMethod), field(r.Action)
	r.Target, r.TargetRef = field(r.Target), field(r.TargetRef)
	r.Outcome = field(r.Outcome)
	r.BeforeHash, r.AfterHash = field(r.BeforeHash), field(r.AfterHash)
	r.RequestID, r.EntryHash = field(r.RequestID), field(r.EntryHash)
	r.PrevHash, r.KeyID = field(r.PrevHash), field(r.KeyID)
	return r
}

// MarshalLine returns the record as JSON plus one trailing newline in a single
// buffer, so the sink emits it with one Write.
func (r AdminRecord) MarshalLine() ([]byte, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	if len(b)+1 > MaxLineBytes {
		return nil, errAdminLineTooLong
	}
	return append(b, '\n'), nil
}
