package auditlog

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
)

const adminSchemaPath = "../../docs/schemas/warden.admin.v1.json"

func loadAdminSchema(t *testing.T) schemaObject {
	t.Helper()
	b, err := os.ReadFile(adminSchemaPath)
	if err != nil {
		t.Fatalf("admin schema missing: %v", err)
	}
	var s schemaObject
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatalf("admin schema is not valid JSON: %v", err)
	}
	return s
}

// TestAdminRecordMatchesSchema pins AdminRecord to the published schema in
// both directions, like TestDecisionRecordMatchesSchema.
func TestAdminRecordMatchesSchema(t *testing.T) {
	s := loadAdminSchema(t)
	if !strings.Contains(s.Schema, "2020-12") {
		t.Errorf("$schema = %q, want JSON Schema 2020-12", s.Schema)
	}

	var rec AdminRecord
	populate(reflect.ValueOf(&rec).Elem())
	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	var inst map[string]any
	if err := json.Unmarshal(raw, &inst); err != nil {
		t.Fatal(err)
	}
	compareObject(t, "admin", s, reflect.TypeOf(rec), inst)

	actor := s.Properties["actor"]
	ainst, _ := inst["actor"].(map[string]any)
	if ainst == nil {
		t.Fatal("populated AdminRecord has no actor object")
	}
	compareObject(t, "admin.actor", actor, reflect.TypeOf(AdminActor{}), ainst)

	if c := s.Properties["schema"].Const; c != SchemaAdminV1 {
		t.Errorf("schema.const = %v, want %q", c, SchemaAdminV1)
	}
	if got := s.Properties["ts"].Format; got != "date-time" {
		t.Errorf("ts.format = %q, want date-time", got)
	}
	want := []string{"ok", "denied", "rejected", "error"}
	if !reflect.DeepEqual(s.Properties["outcome"].Enum, want) {
		t.Errorf("outcome enum = %v, want %v", s.Properties["outcome"].Enum, want)
	}
}

func TestAdminSchemaDescription(t *testing.T) {
	d := loadAdminSchema(t).Description
	for _, need := range []string{
		"additive optional fields", "schema_rev", "v2", "one minor release", "ignore unknown fields",
		"sort by ts", "wall clock", "not ordered", "seq", "boot_id", "gap",
		"chain_seq", "entry_hash", "prev_hash", "key_id", "admin_audit.checkpoint",
		"never exported",
	} {
		if !strings.Contains(d, need) {
			t.Errorf("admin schema description lacks %q", need)
		}
	}
}

// A closed record has no field a body, header, token or cookie could use.
func TestAdminRecordHasNoBodyField(t *testing.T) {
	typ := reflect.TypeOf(AdminRecord{})
	for i := 0; i < typ.NumField(); i++ {
		name, _, ok := jsonTag(typ.Field(i))
		if !ok {
			continue
		}
		for _, bad := range []string{"body", "token", "cookie", "header", "authorization", "secret", "password", "details", "client_ip"} {
			if strings.Contains(strings.ToLower(name), bad) {
				t.Errorf("AdminRecord field %q looks like a place for %s", name, bad)
			}
		}
	}
}

func adminRec() AdminRecord {
	return AdminRecord{
		TS:         FormatTS(time.Unix(1_800_000_000, 5)),
		Actor:      AdminActor{Sub: "alice", Email: "alice@example.com", Role: "admin"},
		AuthMethod: "oidc", Action: "policy.write", Target: "policy", TargetRef: "/dashboard/api/policy",
		Outcome: "ok", BeforeHash: "b1", AfterHash: "a1", RequestID: "req-1",
		ChainSeq: 7, EntryHash: "ee", PrevHash: "pp", KeyID: "k1",
	}
}

func TestWriteAdminLine(t *testing.T) {
	buf := &syncBuf{}
	m := Meta{ProxyID: "cp-host", ProxyIDSource: "hostname", BootID: "b00t"}
	s, err := New(config.JSONLogConfig{Output: config.JSONLogOutputStdout}, m, nil, discardLogger(), WithWriter(buf))
	if err != nil {
		t.Fatal(err)
	}
	r := adminRec()
	r.Schema, r.CPID, r.BootID, r.Seq = "forged", "forged", "forged", 99 // the sink owns these
	s.WriteAdmin(r)
	s.WriteAdmin(adminRec())
	closeSink(t, s)

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines = %d, want 2: %q", len(lines), buf.String())
	}
	for i, ln := range lines {
		var got AdminRecord
		dec := json.NewDecoder(strings.NewReader(ln))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&got); err != nil {
			t.Fatalf("line %d: %v: %q", i, err, ln)
		}
		if got.Schema != SchemaAdminV1 || got.SchemaRev != AdminSchemaRev || got.CPID != "cp-host" || got.BootID != "b00t" || got.Seq != uint64(i+1) {
			t.Errorf("line %d stream fields = %+v", i, got)
		}
		if got.Actor.Sub != "alice" || got.ChainSeq != 7 || got.Action != "policy.write" {
			t.Errorf("line %d = %+v", i, got)
		}
	}
}

func TestWriteAdminBoundsAndCleansFields(t *testing.T) {
	buf := &syncBuf{}
	s, err := New(config.JSONLogConfig{Output: config.JSONLogOutputStdout}, sinkMeta, nil, discardLogger(), WithWriter(buf))
	if err != nil {
		t.Fatal(err)
	}
	r := adminRec()
	r.TargetRef = "/x\n{\"injected\":true}" + strings.Repeat("y", 10_000)
	r.Actor.Email = strings.Repeat("e", 10_000)
	s.WriteAdmin(r)
	closeSink(t, s)

	out := buf.String()
	if strings.Count(out, "\n") != 1 || len(out) > MaxLineBytes {
		t.Fatalf("one bounded line expected, got %d bytes, %d newlines", len(out), strings.Count(out, "\n"))
	}
	var got AdminRecord
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.TargetRef) > maxFieldBytes || len(got.Actor.Email) > maxFieldBytes {
		t.Errorf("fields not capped: %d %d", len(got.TargetRef), len(got.Actor.Email))
	}
}

func TestWriteAdminSharesMetricsAndDrops(t *testing.T) {
	m, scrape := newMetrics(t)
	buf := &syncBuf{}
	s, err := New(config.JSONLogConfig{Output: config.JSONLogOutputStdout}, sinkMeta, m, discardLogger(), WithWriter(buf))
	if err != nil {
		t.Fatal(err)
	}
	s.Observe(events(1))
	s.WriteAdmin(adminRec())
	closeSink(t, s)
	s.WriteAdmin(adminRec()) // after Close: dropped, not a panic

	body := scrape()
	for _, want := range []string{`schema="warden.decision.v1"`, `schema="warden.admin.v1"`, "warden_auditlog_dropped_total"} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics lack %s\n%s", want, body)
		}
	}
	var nilSink *Sink
	nilSink.WriteAdmin(adminRec())
}

func TestWriteAdminFailingWriterNeverBlocks(t *testing.T) {
	s, err := New(config.JSONLogConfig{Output: config.JSONLogOutputStdout}, sinkMeta, nil, discardLogger(), WithWriter(errWriter{}))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		s.WriteAdmin(adminRec())
	}
	closeSink(t, s)
}
