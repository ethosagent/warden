package gateway

import (
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/mcp"
	"github.com/ethosagent/warden/internal/scan"
)

// fakeStore is an in-memory gateway.Store for persistence tests. It records how
// many times each save method was called and retains the last-saved data so a
// second gateway can be constructed against the same store to prove "survives
// restart". It is safe for concurrent use (the flusher goroutine may touch it).
type fakeStore struct {
	mu        sync.Mutex
	inventory []InventoryItem
	schemas   map[string]mcp.ToolProfileView
	invSaves  int
	schSaves  int
}

func newFakeStore() *fakeStore {
	return &fakeStore{schemas: make(map[string]mcp.ToolProfileView)}
}

func (f *fakeStore) LoadMCPInventory() ([]InventoryItem, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]InventoryItem, len(f.inventory))
	copy(out, f.inventory)
	return out, nil
}

func (f *fakeStore) SaveMCPInventory(items []InventoryItem) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.invSaves++
	f.inventory = make([]InventoryItem, len(items))
	copy(f.inventory, items)
	return nil
}

func (f *fakeStore) LoadMCPSchemas() (map[string]mcp.ToolProfileView, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]mcp.ToolProfileView, len(f.schemas))
	for k, v := range f.schemas {
		out[k] = v
	}
	return out, nil
}

func (f *fakeStore) SaveMCPSchemas(schemas map[string]mcp.ToolProfileView) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.schSaves++
	f.schemas = make(map[string]mcp.ToolProfileView, len(schemas))
	for k, v := range schemas {
		f.schemas[k] = v
	}
	return nil
}

func (f *fakeStore) counts() (inv, sch int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.invSaves, f.schSaves
}

func newGWWithStore(t *testing.T, store Store) *Gateway {
	t.Helper()
	cfg := baseCfg(modeMonitor)
	sc := scan.NewScanner(scan.WithPhonePII(cfg.Scan.PII.Phone))
	return New(cfg, sc, testLogger(), WithStore(store))
}

// exercise drives a tools/list + a tools/call through the gateway so both the
// inventory and the schema profiler accumulate state worth persisting.
func exercise(t *testing.T, gw *Gateway) {
	t.Helper()
	if v := gw.OnResponse("s1", 200, nil, toolListResp(`"1"`, "reads a file", "")); len(v.Inventory) != 1 {
		t.Fatalf("expected tools/list to yield 1 inventory item, got %d", len(v.Inventory))
	}
	gw.OnRequest("s1", "tools/call", "", nil, toolCall(`"2"`, "read_file", `{"path":"/etc/hosts"}`))
}

// TestPersist_FlushOnCloseSavesData exercises the gateway, closes it, and
// asserts the store received the inventory and schema that the gateway holds.
func TestPersist_FlushOnCloseSavesData(t *testing.T) {
	store := newFakeStore()
	gw := newGWWithStore(t, store)
	exercise(t, gw)

	if err := gw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	invSaves, schSaves := store.counts()
	if invSaves == 0 {
		t.Fatalf("expected SaveMCPInventory to be called on Close")
	}
	if schSaves == 0 {
		t.Fatalf("expected SaveMCPSchemas to be called on Close")
	}

	saved, _ := store.LoadMCPInventory()
	if len(saved) != 1 || saved[0].Name != "read_file" {
		t.Fatalf("saved inventory = %+v, want one read_file item", saved)
	}
	if !saved[0].HasDescription {
		t.Fatalf("saved inventory item should have HasDescription=true")
	}
	if saved[0].FirstSeen.IsZero() || saved[0].LastSeen.IsZero() {
		t.Fatalf("saved inventory timestamps should be set: %+v", saved[0])
	}

	schemas, _ := store.LoadMCPSchemas()
	if len(schemas) == 0 {
		t.Fatalf("expected saved schema profiles, got none")
	}
}

// TestPersist_SurvivesRestart proves the core guarantee: a second gateway built
// against a store that already holds saved data loads it on start, so its live
// Inventory() and SchemaSnapshot() return the previously observed data.
func TestPersist_SurvivesRestart(t *testing.T) {
	store := newFakeStore()

	// First "process": observe, then shut down (flushing to the store).
	gw1 := newGWWithStore(t, store)
	exercise(t, gw1)
	if err := gw1.Close(); err != nil {
		t.Fatalf("gw1 Close: %v", err)
	}

	wantInv := store.mustInventory(t)
	wantSchema := store.mustSchemas(t)
	if len(wantInv) == 0 || len(wantSchema) == 0 {
		t.Fatalf("precondition: store should hold inventory(%d) + schema(%d)", len(wantInv), len(wantSchema))
	}

	// Second "process": a fresh gateway against the same store must restore.
	gw2 := newGWWithStore(t, store)
	t.Cleanup(func() { _ = gw2.Close() })

	gotInv := gw2.Inventory()
	if len(gotInv) != len(wantInv) {
		t.Fatalf("restored inventory len = %d, want %d", len(gotInv), len(wantInv))
	}
	if gotInv[0].Name != "read_file" || !gotInv[0].HasDescription {
		t.Fatalf("restored inventory item = %+v, want read_file w/ description", gotInv[0])
	}
	if !gotInv[0].FirstSeen.Equal(wantInv[0].FirstSeen) {
		t.Fatalf("restored FirstSeen = %v, want %v", gotInv[0].FirstSeen, wantInv[0].FirstSeen)
	}

	gotSchema := gw2.SchemaSnapshot()
	if len(gotSchema) != len(wantSchema) {
		t.Fatalf("restored schema len = %d, want %d", len(gotSchema), len(wantSchema))
	}
	for key, want := range wantSchema {
		got, ok := gotSchema[key]
		if !ok {
			t.Fatalf("restored schema missing key %q", key)
		}
		if len(got.Fields) != len(want.Fields) {
			t.Fatalf("restored schema %q field count = %d, want %d", key, len(got.Fields), len(want.Fields))
		}
	}
}

// TestPersist_NilStoreCloseIsNoop confirms a gateway with no store starts no
// goroutine and Close is a harmless no-op (and idempotent).
func TestPersist_NilStoreCloseIsNoop(t *testing.T) {
	gw := newGW(t, baseCfg(modeMonitor)) // no WithStore
	if gw.done != nil {
		t.Fatalf("no-store gateway should not start a flusher (done should be nil)")
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("Close (no store) should be nil, got %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("second Close (no store) should be nil, got %v", err)
	}
}

// TestPersist_CloseStopsFlusher confirms Close is idempotent, stops the flusher
// goroutine (no leak), and does not panic on repeated calls. The goroutine count
// is compared before construction and after Close, with a short settle so the
// flusher has exited.
func TestPersist_CloseStopsFlusher(t *testing.T) {
	before := runtime.NumGoroutine()

	store := newFakeStore()
	gw := newGWWithStore(t, store)
	exercise(t, gw)
	if err := gw.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("second Close should be a no-op, got %v", err)
	}
	// After Close the done channel must be closed.
	select {
	case <-gw.done:
	case <-time.After(time.Second):
		t.Fatal("done channel not closed after Close")
	}

	// The flusher goroutine should be gone: allow a brief window for it to exit.
	for i := 0; i < 50; i++ {
		if runtime.NumGoroutine() <= before {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("flusher goroutine leaked: before=%d after=%d", before, runtime.NumGoroutine())
}

// mustInventory / mustSchemas are small read helpers for the restart test.
func (f *fakeStore) mustInventory(t *testing.T) []InventoryItem {
	t.Helper()
	inv, err := f.LoadMCPInventory()
	if err != nil {
		t.Fatalf("LoadMCPInventory: %v", err)
	}
	return inv
}

func (f *fakeStore) mustSchemas(t *testing.T) map[string]mcp.ToolProfileView {
	t.Helper()
	s, err := f.LoadMCPSchemas()
	if err != nil {
		t.Fatalf("LoadMCPSchemas: %v", err)
	}
	return s
}
