package portal_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/portal"
	idplinksqlite "github.com/ethosagent/warden/internal/portal/adapters/sqlite"
	"github.com/ethosagent/warden/internal/secrets"
	"github.com/ethosagent/warden/test/fakes"
)

const (
	linkIss      = "https://idp.example.com/dex"
	linkSub      = "CiQwOGE4Njg0Yi1kYjg4LTRiNzMtOTBhOS0zY2QxNjYxZjU0NjYSBGxkYXA"
	linkToken    = "rt-first-refresh-token-value-0001"
	linkLifetime = 720 * time.Hour
)

var linkEpoch = time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)

type linkRig struct {
	store *portal.LinkStore
	repo  *idplinksqlite.Repo
	db    *cpstate.DB
	logs  *syncBuffer
	mu    sync.Mutex
	now   time.Time
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func (r *linkRig) advance(d time.Duration) {
	r.mu.Lock()
	r.now = r.now.Add(d)
	r.mu.Unlock()
}

func (r *linkRig) clock() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.now
}

// newLinkRig builds a LinkStore over a fresh cpstate DB and st (consent.store),
// with the secrets helpers the control plane injects.
func newLinkRig(t *testing.T, st portal.LinkSecrets) *linkRig {
	t.Helper()
	db, err := cpstate.Open(context.Background(), filepath.Join(t.TempDir(), "warden-cp.db"), idplinksqlite.Migrations())
	if err != nil {
		t.Fatalf("cpstate.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	r := &linkRig{repo: idplinksqlite.New(db), db: db, logs: &syncBuffer{}, now: linkEpoch}
	r.store, err = portal.NewLinkStore(portal.LinkStoreConfig{
		Repo: r.repo, Secrets: st,
		Keys: portal.LinkKeys{
			UserKey: secrets.UserKey, SecretKey: secrets.IdPLinkKey,
			Ref: func(tok string) string { return secrets.Ref(tok).String() },
		},
		RefreshLifetime: linkLifetime, Now: r.clock,
		Logger: slog.New(slog.NewJSONHandler(r.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func (r *linkRig) count(t *testing.T) int {
	t.Helper()
	var n int
	if err := r.db.SQL().QueryRow(`SELECT COUNT(*) FROM idp_links`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// noTokenInLogs fails if the captured log holds any of the tokens.
func (r *linkRig) noTokenInLogs(t *testing.T, tokens ...string) {
	t.Helper()
	for _, tok := range tokens {
		if strings.Contains(r.logs.String(), tok) {
			t.Fatalf("log holds a refresh token: %s", r.logs.String())
		}
	}
}

func userKey(t *testing.T) string {
	t.Helper()
	uk, err := secrets.UserKey(linkIss, linkSub)
	if err != nil {
		t.Fatal(err)
	}
	return uk
}

func link(token string) portal.Link {
	return portal.Link{Iss: linkIss, Sub: linkSub, Email: "dana@example.com", RefreshToken: token}
}

// TestIdPLinkStored: a login's link puts the token at idp/<UserKey(iss,sub)>
// and records only its Reference, generation 1 and the dates; the log names
// the Reference and generation, never the token.
func TestIdPLinkStored(t *testing.T) {
	st := fakes.NewMemorySecretStore()
	r := newLinkRig(t, st)
	if err := r.store.StoreLink(context.Background(), link(linkToken)); err != nil {
		t.Fatalf("StoreLink: %v", err)
	}
	uk := userKey(t)
	if v, ok := st.Value("idp/" + uk); !ok || v != linkToken {
		t.Fatalf("consent.store idp/%s = %q, %v; want the refresh token", uk, v, ok)
	}
	got, err := r.store.Get(context.Background(), linkIss, linkSub)
	if err != nil {
		t.Fatal(err)
	}
	want := portal.IdPLink{
		Iss: linkIss, Sub: linkSub, UserKey: uk, Email: "dana@example.com", SecretKey: "idp/" + uk,
		RefreshRef: secrets.Ref(linkToken).String(), Generation: 1,
		LinkedAt: linkEpoch, RefreshIssuedAt: linkEpoch, RelinkDueAt: linkEpoch.Add(linkLifetime),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("row = %+v\nwant  %+v", got, want)
	}
	if tok, row, err := r.store.TokenAt(context.Background(), linkIss, linkSub); err != nil || tok != linkToken || row != want {
		t.Fatalf("TokenAt = %q, %+v, %v", tok, row, err)
	}
	logs := r.logs.String()
	if !strings.Contains(logs, `"msg":"idp_link_stored"`) || !strings.Contains(logs, want.RefreshRef) || !strings.Contains(logs, `"generation":1`) {
		t.Fatalf("no idp_link_stored line with ref and generation: %s", logs)
	}
	r.noTokenInLogs(t, linkToken)
	if all, err := r.store.List(context.Background()); err != nil || len(all) != 1 || all[0] != want {
		t.Fatalf("List = %+v, %v", all, err)
	}
}

// TestIdPLinkKeyName: on the AWS backend with the default consent.store
// prefix the token lands at warden-cp/idp/<userKey> and nothing is written
// under the distributed secretStore's prefix.
func TestIdPLinkKeyName(t *testing.T) {
	aws := fakes.NewFakeAWSSecretsClient()
	st := secrets.NewAWSSecretStore(aws, "us-east-1", config.DefaultConsentStoreNamePrefix)
	r := newLinkRig(t, st)
	if err := r.store.StoreLink(context.Background(), link(linkToken)); err != nil {
		t.Fatalf("StoreLink: %v", err)
	}
	want := config.DefaultConsentStoreNamePrefix + "idp/" + userKey(t)
	if want != "warden-cp/idp/"+userKey(t) {
		t.Fatalf("default name = %q", want)
	}
	all, err := aws.ListSecrets("")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 || all[0].Name != want {
		t.Fatalf("aws names = %+v, want only %s", all, want)
	}
	if v, err := aws.GetSecretValue(want); err != nil || v != linkToken {
		t.Fatalf("aws %s = %q, %v", want, v, err)
	}
	if under, _ := aws.ListSecrets(secrets.DefaultAWSNamePrefix); len(under) != 0 {
		t.Fatalf("names under the distributed prefix %q: %+v", secrets.DefaultAWSNamePrefix, under)
	}
	r.noTokenInLogs(t, linkToken)
}

// TestIdPLinksValueFree: the idp_links row type and table hold no field able
// to carry a token value. A new string, []byte or other value-bearing field
// fails here until it is reviewed and added to the allowlist.
func TestIdPLinksValueFree(t *testing.T) {
	// Each allowed string field and why it carries no secret.
	allowed := map[string]string{
		"Iss": "issuer URL", "Sub": "subject", "UserKey": "hash of (iss, sub)", "Email": "display address",
		"SecretKey": "logical key name", "RefreshRef": "secrets.Ref: hash prefix, last4, length",
		"LastRefreshStatus": "status word",
	}
	timeT := reflect.TypeOf(time.Time{})
	rt := reflect.TypeOf(portal.IdPLink{})
	seen := map[string]bool{}
	for i := range rt.NumField() {
		f := rt.Field(i)
		switch {
		case f.Type == timeT, f.Type.Kind() == reflect.Int64:
			continue
		case f.Type.Kind() == reflect.String:
			if _, ok := allowed[f.Name]; !ok {
				t.Errorf("IdPLink.%s is a string field that could hold a token; review it and add it to the allowlist", f.Name)
			}
			seen[f.Name] = true
		default:
			t.Errorf("IdPLink.%s has type %s, which could hold a token value", f.Name, f.Type)
		}
	}
	for name := range allowed {
		if !seen[name] {
			t.Errorf("allowlisted field %s no longer exists; drop it from the list", name)
		}
	}
	r := newLinkRig(t, fakes.NewMemorySecretStore())
	rows, err := r.db.SQL().Query(`SELECT name FROM pragma_table_info('idp_links') ORDER BY cid`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var cols []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			t.Fatal(err)
		}
		cols = append(cols, c)
	}
	wantCols := []string{"iss", "sub", "user_key", "email", "secret_key", "refresh_ref", "generation", "linked_at",
		"refresh_issued_at", "relink_due_at", "last_refresh_at", "last_refresh_status", "offboarded_at"}
	if !reflect.DeepEqual(cols, wantCols) {
		t.Fatalf("idp_links columns = %v, want %v (a new column needs this review)", cols, wantCols)
	}
	// And the stored row holds no part of the token beyond the Reference.
	if err := r.store.StoreLink(context.Background(), link(linkToken)); err != nil {
		t.Fatal(err)
	}
	l, err := r.store.Get(context.Background(), linkIss, linkSub)
	if err != nil {
		t.Fatal(err)
	}
	v := reflect.ValueOf(l)
	for i := range v.NumField() {
		if s, ok := v.Field(i).Interface().(string); ok && strings.Contains(s, linkToken[:len(linkToken)-4]) {
			t.Fatalf("IdPLink.%s holds the token", rt.Field(i).Name)
		}
	}
}

// failingPut is a store whose Put error echoes the value it was given, as a
// careless backend might.
type failingPut struct{ *fakes.MemorySecretStore }

func (f failingPut) Put(_ context.Context, key, value string) error {
	return fmt.Errorf("backend refused %s=%s", key, value)
}

// TestIdPLinkFailClosed: a failed Put writes no row, leaves the store as it
// was and returns an error that names no part of the token; a link without a
// token is refused before any write; and admission refuses a login without a
// refresh token (the callback answers 502 offline_access_not_granted).
func TestIdPLinkFailClosed(t *testing.T) {
	mem := fakes.NewMemorySecretStore()
	r := newLinkRig(t, failingPut{mem})
	err := r.store.StoreLink(context.Background(), link(linkToken))
	if !errors.Is(err, portal.ErrLinkSecretStore) {
		t.Fatalf("StoreLink err = %v, want ErrLinkSecretStore", err)
	}
	if strings.Contains(err.Error(), linkToken[4:]) || strings.Contains(err.Error(), linkToken[len(linkToken)-8:]) {
		t.Fatalf("error carries the token: %v", err)
	}
	if n := r.count(t); n != 0 {
		t.Fatalf("idp_links rows = %d after a failed Put, want 0", n)
	}
	if _, ok := mem.Value("idp/" + userKey(t)); ok {
		t.Fatal("store changed by a failed Put")
	}
	r.noTokenInLogs(t, linkToken)

	// An earlier link stays exactly as it was when a later Put fails.
	st := fakes.NewMemorySecretStore()
	r2 := newLinkRig(t, st)
	if err := r2.store.StoreLink(context.Background(), link(linkToken)); err != nil {
		t.Fatal(err)
	}
	before, _ := r2.store.Get(context.Background(), linkIss, linkSub)
	st.SetErrors(nil, errors.New("down"), nil, nil)
	if err := r2.store.StoreLink(context.Background(), link("rt-second")); !errors.Is(err, portal.ErrLinkSecretStore) {
		t.Fatalf("second StoreLink = %v", err)
	}
	after, _ := r2.store.Get(context.Background(), linkIss, linkSub)
	if after != before {
		t.Fatalf("row changed by a failed Put: %+v -> %+v", before, after)
	}
	if v, _ := st.Value("idp/" + userKey(t)); v != linkToken {
		t.Fatalf("stored token = %q", v)
	}

	// No token: refused before any write.
	puts := st.Puts
	if err := r2.store.StoreLink(context.Background(), link("")); !errors.Is(err, portal.ErrNoRefreshToken) {
		t.Fatalf("empty token = %v", err)
	}
	if st.Puts != puts {
		t.Fatal("an empty token reached the store")
	}
	adm := portal.Admission{RequireRefreshToken: true}
	if code := adm.Admit(portal.Candidate{Sub: linkSub}); code != portal.CodeOfflineAccessNotGranted || !strings.Contains(code, "offline_access") {
		t.Fatalf("Admit without a refresh token = %q", code)
	}
}

// TestIdPLinkRotateCAS: each login increments generation and keeps linked_at;
// Rotate with the current generation writes the token and increments it
// without moving refresh_issued_at or relink_due_at; Rotate with a stale
// generation returns ErrStaleGeneration, makes no Put and leaves the stored
// token and row unchanged.
func TestIdPLinkRotateCAS(t *testing.T) {
	st := fakes.NewMemorySecretStore()
	r := newLinkRig(t, st)
	ctx := context.Background()
	if err := r.store.StoreLink(ctx, link(linkToken)); err != nil {
		t.Fatal(err)
	}
	r.advance(time.Hour)
	if err := r.store.StoreLink(ctx, link("rt-relogin-token-0002")); err != nil {
		t.Fatal(err)
	}
	l, err := r.store.Get(ctx, linkIss, linkSub)
	if err != nil {
		t.Fatal(err)
	}
	if l.Generation != 2 || !l.LinkedAt.Equal(linkEpoch) || !l.RefreshIssuedAt.Equal(linkEpoch.Add(time.Hour)) ||
		!l.RelinkDueAt.Equal(linkEpoch.Add(time.Hour+linkLifetime)) || l.RefreshRef != secrets.Ref("rt-relogin-token-0002").String() {
		t.Fatalf("after re-login: %+v", l)
	}

	// A refresh that read generation 1 lost to the re-login.
	puts := st.Puts
	if _, err := r.store.Rotate(ctx, linkIss, linkSub, 1, "rt-stale-rotation-0003"); !errors.Is(err, portal.ErrStaleGeneration) {
		t.Fatalf("stale Rotate = %v, want ErrStaleGeneration", err)
	}
	if st.Puts != puts {
		t.Fatal("a stale Rotate called Put")
	}
	if v, _ := st.Value("idp/" + userKey(t)); v != "rt-relogin-token-0002" {
		t.Fatalf("stored token = %q after a stale Rotate", v)
	}
	if again, _ := r.store.Get(ctx, linkIss, linkSub); again != l {
		t.Fatalf("row changed by a stale Rotate: %+v", again)
	}

	// The current generation wins.
	r.advance(time.Hour)
	got, err := r.store.Rotate(ctx, linkIss, linkSub, 2, "rt-rotated-token-0004")
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	stored, _ := r.store.Get(ctx, linkIss, linkSub)
	if got != stored || stored.Generation != 3 || stored.RefreshRef != secrets.Ref("rt-rotated-token-0004").String() ||
		!stored.RefreshIssuedAt.Equal(l.RefreshIssuedAt) || !stored.RelinkDueAt.Equal(l.RelinkDueAt) ||
		!stored.LastRefreshAt.Equal(linkEpoch.Add(2*time.Hour)) || stored.LastRefreshStatus != portal.RefreshStatusRotated {
		t.Fatalf("after Rotate: returned %+v, stored %+v", got, stored)
	}
	if v, _ := st.Value("idp/" + userKey(t)); v != "rt-rotated-token-0004" {
		t.Fatalf("stored token = %q after Rotate", v)
	}
	// A login after a rotation clears the refresh columns.
	if err := r.store.StoreLink(ctx, link("rt-third-login-0005")); err != nil {
		t.Fatal(err)
	}
	if l4, _ := r.store.Get(ctx, linkIss, linkSub); l4.Generation != 4 || !l4.LastRefreshAt.IsZero() || l4.LastRefreshStatus != "" {
		t.Fatalf("after a third login: %+v", l4)
	}
	// The repo's own CAS refuses a stale generation too (a second process).
	if err := r.repo.Rotate(ctx, linkIss, linkSub, 3, "ref", linkEpoch, "rotated"); !errors.Is(err, portal.ErrStaleGeneration) {
		t.Fatalf("repo Rotate stale = %v", err)
	}
	if _, err := r.store.Rotate(ctx, linkIss, "someone-else", 1, "rt-x"); !errors.Is(err, portal.ErrLinkNotFound) {
		t.Fatalf("Rotate of an unknown link = %v", err)
	}
	r.noTokenInLogs(t, linkToken, "rt-relogin-token-0002", "rt-stale-rotation-0003", "rt-rotated-token-0004", "rt-third-login-0005")
}

// blockingPut holds Put until released, to prove writes of one user are
// serialized.
type blockingPut struct {
	*fakes.MemorySecretStore
	entered chan string
	release chan struct{}
}

func (b blockingPut) Put(ctx context.Context, key, value string) error {
	b.entered <- value
	<-b.release
	return b.MemorySecretStore.Put(ctx, key, value)
}

// TestIdPLinkRotateCASSerialized: a Rotate that starts while a login for the
// same user is between its Put and its upsert waits for it, then sees the new
// generation and returns ErrStaleGeneration without a Put; a wait honours the
// context.
func TestIdPLinkRotateCASSerialized(t *testing.T) {
	mem := fakes.NewMemorySecretStore()
	bp := blockingPut{MemorySecretStore: mem, entered: make(chan string, 4), release: make(chan struct{})}
	r := newLinkRig(t, bp)
	ctx := context.Background()
	close(bp.release)
	if err := r.store.StoreLink(ctx, link(linkToken)); err != nil {
		t.Fatal(err)
	}
	<-bp.entered
	bp.release = make(chan struct{})
	r.store, _ = portal.NewLinkStore(portal.LinkStoreConfig{
		Repo: r.repo, Secrets: bp,
		Keys:            portal.LinkKeys{UserKey: secrets.UserKey, SecretKey: secrets.IdPLinkKey, Ref: func(tok string) string { return secrets.Ref(tok).String() }},
		RefreshLifetime: linkLifetime, Now: r.clock,
	})

	loginDone := make(chan error, 1)
	go func() { loginDone <- r.store.StoreLink(ctx, link("rt-relogin-token-0002")) }()
	if v := <-bp.entered; v != "rt-relogin-token-0002" {
		t.Fatalf("first Put = %q", v)
	}
	// The login holds the user's mutex: a Rotate with a short deadline times out.
	short, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	if _, err := r.store.Rotate(short, linkIss, linkSub, 1, "rt-rotation"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Rotate while the login holds the lock = %v, want a deadline", err)
	}
	rotDone := make(chan error, 1)
	go func() {
		_, err := r.store.Rotate(ctx, linkIss, linkSub, 1, "rt-rotation")
		rotDone <- err
	}()
	close(bp.release)
	if err := <-loginDone; err != nil {
		t.Fatal(err)
	}
	if err := <-rotDone; !errors.Is(err, portal.ErrStaleGeneration) {
		t.Fatalf("Rotate after the login = %v, want ErrStaleGeneration", err)
	}
	select {
	case v := <-bp.entered:
		t.Fatalf("the stale Rotate called Put(%q)", v)
	default:
	}
	if v, _ := mem.Value("idp/" + userKey(t)); v != "rt-relogin-token-0002" {
		t.Fatalf("stored = %q", v)
	}
}

// failingUpsert is a LinkRepo whose Upsert fails while fail is set.
type failingUpsert struct {
	portal.LinkRepo
	fail bool
}

func (f *failingUpsert) Upsert(ctx context.Context, l portal.IdPLink) (portal.IdPLink, error) {
	if f.fail {
		return portal.IdPLink{}, errors.New("database is locked")
	}
	return f.LinkRepo.Upsert(ctx, l)
}

func newStoreOver(t *testing.T, r *linkRig, repo portal.LinkRepo, st portal.LinkSecrets) *portal.LinkStore {
	t.Helper()
	ls, err := portal.NewLinkStore(portal.LinkStoreConfig{
		Repo: repo, Secrets: st,
		Keys:            portal.LinkKeys{UserKey: secrets.UserKey, SecretKey: secrets.IdPLinkKey, Ref: func(tok string) string { return secrets.Ref(tok).String() }},
		RefreshLifetime: linkLifetime, Now: r.clock,
		Logger: slog.New(slog.NewJSONHandler(r.logs, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return ls
}

// TestIdPLinkFailClosedUpsert: a failed row write after the Put returns
// ErrLinkRow with no token in it. For a brand-new link the just-written key
// is deleted; for an existing link the row is unchanged, TokenAt reports the
// split as ErrLinkInconsistent, and the next StoreLink converges.
func TestIdPLinkFailClosedUpsert(t *testing.T) {
	ctx := context.Background()
	st := fakes.NewMemorySecretStore()
	r := newLinkRig(t, st)
	repo := &failingUpsert{LinkRepo: r.repo, fail: true}
	ls := newStoreOver(t, r, repo, st)
	key := "idp/" + userKey(t)

	// New link: no row, and the orphaned key is removed.
	err := ls.StoreLink(ctx, link(linkToken))
	if !errors.Is(err, portal.ErrLinkRow) || strings.Contains(err.Error(), linkToken[4:]) {
		t.Fatalf("StoreLink = %v, want ErrLinkRow without the token", err)
	}
	if _, ok := st.Value(key); ok || r.count(t) != 0 {
		t.Fatal("a failed new-link row write left the key or a row")
	}

	// Existing link: the row stays as it was.
	repo.fail = false
	if err := ls.StoreLink(ctx, link(linkToken)); err != nil {
		t.Fatal(err)
	}
	before, _ := ls.Get(ctx, linkIss, linkSub)
	repo.fail = true
	if err := ls.StoreLink(ctx, link("rt-split-write-0002")); !errors.Is(err, portal.ErrLinkRow) || strings.Contains(err.Error(), "rt-split") {
		t.Fatalf("second StoreLink = %v", err)
	}
	if after, _ := ls.Get(ctx, linkIss, linkSub); after != before {
		t.Fatalf("row changed: %+v -> %+v", before, after)
	}
	if tok, _, err := ls.TokenAt(ctx, linkIss, linkSub); !errors.Is(err, portal.ErrLinkInconsistent) || tok != "" {
		t.Fatalf("TokenAt after a split write = %q, %v; want ErrLinkInconsistent and no token", tok, err)
	}
	// The next login converges.
	repo.fail = false
	if err := ls.StoreLink(ctx, link("rt-converged-0003")); err != nil {
		t.Fatal(err)
	}
	tok, row, err := ls.TokenAt(ctx, linkIss, linkSub)
	if err != nil || tok != "rt-converged-0003" || row.Generation != 2 {
		t.Fatalf("after convergence: %q, %+v, %v", tok, row, err)
	}
	r.noTokenInLogs(t, linkToken, "rt-split-write-0002", "rt-converged-0003")
}

// TestIdPLinkCancelDoesNotSplit: once a write holds the lock, the caller's
// cancellation does not split the Put from the row write.
func TestIdPLinkCancelDoesNotSplit(t *testing.T) {
	mem := fakes.NewMemorySecretStore()
	r := newLinkRig(t, mem)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ls := newStoreOver(t, r, r.repo, cancelOnPut{MemorySecretStore: mem, cancel: cancel})
	if err := ls.StoreLink(ctx, link(linkToken)); err != nil {
		t.Fatalf("StoreLink with a cancel during Put = %v", err)
	}
	if ctx.Err() == nil {
		t.Fatal("the test did not cancel")
	}
	if r.count(t) != 1 {
		t.Fatal("the row was not written after the cancel")
	}
}

// cancelOnPut cancels the caller's context during Put and fails if the
// write context it was given is cancelled too.
type cancelOnPut struct {
	*fakes.MemorySecretStore
	cancel context.CancelFunc
}

func (c cancelOnPut) Put(ctx context.Context, key, value string) error {
	if c.cancel != nil {
		c.cancel()
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return c.MemorySecretStore.Put(ctx, key, value)
}

// failingGet is a LinkRepo whose Get fails.
type failingGet struct{ portal.LinkRepo }

func (failingGet) Get(context.Context, string, string) (portal.IdPLink, error) {
	return portal.IdPLink{}, errors.New("database is locked")
}

// TestIdPLinkStatus: LinkStatus (the LinkReader behind GET /portal/api/me)
// reports missing before a login, linked with relink_due_at after one, and
// unknown with the error when the row cannot be read.
func TestIdPLinkStatus(t *testing.T) {
	ctx := context.Background()
	st := fakes.NewMemorySecretStore()
	r := newLinkRig(t, st)
	if got, err := r.store.LinkStatus(ctx, linkIss, linkSub); err != nil || got.Status != portal.LinkMissing || !got.RelinkDueAt.IsZero() {
		t.Fatalf("before login: %+v, %v; want missing", got, err)
	}
	if err := r.store.StoreLink(ctx, link(linkToken)); err != nil {
		t.Fatal(err)
	}
	got, err := r.store.LinkStatus(ctx, linkIss, linkSub)
	if err != nil || got.Status != portal.LinkLinked || !got.RelinkDueAt.Equal(linkEpoch.Add(linkLifetime)) {
		t.Fatalf("after login: %+v, %v; want linked, due %v", got, err, linkEpoch.Add(linkLifetime))
	}
	ls := newStoreOver(t, r, failingGet{r.repo}, st)
	if got, err := ls.LinkStatus(ctx, linkIss, linkSub); err == nil || got.Status != portal.LinkUnknown {
		t.Fatalf("read error: %+v, %v; want unknown and an error", got, err)
	}
}
