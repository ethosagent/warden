package auditlog

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
)

// setSentinel sets a string or []string field to a value unique to the field.
func setSentinel(v reflect.Value, marker string) bool {
	switch v.Kind() {
	case reflect.String:
		v.SetString(marker)
	case reflect.Slice:
		if v.Type().Elem().Kind() != reflect.String {
			return false
		}
		v.Set(reflect.ValueOf([]string{marker}))
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int64:
		v.SetInt(7)
	case reflect.Float64:
		v.SetFloat(7.5)
	case reflect.Struct:
		if v.Type() != reflect.TypeOf(time.Time{}) {
			return false
		}
		v.Set(reflect.ValueOf(time.Unix(1700000000, 123).UTC()))
	default:
		return false
	}
	return true
}

// baseEvent has every field FromEvent reads set to a harmless value, with a
// valid identity so the user fields are in play.
func baseEvent() analytics.Event {
	return analytics.Event{
		Timestamp:      time.Unix(1600000000, 0).UTC(),
		Domain:         "base.example",
		Protocol:       "https",
		Decision:       "allow",
		Method:         "GET",
		URL:            "https://base.example/p",
		IdentityStatus: "valid",
	}
}

// TestEventFieldsAccountedFor fails when an exported analytics.Event field is
// neither mapped by FromEvent nor listed in excludedEventFields, naming the
// field. A field counts as mapped when changing only it changes the Record.
func TestEventFieldsAccountedFor(t *testing.T) {
	typ := reflect.TypeOf(analytics.Event{})
	excluded := ExcludedEventFields()
	base := FromEvent(baseEvent(), sinkMeta, QueryKeys)

	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if !f.IsExported() {
			continue
		}
		_, isExcluded := excluded[f.Name]

		ev := baseEvent()
		if !setSentinel(reflect.ValueOf(&ev).Elem().Field(i), "SENTINEL-"+f.Name) {
			t.Errorf("Event.%s has kind %s the accounting test cannot set: extend setSentinel, or map/exclude it deliberately", f.Name, f.Type)
			continue
		}
		if f.Name == "URL" {
			ev.URL = "https://base.example/changed?q=1"
		}
		changed := !reflect.DeepEqual(base, FromEvent(ev, sinkMeta, QueryKeys))

		switch {
		case isExcluded && changed:
			t.Errorf("Event.%s is listed in excludedEventFields but FromEvent maps it", f.Name)
		case !isExcluded && !changed:
			t.Errorf("Event.%s is neither mapped by FromEvent nor listed in excludedEventFields: map it in record.go and the schema, or exclude it with a reason", f.Name)
		}
	}
	for name := range excluded {
		if _, ok := typ.FieldByName(name); !ok {
			t.Errorf("excludedEventFields lists %q, which is not an analytics.Event field", name)
		}
	}
}

const (
	leakSecret   = "sk-live-9f8e7d6c5b4a-LEAKCANARY"
	leakSecretRf = "ref:sha256:deadbeef:last4=ABCD"
)

var leakHeaderNames = []string{"Authorization", "Cookie", "X-Api-Key"}

func leakyEvent() analytics.Event {
	ev := baseEvent()
	ev.Decision = "deny"
	ev.Reason = "policy_no_match"
	ev.URL = "https://user:" + leakSecret + "@base.example/v1/path?api_key=" + leakSecret + "&token=" + leakSecret + "#frag-" + leakSecret
	ev.SecretRef = leakSecretRf
	ev.Evidence = []string{"Authorization: Bearer " + leakSecret, "Cookie: sid=" + leakSecret, "X-Api-Key: " + leakSecret}
	// Every deliberately excluded field, set to a canary of its own.
	evv := reflect.ValueOf(&ev).Elem()
	for name := range ExcludedEventFields() {
		setSentinel(evv.FieldByName(name), "EXCLUDED-"+name+"-"+leakSecret)
	}
	ev.IdentityStatus = "expired" // a non-valid identity must not leak sub/email
	ev.UserSub, ev.UserEmail, ev.UserSID = "sub-"+leakSecret, "who@"+leakSecret+".example", "sid-"+leakSecret
	ev.UserGroups = []string{"grp-" + leakSecret}
	return ev
}

// TestNoSecretLeak writes a hostile event through a real Sink and scans the
// bytes: no secret value, secret reference, evidence string, excluded field or
// header name may appear, in either query mode.
func TestNoSecretLeak(t *testing.T) {
	for _, mode := range []string{config.JSONLogQueryDrop, config.JSONLogQueryKeys} {
		t.Run(mode, func(t *testing.T) {
			buf := &syncBuf{}
			s, err := New(config.JSONLogConfig{Enabled: true, Output: config.JSONLogOutputStdout, Query: mode}, sinkMeta, nil, discardLogger(), WithWriter(buf))
			if err != nil {
				t.Fatal(err)
			}
			s.Observe([]analytics.Event{leakyEvent()})
			closeSink(t, s)

			out := buf.String()
			if strings.Count(out, "\n") != 1 {
				t.Fatalf("want exactly one line, got %q", out)
			}
			forbidden := []string{leakSecret, "LEAKCANARY", leakSecretRf, "deadbeef", "SENTINEL", "EXCLUDED-", "user:", "frag-", "who@", "sub-", "sid-", "grp-"}
			forbidden = append(forbidden, leakHeaderNames...)
			lower := strings.ToLower(out)
			for _, bad := range forbidden {
				if strings.Contains(lower, strings.ToLower(bad)) {
					t.Errorf("line contains %q: %s", bad, out)
				}
			}
			recs := decode(t, out)
			if len(recs) != 1 || recs[0].URLPath != "/v1/path" {
				t.Fatalf("record = %+v", recs)
			}
			if mode == config.JSONLogQueryKeys {
				if got := strings.Join(recs[0].QueryKeys, ","); got != "api_key,token" {
					t.Errorf("query_keys = %q, want the names only", got)
				}
			} else if len(recs[0].QueryKeys) != 0 {
				t.Errorf("query_keys = %v in drop mode", recs[0].QueryKeys)
			}
			if u := recs[0].User; u == nil || u.Status != "expired" || u.Sub != "" || u.Email != "" || u.SID != "" || len(u.Groups) != 0 {
				t.Errorf("non-valid identity leaked user fields: %+v", u)
			}
		})
	}
}
