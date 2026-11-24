package controlplane

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/agentreg"
)

func auditAgent(groups []string, keys ...agentreg.Key) agentreg.Agent {
	return agentreg.Agent{ID: "a1", Status: agentreg.StatusActive, AllowedGroups: groups, Keys: keys}
}

func auditKey(kid, jkt string) agentreg.Key { return agentreg.Key{KID: kid, JKT: jkt} }

func checkDetails(t *testing.T, d map[string]string) {
	t.Helper()
	if len(d) > 24 {
		t.Errorf("%d detail keys, the entry limit is 24", len(d))
	}
	for k, v := range d {
		if v == "" {
			t.Errorf("detail %q is empty", k)
		}
		if len(v) > adminaudit.MaxDetailValueLen {
			t.Errorf("detail %q is %d bytes", k, len(v))
		}
		for i := 0; i < len(v); i++ {
			if v[i] < 0x20 || v[i] > 0x7e {
				t.Errorf("detail %q has a byte outside printable ASCII", k)
			}
		}
	}
}

func TestAgentAuditDetails_Create(t *testing.T) {
	after := auditAgent([]string{"b", "a"}, auditKey("k1", "J1"))
	after.AllowedGroups = []string{"a", "b"}
	d := AgentAuditDetails(nil, after)
	checkDetails(t, d)
	want := map[string]string{
		"op": "create", "statusTo": "active",
		"kidsAdded": "k1", "kidsAddedCount": "1", "kidsRemovedCount": "0",
		"jktsAdded": "J1", "jktsAddedCount": "1", "jktsRemovedCount": "0",
		"groupsAdded": "a,b", "groupsAddedCount": "2", "groupsRemovedCount": "0",
	}
	if fmt.Sprint(d) != fmt.Sprint(want) {
		t.Errorf("create details = %v, want %v", d, want)
	}
	if _, ok := d["statusFrom"]; ok {
		t.Error("a create has a statusFrom")
	}
}

// Swapping the key material under the same kid is a change a kid diff cannot
// see; the thumbprint diff names the new and the old key.
func TestAgentAuditDetails_SameKidNewKey(t *testing.T) {
	before := auditAgent([]string{"g"}, auditKey("prod", "OLDJKT"))
	after := auditAgent([]string{"g"}, auditKey("prod", "NEWJKT"))
	after.Revision = 2
	d := AgentAuditDetails(&before, after)
	checkDetails(t, d)
	if d["jktsAdded"] != "NEWJKT" || d["jktsRemoved"] != "OLDJKT" || d["changed"] != "keys" {
		t.Errorf("details = %v, want jkts NEWJKT added, OLDJKT removed, keys changed", d)
	}
	if _, ok := d["kidsAdded"]; ok || d["kidsAddedCount"] != "0" {
		t.Errorf("the kid did not change, details = %v", d)
	}
	if d["op"] != "update" || d["statusFrom"] != "active" || d["statusTo"] != "active" {
		t.Errorf("details = %v", d)
	}
}

func TestAgentAuditDetails_StatusChange(t *testing.T) {
	before := auditAgent([]string{"g"}, auditKey("k", "J"))
	after := before
	after.Status = agentreg.StatusDisabled
	d := AgentAuditDetails(&before, after)
	checkDetails(t, d)
	want := map[string]string{"op": "disable", "changed": "status", "statusFrom": "active", "statusTo": "disabled"}
	if fmt.Sprint(d) != fmt.Sprint(want) {
		t.Errorf("disable details = %v, want %v", d, want)
	}
	d = AgentAuditDetails(&after, before)
	if d["op"] != "enable" || d["statusFrom"] != "disabled" || d["statusTo"] != "active" {
		t.Errorf("enable details = %v", d)
	}
}

// Many long names that sort first cannot hide the real addition: the count and
// the digest of the full list prove it.
func TestAgentAuditDetails_PaddingCannotHideAnAddition(t *testing.T) {
	var groups []string
	for i := range 40 {
		groups = append(groups, fmt.Sprintf("aaaa-padding-group-%02d-%s", i, strings.Repeat("x", 30)))
	}
	before := auditAgent([]string{"keep"}, auditKey("k", "J"))
	after := auditAgent(append(append([]string{"keep"}, groups...), "zz-real-addition"), auditKey("k", "J"))
	d := AgentAuditDetails(&before, after)
	checkDetails(t, d)
	if d["truncated"] != "true" || d["groupsAddedCount"] != "41" {
		t.Fatalf("details = %v, want a truncated list of 41", d)
	}
	if strings.Contains(d["groupsAdded"], "zz-real-addition") {
		t.Fatal("the real addition fit in the cut list; the padding was too short for this test")
	}
	full := append(append([]string{}, groups...), "zz-real-addition")
	enc := make([]string, len(full))
	for i, g := range full {
		enc[i] = auditEscape(g)
	}
	sum := sha256.Sum256([]byte(strings.Join(enc, ",")))
	if d["groupsAddedSha256"] != hex.EncodeToString(sum[:]) {
		t.Errorf("digest = %q, want the digest of the full list including zz-real-addition", d["groupsAddedSha256"])
	}
	without := sha256.Sum256([]byte(strings.Join(enc[:40], ",")))
	if d["groupsAddedSha256"] == hex.EncodeToString(without[:]) {
		t.Error("the digest does not cover the real addition")
	}
}

func TestAgentAuditDetails_TwoMaxLengthKids(t *testing.T) {
	k1, k2 := strings.Repeat("a", 128), strings.Repeat("b", 128)
	after := auditAgent([]string{"g"}, auditKey(k1, "J1"), auditKey(k2, "J2"))
	d := AgentAuditDetails(nil, after)
	checkDetails(t, d)
	if d["kidsAddedCount"] != "2" || d["truncated"] != "true" || d["kidsAdded"] != k1 {
		t.Errorf("kids details = %v, want the first kid, count 2, truncated", d)
	}
	sum := sha256.Sum256([]byte(k1 + "," + k2))
	if d["kidsAddedSha256"] != hex.EncodeToString(sum[:]) {
		t.Errorf("kids digest = %q", d["kidsAddedSha256"])
	}
	if d["jktsAdded"] != "J1,J2" {
		t.Errorf("jkts = %q", d["jktsAdded"])
	}
}

func TestAgentAuditDetails_NamesStayDistinct(t *testing.T) {
	cases := [][]string{
		{"a,b"}, {"a", "b"}, // a comma in a name is not a separator
		{"café"}, {"cafè"}, {"caf?"}, // non-ASCII is not collapsed to ?
		{"100%"}, {"100%25"}, {"a b"}, {"a%20b"},
	}
	seen := map[string]string{}
	for _, groups := range cases {
		after := auditAgent(groups, auditKey("k", "J"))
		d := AgentAuditDetails(nil, after)
		checkDetails(t, d)
		v := d["groupsAdded"]
		if prev, dup := seen[v]; dup {
			t.Errorf("%q and %q both encode to %q", prev, groups, v)
		}
		seen[v] = fmt.Sprint(groups)
		// The encoding is reversible: decode every element and compare.
		var got []string
		for _, e := range strings.Split(v, ",") {
			dec, err := url.PathUnescape(e)
			if err != nil {
				t.Fatalf("%q does not decode: %v", e, err)
			}
			got = append(got, dec)
		}
		if len(got) != len(groups) {
			t.Errorf("groups %q decode to %q", groups, got)
		}
	}
	if d := AgentAuditDetails(nil, auditAgent([]string{"a,b"}, auditKey("k", "J"))); d["groupsAdded"] != "a%2Cb" || d["groupsAddedCount"] != "1" {
		t.Errorf("comma name = %v", d)
	}
}

// The worst case still fits an entry: every list long enough to be cut.
func TestAgentAuditDetails_WorstCaseFitsAnEntry(t *testing.T) {
	var before, after []string
	for i := range 60 {
		before = append(before, fmt.Sprintf("old-group-%02d-%s", i, strings.Repeat("o", 20)))
		after = append(after, fmt.Sprintf("new-group-%02d-%s", i, strings.Repeat("n", 20)))
	}
	b := auditAgent(before, auditKey(strings.Repeat("a", 128), "J1"), auditKey(strings.Repeat("b", 128), "J2"))
	a := auditAgent(after, auditKey(strings.Repeat("c", 128), "J3"), auditKey(strings.Repeat("d", 128), "J4"))
	d := AgentAuditDetails(&b, a)
	checkDetails(t, d)
	if len(d) > 24 {
		t.Fatalf("%d keys", len(d))
	}
}
