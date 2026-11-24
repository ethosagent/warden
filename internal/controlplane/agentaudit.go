package controlplane

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/agentreg"
)

// The one agent registry audit vocabulary (W-P2-AREG-02). The admin API
// handlers and the offline registry CLI both record through it, so a row means
// the same whichever door the change came through.

// AgentAuditTarget is the admin audit target (and state hasher name) of the
// agent registry.
const AgentAuditTarget = "agents"

// Admin audit actions of the registry routes. The first four are the audited
// writes; list and read are the authz table's action names for the reads.
const (
	AgentActionCreate  = "agent.create"
	AgentActionUpdate  = "agent.update"
	AgentActionDisable = "agent.disable"
	AgentActionEnable  = "agent.enable"
	AgentActionList    = "agent.list"
	AgentActionRead    = "agent.read"
)

// AgentAuditRef is the admin audit target_ref of an agent.
func AgentAuditRef(id string) string { return "agent:" + id }

// AgentAuditDetails builds the audit details of one registry write: before is
// the agent as it was (nil for a create) and after the stored result. The keys
// are the closed adminaudit.Detail* set and name fields, key ids, thumbprints
// and groups; no JWK coordinate or owner value is ever in them.
//
//   - op is create, update, disable or enable; statusTo is always set and
//     statusFrom only when there was a before; changed lists the edited fields
//     (displayName, keys, allowedGroups, allowedScopes, status).
//   - Keys are diffed by RFC 7638 thumbprint (jktsAdded/jktsRemoved), so
//     swapping the key material under the same kid is visible; the key ids are
//     diffed too (kidsAdded/kidsRemoved), and so are groups.
//   - Every element is percent-encoded (nothing outside A-Za-z0-9 and -._~:
//     survives, so a comma or a non-ASCII name stays distinct) and joined with
//     a comma. A list that would not fit one 256-byte value is cut at an
//     element; the full number is always in <key>Count, and a cut list also
//     sets truncated "true" and <key>Sha256, the sha256 of the full sorted,
//     encoded, comma-joined list, so a padded list cannot hide an addition.
//   - Empty values are omitted. A create and an update always carry the six
//     counts; a status change carries no list.
func AgentAuditDetails(before *agentreg.Agent, after agentreg.Agent) map[string]string {
	d := map[string]string{
		adminaudit.DetailOp:       auditOp(before, after),
		adminaudit.DetailStatusTo: string(after.Status),
	}
	var prev agentreg.Agent
	if before != nil {
		prev = *before
		d[adminaudit.DetailStatusFrom] = string(prev.Status)
		if c := changedFields(prev, after); len(c) > 0 {
			d[adminaudit.DetailChanged] = strings.Join(c, ",")
		}
	}
	if d[adminaudit.DetailOp] == "disable" || d[adminaudit.DetailOp] == "enable" {
		return d
	}
	for _, l := range []struct {
		added, removed string
		before, after  []string
	}{
		{adminaudit.DetailKidsAdded, adminaudit.DetailKidsRemoved, agentKIDs(prev), agentKIDs(after)},
		{adminaudit.DetailJktsAdded, adminaudit.DetailJktsRemoved, agentreg.Thumbprints(prev), agentreg.Thumbprints(after)},
		{adminaudit.DetailGroupsAdded, adminaudit.DetailGroupsRemoved, prev.AllowedGroups, after.AllowedGroups},
	} {
		added, removed := setDiff(l.before, l.after)
		putList(d, l.added, added)
		putList(d, l.removed, removed)
	}
	return d
}

func auditOp(before *agentreg.Agent, after agentreg.Agent) string {
	switch {
	case before == nil:
		return "create"
	case before.Status != after.Status && after.Status == agentreg.StatusDisabled:
		return "disable"
	case before.Status != after.Status:
		return "enable"
	}
	return "update"
}

func agentKIDs(a agentreg.Agent) []string {
	out := make([]string, 0, len(a.Keys))
	for _, k := range a.Keys {
		out = append(out, k.KID)
	}
	return out
}

// setDiff returns the elements in after and not before (added) and in before
// and not after (removed), each sorted and without duplicates.
func setDiff(before, after []string) (added, removed []string) {
	in := func(set map[string]bool, v string) bool { return set[v] }
	b, a := make(map[string]bool, len(before)), make(map[string]bool, len(after))
	for _, v := range before {
		b[v] = true
	}
	for _, v := range after {
		a[v] = true
	}
	for v := range a {
		if !in(b, v) {
			added = append(added, v)
		}
	}
	for v := range b {
		if !in(a, v) {
			removed = append(removed, v)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

// changedFields names, in the API's member names, the editable fields whose
// value differs between before and after.
func changedFields(before, after agentreg.Agent) []string {
	var out []string
	if before.DisplayName != after.DisplayName {
		out = append(out, "displayName")
	}
	kidA, kidR := setDiff(agentKIDs(before), agentKIDs(after))
	jktA, jktR := setDiff(agentreg.Thumbprints(before), agentreg.Thumbprints(after))
	if len(kidA)+len(kidR)+len(jktA)+len(jktR) > 0 {
		out = append(out, "keys")
	}
	if a, r := setDiff(before.AllowedGroups, after.AllowedGroups); len(a)+len(r) > 0 {
		out = append(out, "allowedGroups")
	}
	if a, r := setDiff(before.AllowedScopes, after.AllowedScopes); len(a)+len(r) > 0 {
		out = append(out, "allowedScopes")
	}
	if before.Status != after.Status {
		out = append(out, "status")
	}
	return out
}

// putList sets key to the encoded elements that fit one detail value, with the
// count and, when it had to cut, the truncation marker and digest.
func putList(d map[string]string, key string, sorted []string) {
	d[key+adminaudit.DetailCountSuffix] = strconv.Itoa(len(sorted))
	if len(sorted) == 0 {
		return
	}
	enc := make([]string, len(sorted))
	for i, v := range sorted {
		enc[i] = auditEscape(v)
	}
	var b strings.Builder
	n := 0
	for _, e := range enc {
		add := len(e)
		if n > 0 {
			add++
		}
		if b.Len()+add > adminaudit.MaxDetailValueLen {
			break
		}
		if n > 0 {
			b.WriteByte(',')
		}
		b.WriteString(e)
		n++
	}
	if b.Len() > 0 {
		d[key] = b.String()
	}
	if n < len(enc) {
		sum := sha256.Sum256([]byte(strings.Join(enc, ",")))
		d[key+adminaudit.DetailSha256Suffix] = hex.EncodeToString(sum[:])
		d[adminaudit.DetailTruncated] = "true"
	}
}

// auditEscape percent-encodes every byte outside A-Za-z0-9 and -._~: , so the
// result is printable ASCII, contains no comma and decodes back to s.
func auditEscape(s string) string {
	const hexdigits = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '-', c == '.', c == '_', c == '~', c == ':':
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hexdigits[c>>4])
			b.WriteByte(hexdigits[c&15])
		}
	}
	return b.String()
}
