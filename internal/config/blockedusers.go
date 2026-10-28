package config

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode"
)

// Limits on the user block list. MaxBlockedUsersBytes is half of the worker's
// 1 MiB maxPolicyBytes (remote.go) so the rest of the policy always fits next
// to a full list; it, not the count, is the real bound (5000 maximum-length
// entries would be about 2.5 MB).
const (
	MaxBlockedUsers      = 5000
	MaxBlockedUsersBytes = 512 << 10

	maxBlockedSubBytes   = 255
	maxBlockedEmailBytes = 254
)

// BlockedUser is one entry of the admin user block list: an IdP subject, an email,
// or both. Workers deny any request or session whose identity claims match.
// Only these two fields ride the policy wire; reason and actor stay on the CP.
type BlockedUser struct {
	Sub   string `yaml:"sub" json:"sub,omitempty"`
	Email string `yaml:"email" json:"email,omitempty"`
}

// normalizeBlockedUsers trims spaces, lowercases emails, drops duplicates and
// sorts by (sub, email). An empty result is nil so the wire key stays absent.
// Entries with neither field are kept (not dropped) for ValidateBlockedUsers
// to reject; its indexes refer to this normalized order.
func normalizeBlockedUsers(in []BlockedUser) []BlockedUser {
	if len(in) == 0 {
		return nil
	}
	out := make([]BlockedUser, 0, len(in))
	seen := make(map[BlockedUser]struct{}, len(in))
	for _, u := range in {
		u.Sub = strings.TrimSpace(u.Sub)
		u.Email = strings.ToLower(strings.TrimSpace(u.Email))
		if _, dup := seen[u]; dup {
			continue
		}
		seen[u] = struct{}{}
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Sub != out[j].Sub {
			return out[i].Sub < out[j].Sub
		}
		return out[i].Email < out[j].Email
	})
	return out
}

// ValidateBlockedUsers checks a (normalized) block list. The control plane
// calls it too, so it can refuse any entry a worker would reject and a bad row
// can never freeze policy updates across the fleet. Errors name the entry
// index or the total size, never an entry value.
func ValidateBlockedUsers(list []BlockedUser) error {
	if len(list) > MaxBlockedUsers {
		return fmt.Errorf("config: policy.blockedUsers: %d entries exceeds the limit of %d", len(list), MaxBlockedUsers)
	}
	for i, u := range list {
		if strings.TrimSpace(u.Sub) == "" && strings.TrimSpace(u.Email) == "" {
			return fmt.Errorf("config: policy.blockedUsers[%d]: sub or email is required", i)
		}
		if len(u.Sub) > maxBlockedSubBytes {
			return fmt.Errorf("config: policy.blockedUsers[%d]: sub exceeds %d bytes", i, maxBlockedSubBytes)
		}
		if len(u.Email) > maxBlockedEmailBytes {
			return fmt.Errorf("config: policy.blockedUsers[%d]: email exceeds %d bytes", i, maxBlockedEmailBytes)
		}
		if u.Email != "" && !strings.Contains(u.Email, "@") {
			return fmt.Errorf("config: policy.blockedUsers[%d]: email must contain '@'", i)
		}
		if hasControlRune(u.Sub) || hasControlRune(u.Email) {
			return fmt.Errorf("config: policy.blockedUsers[%d]: control character not allowed", i)
		}
	}
	if len(list) > 0 {
		b, err := json.Marshal(list)
		if err != nil {
			return fmt.Errorf("config: policy.blockedUsers: encode: %w", err)
		}
		if len(b) > MaxBlockedUsersBytes {
			return fmt.Errorf("config: policy.blockedUsers: total size %d bytes exceeds the limit of %d", len(b), MaxBlockedUsersBytes)
		}
	}
	return nil
}

func hasControlRune(s string) bool {
	return strings.IndexFunc(s, unicode.IsControl) >= 0
}
