package identityclient

import (
	"errors"
	"strings"
	"testing"
)

func TestParseRunAs(t *testing.T) {
	good, err := ParseRunAs("1000:2000")
	if err != nil || good != (RunAs{UID: 1000, GID: 2000}) {
		t.Fatalf("ParseRunAs = %+v, %v", good, err)
	}
	for _, spec := range []string{
		"", "1000", ":", "1000:", ":2000", "1000:2000:3", "a:1", "1:b", "-1:5", "5:-1", "+5:5", "0x10:5", " 5:5",
		"0:5", "5:0", "00:5", "4294967295:5", "5:4294967295", "4294967296:5", "99999999999999999999:5",
	} {
		if r, err := ParseRunAs(spec); err == nil {
			t.Errorf("ParseRunAs(%q) = %+v, want an error", spec, r)
		}
	}
	if r, err := ParseRunAs("4294967294:4294967294"); err != nil || r.UID != 4294967294 {
		t.Errorf("the largest valid id: %+v, %v", r, err)
	}
}

func TestResolveRunAsNeedsRoot(t *testing.T) {
	if !RunAsSupported {
		if _, err := ResolveRunAs("1:1", func() int { return 0 }); err == nil || !strings.Contains(err.Error(), "Linux only") {
			t.Fatalf("err = %v, want Linux only", err)
		}
		return
	}
	for _, euid := range []int{1000, 1, -1} {
		if _, err := ResolveRunAs("65534:65534", func() int { return euid }); !errors.Is(err, ErrRunAsNotRoot) {
			t.Errorf("euid %d: err = %v, want ErrRunAsNotRoot", euid, err)
		}
	}
	// A bad spec is reported even for root, and before the root check for
	// non-root, so the message always names the real problem first.
	if _, err := ResolveRunAs("0:0", func() int { return 0 }); err == nil || errors.Is(err, ErrRunAsNotRoot) {
		t.Errorf("0:0 as root: err = %v, want the uid 0 refusal", err)
	}
	r, err := ResolveRunAs("65534:65533", func() int { return 0 })
	if err != nil || r != (RunAs{UID: 65534, GID: 65533}) {
		t.Fatalf("root: %+v, %v", r, err)
	}
}

func TestBuildChildEnvOmit(t *testing.T) {
	parent := map[string]string{"PATH": "/bin", "HOME": "/root", "USER": "root", "LOGNAME": "root", "SHELL": "/bin/sh", "TERM": "xterm"}
	lookup := func(k string) (string, bool) { v, ok := parent[k]; return v, ok }
	env, _, err := BuildChildEnv(lookup, "http://wx:c@127.0.0.1:1", ChildEnvOptions{Omit: RunAsOmittedEnv, Passthrough: []string{"HOME", "HOME"}})
	if err != nil {
		t.Fatal(err)
	}
	joined := "\n" + strings.Join(env, "\n") + "\n"
	for _, gone := range []string{"\nUSER=", "\nLOGNAME=", "\nSHELL="} {
		if strings.Contains(joined, gone) {
			t.Errorf("env holds %q despite Omit", gone)
		}
	}
	for _, want := range []string{"\nPATH=/bin\n", "\nTERM=xterm\n"} {
		if !strings.Contains(joined, want) {
			t.Errorf("env lacks %q", want)
		}
	}
	// --env HOME still passes it, once.
	if strings.Count(joined, "\nHOME=/root\n") != 1 {
		t.Errorf("HOME passed by name should appear once:\n%s", joined)
	}
}
