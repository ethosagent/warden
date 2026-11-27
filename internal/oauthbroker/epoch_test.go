package oauthbroker

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
)

type fakeBumper struct {
	err  error
	keys []string
}

func (f *fakeBumper) Bump(_ context.Context, k string) error {
	f.keys = append(f.keys, k)
	return f.err
}

type fakeCaps struct{ got string }

func (f *fakeCaps) WorkersWithoutCap(cap string) []string { f.got = cap; return []string{"w1"} }

func TestBumpGrantEpoch(t *testing.T) {
	boom := errors.New("boom")
	cases := []struct {
		name    string
		b       EpochBumper
		caps    WorkerCapsReader
		status  string
		partial bool
		workers []string
	}{
		{"ok", &fakeBumper{}, &fakeCaps{}, EpochOK, false, []string{"w1"}},
		{"failed is partial and keeps the worker list", &fakeBumper{err: boom}, &fakeCaps{}, EpochFailed, true, []string{"w1"}},
		{"no bumper is skipped and partial", nil, &fakeCaps{}, EpochSkipped, true, []string{"w1"}},
		{"a bump that published nothing is skipped and partial", &fakeBumper{err: fmt.Errorf("off: %w", ErrEpochSkipped)}, &fakeCaps{}, EpochSkipped, true, []string{"w1"}},
		{"no caps reader", &fakeBumper{}, nil, EpochOK, false, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := BumpGrantEpoch(context.Background(), c.b, c.caps, "usersecrets/v1", "userkey")
			if out.Status != c.status || out.Partial() != c.partial || !slices.Equal(out.WorkersWithoutCap, c.workers) {
				t.Errorf("outcome = %+v", out)
			}
			if c.name == "failed is partial and keeps the worker list" && !errors.Is(out.Err, boom) {
				t.Errorf("error = %v, want boom", out.Err)
			}
			if fb, ok := c.b.(*fakeBumper); ok && !slices.Equal(fb.keys, []string{"userkey"}) {
				t.Errorf("bumped %v", fb.keys)
			}
			if fc, ok := c.caps.(*fakeCaps); ok && fc.got != "usersecrets/v1" {
				t.Errorf("asked for cap %q", fc.got)
			}
		})
	}
}
