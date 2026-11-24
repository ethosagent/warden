package policy

import (
	"testing"
	"time"
)

func TestParseRateLimit(t *testing.T) {
	l, w, err := ParseRateLimit("10/minute")
	if err != nil || l != 10 || w != time.Minute {
		t.Fatalf("got %d %v %v", l, w, err)
	}
	for _, bad := range []string{"", "10", "0/minute", "x/hour", "5/day"} {
		if _, _, err := ParseRateLimit(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

func TestTimeWindowHours(t *testing.T) {
	tests := []struct {
		in    string
		hours []int
	}{
		{"9-12", []int{9, 10, 11}},
		{"22-2", []int{22, 23, 0, 1}},
		{"5-5", nil},
	}
	for _, tc := range tests {
		m, err := TimeWindowHours(tc.in)
		if err != nil {
			t.Fatalf("%s: %v", tc.in, err)
		}
		var want uint32
		for _, h := range tc.hours {
			want |= 1 << uint(h)
		}
		if m != want {
			t.Errorf("%s: mask %b, want %b", tc.in, m, want)
		}
	}
	for _, bad := range []string{"", "9", "24-1", "a-b"} {
		if _, err := TimeWindowHours(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}
