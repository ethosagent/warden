package policy

import "testing"

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

func TestRateBucketKeys(t *testing.T) {
	if got := RateBucketKeys("D.com.", 443); len(got) != 1 || got[0] != "d.com:443" {
		t.Fatalf("got %v", got)
	}
	if got := RateBucketKeys("d.com", 0); len(got) != 2 || got[0] != "d.com:443" || got[1] != "d.com:80" {
		t.Fatalf("got %v", got)
	}
	if got := RateBucketKeys("~^A.$", 80); got[0] != "~^A.$:80" {
		t.Fatalf("regex pattern must stay raw: %v", got)
	}
}
