package compose

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/ethosagent/warden/test/harness"
)

// Request is one request the fake upstream recorded — its /_recorded shape.
type Request struct {
	ID     int         `json:"id"`
	Method string      `json:"method"`
	Host   string      `json:"host"`
	Path   string      `json:"path"`
	Query  string      `json:"query"`
	Proto  string      `json:"proto"`
	Header http.Header `json:"header"`
	Body   string      `json:"body"`
}

// DecodeRecorded parses the recorder's response. A recorder that DROPPED
// records is an error: the ring is sized for the scenarios, and a dropped
// record would quietly hollow out the upstream oracle — reset between
// scenarios instead.
func DecodeRecorded(body []byte) ([]Request, error) {
	var env struct {
		Records []Request `json:"records"`
		Dropped int       `json:"dropped"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("compose: decode the recorder: %v", err)
	}
	if env.Dropped > 0 {
		return nil, fmt.Errorf("compose: the recorder dropped %d record(s); reset it between scenarios", env.Dropped)
	}
	return env.Records, nil
}

// FilterRecorded keeps one host's records, mapped into the harness's
// RecordedRequest — the shape h.Upstream(host).Requests() hands to scenarios
// and to the canary sweep on this target.
func FilterRecorded(recs []Request, host string) []harness.RecordedRequest {
	var out []harness.RecordedRequest
	for _, r := range recs {
		if r.Host != host {
			continue
		}
		out = append(out, harness.RecordedRequest{
			Method: r.Method,
			Host:   r.Host,
			Path:   r.Path,
			Proto:  r.Proto,
			Header: r.Header,
			Body:   []byte(r.Body),
		})
	}
	return out
}
