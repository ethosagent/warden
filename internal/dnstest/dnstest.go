// Package dnstest provides an in-process stub DNS server for tests. It answers
// A queries from a fixed name→IP map over UDP on 127.0.0.1:0, so tests exercise
// real DNS resolution (a *net.Resolver dialing a real UDP socket) with no
// dependency on the host's resolver or the network.
package dnstest

import (
	"net"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// Server is a minimal UDP DNS server answering A queries from a fixed map.
type Server struct {
	conn *net.UDPConn
	// Queries counts the DNS questions this server has received, so a test can
	// prove a lookup actually traveled through it rather than the system resolver.
	Queries atomic.Int64
	// records maps a lowercase FQDN (no trailing dot) to its A record.
	records map[string][4]byte
}

// New starts a stub DNS server on 127.0.0.1:0 answering A queries per records
// (name → dotted-quad IPv4). A query for a name outside the map is answered
// NXDOMAIN; an AAAA query is answered NOERROR-empty (A-only stub). The server
// stops automatically via t.Cleanup.
func New(t *testing.T, records map[string]string) *Server {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("dnstest: listen: %v", err)
	}
	s := &Server{conn: conn, records: make(map[string][4]byte, len(records))}
	for name, ip := range records {
		v4 := net.ParseIP(ip).To4()
		if v4 == nil {
			_ = conn.Close()
			t.Fatalf("dnstest: record %q: %q is not an IPv4 address", name, ip)
		}
		var a [4]byte
		copy(a[:], v4)
		s.records[strings.ToLower(strings.TrimSuffix(name, "."))] = a
	}
	t.Cleanup(func() { _ = s.conn.Close() })
	go s.serve()
	return s
}

// Addr returns the 127.0.0.1:<port> address a test configures as its resolver.
func (s *Server) Addr() string { return s.conn.LocalAddr().String() }

// serve reads queries until the socket closes (via Cleanup). One goroutine
// total; each answer is one small packet, so serial handling is plenty.
func (s *Server) serve() {
	buf := make([]byte, 512) // classic UDP DNS message size cap
	for {
		n, from, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			return // socket closed
		}
		s.Queries.Add(1)
		if resp := s.respond(buf[:n]); resp != nil {
			_, _ = s.conn.WriteToUDP(resp, from)
		}
	}
}

// respond unpacks one query and packs the reply: the configured A record, an
// empty NOERROR for AAAA, or NXDOMAIN for an unknown name. Malformed packets
// are dropped (nil).
func (s *Server) respond(query []byte) []byte {
	var q dnsmessage.Message
	if err := q.Unpack(query); err != nil || len(q.Questions) == 0 {
		return nil
	}
	question := q.Questions[0]
	name := strings.ToLower(strings.TrimSuffix(question.Name.String(), "."))

	resp := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 q.ID,
			Response:           true,
			RecursionAvailable: true,
			RCode:              dnsmessage.RCodeSuccess,
		},
		Questions: q.Questions,
	}
	switch question.Type {
	case dnsmessage.TypeA:
		ip, ok := s.records[name]
		if !ok {
			resp.RCode = dnsmessage.RCodeNameError
			break
		}
		resp.Answers = []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{
				Name:  question.Name,
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
				TTL:   1,
			},
			Body: &dnsmessage.AResource{A: ip},
		}}
	case dnsmessage.TypeAAAA:
		// A-only stub: an empty success means "no AAAA", not an error.
	default:
		resp.RCode = dnsmessage.RCodeNotImplemented
	}
	b, err := resp.Pack()
	if err != nil {
		return nil
	}
	return b
}
