package main

import (
	"context"
	"encoding/binary"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRangeSetAndCNAME(t *testing.T) {
	rs := &RangeSet{}
	rs.addStrings(embeddedFastlyCIDRs)

	if !rs.Contains(netip.MustParseAddr("151.101.1.140")) {
		t.Fatal("expected 151.101.1.140 to be in Fastly ranges")
	}
	if !rs.Contains(netip.MustParseAddr("2a04:4e42::140")) {
		t.Fatal("expected 2a04:4e42::140 to be in Fastly IPv6 ranges")
	}
	if rs.Contains(netip.MustParseAddr("1.1.1.1")) {
		t.Fatal("did not expect 1.1.1.1 in Fastly ranges")
	}

	cases := map[string]bool{
		"dualstack.g.shared.global.fastly.net.": true,
		"media.amazon.map.fastly.net":           true,
		"foo.fastlylb.net.":                     true,
		"notfastly.net":                         false,
		"evilfastly.net":                        false,
	}
	for host, want := range cases {
		if got := IsFastlyCNAME(host); got != want {
			t.Fatalf("IsFastlyCNAME(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestLoadRangesFromFile(t *testing.T) {
	dir := t.TempDir()
	txtPath := filepath.Join(dir, "cidrs.txt")
	if err := os.WriteFile(txtPath, []byte("# comment\n151.101.0.0/16\n2a04:4e40::/32\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rs, err := loadRangesFromFile(txtPath)
	if err != nil {
		t.Fatal(err)
	}
	v4, v6 := rs.Count()
	if v4 != 1 || v6 != 1 {
		t.Fatalf("got %d v4, %d v6; want 1, 1", v4, v6)
	}

	jsonPath := filepath.Join(dir, "fastly.json")
	if err := os.WriteFile(jsonPath, []byte(`{"addresses":["23.235.32.0/20"],"ipv6_addresses":["2a04:4e42::/32"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	rsJSON, err := loadRangesFromFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	if !rsJSON.Contains(netip.MustParseAddr("23.235.33.1")) {
		t.Fatal("expected 23.235.33.1 in JSON-loaded ranges")
	}
}

func TestDNSWireBuildAndParse(t *testing.T) {
	id, q, err := buildDNSQuery("www.example.com", dnsTypeA)
	if err != nil {
		t.Fatal(err)
	}
	if len(q) < 12 {
		t.Fatalf("query too short: %d", len(q))
	}

	// Build synthetic response: Answer 1 = CNAME -> a.sni.global.fastly.net, Answer 2 = A -> 151.101.1.140
	var resp []byte
	resp = append(resp, q[:2]...)                  // ID
	resp = append(resp, 0x81, 0x80)                // QR=1, RD=1, RA=1, RCODE=0
	resp = append(resp, 0x00, 0x01)                // QDCOUNT=1
	resp = append(resp, 0x00, 0x02)                // ANCOUNT=2
	resp = append(resp, 0x00, 0x00, 0x00, 0x00)    // NSCOUNT=0, ARCOUNT=0
	resp = append(resp, q[12:]...)                 // Question section

	// Answer 1: compressed name pointer to offset 12 (0xC00C), type CNAME (5), class IN (1), TTL 60
	cnameWire := encodeWireLabels("a.sni.global.fastly.net")
	resp = append(resp, 0xC0, 0x0C)
	resp = binary.BigEndian.AppendUint16(resp, dnsTypeCNAME)
	resp = binary.BigEndian.AppendUint16(resp, dnsClassIN)
	resp = binary.BigEndian.AppendUint32(resp, 60)
	resp = binary.BigEndian.AppendUint16(resp, uint16(len(cnameWire)))
	cnameOffset := len(resp)
	resp = append(resp, cnameWire...)

	// Answer 2: compressed name pointer to cnameOffset, type A (1), class IN (1), TTL 60, 151.101.1.140
	ptr := uint16(0xC000 | cnameOffset)
	resp = binary.BigEndian.AppendUint16(resp, ptr)
	resp = binary.BigEndian.AppendUint16(resp, dnsTypeA)
	resp = binary.BigEndian.AppendUint16(resp, dnsClassIN)
	resp = binary.BigEndian.AppendUint32(resp, 60)
	resp = binary.BigEndian.AppendUint16(resp, 4)
	resp = append(resp, 151, 101, 1, 140)

	cnames, ips, err := parseDNSResponse(resp, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(cnames) != 1 || cnames[0] != "a.sni.global.fastly.net" {
		t.Fatalf("unexpected cnames: %+v", cnames)
	}
	if len(ips) != 1 || ips[0].String() != "151.101.1.140" {
		t.Fatalf("unexpected ips: %+v", ips)
	}
}

func encodeWireLabels(host string) []byte {
	var out []byte
	for _, lbl := range strings.Split(host, ".") {
		out = append(out, byte(len(lbl)))
		out = append(out, lbl...)
	}
	out = append(out, 0)
	return out
}

func TestNormalizeAndCSVSeeds(t *testing.T) {
	if got := NormalizeHost("  *.CDN.Example.COM:443/path "); got != "cdn.example.com" {
		t.Fatalf("got %q", got)
	}
	if got := NormalizeHost("bad host"); got != "" {
		t.Fatalf("expected empty for invalid host, got %q", got)
	}

	csvData := "1,example.com\n2,reddit.com\n3,www.already.org\n"
	store := newCandidateStore()
	n := parseCSVHosts(strings.NewReader(csvData), 1, false, 2, "tranco", true, store)
	if n != 2 {
		t.Fatalf("expected 2 seed rows parsed, got %d", n)
	}
	list := store.sortedList()
	if len(list) != 4 {
		t.Fatalf("expected 4 hosts with www expansion, got %d: %+v", len(list), list)
	}
}

func TestProbeAndClassification(t *testing.T) {
	// Mock Fastly edge server answering with X-Served-By / Fastly-Debug-Path.
	srvConfirmed := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Fastly-Debug") == "1" {
			w.Header().Set("Fastly-Debug-Path", "(D cache-fra-eddf8230099-FRA 1700000000)")
		}
		w.Header().Set("X-Served-By", "cache-fra-eddf8230099-FRA")
		w.Header().Set("X-Cache", "HIT")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srvConfirmed.Close()

	u, err := url.Parse(srvConfirmed.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, port, _ := net.SplitHostPort(u.Host)
	if host == "" || port == "" {
		t.Fatal("bad test server host/port")
	}

	// Test directFastlyHTTPProbe directly against httptest TLS server.
	out := doFastlyHTTPProbe(context.Background(), srvConfirmed.Client(), srvConfirmed.URL, "example.com")
	if !out.hasFastlyHdr || out.unknownDomain {
		t.Fatalf("expected Fastly headers and no unknownDomain, got %+v", out)
	}

	// Test unknown domain detection.
	srvUnknown := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("<html><title>Fastly error: unknown domain: foo.example.com</title></html>"))
	}))
	defer srvUnknown.Close()

	outUnk := doFastlyHTTPProbe(context.Background(), srvUnknown.Client(), srvUnknown.URL, "foo.example.com")
	if !outUnk.unknownDomain {
		t.Fatal("expected unknownDomain=true")
	}
	if cls := classifyFinding(true, httpProbeOutcome{}, outUnk); cls != "unknown_domain" {
		t.Fatalf("expected unknown_domain, got %q", cls)
	}
	if cls := classifyFinding(false, httpProbeOutcome{statusCode: 200}, outUnk); cls != "not_fastly" {
		t.Fatalf("expected not_fastly when DNS is off-Fastly, got %q", cls)
	}
	if cls := classifyFinding(true, httpProbeOutcome{statusCode: 200}, httpProbeOutcome{statusCode: 200}); cls != "fastly_dns_headers_hidden" {
		t.Fatalf("expected fastly_dns_headers_hidden, got %q", cls)
	}
	if cls := classifyFinding(true, out, httpProbeOutcome{}); cls != "confirmed" {
		t.Fatalf("expected confirmed, got %q", cls)
	}
}

func TestPGHelpers(t *testing.T) {
	if got := sanitizeTSQueryDomain("sub.Example-1.COM; DROP TABLE"); got != "sub.example-1.comdroptable" {
		t.Fatalf("unexpected sanitized tsquery: %q", got)
	}
	// DataRow: 2 cols -> "a.example.com", NULL (-1)
	var payload []byte
	payload = binary.BigEndian.AppendUint16(payload, 2)
	payload = binary.BigEndian.AppendUint32(payload, 13)
	payload = append(payload, []byte("a.example.com")...)
	payload = binary.BigEndian.AppendUint32(payload, 0xFFFFFFFF)
	row, err := pgParseDataRow(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(row) != 2 || row[0] != "a.example.com" || row[1] != "" {
		t.Fatalf("unexpected DataRow parse: %+v", row)
	}
	_ = time.Second
}
