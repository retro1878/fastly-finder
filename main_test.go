package main

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"
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

	// Test doFastlyHTTPProbe directly against httptest TLS server.
	out := doFastlyHTTPProbe(context.Background(), srvConfirmed.Client(), srvConfirmed.URL, "example.com")
	if !out.hasFastlyHdr || out.unknownDomain {
		t.Fatalf("expected Fastly headers and no unknownDomain, got %+v", out)
	}

	// Test unknown domain detection (even when Fastly attaches X-Served-By).
	srvUnknown := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Served-By", "cache-fra-eddf8230171-FRA")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("<html><title>Fastly error: unknown domain: foo.example.com</title></html>"))
	}))
	defer srvUnknown.Close()

	outUnk := doFastlyHTTPProbe(context.Background(), srvUnknown.Client(), srvUnknown.URL, "foo.example.com")
	if !outUnk.unknownDomain || outUnk.hasFastlyHdr {
		t.Fatalf("expected unknownDomain=true and hasFastlyHdr=false, got %+v", outUnk)
	}
	if cls := classifyFinding(true, httpProbeOutcome{}, outUnk); cls != "unknown_domain" {
		t.Fatalf("expected unknown_domain, got %q", cls)
	}
	if cls := classifyFinding(false, httpProbeOutcome{statusCode: 200}, outUnk); cls != "not_fastly" {
		t.Fatalf("expected not_fastly when DNS is off-Fastly, got %q", cls)
	}
	// HTTPS 421 Misdirected Request with X-Served-By and !certMatch must not confirm Fastly.
	srv421 := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Served-By", "cache-fra-eddf8230135")
		w.WriteHeader(http.StatusMisdirectedRequest)
		_, _ = w.Write([]byte("Requested host does not match any Subject Alternative Names"))
	}))
	defer srv421.Close()
	out421 := doFastlyHTTPProbe(context.Background(), srv421.Client(), srv421.URL, "not-fastly.invalid")
	if out421.hasFastlyHdr || out421.certMatch {
		t.Fatalf("expected 421 without certMatch to clear hasFastlyHdr, got %+v", out421)
	}
	if cls := classifyFinding(false, httpProbeOutcome{statusCode: 200}, out421); cls != "not_fastly" {
		t.Fatalf("expected not_fastly for off-DNS 421, got %q", cls)
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
}

func TestParseCTEntryCert(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	parent := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Certainly Intermediate R1", Organization: []string{"Certainly"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "app.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"app.example.com", "cdn.example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	// Build x509_entry (entry_type = 0) MerkleTreeLeaf
	leaf := make([]byte, 12)                   // version=0, leaf_type=0, zeroed timestamp
	binary.BigEndian.PutUint16(leaf[10:12], 0) // entry_type=0
	leaf = append(leaf, byte(len(der)>>16), byte(len(der)>>8), byte(len(der)))
	leaf = append(leaf, der...)

	cert, err := parseCTEntryCert(base64.StdEncoding.EncodeToString(leaf), "")
	if err != nil {
		t.Fatal(err)
	}
	if !isFastlyCTCert(cert) {
		t.Fatal("expected Certainly cert to match isFastlyCTCert")
	}
	if len(cert.DNSNames) != 2 || cert.DNSNames[0] != "app.example.com" {
		t.Fatalf("unexpected SANs: %+v", cert.DNSNames)
	}
}

func TestCruxAndChaosParsers(t *testing.T) {
	// CrUX gzip CSV
	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	_, _ = gw.Write([]byte("origin,rank\nhttps://www.fastly.com,1000\nhttps://docs.example.com,10000\n"))
	_ = gw.Close()

	cruxStore := newCandidateStore()
	n, err := parseCruxGzip(&gzBuf, 0, cruxStore)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 || len(cruxStore.sortedList()) != 2 {
		t.Fatalf("expected 2 crux hosts, got n=%d list=%+v", n, cruxStore.sortedList())
	}

	// Chaos zip
	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)
	w, err := zw.Create("example.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("cdn.example.com\nstatic.example.com\n"))
	_ = zw.Close()

	chaosStore := newCandidateStore()
	added := parseChaosZip(zipBuf.Bytes(), 10, chaosStore)
	if added != 2 || len(chaosStore.sortedList()) != 2 {
		t.Fatalf("expected 2 chaos hosts, got added=%d list=%+v", added, chaosStore.sortedList())
	}
}

func TestWriteFindingsTableAndAutoFormat(t *testing.T) {
	if got := resolveOutputFormat("auto", "", true); got != "table" {
		t.Fatalf("expected table on TTY, got %q", got)
	}
	if got := resolveOutputFormat("auto", "", false); got != "jsonl" {
		t.Fatalf("expected jsonl on pipe, got %q", got)
	}
	if got := resolveOutputFormat("auto", "out.csv", true); got != "csv" {
		t.Fatalf("expected csv from .csv extension, got %q", got)
	}
	if got := resolveOutputFormat("txt", "out.csv", true); got != "txt" {
		t.Fatalf("explicit --format should override extension, got %q", got)
	}

	var buf bytes.Buffer
	err := writeFindings(&buf, "table", []Finding{{
		Host:             "www.example.com",
		Status:           "confirmed",
		HTTPStatus:       200,
		EdgeSNICertMatch: true,
		FastlyIPs:        []string{"151.101.1.140"},
		FastlyCNAMEs:     []string{"j.sni.global.fastly.net"},
		FastlyHeaders:    map[string]string{"X-Served-By": "cache-ams-eham8680059-AMS"},
		TLSIssuer:        "Certainly Intermediate R1",
		Sources:          []string{"ct-log"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "HOST") || !strings.Contains(out, "www.example.com") || !strings.Contains(out, "confirmed") {
		t.Fatalf("unexpected table output:\n%s", out)
	}
}

func TestWebAuthTLSAndSandbox(t *testing.T) {
	// 1. Credentials resolution
	u, p, gen, err := resolveWebCredentials("ops:s3cr3t")
	if err != nil || u != "ops" || p != "s3cr3t" || gen {
		t.Fatalf("unexpected explicit creds: %q %q %v err=%v", u, p, gen, err)
	}
	u, p, gen, err = resolveWebCredentials("onlypass")
	if err != nil || u != "admin" || p != "onlypass" || gen {
		t.Fatalf("unexpected pass-only creds: %q %q %v err=%v", u, p, gen, err)
	}
	for _, badCred := range []string{"admin:", ":pass"} {
		if _, _, _, cerr := resolveWebCredentials(badCred); cerr == nil {
			t.Fatalf("expected error for malformed auth %q", badCred)
		}
	}
	t.Setenv("FASTLY_FINDER_WEB_AUTH", "envu:envp")
	u, p, gen, err = resolveWebCredentials("")
	if err != nil || u != "envu" || p != "envp" || gen {
		t.Fatalf("expected env creds, got %q %q %v err=%v", u, p, gen, err)
	}
	t.Setenv("FASTLY_FINDER_WEB_AUTH", "")
	u, p, gen, err = resolveWebCredentials("")
	if err != nil || u != "admin" || p == "" || !gen {
		t.Fatalf("expected generated creds, got %q %q %v err=%v", u, p, gen, err)
	}

	// 2. Scan filename sandbox
	dir := t.TempDir()
	for _, bad := range []string{"", "../etc.jsonl", "sub/a.jsonl", "a.txt", ".."} {
		if _, err := sanitizeScanFilename(dir, bad); err == nil {
			t.Fatalf("expected error for %q", bad)
		}
	}
	good, err := sanitizeScanFilename(dir, "scan_2026_test.jsonl")
	if err != nil || good != filepath.Join(dir, "scan_2026_test.jsonl") {
		t.Fatalf("expected valid path, got %q err=%v", good, err)
	}

	// 3. Login rate limiter
	lim := newLoginLimiter()
	ip := "1.2.3.4"
	for i := 0; i < 5; i++ {
		if !lim.allow(ip) {
			t.Fatalf("expected allow before 5th failure (i=%d)", i)
		}
		lim.recordFailure(ip)
	}
	if lim.allow(ip) {
		t.Fatalf("expected rate limit after 5 failures")
	}
	lim.reset(ip)
	if !lim.allow(ip) {
		t.Fatalf("expected allow after reset")
	}

	// 4. Self-signed ECDSA cert generation & reloader
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	cert1, err := loadOrCreateSelfSigned(certPath, keyPath)
	if err != nil || len(cert1.Certificate) == 0 {
		t.Fatalf("loadOrCreateSelfSigned failed: %v", err)
	}
	reloader, err := newCertReloader(certPath, keyPath)
	if err != nil {
		t.Fatalf("newCertReloader failed: %v", err)
	}
	if gotCert, gerr := reloader.getCertificate(nil); gerr != nil || gotCert == nil {
		t.Fatalf("getCertificate failed: %v", gerr)
	}

	// 5. Auth + CSRF + Export HTTP handlers
	ws := &webServer{
		opts:     WebOptions{WebDir: dir},
		authUser: "admin",
		authPass: "topsecret",
		hmacKey:  []byte("0123456789abcdef0123456789abcdef"),
		limiter:  newLoginLimiter(),
		state:    "idle",
		counts:   make(map[string]int),
		findings: []Finding{{Host: "cdn.example.com", Status: "confirmed", Sources: []string{"ct-log"}}},
	}

	// Unauthenticated /api/me -> 401
	req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	rec := httptest.NewRecorder()
	ws.handleMe(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauth /api/me, got %d", rec.Code)
	}

	// Valid login -> sets HttpOnly Secure SameSite=Strict cookie
	loginReq := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"user":"admin","pass":"topsecret"}`))
	loginReq.RemoteAddr = "127.0.0.1:50000"
	loginRec := httptest.NewRecorder()
	ws.handleLogin(loginRec, loginReq)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("expected 200 on login, got %d (%s)", loginRec.Code, loginRec.Body.String())
	}
	cookies := loginRec.Result().Cookies()
	if len(cookies) == 0 || cookies[0].Name != "ff_session" || !cookies[0].HttpOnly || !cookies[0].Secure {
		t.Fatalf("expected secure HttpOnly ff_session cookie, got %+v", cookies)
	}
	sessCookie := cookies[0]

	// Tampered cookie rejected
	tampered := &http.Cookie{Name: "ff_session", Value: sessCookie.Value + "00"}
	if ws.verifySession(tampered.Value) {
		t.Fatalf("tampered session token should fail verification")
	}

	// Authenticated /api/me -> 200
	meReq := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	meReq.AddCookie(sessCookie)
	meRec := httptest.NewRecorder()
	ws.handleMe(meRec, meReq)
	if meRec.Code != http.StatusOK {
		t.Fatalf("expected 200 for auth /api/me, got %d", meRec.Code)
	}

	// CSRF guard blocks missing X-Requested-With on POST action
	csrfHandler := ws.requireAuth(ws.requireCSRF(ws.handleScanCancel))
	noCSRFReq := httptest.NewRequest(http.MethodPost, "/api/scan/cancel", nil)
	noCSRFReq.AddCookie(sessCookie)
	noCSRFRec := httptest.NewRecorder()
	csrfHandler(noCSRFRec, noCSRFReq)
	if noCSRFRec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 without CSRF header, got %d", noCSRFRec.Code)
	}

	withCSRFReq := httptest.NewRequest(http.MethodPost, "/api/scan/cancel", nil)
	withCSRFReq.AddCookie(sessCookie)
	withCSRFReq.Header.Set("X-Requested-With", "fastly-finder")
	withCSRFRec := httptest.NewRecorder()
	csrfHandler(withCSRFRec, withCSRFReq)
	if withCSRFRec.Code != http.StatusOK {
		t.Fatalf("expected 200 with CSRF header, got %d", withCSRFRec.Code)
	}

	// Export CSV
	expReq := httptest.NewRequest(http.MethodGet, "/api/export?format=csv", nil)
	expReq.AddCookie(sessCookie)
	expRec := httptest.NewRecorder()
	ws.requireAuth(ws.handleExport)(expRec, expReq)
	if expRec.Code != http.StatusOK || !strings.Contains(expRec.Body.String(), "cdn.example.com") {
		t.Fatalf("unexpected export response %d: %s", expRec.Code, expRec.Body.String())
	}

	// Embedded bilingual Persian-default + tooltip UI
	idxReq := httptest.NewRequest(http.MethodGet, "/", nil)
	idxRec := httptest.NewRecorder()
	ws.handleIndex(idxRec, idxReq)
	body := idxRec.Body.String()
	if idxRec.Code != http.StatusOK || !strings.Contains(body, `lang="fa" dir="rtl"`) || !strings.Contains(body, "hoverTip") || !strings.Contains(body, "tip_with_www") {
		t.Fatalf("embedded UI missing expected bilingual/tooltip markup (status=%d)", idxRec.Code)
	}

	// Logout rotates key and invalidates prior session cookie
	logoutReq := httptest.NewRequest(http.MethodPost, "/api/logout", nil)
	logoutReq.AddCookie(sessCookie)
	logoutReq.Header.Set("X-Requested-With", "fastly-finder")
	logoutRec := httptest.NewRecorder()
	ws.requireAuth(ws.requireCSRF(ws.handleLogout))(logoutRec, logoutReq)
	if logoutRec.Code != http.StatusOK {
		t.Fatalf("expected 200 on logout, got %d", logoutRec.Code)
	}
	if ws.verifySession(sessCookie.Value) {
		t.Fatal("expected old session cookie to be invalidated after logout")
	}

	// Partial TLS cert/key flags must fail instead of silently falling back
	if _, _, err := buildWebTLSConfig(certPath, "", dir); err == nil {
		t.Fatal("expected error when only certFile is provided")
	}

	// Global scan without seeds must return 400
	emptySeedReq := httptest.NewRequest(http.MethodPost, "/api/scan/start", strings.NewReader(`{"global":true,"seeds":[]}`))
	emptySeedRec := httptest.NewRecorder()
	ws.handleScanStart(emptySeedRec, emptySeedReq)
	if emptySeedRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for global scan with empty seeds, got %d", emptySeedRec.Code)
	}

	// saveScanJSONL sanitizes ".." in domain tag so sanitizeScanFilename accepts it
	savedName, err := saveScanJSONL(dir, ScanConfig{Domains: []string{"a..b.example.com"}}, ws.findings)
	if err != nil {
		t.Fatalf("saveScanJSONL failed: %v", err)
	}
	if _, err := sanitizeScanFilename(dir, savedName); err != nil {
		t.Fatalf("saved filename %q rejected by sanitizeScanFilename: %v", savedName, err)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestRegressionGuardsAndEdgeCases(t *testing.T) {
	// 1. SSRF public-unicast IP check
	for _, bad := range []string{"127.0.0.1", "169.254.169.254", "10.0.0.1", "192.168.1.1", "::1", "fc00::1", "bad"} {
		if isPublicUnicastIP(bad) {
			t.Fatalf("expected %q to be rejected by isPublicUnicastIP", bad)
		}
	}
	if !isPublicUnicastIP("151.101.1.140") {
		t.Fatal("expected 151.101.1.140 to pass isPublicUnicastIP")
	}

	// 2. Wire DNS NXDOMAIN (RCODE=3) keeps dangling CNAME
	id, q, err := buildDNSQuery("dangling.example.com", dnsTypeA)
	if err != nil {
		t.Fatal(err)
	}
	var nxResp []byte
	nxResp = append(nxResp, q[:2]...)
	nxResp = append(nxResp, 0x81, 0x83) // QR=1, RD=1, RA=1, RCODE=3 (NXDOMAIN)
	nxResp = append(nxResp, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00)
	nxResp = append(nxResp, q[12:]...)
	cnameWire := encodeWireLabels("dead.sni.global.fastly.net")
	nxResp = append(nxResp, 0xC0, 0x0C)
	nxResp = binary.BigEndian.AppendUint16(nxResp, dnsTypeCNAME)
	nxResp = binary.BigEndian.AppendUint16(nxResp, dnsClassIN)
	nxResp = binary.BigEndian.AppendUint32(nxResp, 60)
	nxResp = binary.BigEndian.AppendUint16(nxResp, uint16(len(cnameWire)))
	nxResp = append(nxResp, cnameWire...)
	cnames, ips, err := parseDNSResponse(nxResp, id)
	if err != nil || len(cnames) != 1 || cnames[0] != "dead.sni.global.fastly.net" || len(ips) != 0 {
		t.Fatalf("unexpected NXDOMAIN CNAME parse: cnames=%v ips=%v err=%v", cnames, ips, err)
	}

	// 3. DoH checks Status != 0 && != 3, and resolveOne sorts IPv4 before IPv6
	dohSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("name") {
		case "servfail.example.com":
			_, _ = io.WriteString(w, `{"Status":2}`)
		default:
			_, _ = io.WriteString(w, `{"Status":0,"Answer":[{"type":28,"data":"2a04:4e42::140"},{"type":1,"data":"151.101.1.140"}]}`)
		}
	}))
	defer dohSrv.Close()
	if _, _, derr := queryDoH(context.Background(), dohSrv.Client(), dohSrv.URL, "servfail.example.com", dnsTypeA, time.Second); derr == nil {
		t.Fatal("expected error for DoH Status=2")
	}
	rs := &RangeSet{}
	rs.addStrings(embeddedFastlyCIDRs)
	var rr atomic.Uint64
	dr := resolveOne(context.Background(), "dual.example.com", rs, DNSOptions{UseDoH: true, DoHURL: dohSrv.URL, QueryAAAA: true, Timeout: time.Second}, dohSrv.Client(), &rr)
	if len(dr.FastlyIPs) != 2 || dr.FastlyIPs[0] != "151.101.1.140" {
		t.Fatalf("expected IPv4 sorted before IPv6, got %+v", dr.FastlyIPs)
	}

	// 4. Cancelled ResolveAll / VerifyHosts emit no empty host records
	cCtx, cCancel := context.WithCancel(context.Background())
	cCancel()
	if got := ResolveAll(cCtx, []string{"a.example.com", "b.example.com"}, rs, DNSOptions{Workers: 2}, dohSrv.Client(), nil); len(got) != 0 {
		t.Fatalf("expected 0 records on pre-cancelled ResolveAll, got %+v", got)
	}
	if got := VerifyHosts(cCtx, []Candidate{{Host: "a.example.com"}}, []DNSResult{{Host: "a.example.com", OnFastlyDNS: true}}, ProbeOptions{Workers: 1}, nil); len(got) != 0 {
		t.Fatalf("expected 0 records on pre-cancelled VerifyHosts, got %+v", got)
	}

	// 5. Host normalization, Chaos URL validation, httpGetBytes limit, atomic write
	for _, bad := range []string{"a..b.com", "-bad.com", "bad-.com", "151.101.1.140", strings.Repeat("a", 64) + ".com"} {
		if got := NormalizeHost(bad); got != "" {
			t.Fatalf("NormalizeHost(%q) = %q, want empty", bad, got)
		}
	}
	if isAllowedChaosURL("http://chaos-data.projectdiscovery.io/a.zip") || isAllowedChaosURL("https://127.0.0.1/a.zip") {
		t.Fatal("expected disallowed Chaos URL to be rejected")
	}
	if !isAllowedChaosURL("https://chaos-data.projectdiscovery.io/a.zip") {
		t.Fatal("expected official Chaos HTTPS URL to be allowed")
	}
	bigSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "0123456789abcdef")
	}))
	defer bigSrv.Close()
	if _, err := httpGetBytes(context.Background(), bigSrv.Client(), bigSrv.URL, 8); err == nil {
		t.Fatal("expected httpGetBytes to fail when response exceeds maxBytes")
	}
	atomicPath := filepath.Join(t.TempDir(), "sub", "cache.json")
	if err := writeFileAtomic(atomicPath, []byte(`{"ok":true}`), 0o644); err != nil {
		t.Fatalf("writeFileAtomic failed: %v", err)
	}

	// 6. writeFindings error propagation, CSV escaping, UTF-8 truncateStr
	sample := []Finding{{
		Host:          "www.example.com",
		Status:        "confirmed",
		FastlyHeaders: map[string]string{"X-Served-By": "=cmd|' /C calc'!A0"},
		TLSIssuer:     "ایران‌سرت-آزمایش-طولانی-برای-تست-یوتی‌اف۸",
	}}
	for _, fmtName := range []string{"table", "jsonl", "txt", "csv"} {
		if err := writeFindings(failWriter{}, fmtName, sample); err == nil {
			t.Fatalf("expected writeFindings(%s) to propagate write error", fmtName)
		}
	}
	var csvBuf bytes.Buffer
	if err := writeFindings(&csvBuf, "csv", sample); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(csvBuf.String(), "'=cmd") {
		t.Fatalf("expected CSV formula prefix escaping, got:\n%s", csvBuf.String())
	}
	if tr := truncateStr(sample[0].TLSIssuer, 15); !utf8.ValidString(tr) {
		t.Fatalf("truncateStr produced invalid UTF-8: %q", tr)
	}

	// 7. Concurrent loginLimiter blocks brute-force bursts at 5 attempts
	concLim := newLoginLimiter()
	var wg sync.WaitGroup
	var allowedCount atomic.Int32
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			allowed, _ := concLim.authenticate("9.9.9.9", func() bool { return false })
			if allowed {
				allowedCount.Add(1)
			}
		}()
	}
	wg.Wait()
	if allowedCount.Load() != loginMaxFailures {
		t.Fatalf("expected exactly %d allowed failed attempts concurrently, got %d", loginMaxFailures, allowedCount.Load())
	}
}
