package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed web/index.html
var webIndexHTML []byte

// WebOptions configures the HTTPS-only authenticated web dashboard.
type WebOptions struct {
	Addr     string
	Auth     string
	CertFile string
	KeyFile  string
	WebDir   string
	CacheDir string
	BaseCfg  ScanConfig
}

type webServer struct {
	opts       WebOptions
	authUser   string
	authPass   string
	hmacKey    []byte
	limiter    *loginLimiter
	mu         sync.Mutex
	running    bool
	state      string // idle, running, completed, cancelled, error
	message    string
	done       int
	total      int
	candidates int
	fastlyDNS  int
	counts     map[string]int
	findings   []Finding
	logs       []string
	activeFile string
	cancelFn   context.CancelFunc
}

// RunWebServer starts the HTTPS-only authenticated dashboard and blocks until ctx is cancelled.
func RunWebServer(ctx context.Context, opts WebOptions) error {
	if opts.Addr == "" {
		opts.Addr = "127.0.0.1:8443"
	}
	if opts.WebDir == "" {
		opts.WebDir = "scans"
	}
	if err := os.MkdirAll(opts.WebDir, 0o750); err != nil {
		return fmt.Errorf("create web-dir %s: %w", opts.WebDir, err)
	}

	user, pass, generated := resolveWebCredentials(opts.Auth)
	hmacKey := make([]byte, 32)
	if _, err := rand.Read(hmacKey); err != nil {
		return err
	}

	tlsCfg, certSource, err := buildWebTLSConfig(opts.CertFile, opts.KeyFile, opts.CacheDir)
	if err != nil {
		return fmt.Errorf("tls setup: %w", err)
	}

	ws := &webServer{
		opts:     opts,
		authUser: user,
		authPass: pass,
		hmacKey:  hmacKey,
		limiter:  newLoginLimiter(),
		state:    "idle",
		counts:   make(map[string]int),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", ws.handleIndex)
	mux.HandleFunc("/api/me", ws.handleMe)
	mux.HandleFunc("/api/login", ws.handleLogin)
	mux.HandleFunc("/api/logout", ws.requireAuth(ws.requireCSRF(ws.handleLogout)))
	mux.HandleFunc("/api/status", ws.requireAuth(ws.handleStatus))
	mux.HandleFunc("/api/results", ws.requireAuth(ws.handleResults))
	mux.HandleFunc("/api/files", ws.requireAuth(ws.handleFiles))
	mux.HandleFunc("/api/export", ws.requireAuth(ws.handleExport))
	mux.HandleFunc("/api/scan/start", ws.requireAuth(ws.requireCSRF(ws.handleScanStart)))
	mux.HandleFunc("/api/scan/cancel", ws.requireAuth(ws.requireCSRF(ws.handleScanCancel)))

	ln, err := net.Listen("tcp", opts.Addr)
	if err != nil {
		return err
	}
	tlsLn := tls.NewListener(ln, tlsCfg)

	srv := &http.Server{
		Handler:           securityHeaders(mux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	fmt.Fprintf(os.Stderr, "[*] HTTPS dashboard listening on https://%s (TLS: %s, scans: %s)\n", opts.Addr, certSource, opts.WebDir)
	if generated {
		fmt.Fprintf(os.Stderr, "[*] Generated web login -> user=%s password=%s\n", user, pass)
	} else {
		fmt.Fprintf(os.Stderr, "[*] Web authentication enabled for user=%s\n", user)
	}

	errCh := make(chan error, 1)
	go func() {
		if err := srv.Serve(tlsLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		ws.cancelActive()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		return nil
	case err := <-errCh:
		return err
	}
}

func resolveWebCredentials(flagAuth string) (user, pass string, generated bool) {
	raw := strings.TrimSpace(flagAuth)
	if raw == "" {
		raw = strings.TrimSpace(os.Getenv("FASTLY_FINDER_WEB_AUTH"))
	}
	if raw != "" {
		if u, p, ok := strings.Cut(raw, ":"); ok && u != "" && p != "" {
			return u, p, false
		}
		return "admin", raw, false
	}
	buf := make([]byte, 18)
	_, _ = rand.Read(buf)
	return "admin", base64.RawURLEncoding.EncodeToString(buf), true
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

func (ws *webServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(webIndexHTML)
}

func (ws *webServer) handleMe(w http.ResponseWriter, r *http.Request) {
	if !ws.isAuthenticated(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": true, "user": ws.authUser})
}

func (ws *webServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	ip := clientIP(r.RemoteAddr)
	if !ws.limiter.allow(ip) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many failed attempts; wait 60s"})
		return
	}
	var req struct {
		User string `json:"user"`
		Pass string `json:"pass"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	userOK := subtle.ConstantTimeCompare([]byte(req.User), []byte(ws.authUser)) == 1
	passOK := subtle.ConstantTimeCompare([]byte(req.Pass), []byte(ws.authPass)) == 1
	if !userOK || !passOK {
		ws.limiter.recordFailure(ip)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}
	ws.limiter.reset(ip)

	exp := time.Now().Add(24 * time.Hour).Unix()
	token := ws.signSession(exp)
	http.SetCookie(w, &http.Cookie{
		Name:     "ff_session",
		Value:    token,
		Path:     "/",
		MaxAge:   86400,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": true, "user": ws.authUser})
}

func (ws *webServer) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "ff_session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (ws *webServer) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !ws.isAuthenticated(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next(w, r)
	}
}

func (ws *webServer) requireCSRF(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		if r.Header.Get("X-Requested-With") != "fastly-finder" {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "missing X-Requested-With header"})
			return
		}
		next(w, r)
	}
}

func (ws *webServer) isAuthenticated(r *http.Request) bool {
	c, err := r.Cookie("ff_session")
	if err != nil || c.Value == "" {
		return false
	}
	return ws.verifySession(c.Value)
}

func (ws *webServer) signSession(exp int64) string {
	payload := strconv.FormatInt(exp, 10)
	mac := hmac.New(sha256.New, ws.hmacKey)
	mac.Write([]byte(payload))
	return payload + "." + hex.EncodeToString(mac.Sum(nil))
}

func (ws *webServer) verifySession(tok string) bool {
	payload, sigHex, ok := strings.Cut(tok, ".")
	if !ok {
		return false
	}
	exp, err := strconv.ParseInt(payload, 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return false
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, ws.hmacKey)
	mac.Write([]byte(payload))
	expected := mac.Sum(nil)
	return hmac.Equal(sig, expected)
}

func (ws *webServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	countsCopy := make(map[string]int, len(ws.counts))
	for k, v := range ws.counts {
		countsCopy[k] = v
	}
	logsCopy := append([]string(nil), ws.logs...)
	writeJSON(w, http.StatusOK, map[string]any{
		"running":     ws.running,
		"state":       ws.state,
		"message":     ws.message,
		"done":        ws.done,
		"total":       ws.total,
		"candidates":  ws.candidates,
		"fastly_dns":  ws.fastlyDNS,
		"counts":      countsCopy,
		"logs":        logsCopy,
		"active_file": ws.activeFile,
	})
}

func (ws *webServer) handleScanStart(w http.ResponseWriter, r *http.Request) {
	var req ScanConfig
	if err := json.NewDecoder(io.LimitReader(r.Body, 2<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid scan config"})
		return
	}
	if !req.Global && len(req.Domains) == 0 && len(req.DirectHosts) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "specify target domain(s), host list, or enable global discovery"})
		return
	}

	cfg := ws.opts.BaseCfg
	cfg.Domains = req.Domains
	cfg.DirectHosts = req.DirectHosts
	cfg.Global = req.Global
	cfg.Seeds = req.Seeds
	cfg.Limit = req.Limit
	if req.CTEntries > 0 {
		cfg.CTEntries = req.CTEntries
	}
	cfg.WithWWW = req.WithWWW
	cfg.UseDoH = req.UseDoH
	cfg.IncludeBGP = req.IncludeBGP
	cfg.SkipProbe = req.SkipProbe
	cfg.OnlyConfirmed = req.OnlyConfirmed
	cfg.QueryAAAA = true
	if req.DNSWorkers > 0 && req.DNSWorkers <= 1000 {
		cfg.DNSWorkers = req.DNSWorkers
	}
	if req.HTTPWorkers > 0 && req.HTTPWorkers <= 500 {
		cfg.HTTPWorkers = req.HTTPWorkers
	}

	ws.mu.Lock()
	if ws.running {
		ws.mu.Unlock()
		writeJSON(w, http.StatusConflict, map[string]string{"error": "a scan is already running"})
		return
	}
	scanCtx, cancel := context.WithCancel(context.Background())
	ws.running = true
	ws.state = "running"
	ws.message = "starting scan..."
	ws.done = 0
	ws.total = 0
	ws.candidates = 0
	ws.fastlyDNS = 0
	ws.counts = make(map[string]int)
	ws.findings = nil
	ws.logs = nil
	ws.activeFile = ""
	ws.cancelFn = cancel
	ws.mu.Unlock()

	go ws.runScanWorker(scanCtx, cfg)
	writeJSON(w, http.StatusAccepted, map[string]any{"started": true})
}

func (ws *webServer) handleScanCancel(w http.ResponseWriter, r *http.Request) {
	ws.cancelActive()
	writeJSON(w, http.StatusOK, map[string]any{"cancelled": true})
}

func (ws *webServer) cancelActive() {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	if ws.cancelFn != nil {
		ws.cancelFn()
	}
}

func (ws *webServer) runScanWorker(ctx context.Context, cfg ScanConfig) {
	defer func() {
		ws.mu.Lock()
		ws.running = false
		ws.cancelFn = nil
		ws.mu.Unlock()
	}()

	outcome, err := RunScan(ctx, cfg, func(ev ScanEvent) {
		ws.mu.Lock()
		defer ws.mu.Unlock()
		if ev.Message != "" {
			ws.message = ev.Message
			if ev.Stage != "dns" && ev.Stage != "probe" {
				ws.appendLogLocked(ev.Message)
			}
		}
		if ev.Total > 0 {
			ws.done = ev.Done
			ws.total = ev.Total
		}
	})

	ws.mu.Lock()
	defer ws.mu.Unlock()
	if err != nil {
		if ctx.Err() != nil {
			ws.state = "cancelled"
			ws.message = "scan cancelled"
		} else {
			ws.state = "error"
			ws.message = err.Error()
		}
		ws.appendLogLocked(ws.message)
		return
	}

	ws.findings = outcome.Findings
	ws.counts = outcome.Counts
	ws.candidates = outcome.CandidatesCount
	ws.fastlyDNS = outcome.FastlyDNSCount
	ws.state = "completed"
	if ctx.Err() != nil {
		ws.state = "cancelled"
	}

	if len(outcome.Findings) > 0 {
		if name, serr := saveScanJSONL(ws.opts.WebDir, cfg, outcome.Findings); serr == nil {
			ws.activeFile = name
			ws.appendLogLocked("saved " + name)
		}
	}
}

func (ws *webServer) appendLogLocked(line string) {
	ts := time.Now().Format("15:04:05")
	ws.logs = append(ws.logs, ts+" "+line)
	if len(ws.logs) > 120 {
		ws.logs = ws.logs[len(ws.logs)-120:]
	}
}

func (ws *webServer) handleResults(w http.ResponseWriter, r *http.Request) {
	file := strings.TrimSpace(r.URL.Query().Get("file"))
	findings, err := ws.getFindingsForFile(file)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"findings": findings})
}

func (ws *webServer) handleFiles(w http.ResponseWriter, r *http.Request) {
	entries, err := os.ReadDir(ws.opts.WebDir)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	type fileMeta struct {
		Name    string    `json:"name"`
		Size    int64     `json:"size"`
		ModTime time.Time `json:"mod_time"`
	}
	var files []fileMeta
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".jsonl") {
			continue
		}
		if info, err := e.Info(); err == nil {
			files = append(files, fileMeta{Name: e.Name(), Size: info.Size(), ModTime: info.ModTime()})
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].ModTime.After(files[j].ModTime) })
	writeJSON(w, http.StatusOK, map[string]any{"files": files})
}

func (ws *webServer) handleExport(w http.ResponseWriter, r *http.Request) {
	file := strings.TrimSpace(r.URL.Query().Get("file"))
	findings, err := ws.getFindingsForFile(file)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if r.URL.Query().Get("only_confirmed") == "1" {
		var only []Finding
		for _, f := range findings {
			if f.Status == "confirmed" {
				only = append(only, f)
			}
		}
		findings = only
	}
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "jsonl"
	}
	var buf bytes.Buffer
	if err := writeFindings(&buf, format, findings); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	ext := format
	if ext == "json" {
		ext = "jsonl"
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="fastly_findings.%s"`, ext))
	_, _ = w.Write(buf.Bytes())
}

func (ws *webServer) getFindingsForFile(name string) ([]Finding, error) {
	if name == "" {
		ws.mu.Lock()
		defer ws.mu.Unlock()
		return append([]Finding(nil), ws.findings...), nil
	}
	safe, err := sanitizeScanFilename(ws.opts.WebDir, name)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(safe)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Finding
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var item Finding
		if err := json.Unmarshal([]byte(line), &item); err == nil {
			out = append(out, item)
		}
	}
	return out, sc.Err()
}

func sanitizeScanFilename(dir, name string) (string, error) {
	if name == "" || filepath.Base(name) != name || strings.Contains(name, "..") || !strings.HasSuffix(strings.ToLower(name), ".jsonl") {
		return "", errors.New("invalid scan filename")
	}
	return filepath.Join(dir, name), nil
}

func saveScanJSONL(dir string, cfg ScanConfig, findings []Finding) (string, error) {
	tag := "hosts"
	if cfg.Global {
		tag = "global"
	} else if len(cfg.Domains) > 0 {
		if clean := sanitizeTSQueryDomain(cfg.Domains[0]); clean != "" {
			tag = clean
		}
	}
	name := fmt.Sprintf("scan_%s_%s.jsonl", time.Now().UTC().Format("20060102_150405"), tag)
	path := filepath.Join(dir, name)
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if err := writeFindings(f, "jsonl", findings); err != nil {
		return "", err
	}
	return name, nil
}

// buildWebTLSConfig uses Certbot/CA files with automatic hot-reload via GetCertificate,
// or generates and caches a persistent ECDSA P-256 self-signed cert in cacheDir.
func buildWebTLSConfig(certFile, keyFile, cacheDir string) (*tls.Config, string, error) {
	if certFile == "" {
		certFile = strings.TrimSpace(os.Getenv("FASTLY_FINDER_WEB_CERT"))
	}
	if keyFile == "" {
		keyFile = strings.TrimSpace(os.Getenv("FASTLY_FINDER_WEB_KEY"))
	}
	if certFile != "" && keyFile != "" {
		reloader, err := newCertReloader(certFile, keyFile)
		if err != nil {
			return nil, "", err
		}
		return &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: reloader.getCertificate,
		}, "file:" + certFile + " (hot-reload)", nil
	}

	if cacheDir == "" {
		cacheDir = defaultCacheDir()
	}
	selfCert := filepath.Join(cacheDir, "web_cert.pem")
	selfKey := filepath.Join(cacheDir, "web_key.pem")
	cert, err := loadOrCreateSelfSigned(selfCert, selfKey)
	if err != nil {
		return nil, "", err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}, "self-signed:" + selfCert, nil
}

type certReloader struct {
	certFile  string
	keyFile   string
	mu        sync.Mutex
	cert      *tls.Certificate
	certMtime time.Time
	keyMtime  time.Time
	lastCheck time.Time
}

func newCertReloader(certFile, keyFile string) (*certReloader, error) {
	cr := &certReloader{certFile: certFile, keyFile: keyFile}
	if err := cr.reloadLocked(); err != nil {
		return nil, err
	}
	return cr, nil
}

func (cr *certReloader) reloadLocked() error {
	cInfo, err := os.Stat(cr.certFile)
	if err != nil {
		return err
	}
	kInfo, err := os.Stat(cr.keyFile)
	if err != nil {
		return err
	}
	pair, err := tls.LoadX509KeyPair(cr.certFile, cr.keyFile)
	if err != nil {
		return err
	}
	cr.cert = &pair
	cr.certMtime = cInfo.ModTime()
	cr.keyMtime = kInfo.ModTime()
	cr.lastCheck = time.Now()
	return nil
}

func (cr *certReloader) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	cr.mu.Lock()
	defer cr.mu.Unlock()
	if time.Since(cr.lastCheck) > 10*time.Second {
		cr.lastCheck = time.Now()
		cInfo, cErr := os.Stat(cr.certFile)
		kInfo, kErr := os.Stat(cr.keyFile)
		if cErr == nil && kErr == nil && (cInfo.ModTime().After(cr.certMtime) || kInfo.ModTime().After(cr.keyMtime)) {
			if err := cr.reloadLocked(); err != nil {
				fmt.Fprintf(os.Stderr, "[!] TLS cert reload error (keeping previous cert): %v\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "[*] Reloaded TLS certificate from %s\n", cr.certFile)
			}
		}
	}
	return cr.cert, nil
}

func loadOrCreateSelfSigned(certPath, keyPath string) (tls.Certificate, error) {
	if cert, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		if len(cert.Certificate) > 0 {
			if parsed, perr := x509.ParseCertificate(cert.Certificate[0]); perr == nil && time.Until(parsed.NotAfter) > 30*24*time.Hour {
				return cert, nil
			}
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	ips := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipNet, ok := a.(*net.IPNet); ok && ipNet.IP != nil && !ipNet.IP.IsLoopback() {
				ips = append(ips, ipNet.IP)
			}
		}
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "fastly-finder"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}

	_ = os.MkdirAll(filepath.Dir(certPath), 0o750)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

type loginAttempt struct {
	fails int
	until time.Time
}

type loginLimiter struct {
	mu       sync.Mutex
	attempts map[string]*loginAttempt
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{attempts: make(map[string]*loginAttempt)}
}

func (l *loginLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	a, ok := l.attempts[ip]
	if !ok {
		return true
	}
	if time.Now().After(a.until) {
		if a.fails >= 5 {
			delete(l.attempts, ip)
		}
		return true
	}
	return a.fails < 5
}

func (l *loginLimiter) recordFailure(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	a, ok := l.attempts[ip]
	if !ok {
		a = &loginAttempt{}
		l.attempts[ip] = a
	}
	a.fails++
	if a.fails >= 5 {
		a.until = time.Now().Add(60 * time.Second)
	}
}

func (l *loginLimiter) reset(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.attempts, ip)
}

func clientIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
