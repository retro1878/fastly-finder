package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	trancoZipURL   = "https://tranco-list.eu/top-1m.csv.zip"
	umbrellaZipURL = "http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip"
	majesticCSVURL = "https://downloads.majestic.com/majestic_million.csv"
)

// Candidate represents a normalized hostname and the free sources that discovered it.
type Candidate struct {
	Host    string
	Sources []string
}

// SourceOptions configures candidate collection.
type SourceOptions struct {
	Domains      []string
	InputFile    string
	Global       bool
	Seeds        []string
	Limit        int
	WithWWW      bool
	UseSubfinder bool
	CacheDir     string
	Refresh      bool
	Verbose      bool
	Logf         func(format string, args ...any)
}

// CollectCandidates gathers, normalizes, and deduplicates hostnames from all configured free sources.
func CollectCandidates(ctx context.Context, client *http.Client, opts SourceOptions) ([]Candidate, error) {
	store := newCandidateStore()

	if opts.InputFile != "" {
		if err := loadCandidatesFromInput(opts.InputFile, store); err != nil {
			return nil, err
		}
	}

	for _, rawDom := range opts.Domains {
		dom := NormalizeHost(rawDom)
		if dom == "" {
			continue
		}
		collectForDomain(ctx, client, dom, opts, store)
	}

	if opts.Global {
		collectGlobal(ctx, client, opts, store)
	}

	return store.sortedList(), nil
}

type candidateStore struct {
	mu    sync.Mutex
	order []string
	srcs  map[string]map[string]struct{}
}

func newCandidateStore() *candidateStore {
	return &candidateStore{srcs: make(map[string]map[string]struct{})}
}

func (s *candidateStore) add(host, source string) {
	h := NormalizeHost(host)
	if h == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	set, exists := s.srcs[h]
	if !exists {
		set = make(map[string]struct{}, 2)
		s.srcs[h] = set
		s.order = append(s.order, h)
	}
	if source != "" {
		set[source] = struct{}{}
	}
}

func (s *candidateStore) addDomainScoped(host, apex, source string) {
	h := NormalizeHost(host)
	if h == "" || !belongsToDomain(h, apex) {
		return
	}
	s.add(h, source)
}

func (s *candidateStore) sortedList() []Candidate {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Candidate, 0, len(s.order))
	for _, h := range s.order {
		var srcs []string
		for k := range s.srcs[h] {
			srcs = append(srcs, k)
		}
		out = append(out, Candidate{Host: h, Sources: srcs})
	}
	return out
}

// NormalizeHost strips wildcard prefixes, ports, schemes, and trailing dots, returning empty if invalid.
func NormalizeHost(raw string) string {
	s := strings.TrimSpace(strings.ToLower(raw))
	if s == "" {
		return ""
	}
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil {
			s = u.Hostname()
		}
	}
	if idx := strings.IndexAny(s, "/?#"); idx >= 0 {
		s = s[:idx]
	}
	if hostPart, _, found := strings.Cut(s, ":"); found && !strings.Contains(s, "::") {
		s = hostPart
	}
	s = strings.TrimPrefix(s, "*.")
	s = strings.Trim(s, ".")
	if s == "" || len(s) > 253 || !strings.Contains(s, ".") {
		return ""
	}
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '.' || r == '_') {
			return ""
		}
	}
	return s
}

func belongsToDomain(host, apex string) bool {
	return host == apex || strings.HasSuffix(host, "."+apex)
}

func loadCandidatesFromInput(path string, store *candidateStore) error {
	var r io.Reader
	if path == "-" {
		r = os.Stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("open input %s: %w", path, err)
		}
		defer f.Close()
		r = f
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Allow rank,domain CSV lines or whitespace-separated first/last tokens.
		if strings.Contains(line, ",") {
			parts := strings.Split(line, ",")
			for _, p := range parts {
				if h := NormalizeHost(p); h != "" {
					store.add(h, "input")
					break
				}
			}
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 {
			store.add(fields[0], "input")
		}
	}
	return sc.Err()
}

func collectForDomain(ctx context.Context, client *http.Client, domain string, opts SourceOptions, store *candidateStore) {
	store.add(domain, "seed")
	store.add("www."+domain, "seed")

	var wg sync.WaitGroup
	run := func(name string, fn func() ([]string, error)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			hosts, err := fn()
			if err != nil {
				if opts.Verbose && opts.Logf != nil {
					opts.Logf("[%s] %s: %v", name, domain, err)
				}
				return
			}
			added := 0
			for _, h := range hosts {
				for _, item := range strings.Split(h, "\n") {
					norm := NormalizeHost(item)
					if norm != "" && belongsToDomain(norm, domain) {
						store.add(norm, name)
						added++
					}
				}
			}
			if opts.Verbose && opts.Logf != nil {
				opts.Logf("[%s] %s: +%d names", name, domain, added)
			}
		}()
	}

	run("crt.sh-json", func() ([]string, error) { return fetchCrtshJSON(ctx, client, domain) })
	run("crt.sh-sql", func() ([]string, error) { return fetchCrtshSQLDomain(ctx, domain) })
	run("certspotter", func() ([]string, error) { return fetchCertSpotterDomain(ctx, client, domain) })
	run("hackertarget", func() ([]string, error) { return fetchHackerTarget(ctx, client, domain) })
	run("alienvault-otx", func() ([]string, error) { return fetchOTX(ctx, client, domain) })
	run("wayback", func() ([]string, error) { return fetchWayback(ctx, client, domain) })

	if opts.UseSubfinder {
		run("subfinder", func() ([]string, error) { return runSubfinder(ctx, domain) })
	}

	wg.Wait()
}

func fetchCrtshJSON(ctx context.Context, client *http.Client, domain string) ([]string, error) {
	u := "https://crt.sh/?q=%25." + url.QueryEscape(domain) + "&output=json"
	body, err := httpGetBytes(ctx, client, u, 24<<20)
	if err != nil {
		return nil, err
	}
	var entries []struct {
		NameValue  string `json:"name_value"`
		CommonName string `json:"common_name"`
	}
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(entries)*2)
	for _, e := range entries {
		if e.NameValue != "" {
			out = append(out, e.NameValue)
		}
		if e.CommonName != "" {
			out = append(out, e.CommonName)
		}
	}
	return out, nil
}

func fetchCrtshSQLDomain(ctx context.Context, domain string) ([]string, error) {
	clean := sanitizeTSQueryDomain(domain)
	if clean == "" {
		return nil, fmt.Errorf("invalid domain %q", domain)
	}
	q := fmt.Sprintf(`
SELECT DISTINCT san
FROM certificate c, LATERAL unnest(x509_altNames(c.certificate)) san
WHERE to_tsquery('certwatch', '%s') @@ identities(c.certificate)
LIMIT 10000;`, clean)
	rows, err := queryCrtshPostgres(ctx, q, 25*time.Second)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		if len(r) > 0 && r[0] != "" {
			out = append(out, r[0])
		}
	}
	return out, nil
}

func fetchCertSpotterDomain(ctx context.Context, client *http.Client, domain string) ([]string, error) {
	u := fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", url.QueryEscape(domain))
	body, err := httpGetBytes(ctx, client, u, 8<<20)
	if err != nil {
		return nil, err
	}
	var entries []struct {
		DNSNames []string `json:"dns_names"`
	}
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.DNSNames...)
	}
	return out, nil
}

func fetchHackerTarget(ctx context.Context, client *http.Client, domain string) ([]string, error) {
	u := "https://api.hackertarget.com/hostsearch/?q=" + url.QueryEscape(domain)
	body, err := httpGetBytes(ctx, client, u, 4<<20)
	if err != nil {
		return nil, err
	}
	txt := string(body)
	if strings.HasPrefix(txt, "error") || strings.Contains(txt, "API count exceeded") {
		return nil, fmt.Errorf("hackertarget: %s", strings.TrimSpace(txt))
	}
	var out []string
	sc := bufio.NewScanner(strings.NewReader(txt))
	for sc.Scan() {
		host, _, _ := strings.Cut(sc.Text(), ",")
		if host != "" {
			out = append(out, host)
		}
	}
	return out, nil
}

func fetchOTX(ctx context.Context, client *http.Client, domain string) ([]string, error) {
	u := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", url.PathEscape(domain))
	body, err := httpGetBytes(ctx, client, u, 16<<20)
	if err != nil {
		return nil, err
	}
	var doc struct {
		PassiveDNS []struct {
			Hostname string `json:"hostname"`
		} `json:"passive_dns"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(doc.PassiveDNS))
	for _, r := range doc.PassiveDNS {
		if r.Hostname != "" {
			out = append(out, r.Hostname)
		}
	}
	return out, nil
}

func fetchWayback(ctx context.Context, client *http.Client, domain string) ([]string, error) {
	u := fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=*.%s/*&output=json&fl=original&collapse=urlkey&limit=5000", url.QueryEscape(domain))
	body, err := httpGetBytes(ctx, client, u, 16<<20)
	if err != nil {
		return nil, err
	}
	var rows [][]string
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, err
	}
	var out []string
	for i, row := range rows {
		if i == 0 || len(row) == 0 {
			continue
		}
		if h := NormalizeHost(row[0]); h != "" {
			out = append(out, h)
		}
	}
	return out, nil
}

func runSubfinder(ctx context.Context, domain string) ([]string, error) {
	bin, err := exec.LookPath("subfinder")
	if err != nil {
		return nil, fmt.Errorf("subfinder not in PATH")
	}
	cmdCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cmdCtx, bin, "-d", domain, "-all", "-silent").Output()
	if err != nil {
		return nil, err
	}
	return strings.Split(string(out), "\n"), nil
}

func collectGlobal(ctx context.Context, client *http.Client, opts SourceOptions, store *candidateStore) {
	seeds := opts.Seeds
	if len(seeds) == 0 {
		seeds = []string{"tranco", "ct-fastly"}
	}
	for _, seed := range seeds {
		s := strings.ToLower(strings.TrimSpace(seed))
		switch s {
		case "tranco":
			loadSeedZip(ctx, client, "tranco", trancoZipURL, "tranco_top1m.zip", 1, opts, store, true)
		case "umbrella":
			loadSeedZip(ctx, client, "umbrella", umbrellaZipURL, "umbrella_top1m.zip", 1, opts, store, false)
		case "majestic":
			loadMajestic(ctx, client, opts, store)
		case "ct-fastly":
			collectGlobalCTFastly(ctx, opts, store)
		case "all":
			loadSeedZip(ctx, client, "tranco", trancoZipURL, "tranco_top1m.zip", 1, opts, store, true)
			loadSeedZip(ctx, client, "umbrella", umbrellaZipURL, "umbrella_top1m.zip", 1, opts, store, false)
			loadMajestic(ctx, client, opts, store)
			collectGlobalCTFastly(ctx, opts, store)
		default:
			if opts.Logf != nil {
				opts.Logf("unknown global seed %q (supported: tranco, umbrella, majestic, ct-fastly, all)", s)
			}
		}
	}
}

func loadSeedZip(ctx context.Context, client *http.Client, name, remoteURL, cacheFile string, colIdx int, opts SourceOptions, store *candidateStore, apexList bool) {
	data, err := fetchOrReadCache(ctx, client, remoteURL, opts.CacheDir, cacheFile, 7*24*time.Hour, opts.Refresh, 64<<20)
	if err != nil {
		if opts.Logf != nil {
			opts.Logf("[%s] fetch failed: %v", name, err)
		}
		return
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		if opts.Logf != nil {
			opts.Logf("[%s] zip parse failed: %v", name, err)
		}
		return
	}
	count := 0
	for _, f := range zr.File {
		if !strings.HasSuffix(strings.ToLower(f.Name), ".csv") && !strings.HasSuffix(strings.ToLower(f.Name), ".txt") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		count += parseCSVHosts(rc, colIdx, false, opts.Limit, name, apexList && opts.WithWWW, store)
		rc.Close()
		break
	}
	if opts.Logf != nil {
		opts.Logf("[%s] loaded %d seed domains", name, count)
	}
}

func loadMajestic(ctx context.Context, client *http.Client, opts SourceOptions, store *candidateStore) {
	data, err := fetchOrReadCache(ctx, client, majesticCSVURL, opts.CacheDir, "majestic_million.csv", 7*24*time.Hour, opts.Refresh, 128<<20)
	if err != nil {
		if opts.Logf != nil {
			opts.Logf("[majestic] fetch failed: %v", err)
		}
		return
	}
	count := parseCSVHosts(bytes.NewReader(data), 2, true, opts.Limit, "majestic", opts.WithWWW, store)
	if opts.Logf != nil {
		opts.Logf("[majestic] loaded %d seed domains", count)
	}
}

func parseCSVHosts(r io.Reader, colIdx int, hasHeader bool, limit int, source string, addWWW bool, store *candidateStore) int {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	cr.ReuseRecord = true
	count := 0
	first := true
	for {
		rec, err := cr.Read()
		if err != nil {
			break
		}
		if first && hasHeader {
			first = false
			continue
		}
		first = false
		if colIdx >= len(rec) {
			continue
		}
		h := NormalizeHost(rec[colIdx])
		if h == "" {
			continue
		}
		store.add(h, source)
		if addWWW && !strings.HasPrefix(h, "www.") {
			store.add("www."+h, source)
		}
		count++
		if limit > 0 && count >= limit {
			break
		}
	}
	return count
}

func collectGlobalCTFastly(ctx context.Context, opts SourceOptions, store *candidateStore) {
	// 1. Shared Fastly SSL certs carrying global.ssl.fastly.net in SANs.
	qShared := `
SELECT DISTINCT san
FROM certificate c, LATERAL unnest(x509_altNames(c.certificate)) san
WHERE to_tsquery('certwatch', 'global.ssl.fastly.net') @@ identities(c.certificate)
  AND x509_notAfter(c.certificate) > now()
LIMIT 5000;`
	if rows, err := queryCrtshPostgres(ctx, qShared, 35*time.Second); err != nil {
		if opts.Logf != nil {
			opts.Logf("[ct-fastly] shared-cert SQL: %v", err)
		}
	} else {
		n := 0
		for _, r := range rows {
			if len(r) == 0 {
				continue
			}
			h := NormalizeHost(r[0])
			if h != "" && !IsFastlyCNAME(h) {
				store.add(h, "crt.sh-shared")
				n++
			}
		}
		if opts.Logf != nil {
			opts.Logf("[ct-fastly] shared-cert SANs: +%d hosts", n)
		}
	}

	// 2. Recent Certainly-issued certs (Fastly's own CA). Query bounded by recent ID window to stay under 54s timeout.
	qCertainly := `
SELECT DISTINCT san
FROM (
    SELECT c.certificate
    FROM certificate c
    WHERE x509_issuerName(c.certificate) ILIKE '%Certainly%'
    ORDER BY c.id DESC
    LIMIT 1500
) sub, LATERAL unnest(x509_altNames(sub.certificate)) san
LIMIT 5000;`
	if rows, err := queryCrtshPostgres(ctx, qCertainly, 35*time.Second); err != nil {
		if opts.Logf != nil {
			opts.Logf("[ct-fastly] certainly SQL: %v", err)
		}
	} else {
		n := 0
		for _, r := range rows {
			if len(r) == 0 {
				continue
			}
			h := NormalizeHost(r[0])
			if h != "" && !IsFastlyCNAME(h) {
				store.add(h, "crt.sh-certainly")
				n++
			}
		}
		if opts.Logf != nil {
			opts.Logf("[ct-fastly] certainly CA SANs: +%d hosts", n)
		}
	}
}

func fetchOrReadCache(ctx context.Context, client *http.Client, remoteURL, cacheDir, fileName string, maxAge time.Duration, refresh bool, maxBytes int64) ([]byte, error) {
	var cachePath string
	if cacheDir != "" {
		cachePath = filepath.Join(cacheDir, fileName)
		if !refresh {
			if st, err := os.Stat(cachePath); err == nil && time.Since(st.ModTime()) <= maxAge {
				if data, err := os.ReadFile(cachePath); err == nil && len(data) > 0 {
					return data, nil
				}
			}
		}
	}
	data, err := httpGetBytes(ctx, client, remoteURL, maxBytes)
	if err != nil {
		// Fall back to stale cache if offline.
		if cachePath != "" {
			if stale, rerr := os.ReadFile(cachePath); rerr == nil && len(stale) > 0 {
				return stale, nil
			}
		}
		return nil, err
	}
	if cachePath != "" {
		_ = os.MkdirAll(filepath.Dir(cachePath), 0o755)
		_ = os.WriteFile(cachePath, data, 0o644)
	}
	return data, nil
}
