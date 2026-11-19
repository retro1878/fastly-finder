package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	fastlyIPListURL = "https://api.fastly.com/public-ip-list"
	mispFastlyURL   = "https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/fastly/list.json"
	ripeStatURLFmt  = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS%s"
	defaultEdgeIP   = "151.101.1.140"
)

// embeddedFastlyCIDRs is a snapshot of MISP misp-warninglists Fastly (version 20261014)
// used only if all remote range endpoints are unreachable.
var embeddedFastlyCIDRs = []string{
	"103.244.50.0/24",
	"103.245.222.0/23",
	"103.245.224.0/24",
	"104.156.80.0/20",
	"140.248.128.0/17",
	"140.248.64.0/18",
	"146.75.0.0/17",
	"151.101.0.0/16",
	"157.52.64.0/18",
	"167.82.0.0/17",
	"167.82.128.0/20",
	"167.82.160.0/20",
	"167.82.224.0/20",
	"172.111.64.0/18",
	"185.31.16.0/22",
	"199.232.0.0/16",
	"199.27.72.0/21",
	"23.235.32.0/20",
	"43.249.72.0/22",
	"2a04:4e40::/32",
	"2a04:4e42::/32",
}

// upcoming2027CIDRs were announced Oct 13, 2026 for activation on Jan 11, 2027.
var upcoming2027CIDRs = []string{
	"90.98.0.0/17",
	"90.98.128.0/18",
	"2a04:4e42::/31",
	"2a04:4e44::/32",
}

// RangeSet holds Fastly IPv4 and IPv6 prefixes and reports how they were loaded.
type RangeSet struct {
	V4     []netip.Prefix
	V6     []netip.Prefix
	Source string
}

// RangeOptions controls how Fastly IP ranges are loaded.
type RangeOptions struct {
	CIDRFile        string
	CacheDir        string
	IncludeBGP      bool
	IncludeUpcoming bool
	Refresh         bool
}

type cachedRanges struct {
	Source    string    `json:"source"`
	FetchedAt time.Time `json:"fetched_at"`
	CIDRs     []string  `json:"cidrs"`
}

// LoadRanges loads Fastly IP ranges from a local file, cache, live Fastly API,
// MISP mirror, RIPEstat AS54113/AS394192, or the embedded fallback snapshot.
func LoadRanges(ctx context.Context, client *http.Client, opts RangeOptions) (*RangeSet, error) {
	if opts.CIDRFile != "" {
		rs, err := loadRangesFromFile(opts.CIDRFile)
		if err != nil {
			return nil, err
		}
		if opts.IncludeBGP {
			bgpCIDRs, err := fetchRIPEstatFastly(ctx, client)
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if err == nil && len(bgpCIDRs) > 0 {
				rs.addStrings(bgpCIDRs)
				rs.Source += "+ripestat-bgp"
			}
		}
		if opts.IncludeUpcoming {
			rs.addStrings(upcoming2027CIDRs)
		}
		return rs, nil
	}

	var cidrs []string
	var source string

	cachePath := ""
	if opts.CacheDir != "" {
		cachePath = filepath.Join(opts.CacheDir, "fastly_ranges.json")
	}

	if cachePath != "" && !opts.Refresh {
		if cached, ok := readCachedRanges(cachePath, 24*time.Hour); ok {
			cidrs = cached.CIDRs
			source = cached.Source + " (cached)"
		}
	}

	if len(cidrs) == 0 {
		var errs []string
		if apiCIDRs, err := fetchFastlyAPI(ctx, client); err == nil && len(apiCIDRs) > 0 {
			cidrs = apiCIDRs
			source = "api.fastly.com"
		} else {
			if err != nil {
				errs = append(errs, "fastly-api: "+err.Error())
			}
			if mispCIDRs, err := fetchMISPFastly(ctx, client); err == nil && len(mispCIDRs) > 0 {
				cidrs = mispCIDRs
				source = "misp-warninglists"
			} else if err != nil {
				errs = append(errs, "misp: "+err.Error())
			}
		}

		if len(cidrs) == 0 {
			if bgpCIDRs, err := fetchRIPEstatFastly(ctx, client); err == nil && len(bgpCIDRs) > 0 {
				cidrs = bgpCIDRs
				source = "ripestat-bgp"
			} else {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				if err != nil {
					errs = append(errs, "ripestat: "+err.Error())
				}
				cidrs = append([]string(nil), embeddedFastlyCIDRs...)
				source = "embedded-fallback (" + strings.Join(errs, "; ") + ")"
			}
		} else if cachePath != "" {
			_ = writeCachedRanges(cachePath, cachedRanges{
				Source:    source,
				FetchedAt: time.Now().UTC(),
				CIDRs:     cidrs,
			})
		}
	}

	rs := &RangeSet{Source: source}
	rs.addStrings(cidrs)

	if opts.IncludeBGP && !strings.HasPrefix(source, "ripestat-bgp") {
		if bgpCIDRs, err := fetchRIPEstatFastly(ctx, client); err == nil && len(bgpCIDRs) > 0 {
			rs.addStrings(bgpCIDRs)
			rs.Source += "+ripestat-bgp"
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}

	if opts.IncludeUpcoming || time.Now().UTC().After(time.Date(2027, 1, 11, 0, 0, 0, 0, time.UTC)) {
		rs.addStrings(upcoming2027CIDRs)
	}

	if len(rs.V4) == 0 && len(rs.V6) == 0 {
		return nil, errors.New("no valid Fastly CIDRs loaded")
	}
	return rs, nil
}

// Contains reports whether ip falls inside any loaded Fastly prefix.
func (r *RangeSet) Contains(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	ip = ip.Unmap()
	if ip.Is4() {
		for _, p := range r.V4 {
			if p.Contains(ip) {
				return true
			}
		}
		return false
	}
	for _, p := range r.V6 {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// Count returns total IPv4 and IPv6 prefix counts.
func (r *RangeSet) Count() (v4, v6 int) {
	return len(r.V4), len(r.V6)
}

func (r *RangeSet) addStrings(items []string) {
	seen := make(map[netip.Prefix]struct{}, len(r.V4)+len(r.V6)+len(items))
	for _, p := range r.V4 {
		seen[p] = struct{}{}
	}
	for _, p := range r.V6 {
		seen[p] = struct{}{}
	}
	for _, raw := range items {
		raw = strings.TrimSpace(raw)
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			continue
		}
		p = p.Masked()
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		if p.Addr().Is4() {
			r.V4 = append(r.V4, p)
		} else {
			r.V6 = append(r.V6, p)
		}
	}
}

// IsFastlyCNAME reports whether cname points to a Fastly-owned delivery domain.
func IsFastlyCNAME(cname string) bool {
	c := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(cname)), ".")
	if c == "" {
		return false
	}
	return c == "fastly.net" || strings.HasSuffix(c, ".fastly.net") ||
		c == "fastlylb.net" || strings.HasSuffix(c, ".fastlylb.net")
}

func loadRangesFromFile(path string) (*RangeSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read cidr file %s: %w", path, err)
	}
	rs := &RangeSet{Source: "file:" + path}

	// Support Fastly API JSON or MISP JSON as well as plain line-by-line CIDRs.
	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "{") {
		var api struct {
			Addresses     []string `json:"addresses"`
			IPv6Addresses []string `json:"ipv6_addresses"`
			List          []string `json:"list"`
		}
		if err := json.Unmarshal(data, &api); err == nil {
			rs.addStrings(api.Addresses)
			rs.addStrings(api.IPv6Addresses)
			rs.addStrings(api.List)
			if len(rs.V4)+len(rs.V6) > 0 {
				return rs, nil
			}
		}
	}

	sc := bufio.NewScanner(strings.NewReader(string(data)))
	var lines []string
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	rs.addStrings(lines)
	if len(rs.V4)+len(rs.V6) == 0 {
		return nil, fmt.Errorf("no valid CIDRs found in %s", path)
	}
	return rs, nil
}

func fetchFastlyAPI(ctx context.Context, client *http.Client) ([]string, error) {
	body, err := httpGetBytes(ctx, client, fastlyIPListURL, 2<<20)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Addresses     []string `json:"addresses"`
		IPv6Addresses []string `json:"ipv6_addresses"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(doc.Addresses)+len(doc.IPv6Addresses))
	out = append(out, doc.Addresses...)
	out = append(out, doc.IPv6Addresses...)
	if len(out) == 0 {
		return nil, errors.New("empty Fastly API IP list")
	}
	return out, nil
}

func fetchMISPFastly(ctx context.Context, client *http.Client) ([]string, error) {
	body, err := httpGetBytes(ctx, client, mispFastlyURL, 2<<20)
	if err != nil {
		return nil, err
	}
	var doc struct {
		List []string `json:"list"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	if len(doc.List) == 0 {
		return nil, errors.New("empty MISP Fastly list")
	}
	return doc.List, nil
}

func fetchRIPEstatFastly(ctx context.Context, client *http.Client) ([]string, error) {
	var all []string
	for _, asn := range []string{"54113", "394192"} {
		body, err := httpGetBytes(ctx, client, fmt.Sprintf(ripeStatURLFmt, asn), 8<<20)
		if err != nil {
			continue
		}
		var doc struct {
			Data struct {
				Prefixes []struct {
					Prefix string `json:"prefix"`
				} `json:"prefixes"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			continue
		}
		for _, p := range doc.Data.Prefixes {
			all = append(all, p.Prefix)
		}
	}
	if len(all) == 0 {
		return nil, errors.New("no RIPEstat prefixes returned")
	}
	return all, nil
}

func readCachedRanges(path string, maxAge time.Duration) (cachedRanges, bool) {
	var c cachedRanges
	data, err := os.ReadFile(path)
	if err != nil {
		return c, false
	}
	if err := json.Unmarshal(data, &c); err != nil {
		return c, false
	}
	if time.Since(c.FetchedAt) > maxAge || len(c.CIDRs) == 0 {
		return c, false
	}
	for _, raw := range c.CIDRs {
		if _, err := netip.ParsePrefix(strings.TrimSpace(raw)); err == nil {
			return c, true
		}
	}
	return c, false
}

func writeCachedRanges(path string, c cachedRanges) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, data, 0o644)
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func httpGetBytes(ctx context.Context, client *http.Client, url string, maxBytes int64) ([]byte, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 45*time.Second)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "fastly-finder/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("response from %s exceeds %d byte limit", url, maxBytes)
	}
	return data, nil
}
