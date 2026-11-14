package main

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// ScanConfig holds all options for a Fastly discovery scan (shared by CLI and Web UI).
type ScanConfig struct {
	Domains         []string      `json:"domains,omitempty"`
	DirectHosts     []string      `json:"hosts,omitempty"`
	InputFile       string        `json:"input_file,omitempty"`
	Global          bool          `json:"global,omitempty"`
	Seeds           []string      `json:"seeds,omitempty"`
	Limit           int           `json:"limit,omitempty"`
	CTEntries       int           `json:"ct_entries,omitempty"`
	WithWWW         bool          `json:"with_www"`
	UseSubfinder    bool          `json:"use_subfinder,omitempty"`
	CIDRFile        string        `json:"cidr_file,omitempty"`
	IncludeBGP      bool          `json:"include_bgp,omitempty"`
	IncludeUpcoming bool          `json:"include_upcoming,omitempty"`
	Resolvers       string        `json:"resolvers,omitempty"`
	UseDoH          bool          `json:"doh,omitempty"`
	DoHURL          string        `json:"doh_url,omitempty"`
	QueryAAAA       bool          `json:"aaaa"`
	DNSWorkers      int           `json:"dns_workers,omitempty"`
	DNSTimeout      time.Duration `json:"-"`
	SkipProbe       bool          `json:"skip_probe,omitempty"`
	ProbeAll        bool          `json:"probe_all,omitempty"`
	EdgeIP          string        `json:"edge_ip,omitempty"`
	HTTPWorkers     int           `json:"http_workers,omitempty"`
	HTTPTimeout     time.Duration `json:"-"`
	OnlyConfirmed   bool          `json:"only_confirmed,omitempty"`
	CacheDir        string        `json:"-"`
	Refresh         bool          `json:"refresh,omitempty"`
	Verbose         bool          `json:"verbose,omitempty"`
}

// ScanEvent reports progress and log updates during a scan.
type ScanEvent struct {
	Stage   string
	Message string
	Done    int
	Total   int
}

// ScanOutcome holds the finished results and summary metrics of one scan.
type ScanOutcome struct {
	Findings        []Finding
	Counts          map[string]int
	RangeSource     string
	V4Prefixes      int
	V6Prefixes      int
	CandidatesCount int
	FastlyDNSCount  int
	Elapsed         time.Duration
}

// RunScan executes the full Fastly discovery and verification pipeline.
func RunScan(ctx context.Context, cfg ScanConfig, emit func(ScanEvent)) (*ScanOutcome, error) {
	if emit == nil {
		emit = func(ScanEvent) {}
	}
	start := time.Now()
	httpClient := &http.Client{Timeout: 30 * time.Second}

	logMsg := func(stage, format string, args ...any) {
		emit(ScanEvent{Stage: stage, Message: fmt.Sprintf(format, args...)})
	}

	// 1. Load Fastly IP ranges.
	logMsg("ranges", "loading Fastly IP ranges...")
	ranges, err := LoadRanges(ctx, httpClient, RangeOptions{
		CIDRFile:        cfg.CIDRFile,
		CacheDir:        cfg.CacheDir,
		IncludeBGP:      cfg.IncludeBGP,
		IncludeUpcoming: cfg.IncludeUpcoming,
		Refresh:         cfg.Refresh,
	})
	if err != nil {
		return nil, fmt.Errorf("loading Fastly ranges: %w", err)
	}
	v4c, v6c := ranges.Count()
	logMsg("ranges", "loaded Fastly ranges (%s): %d IPv4, %d IPv6 prefixes", ranges.Source, v4c, v6c)

	// 2. Collect candidate hosts.
	logMsg("sources", "collecting candidate hostnames...")
	candidates, err := CollectCandidates(ctx, httpClient, SourceOptions{
		Domains:      cfg.Domains,
		DirectHosts:  cfg.DirectHosts,
		InputFile:    cfg.InputFile,
		Global:       cfg.Global,
		Seeds:        cfg.Seeds,
		Limit:        cfg.Limit,
		CTEntries:    cfg.CTEntries,
		WithWWW:      cfg.WithWWW,
		UseSubfinder: cfg.UseSubfinder,
		CacheDir:     cfg.CacheDir,
		Refresh:      cfg.Refresh,
		Verbose:      cfg.Verbose,
		Logf: func(f string, a ...any) {
			logMsg("sources", f, a...)
		},
	})
	if err != nil {
		return nil, fmt.Errorf("collecting candidates: %w", err)
	}
	outcome := &ScanOutcome{
		Counts:          make(map[string]int),
		RangeSource:     ranges.Source,
		V4Prefixes:      v4c,
		V6Prefixes:      v6c,
		CandidatesCount: len(candidates),
	}
	if len(candidates) == 0 {
		logMsg("done", "no valid candidate hostnames collected")
		outcome.Elapsed = time.Since(start)
		return outcome, nil
	}
	logMsg("sources", "collected %d unique candidate hostnames", len(candidates))

	// 3. Bulk DNS resolution + CNAME/IP matching.
	hostList := make([]string, len(candidates))
	for i, c := range candidates {
		hostList[i] = c.Host
	}
	dnsOpts := DNSOptions{
		Resolvers: ParseResolvers(cfg.Resolvers),
		UseDoH:    cfg.UseDoH,
		DoHURL:    cfg.DoHURL,
		QueryAAAA: cfg.QueryAAAA,
		Workers:   cfg.DNSWorkers,
		Timeout:   cfg.DNSTimeout,
		Retries:   1,
	}
	dnsResults := ResolveAll(ctx, hostList, ranges, dnsOpts, httpClient, func(done, total int) {
		emit(ScanEvent{
			Stage:   "dns",
			Message: fmt.Sprintf("dns progress: %d/%d", done, total),
			Done:    done,
			Total:   total,
		})
	})

	for _, r := range dnsResults {
		if r.OnFastlyDNS {
			outcome.FastlyDNSCount++
		}
	}
	logMsg("dns", "DNS matched %d/%d hosts on Fastly CNAMEs/CIDRs", outcome.FastlyDNSCount, len(hostList))

	// 4. Verify via Fastly-Debug headers + direct-IP SNI/Host probe.
	findings := VerifyHosts(ctx, candidates, dnsResults, ProbeOptions{
		Workers:  cfg.HTTPWorkers,
		Timeout:  cfg.HTTPTimeout,
		EdgeIP:   cfg.EdgeIP,
		Skip:     cfg.SkipProbe,
		ProbeAll: cfg.ProbeAll,
	}, func(done, total int) {
		emit(ScanEvent{
			Stage:   "probe",
			Message: fmt.Sprintf("probe progress: %d/%d", done, total),
			Done:    done,
			Total:   total,
		})
	})

	for _, f := range findings {
		outcome.Counts[f.Status]++
		if cfg.OnlyConfirmed && f.Status != "confirmed" {
			continue
		}
		if f.Status == "not_fastly" && !cfg.ProbeAll {
			continue
		}
		outcome.Findings = append(outcome.Findings, f)
	}
	outcome.Elapsed = time.Since(start)
	logMsg("done", "done in %s | confirmed=%d headers_hidden=%d unknown_domain=%d unreachable=%d fastly_dns=%d",
		outcome.Elapsed.Round(time.Millisecond),
		outcome.Counts["confirmed"],
		outcome.Counts["fastly_dns_headers_hidden"],
		outcome.Counts["unknown_domain"],
		outcome.Counts["dns_only_unreachable"],
		outcome.Counts["fastly_dns"],
	)
	return outcome, nil
}
