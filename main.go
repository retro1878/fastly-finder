package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("fastly-finder", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var (
		domain          = fs.String("d", "", "target apex domain to enumerate (e.g. example.com)")
		domainsFile     = fs.String("D", "", "file of target domains (one per line)")
		inputFile       = fs.String("i", "", "file of candidate hostnames ('-' for stdin)")
		globalMode      = fs.Bool("global", false, "enable global Fastly discovery using free seed lists and CT")
		seedSpec        = fs.String("seed", "tranco,ct-fastly", "comma-separated global seeds: tranco,umbrella,majestic,crux,chaos,ct-fastly,ct-logs,all")
		limit           = fs.Int("limit", 50000, "max entries per global seed list (0 = all)")
		ctEntries       = fs.Int("ct-entries", 3000, "recent certificates to scan per CT log for ct-fastly/ct-logs")
		withWWW         = fs.Bool("with-www", true, "also test www.<domain> for apex-only global seeds")
		useSubfinder    = fs.Bool("use-subfinder", false, "also invoke local subfinder binary if installed")
		cidrFile        = fs.String("cidr-file", "", "load Fastly CIDRs from local file instead of remote API")
		includeBGP      = fs.Bool("include-bgp", false, "also include RIPEstat AS54113/AS394192 announced prefixes")
		includeUpcoming = fs.Bool("include-upcoming", false, "include Fastly Jan 2027 announced prefixes")
		resolversSpec   = fs.String("resolvers", "1.1.1.1:53,8.8.8.8:53,9.9.9.9:53", "comma-separated DNS servers or 'system'")
		useDoH          = fs.Bool("doh", false, "resolve via DNS-over-HTTPS instead of UDP/53")
		dohURL          = fs.String("doh-url", "https://dns.google/resolve", "DNS-over-HTTPS JSON endpoint")
		queryAAAA       = fs.Bool("aaaa", true, "query AAAA records in addition to A/CNAME")
		dnsWorkers      = fs.Int("dns-workers", 150, "concurrent DNS workers")
		dnsTimeout      = fs.Duration("dns-timeout", 3*time.Second, "per-DNS query timeout")
		skipProbe       = fs.Bool("skip-probe", false, "skip HTTP/TLS verification (DNS/CIDR matching only)")
		probeAll        = fs.Bool("probe-all", false, "probe all candidates even if DNS is not on Fastly")
		edgeIP          = fs.String("edge-ip", defaultEdgeIP, "fallback Fastly edge IP for direct SNI/Host probe")
		httpWorkers     = fs.Int("http-workers", 40, "concurrent HTTP/TLS probe workers")
		httpTimeout     = fs.Duration("http-timeout", 8*time.Second, "per-HTTP/TLS probe timeout")
		outFile         = fs.String("o", "", "output file path (default stdout)")
		format          = fs.String("format", "auto", "output format: auto, table, jsonl, csv, txt")
		onlyConfirmed   = fs.Bool("only-confirmed", false, "only output confirmed Fastly hosts")
		cacheDir        = fs.String("cache-dir", defaultCacheDir(), "cache directory for ranges and seed lists")
		refresh         = fs.Bool("refresh", false, "force refresh of cached ranges and seed lists")
		verbose         = fs.Bool("v", false, "verbose logging on stderr")
	)

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "fastly-finder: free, zero-subscription Fastly CDN domain/subdomain discovery\n\nUsage:\n")
		fmt.Fprintf(os.Stderr, "  fastly-finder -d example.com\n")
		fmt.Fprintf(os.Stderr, "  fastly-finder --global --seed tranco,ct-fastly --limit 50000 -o fastly.jsonl\n")
		fmt.Fprintf(os.Stderr, "  fastly-finder -i hosts.txt --format csv\n\nFlags:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}

	if *domain == "" && *domainsFile == "" && *inputFile == "" && !*globalMode {
		fs.Usage()
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logf := func(f string, a ...any) {
		fmt.Fprintf(os.Stderr, "[*] "+f+"\n", a...)
	}

	httpClient := &http.Client{Timeout: 30 * time.Second}
	start := time.Now()

	// 1. Load Fastly IP ranges.
	ranges, err := LoadRanges(ctx, httpClient, RangeOptions{
		CIDRFile:        *cidrFile,
		CacheDir:        *cacheDir,
		IncludeBGP:      *includeBGP,
		IncludeUpcoming: *includeUpcoming,
		Refresh:         *refresh,
	})
	if err != nil {
		logf("error loading Fastly ranges: %v", err)
		return 1
	}
	v4c, v6c := ranges.Count()
	logf("loaded Fastly ranges (%s): %d IPv4, %d IPv6 prefixes", ranges.Source, v4c, v6c)

	// 2. Collect candidate hosts.
	var targetDomains []string
	if *domain != "" {
		targetDomains = append(targetDomains, *domain)
	}
	if *domainsFile != "" {
		loaded, err := readLines(*domainsFile)
		if err != nil {
			logf("error reading -D %s: %v", *domainsFile, err)
			return 1
		}
		targetDomains = append(targetDomains, loaded...)
	}

	var seeds []string
	for _, s := range strings.Split(*seedSpec, ",") {
		if t := strings.TrimSpace(s); t != "" {
			seeds = append(seeds, t)
		}
	}

	candidates, err := CollectCandidates(ctx, httpClient, SourceOptions{
		Domains:      targetDomains,
		InputFile:    *inputFile,
		Global:       *globalMode,
		Seeds:        seeds,
		Limit:        *limit,
		CTEntries:    *ctEntries,
		WithWWW:      *withWWW,
		UseSubfinder: *useSubfinder,
		CacheDir:     *cacheDir,
		Refresh:      *refresh,
		Verbose:      *verbose,
		Logf:         logf,
	})
	if err != nil {
		logf("error collecting candidates: %v", err)
		return 1
	}
	if len(candidates) == 0 {
		logf("no valid candidate hostnames collected")
		return 0
	}
	logf("collected %d unique candidate hostnames", len(candidates))

	// 3. Bulk DNS resolution + CNAME/IP matching.
	hostList := make([]string, len(candidates))
	for i, c := range candidates {
		hostList[i] = c.Host
	}
	dnsOpts := DNSOptions{
		Resolvers: ParseResolvers(*resolversSpec),
		UseDoH:    *useDoH,
		DoHURL:    *dohURL,
		QueryAAAA: *queryAAAA,
		Workers:   *dnsWorkers,
		Timeout:   *dnsTimeout,
		Retries:   1,
	}
	dnsResults := ResolveAll(ctx, hostList, ranges, dnsOpts, httpClient, func(done, total int) {
		if *verbose || total >= 2000 {
			logf("dns progress: %d/%d", done, total)
		}
	})

	fastlyDNSCount := 0
	for _, r := range dnsResults {
		if r.OnFastlyDNS {
			fastlyDNSCount++
		}
	}
	logf("DNS matched %d/%d hosts on Fastly CNAMEs/CIDRs", fastlyDNSCount, len(hostList))

	// 4. Verify via Fastly-Debug headers + direct-IP SNI/Host probe.
	findings := VerifyHosts(ctx, candidates, dnsResults, ProbeOptions{
		Workers:  *httpWorkers,
		Timeout:  *httpTimeout,
		EdgeIP:   *edgeIP,
		Skip:     *skipProbe,
		ProbeAll: *probeAll,
	}, func(done, total int) {
		if *verbose || total >= 100 {
			logf("probe progress: %d/%d", done, total)
		}
	})

	// 5. Filter & write output.
	var filtered []Finding
	counts := make(map[string]int)
	for _, f := range findings {
		counts[f.Status]++
		if *onlyConfirmed && f.Status != "confirmed" {
			continue
		}
		if f.Status == "not_fastly" && !*probeAll {
			continue
		}
		filtered = append(filtered, f)
	}

	var out io.Writer = os.Stdout
	isTTY := false
	if *outFile != "" {
		f, err := os.Create(*outFile)
		if err != nil {
			logf("error creating output %s: %v", *outFile, err)
			return 1
		}
		defer f.Close()
		out = f
	} else if st, err := os.Stdout.Stat(); err == nil && (st.Mode()&os.ModeCharDevice) != 0 {
		isTTY = true
	}

	resolvedFmt := resolveOutputFormat(*format, *outFile, isTTY)
	if err := writeFindings(out, resolvedFmt, filtered); err != nil {
		logf("error writing output: %v", err)
		return 1
	}

	logf("done in %s | confirmed=%d headers_hidden=%d unknown_domain=%d unreachable=%d fastly_dns=%d",
		time.Since(start).Round(time.Millisecond),
		counts["confirmed"],
		counts["fastly_dns_headers_hidden"],
		counts["unknown_domain"],
		counts["dns_only_unreachable"],
		counts["fastly_dns"],
	)
	return 0
}

func resolveOutputFormat(requested, outFile string, isTTY bool) string {
	f := strings.ToLower(strings.TrimSpace(requested))
	if f != "" && f != "auto" {
		return f
	}
	if outFile != "" {
		switch strings.ToLower(filepath.Ext(outFile)) {
		case ".csv":
			return "csv"
		case ".txt":
			return "txt"
		case ".table", ".tsv":
			return "table"
		default:
			return "jsonl"
		}
	}
	if isTTY {
		return "table"
	}
	return "jsonl"
}

func writeFindings(w io.Writer, format string, findings []Finding) error {
	bw := bufio.NewWriter(w)
	defer bw.Flush()

	switch strings.ToLower(strings.TrimSpace(format)) {
	case "table":
		tw := tabwriter.NewWriter(bw, 0, 0, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "HOST\tSTATUS\tHTTP\tSNI\tFASTLY_IP\tCNAME\tX-SERVED-BY\tTLS_ISSUER\tSOURCES")
		for _, f := range findings {
			httpStr := "-"
			if f.HTTPStatus > 0 {
				httpStr = fmt.Sprintf("%d", f.HTTPStatus)
			}
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%t\t%s\t%s\t%s\t%s\t%s\n",
				f.Host,
				f.Status,
				httpStr,
				f.EdgeSNICertMatch,
				firstOrDash(f.FastlyIPs),
				firstOrDash(f.FastlyCNAMEs),
				truncateStr(strOrDash(f.FastlyHeaders["X-Served-By"]), 28),
				truncateStr(strOrDash(f.TLSIssuer), 28),
				strOrDash(strings.Join(f.Sources, ",")),
			)
		}
		return tw.Flush()
	case "jsonl", "json":
		enc := json.NewEncoder(bw)
		for _, f := range findings {
			if err := enc.Encode(f); err != nil {
				return err
			}
		}
	case "txt":
		for _, f := range findings {
			if _, err := fmt.Fprintln(bw, f.Host); err != nil {
				return err
			}
		}
	case "csv":
		cw := csv.NewWriter(bw)
		_ = cw.Write([]string{
			"host", "status", "fastly_cnames", "fastly_ips", "http_status",
			"x_served_by", "tls_issuer", "edge_ip_tested", "edge_sni_cert_match", "sources",
		})
		for _, f := range findings {
			_ = cw.Write([]string{
				f.Host,
				f.Status,
				strings.Join(f.FastlyCNAMEs, ";"),
				strings.Join(f.FastlyIPs, ";"),
				fmt.Sprintf("%d", f.HTTPStatus),
				f.FastlyHeaders["X-Served-By"],
				f.TLSIssuer,
				f.EdgeIPTested,
				fmt.Sprintf("%t", f.EdgeSNICertMatch),
				strings.Join(f.Sources, ";"),
			})
		}
		cw.Flush()
		return cw.Error()
	default:
		return fmt.Errorf("unsupported format %q (use auto, table, jsonl, csv, txt)", format)
	}
	return nil
}

func firstOrDash(items []string) string {
	if len(items) == 0 || items[0] == "" {
		return "-"
	}
	return items[0]
}

func strOrDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func truncateStr(s string, max int) string {
	if max <= 3 || len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return lines, sc.Err()
}

func defaultCacheDir() string {
	if dir, err := os.UserCacheDir(); err == nil && dir != "" {
		return filepath.Join(dir, "fastly-finder")
	}
	return filepath.Join(os.TempDir(), "fastly-finder")
}
