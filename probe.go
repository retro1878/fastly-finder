package main

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Finding is the final per-host output record combining DNS, HTTP headers, and edge SNI probe.
type Finding struct {
	Host             string            `json:"host"`
	Status           string            `json:"status"`
	Sources          []string          `json:"sources,omitempty"`
	CNAMEs           []string          `json:"cnames,omitempty"`
	FastlyCNAMEs     []string          `json:"fastly_cnames,omitempty"`
	IPs              []string          `json:"ips,omitempty"`
	FastlyIPs        []string          `json:"fastly_ips,omitempty"`
	HTTPStatus       int               `json:"http_status,omitempty"`
	HTTPScheme       string            `json:"http_scheme,omitempty"`
	FastlyHeaders    map[string]string `json:"fastly_headers,omitempty"`
	TLSIssuer        string            `json:"tls_issuer,omitempty"`
	TLSSubject       string            `json:"tls_subject,omitempty"`
	EdgeIPTested     string            `json:"edge_ip_tested,omitempty"`
	EdgeHTTPStatus   int               `json:"edge_http_status,omitempty"`
	EdgeSNICertMatch bool              `json:"edge_sni_cert_match,omitempty"`
	EdgeTLSIssuer    string            `json:"edge_tls_issuer,omitempty"`
	EdgeUnknownDom   bool              `json:"edge_unknown_domain,omitempty"`
	ProbeError       string            `json:"probe_error,omitempty"`
}

// ProbeOptions controls active HTTP/TLS verification.
type ProbeOptions struct {
	Workers  int
	Timeout  time.Duration
	EdgeIP   string
	Skip     bool
	ProbeAll bool
}

type httpProbeOutcome struct {
	statusCode    int
	scheme        string
	headers       map[string]string
	hasFastlyHdr  bool
	unknownDomain bool
	tlsIssuer     string
	tlsSubject    string
	certMatch     bool
	errStr        string
}

var fastlyHeaderNames = []string{
	"X-Served-By",
	"X-Cache",
	"X-Cache-Hits",
	"X-Timer",
	"Via",
	"Fastly-Debug-Path",
	"Fastly-Debug-TTL",
	"Fastly-Debug-Digest",
}

// VerifyHosts runs HTTP Fastly-Debug header checks and direct-IP edge SNI/Host probes.
func VerifyHosts(ctx context.Context, candidates []Candidate, dnsResults []DNSResult, opts ProbeOptions, onProgress func(done, total int)) []Finding {
	srcMap := make(map[string][]string, len(candidates))
	for _, c := range candidates {
		srcMap[c.Host] = c.Sources
	}

	var targets []DNSResult
	for _, dr := range dnsResults {
		if dr.Host == "" {
			continue
		}
		if dr.OnFastlyDNS || opts.ProbeAll {
			targets = append(targets, dr)
		}
	}
	if len(targets) == 0 {
		return nil
	}

	findings := make([]Finding, len(targets))
	if opts.Skip {
		for i, dr := range targets {
			findings[i] = Finding{
				Host:         dr.Host,
				Status:       "fastly_dns",
				Sources:      srcMap[dr.Host],
				CNAMEs:       dr.CNAMEs,
				FastlyCNAMEs: dr.FastlyCNAMEs,
				IPs:          dr.IPs,
				FastlyIPs:    dr.FastlyIPs,
			}
		}
		return findings
	}

	workers := opts.Workers
	if workers <= 0 {
		workers = 40
	}
	if workers > len(targets) && len(targets) > 0 {
		workers = len(targets)
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	edgeFallback := opts.EdgeIP
	if edgeFallback == "" {
		edgeFallback = defaultEdgeIP
	}

	jobs := make(chan int, workers*2)
	var done atomic.Int64
	var wg sync.WaitGroup

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				if ctx.Err() != nil {
					return
				}
				dr := targets[idx]
				findings[idx] = verifyOne(ctx, dr, srcMap[dr.Host], edgeFallback, timeout)
				n := int(done.Add(1))
				if onProgress != nil && (n%50 == 0 || n == len(targets)) {
					onProgress(n, len(targets))
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for i := range targets {
			select {
			case <-ctx.Done():
				return
			case jobs <- i:
			}
		}
	}()

	wg.Wait()
	if ctx.Err() != nil {
		filtered := findings[:0]
		for _, f := range findings {
			if f.Host != "" {
				filtered = append(filtered, f)
			}
		}
		return filtered
	}
	return findings
}

func isPublicUnicastIP(s string) bool {
	ip, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	return ip.IsValid() && ip.IsGlobalUnicast() && !ip.IsPrivate()
}

func verifyOne(ctx context.Context, dr DNSResult, sources []string, edgeFallback string, timeout time.Duration) Finding {
	f := Finding{
		Host:         dr.Host,
		Sources:      sources,
		CNAMEs:       dr.CNAMEs,
		FastlyCNAMEs: dr.FastlyCNAMEs,
		IPs:          dr.IPs,
		FastlyIPs:    dr.FastlyIPs,
	}

	// Fastly-DNS hosts with resolved Fastly IP(s) can be probed once directly against
	// their verified Fastly IP (honoring --doh/--resolvers and preventing SSRF).
	if dr.OnFastlyDNS && len(dr.FastlyIPs) > 0 {
		edgeIP := dr.FastlyIPs[0]
		edge := probeAtIP(ctx, dr.Host, edgeIP, timeout)
		if edge.statusCode == 0 && edgeIP != edgeFallback {
			if addr, err := netip.ParseAddr(edgeIP); err == nil && addr.Unmap().Is6() {
				if fb := probeAtIP(ctx, dr.Host, edgeFallback, timeout); fb.statusCode > 0 {
					edge = fb
					edgeIP = edgeFallback
				}
			}
		}
		f.HTTPStatus = edge.statusCode
		f.HTTPScheme = edge.scheme
		f.FastlyHeaders = edge.headers
		f.TLSIssuer = edge.tlsIssuer
		f.TLSSubject = edge.tlsSubject
		f.EdgeIPTested = edgeIP
		f.EdgeHTTPStatus = edge.statusCode
		f.EdgeSNICertMatch = edge.certMatch
		f.EdgeTLSIssuer = edge.tlsIssuer
		f.EdgeUnknownDom = edge.unknownDomain
		f.ProbeError = edge.errStr
		f.Status = classifyFinding(true, edge, edge)
		return f
	}

	// CNAME-only Fastly DNS or --probe-all: probe the resolved public IP (if any) and the fallback edge IP.
	var live httpProbeOutcome
	liveIP := ""
	for _, ip := range dr.IPs {
		if isPublicUnicastIP(ip) {
			liveIP = ip
			break
		}
	}
	if liveIP != "" {
		live = probeAtIP(ctx, dr.Host, liveIP, timeout)
	}

	edge := probeAtIP(ctx, dr.Host, edgeFallback, timeout)

	f.HTTPStatus = live.statusCode
	f.HTTPScheme = live.scheme
	f.FastlyHeaders = live.headers
	f.TLSIssuer = live.tlsIssuer
	f.TLSSubject = live.tlsSubject
	if f.HTTPStatus == 0 && edge.statusCode > 0 {
		f.HTTPStatus = edge.statusCode
		f.HTTPScheme = edge.scheme
		f.TLSIssuer = edge.tlsIssuer
		f.TLSSubject = edge.tlsSubject
	}
	if len(f.FastlyHeaders) == 0 && len(edge.headers) > 0 {
		f.FastlyHeaders = edge.headers
	}

	f.EdgeIPTested = edgeFallback
	f.EdgeHTTPStatus = edge.statusCode
	f.EdgeSNICertMatch = edge.certMatch
	f.EdgeTLSIssuer = edge.tlsIssuer
	f.EdgeUnknownDom = live.unknownDomain || edge.unknownDomain
	if (liveIP == "" || live.errStr != "") && edge.errStr != "" {
		if live.errStr != "" {
			f.ProbeError = live.errStr
		} else {
			f.ProbeError = edge.errStr
		}
	}

	f.Status = classifyFinding(dr.OnFastlyDNS, live, edge)
	return f
}

func classifyFinding(onFastlyDNS bool, live, edge httpProbeOutcome) string {
	if live.unknownDomain || (onFastlyDNS && !live.hasFastlyHdr && edge.unknownDomain) {
		return "unknown_domain"
	}
	edgePositive := !edge.unknownDomain && (edge.hasFastlyHdr || (edge.certMatch && edge.statusCode > 0 && edge.statusCode != http.StatusMisdirectedRequest))
	if live.hasFastlyHdr || edgePositive {
		if onFastlyDNS || live.hasFastlyHdr {
			return "confirmed"
		}
		// Host's public DNS points elsewhere, yet Fastly edge recognizes Host/SNI.
		return "edge_configured_off_dns"
	}
	if onFastlyDNS {
		if live.statusCode > 0 || edge.statusCode > 0 {
			return "fastly_dns_headers_hidden"
		}
		return "dns_only_unreachable"
	}
	return "not_fastly"
}

func probeAtIP(ctx context.Context, host, ip string, timeout time.Duration) httpProbeOutcome {
	dialer := &net.Dialer{Timeout: timeout}
	tr := &http.Transport{
		DialContext: func(dCtx context.Context, network, addr string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(addr)
			if err != nil || port == "" {
				port = "443"
			}
			return dialer.DialContext(dCtx, network, net.JoinHostPort(ip, port))
		},
		TLSClientConfig: &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true, // Inspect peer cert directly without failing on origin/default mismatch.
		},
		DisableKeepAlives: true,
	}
	defer tr.CloseIdleConnections()

	client := &http.Client{
		Transport:     tr,
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	res := doFastlyHTTPProbe(ctx, client, "https://"+host+"/", host)
	if res.statusCode > 0 {
		res.scheme = "https"
		if res.statusCode == http.StatusMisdirectedRequest && !res.certMatch {
			res.hasFastlyHdr = false
		} else {
			return res
		}
	}

	httpRes := doFastlyHTTPProbe(ctx, client, "http://"+host+"/", host)
	if httpRes.statusCode > 0 {
		httpRes.scheme = "http"
		return httpRes
	}
	return res
}

func doFastlyHTTPProbe(ctx context.Context, client *http.Client, targetURL, host string) httpProbeOutcome {
	var out httpProbeOutcome
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		out.errStr = err.Error()
		return out
	}
	req.Host = host
	req.Header.Set("User-Agent", "fastly-finder/1.0")
	req.Header.Set("Fastly-Debug", "1")

	resp, err := client.Do(req)
	if err != nil {
		out.errStr = err.Error()
		return out
	}
	defer resp.Body.Close()

	out.statusCode = resp.StatusCode
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		leaf := resp.TLS.PeerCertificates[0]
		out.tlsIssuer = leaf.Issuer.CommonName
		if out.tlsIssuer == "" && len(leaf.Issuer.Organization) > 0 {
			out.tlsIssuer = leaf.Issuer.Organization[0]
		}
		out.tlsSubject = leaf.Subject.CommonName
		out.certMatch = leaf.VerifyHostname(host) == nil
	}

	hdrs := make(map[string]string)
	for _, name := range fastlyHeaderNames {
		if vals := resp.Header.Values(name); len(vals) > 0 {
			hdrs[name] = strings.Join(vals, ", ")
		}
	}
	if len(hdrs) > 0 {
		out.headers = hdrs
		out.hasFastlyHdr = hasStrongFastlySignal(hdrs)
	}

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
	if strings.Contains(string(bodyBytes), "Fastly error: unknown domain") {
		out.unknownDomain = true
	}
	if out.unknownDomain || (out.statusCode == http.StatusMisdirectedRequest && !out.certMatch) {
		out.hasFastlyHdr = false
	}
	return out
}

func hasStrongFastlySignal(hdrs map[string]string) bool {
	if sb, ok := hdrs["X-Served-By"]; ok && strings.Contains(strings.ToLower(sb), "cache-") {
		return true
	}
	for _, k := range []string{"Fastly-Debug-Path", "Fastly-Debug-TTL", "Fastly-Debug-Digest"} {
		if _, ok := hdrs[k]; ok {
			return true
		}
	}
	if xt, ok := hdrs["X-Timer"]; ok && strings.HasPrefix(xt, "S") && strings.Contains(xt, ",VS") {
		return true
	}
	if via, ok := hdrs["Via"]; ok && strings.Contains(strings.ToLower(via), "varnish") {
		if _, hasCache := hdrs["X-Cache"]; hasCache {
			return true
		}
	}
	return false
}
