package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	dnsTypeA     uint16 = 1
	dnsTypeCNAME uint16 = 5
	dnsTypeAAAA  uint16 = 28
	dnsClassIN   uint16 = 1
)

// DNSResult holds resolved records and Fastly classification for one host.
type DNSResult struct {
	Host         string   `json:"host"`
	CNAMEs       []string `json:"cnames,omitempty"`
	FastlyCNAMEs []string `json:"fastly_cnames,omitempty"`
	IPs          []string `json:"ips,omitempty"`
	FastlyIPs    []string `json:"fastly_ips,omitempty"`
	OnFastlyDNS  bool     `json:"on_fastly_dns"`
	Error        string   `json:"dns_error,omitempty"`
}

// DNSOptions configures concurrent DNS resolution.
type DNSOptions struct {
	Resolvers []string
	UseDoH    bool
	DoHURL    string
	QueryAAAA bool
	Workers   int
	Timeout   time.Duration
	Retries   int
}

// ParseResolvers splits a comma-separated list of DNS resolvers and ensures :53 port.
func ParseResolvers(spec string) []string {
	spec = strings.TrimSpace(spec)
	if spec == "" || strings.EqualFold(spec, "system") {
		if sys := readSystemResolvers(); len(sys) > 0 {
			return sys
		}
		return []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"}
	}
	var out []string
	for _, part := range strings.Split(spec, ",") {
		p := strings.TrimSpace(part)
		if p == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(p); err != nil {
			p = net.JoinHostPort(p, "53")
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"}
	}
	return out
}

func readSystemResolvers() []string {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" {
			if ip, err := netip.ParseAddr(fields[1]); err == nil {
				out = append(out, net.JoinHostPort(ip.String(), "53"))
			}
		}
	}
	return out
}

// ResolveAll resolves all hosts concurrently and tags Fastly CNAMEs and Fastly IPs.
func ResolveAll(ctx context.Context, hosts []string, ranges *RangeSet, opts DNSOptions, httpClient *http.Client, onProgress func(done, total int)) []DNSResult {
	if len(hosts) == 0 {
		return nil
	}
	workers := opts.Workers
	if workers <= 0 {
		workers = 100
	}
	if workers > len(hosts) {
		workers = len(hosts)
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 3 * time.Second
	}
	if opts.Retries < 0 {
		opts.Retries = 1
	}

	results := make([]DNSResult, len(hosts))
	type job struct {
		idx  int
		host string
	}
	jobs := make(chan job, workers*2)
	var done atomic.Int64
	var wg sync.WaitGroup
	var rrCounter atomic.Uint64

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if ctx.Err() != nil {
					return
				}
				res := resolveOne(ctx, j.host, ranges, opts, httpClient, &rrCounter)
				results[j.idx] = res
				n := int(done.Add(1))
				if onProgress != nil && (n%500 == 0 || n == len(hosts)) {
					onProgress(n, len(hosts))
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for i, h := range hosts {
			select {
			case <-ctx.Done():
				return
			case jobs <- job{idx: i, host: h}:
			}
		}
	}()

	wg.Wait()
	if ctx.Err() != nil {
		filtered := results[:0]
		for _, r := range results {
			if r.Host != "" {
				filtered = append(filtered, r)
			}
		}
		return filtered
	}
	return results
}

func resolveOne(ctx context.Context, host string, ranges *RangeSet, opts DNSOptions, httpClient *http.Client, rr *atomic.Uint64) DNSResult {
	res := DNSResult{Host: host}
	cnameSet := make(map[string]struct{})
	ipSet := make(map[netip.Addr]struct{})
	var firstErr error

	qtypes := []uint16{dnsTypeA}
	if opts.QueryAAAA {
		qtypes = append(qtypes, dnsTypeAAAA)
	}

	for _, qt := range qtypes {
		var cnames []string
		var ips []netip.Addr
		var err error
		if opts.UseDoH {
			cnames, ips, err = queryDoHWithRetries(ctx, httpClient, opts.DoHURL, host, qt, opts.Timeout, opts.Retries)
		} else {
			cnames, ips, err = queryWireWithRetries(ctx, host, qt, opts, rr)
		}
		if err != nil && firstErr == nil {
			firstErr = err
		}
		for _, c := range cnames {
			cnameSet[c] = struct{}{}
		}
		for _, ip := range ips {
			ipSet[ip.Unmap()] = struct{}{}
		}
	}

	for c := range cnameSet {
		res.CNAMEs = append(res.CNAMEs, c)
		if IsFastlyCNAME(c) {
			res.FastlyCNAMEs = append(res.FastlyCNAMEs, c)
			res.OnFastlyDNS = true
		}
	}
	sort.Strings(res.CNAMEs)
	sort.Strings(res.FastlyCNAMEs)

	ipList := make([]netip.Addr, 0, len(ipSet))
	for ip := range ipSet {
		ipList = append(ipList, ip)
	}
	sort.Slice(ipList, func(i, j int) bool {
		if ipList[i].Is4() != ipList[j].Is4() {
			return ipList[i].Is4()
		}
		return ipList[i].Compare(ipList[j]) < 0
	})
	for _, ip := range ipList {
		s := ip.String()
		res.IPs = append(res.IPs, s)
		if ranges != nil && ranges.Contains(ip) {
			res.FastlyIPs = append(res.FastlyIPs, s)
			res.OnFastlyDNS = true
		}
	}
	if len(res.CNAMEs) == 0 && len(res.IPs) == 0 && firstErr != nil {
		res.Error = firstErr.Error()
	}
	return res
}

func queryWireWithRetries(ctx context.Context, host string, qtype uint16, opts DNSOptions, rr *atomic.Uint64) ([]string, []netip.Addr, error) {
	if len(opts.Resolvers) == 0 {
		return nil, nil, errors.New("no DNS resolvers configured")
	}
	var lastErr error
	attempts := opts.Retries + 1
	for i := 0; i < attempts; i++ {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		idx := rr.Add(1) % uint64(len(opts.Resolvers))
		resolver := opts.Resolvers[idx]
		cnames, ips, err := queryDNSWire(ctx, resolver, host, qtype, opts.Timeout)
		if err == nil {
			return cnames, ips, nil
		}
		lastErr = err
	}
	return nil, nil, lastErr
}

func queryDNSWire(ctx context.Context, resolver, host string, qtype uint16, timeout time.Duration) ([]string, []netip.Addr, error) {
	id, pkt, err := buildDNSQuery(host, qtype)
	if err != nil {
		return nil, nil, err
	}
	resp, truncated, err := exchangeUDP(ctx, resolver, pkt, timeout)
	if err != nil {
		return nil, nil, err
	}
	if truncated {
		resp, err = exchangeTCP(ctx, resolver, pkt, timeout)
		if err != nil {
			return nil, nil, err
		}
	}
	return parseDNSResponse(resp, id)
}

func deadlineFor(ctx context.Context, timeout time.Duration) time.Time {
	dl := time.Now().Add(timeout)
	if cdl, ok := ctx.Deadline(); ok && cdl.Before(dl) {
		return cdl
	}
	return dl
}

func exchangeUDP(ctx context.Context, resolver string, pkt []byte, timeout time.Duration) ([]byte, bool, error) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "udp", resolver)
	if err != nil {
		return nil, false, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()
	_ = conn.SetDeadline(deadlineFor(ctx, timeout))
	if _, err := conn.Write(pkt); err != nil {
		return nil, false, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, false, err
	}
	if n < 12 {
		return nil, false, errors.New("short DNS response")
	}
	flags := binary.BigEndian.Uint16(buf[2:4])
	truncated := (flags & 0x0200) != 0
	return buf[:n], truncated, nil
}

func exchangeTCP(ctx context.Context, resolver string, pkt []byte, timeout time.Duration) ([]byte, error) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", resolver)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()
	_ = conn.SetDeadline(deadlineFor(ctx, timeout))

	frame := make([]byte, 2+len(pkt))
	binary.BigEndian.PutUint16(frame[0:2], uint16(len(pkt)))
	copy(frame[2:], pkt)
	if _, err := conn.Write(frame); err != nil {
		return nil, err
	}
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	msgLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if msgLen < 12 || msgLen > 65535 {
		return nil, errors.New("invalid TCP DNS length")
	}
	resp := make([]byte, msgLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func buildDNSQuery(host string, qtype uint16) (uint16, []byte, error) {
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	if host == "" || len(host) > 253 {
		return 0, nil, fmt.Errorf("invalid hostname %q", host)
	}
	var idBuf [2]byte
	if _, err := rand.Read(idBuf[:]); err != nil {
		return 0, nil, err
	}
	id := binary.BigEndian.Uint16(idBuf[:])

	buf := make([]byte, 12, 64)
	binary.BigEndian.PutUint16(buf[0:2], id)
	binary.BigEndian.PutUint16(buf[2:4], 0x0100) // RD=1
	binary.BigEndian.PutUint16(buf[4:6], 1)      // QDCOUNT=1

	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 {
			return 0, nil, fmt.Errorf("invalid DNS label in %q", host)
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	buf = append(buf, 0) // root label

	tail := make([]byte, 4)
	binary.BigEndian.PutUint16(tail[0:2], qtype)
	binary.BigEndian.PutUint16(tail[2:4], dnsClassIN)
	buf = append(buf, tail...)
	return id, buf, nil
}

func parseDNSResponse(msg []byte, expectedID uint16) ([]string, []netip.Addr, error) {
	if len(msg) < 12 {
		return nil, nil, errors.New("short DNS packet")
	}
	id := binary.BigEndian.Uint16(msg[0:2])
	if id != expectedID {
		return nil, nil, errors.New("mismatched DNS transaction ID")
	}
	flags := binary.BigEndian.Uint16(msg[2:4])
	rcode := flags & 0x000F
	if rcode != 0 && rcode != 3 {
		return nil, nil, fmt.Errorf("dns rcode %d", rcode)
	}

	qdCount := int(binary.BigEndian.Uint16(msg[4:6]))
	anCount := int(binary.BigEndian.Uint16(msg[6:8]))
	off := 12

	for i := 0; i < qdCount; i++ {
		_, next, err := readDNSName(msg, off)
		if err != nil {
			return nil, nil, err
		}
		off = next + 4
		if off > len(msg) {
			return nil, nil, errors.New("truncated DNS question")
		}
	}

	var cnames []string
	var ips []netip.Addr
	for i := 0; i < anCount; i++ {
		_, next, err := readDNSName(msg, off)
		if err != nil {
			return cnames, ips, err
		}
		if next+10 > len(msg) {
			return cnames, ips, errors.New("truncated DNS RR header")
		}
		rtype := binary.BigEndian.Uint16(msg[next : next+2])
		rclass := binary.BigEndian.Uint16(msg[next+2 : next+4])
		rdlen := int(binary.BigEndian.Uint16(msg[next+8 : next+10]))
		rdataStart := next + 10
		rdataEnd := rdataStart + rdlen
		if rdataEnd > len(msg) {
			return cnames, ips, errors.New("truncated DNS rdata")
		}
		if rclass == dnsClassIN {
			switch rtype {
			case dnsTypeCNAME:
				target, _, err := readDNSName(msg, rdataStart)
				if err == nil && target != "" {
					cnames = append(cnames, strings.ToLower(target))
				}
			case dnsTypeA:
				if rdlen == 4 {
					var b [4]byte
					copy(b[:], msg[rdataStart:rdataEnd])
					ips = append(ips, netip.AddrFrom4(b))
				}
			case dnsTypeAAAA:
				if rdlen == 16 {
					var b [16]byte
					copy(b[:], msg[rdataStart:rdataEnd])
					ips = append(ips, netip.AddrFrom16(b))
				}
			}
		}
		off = rdataEnd
	}
	return cnames, ips, nil
}

func readDNSName(msg []byte, offset int) (string, int, error) {
	var labels []string
	cur := offset
	nextAfter := -1
	jumped := false
	for hops := 0; hops < 64; hops++ {
		if cur >= len(msg) {
			return "", 0, errors.New("DNS name out of bounds")
		}
		length := int(msg[cur])
		if length == 0 {
			if !jumped {
				nextAfter = cur + 1
			}
			return strings.Join(labels, "."), nextAfter, nil
		}
		if (length & 0xC0) == 0xC0 {
			if cur+1 >= len(msg) {
				return "", 0, errors.New("truncated DNS pointer")
			}
			ptr := int(binary.BigEndian.Uint16(msg[cur:cur+2]) & 0x3FFF)
			if !jumped {
				nextAfter = cur + 2
				jumped = true
			}
			cur = ptr
			continue
		}
		if (length & 0xC0) != 0 {
			return "", 0, errors.New("invalid DNS label mask")
		}
		cur++
		if cur+length > len(msg) {
			return "", 0, errors.New("DNS label exceeds packet")
		}
		labels = append(labels, string(msg[cur:cur+length]))
		cur += length
	}
	return "", 0, errors.New("DNS pointer loop")
}

func queryDoHWithRetries(ctx context.Context, client *http.Client, dohURL, host string, qtype uint16, timeout time.Duration, retries int) ([]string, []netip.Addr, error) {
	var lastErr error
	attempts := retries + 1
	if attempts < 1 {
		attempts = 1
	}
	for i := 0; i < attempts; i++ {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		cnames, ips, err := queryDoH(ctx, client, dohURL, host, qtype, timeout)
		if err == nil {
			return cnames, ips, nil
		}
		lastErr = err
	}
	return nil, nil, lastErr
}

func queryDoH(ctx context.Context, client *http.Client, dohURL, host string, qtype uint16, timeout time.Duration) ([]string, []netip.Addr, error) {
	if dohURL == "" {
		dohURL = "https://dns.google/resolve"
	}
	u, err := url.Parse(dohURL)
	if err != nil {
		return nil, nil, err
	}
	q := u.Query()
	q.Set("name", host)
	if qtype == dnsTypeAAAA {
		q.Set("type", "AAAA")
	} else {
		q.Set("type", "A")
	}
	u.RawQuery = q.Encode()

	qCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(qCtx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Accept", "application/dns-json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("DoH HTTP %d", resp.StatusCode)
	}
	var doc struct {
		Status int `json:"Status"`
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return nil, nil, err
	}
	if doc.Status != 0 && doc.Status != 3 {
		return nil, nil, fmt.Errorf("DoH DNS status %d", doc.Status)
	}
	var cnames []string
	var ips []netip.Addr
	for _, ans := range doc.Answer {
		switch ans.Type {
		case int(dnsTypeCNAME):
			c := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(ans.Data)), ".")
			if c != "" {
				cnames = append(cnames, c)
			}
		case int(dnsTypeA), int(dnsTypeAAAA):
			if ip, err := netip.ParseAddr(strings.TrimSpace(ans.Data)); err == nil {
				ips = append(ips, ip)
			}
		}
	}
	return cnames, ips, nil
}
