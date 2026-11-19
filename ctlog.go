package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const googleCTLogListURL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"

type ctLogInfo struct {
	URL         string
	Description string
}

// collectDirectCTLogs samples recent entries from active public RFC 6962 CT logs
// and extracts DNS names from Certainly-issued certificates and Fastly shared SAN certs.
func collectDirectCTLogs(ctx context.Context, client *http.Client, entriesPerLog int, opts SourceOptions, store *candidateStore) {
	if entriesPerLog <= 0 {
		entriesPerLog = 3000
	}
	maxLogs := 8
	if entriesPerLog > 5000 {
		maxLogs = 12
	}
	logs, err := fetchUsableCTLogs(ctx, client, maxLogs)
	if err != nil {
		if opts.Logf != nil {
			opts.Logf("[ct-logs] log list fetch failed: %v", err)
		}
		return
	}
	if len(logs) == 0 {
		return
	}

	var totalAdded atomic.Int64
	var scannedCerts atomic.Int64
	var matchedCerts atomic.Int64
	var wg sync.WaitGroup

	// Limit concurrent log scanners so we stay polite to CT log operators.
	sem := make(chan struct{}, 4)
	for _, lg := range logs {
		wg.Add(1)
		go func(info ctLogInfo) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			scanned, matched, added := scanCTLogTail(ctx, client, info, entriesPerLog, store)
			scannedCerts.Add(int64(scanned))
			matchedCerts.Add(int64(matched))
			totalAdded.Add(int64(added))
		}(lg)
	}
	wg.Wait()

	if opts.Logf != nil {
		opts.Logf("[ct-logs] scanned %d recent certs across %d CT logs (%d Fastly/Certainly certs, +%d hosts)",
			scannedCerts.Load(), len(logs), matchedCerts.Load(), totalAdded.Load())
	}
}

func fetchUsableCTLogs(ctx context.Context, client *http.Client, maxLogs int) ([]ctLogInfo, error) {
	body, err := httpGetBytes(ctx, client, googleCTLogListURL, 4<<20)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Operators []struct {
			Name string `json:"name"`
			Logs []struct {
				Description      string         `json:"description"`
				URL              string         `json:"url"`
				State            map[string]any `json:"state"`
				TemporalInterval *struct {
					StartInclusive time.Time `json:"start_inclusive"`
					EndExclusive   time.Time `json:"end_exclusive"`
				} `json:"temporal_interval"`
			} `json:"logs"`
		} `json:"operators"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	nearFuture := now.Add(90 * 24 * time.Hour)
	var activeNow, activeSoon, future []ctLogInfo
	for _, op := range doc.Operators {
		for _, l := range op.Logs {
			if _, usable := l.State["usable"]; !usable {
				continue
			}
			u := strings.TrimRight(l.URL, "/") + "/"
			if !strings.HasPrefix(u, "https://") {
				continue
			}
			info := ctLogInfo{URL: u, Description: l.Description}
			ti := l.TemporalInterval
			switch {
			case ti == nil || (!ti.StartInclusive.After(now) && (ti.EndExclusive.IsZero() || ti.EndExclusive.After(now))):
				activeNow = append(activeNow, info)
			case !ti.StartInclusive.After(nearFuture) && (ti.EndExclusive.IsZero() || ti.EndExclusive.After(now)):
				activeSoon = append(activeSoon, info)
			default:
				future = append(future, info)
			}
		}
	}
	out := append(activeNow, activeSoon...)
	out = append(out, future...)
	if maxLogs > 0 && len(out) > maxLogs {
		out = out[:maxLogs]
	}
	return out, nil
}

func scanCTLogTail(ctx context.Context, client *http.Client, info ctLogInfo, count int, store *candidateStore) (scanned, matched, added int) {
	timeout := 20*time.Second + time.Duration(count/500)*time.Second
	if timeout > 5*time.Minute {
		timeout = 5 * time.Minute
	}
	logCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	sthBody, err := httpGetBytes(logCtx, client, info.URL+"ct/v1/get-sth", 256<<10)
	if err != nil {
		return 0, 0, 0
	}
	var sth struct {
		TreeSize int64 `json:"tree_size"`
	}
	if err := json.Unmarshal(sthBody, &sth); err != nil || sth.TreeSize <= 0 {
		return 0, 0, 0
	}

	end := sth.TreeSize - 1
	start := end - int64(count) + 1
	if start < 0 {
		start = 0
	}

	for cur := start; cur <= end; {
		if logCtx.Err() != nil {
			break
		}
		batchEnd := cur + 255
		if batchEnd > end {
			batchEnd = end
		}
		u := fmt.Sprintf("%sct/v1/get-entries?start=%d&end=%d", info.URL, cur, batchEnd)
		body, err := httpGetBytes(logCtx, client, u, 8<<20)
		if err != nil {
			break
		}
		var resp struct {
			Entries []struct {
				LeafInput string `json:"leaf_input"`
				ExtraData string `json:"extra_data"`
			} `json:"entries"`
		}
		if err := json.Unmarshal(body, &resp); err != nil || len(resp.Entries) == 0 {
			break
		}
		for _, entry := range resp.Entries {
			cert, err := parseCTEntryCert(entry.LeafInput, entry.ExtraData)
			if err != nil {
				continue
			}
			scanned++
			if !isFastlyCTCert(cert) {
				continue
			}
			matched++
			for _, name := range cert.DNSNames {
				h := NormalizeHost(name)
				if h != "" && !IsFastlyCNAME(h) {
					store.add(h, "ct-log")
					added++
				}
			}
			if cn := NormalizeHost(cert.Subject.CommonName); cn != "" && !IsFastlyCNAME(cn) {
				store.add(cn, "ct-log")
				added++
			}
		}
		cur += int64(len(resp.Entries))
	}
	return scanned, matched, added
}

func parseCTEntryCert(leafB64, extraB64 string) (*x509.Certificate, error) {
	leaf, err := base64.StdEncoding.DecodeString(leafB64)
	if err != nil || len(leaf) < 15 {
		return nil, fmt.Errorf("invalid leaf_input")
	}
	// RFC 6962 §3.4: version(1)=0, leaf_type(1)=0, timestamp(8), entry_type(2)
	if leaf[0] != 0 || leaf[1] != 0 {
		return nil, fmt.Errorf("unsupported leaf header")
	}
	entryType := int(leaf[10])<<8 | int(leaf[11])
	switch entryType {
	case 0: // x509_entry
		certLen := int(leaf[12])<<16 | int(leaf[13])<<8 | int(leaf[14])
		if certLen <= 0 || 15+certLen > len(leaf) {
			return nil, fmt.Errorf("truncated x509_entry")
		}
		return x509.ParseCertificate(leaf[15 : 15+certLen])
	case 1: // precert_entry: pre_certificate is first ASN.1Cert in extra_data
		extra, err := base64.StdEncoding.DecodeString(extraB64)
		if err != nil || len(extra) < 3 {
			return nil, fmt.Errorf("invalid extra_data")
		}
		certLen := int(extra[0])<<16 | int(extra[1])<<8 | int(extra[2])
		if certLen <= 0 || 3+certLen > len(extra) {
			return nil, fmt.Errorf("truncated precert extra_data")
		}
		return x509.ParseCertificate(extra[3 : 3+certLen])
	default:
		return nil, fmt.Errorf("unknown CT entry_type %d", entryType)
	}
}

func isFastlyCTCert(cert *x509.Certificate) bool {
	if strings.Contains(strings.ToLower(cert.Issuer.CommonName), "certainly") {
		return true
	}
	for _, org := range cert.Issuer.Organization {
		if strings.Contains(strings.ToLower(org), "certainly") {
			return true
		}
	}
	for _, name := range cert.DNSNames {
		if IsFastlyCNAME(name) {
			return true
		}
	}
	return false
}
