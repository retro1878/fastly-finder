# fastly-finder

Zero-cost, zero-subscription Linux CLI to discover and verify domains/subdomains served on Fastly CDN.

## Build (Static Linux Binary)

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o fastly-finder-linux-amd64 .
```

Zero runtime dependencies (no `subfinder`, `dnsx`, `httpx`, `jq`, `grepcidr`, or `psql` required).

## Usage Examples

### 1. Target-domain mode (subdomains of a specific domain)
```bash
./fastly-finder-linux-amd64 -d reddit.com -o reddit_fastly.jsonl
```
Queries free passive/CT sources (`crt.sh` JSON + PostgreSQL `identities()`, Cert Spotter, HackerTarget, AlienVault OTX, Wayback CDX, plus optional `--use-subfinder`), resolves CNAME/A/AAAA concurrently, matches against Fastly CIDRs/CNAMEs, sends `Fastly-Debug: 1`, and probes the Fastly edge IP with SNI + `Host`.

### 2. Global Fastly discovery (no target domain, \$0)
```bash
# Bulk-resolve top 50k Tranco domains (+ www.) + crt.sh Fastly shared/Certainly certs
./fastly-finder-linux-amd64 --global --seed tranco,ct-fastly --limit 50000 -o fastly_global.jsonl

# Include Chrome CrUX origins + ProjectDiscovery Chaos subdomains + deeper CT log tailing
./fastly-finder-linux-amd64 --global --seed crux,chaos,ct-fastly --limit 100000 --ct-entries 20000 --format csv -o fastly.csv
```

### 3. Candidate list mode
```bash
./fastly-finder-linux-amd64 -i hosts.txt --format txt --only-confirmed
```

### 4. Restricted networks / DNS-over-HTTPS
```bash
./fastly-finder-linux-amd64 -d example.com --doh
```

## Status Classifications

- `confirmed`: DNS matches Fastly (`*.fastly.net` / `*.fastlylb.net` / Fastly CIDR) and HTTP/edge probe sees Fastly headers (`X-Served-By: cache-...`, `Fastly-Debug-*`, `X-Timer`, `Via`) or a matching edge TLS cert.
- `fastly_dns_headers_hidden`: DNS points to Fastly, HTTP responded, but Fastly headers are stripped/hidden.
- `unknown_domain`: DNS points to Fastly, but Fastly returns `Fastly error: unknown domain` (unconfigured/dangling hostname).
- `dns_only_unreachable`: DNS points to Fastly, but HTTP/TLS probes timed out or were refused.
- `edge_configured_off_dns`: With `--probe-all`, public DNS points elsewhere, yet the Fastly edge IP recognizes the SNI/Host.

## Fastly Range Sources

Loads ranges in order: `--cidr-file` → 24h cache → `https://api.fastly.com/public-ip-list` → MISP `misp-warninglists` Fastly list → RIPEstat (`AS54113` / `AS394192`) → embedded fallback snapshot. Use `--include-bgp` to merge BGP prefixes and `--include-upcoming` for Fastly's Jan 11, 2027 ranges (`90.98.0.0/17`, `90.98.128.0/18`, `2a04:4e42::/31`, `2a04:4e44::/32`).
