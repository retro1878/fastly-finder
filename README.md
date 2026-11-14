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

### 5. Readable terminal table vs machine-readable exports
By default (`--format auto`), stdout on an interactive TTY renders an aligned table, while redirected output or `.jsonl` / `.csv` / `.txt` file extensions choose the matching format automatically. Override explicitly with `--format table|jsonl|csv|txt`.

### 6. HTTPS-only authenticated Web Dashboard
Start an interactive web dashboard embedded right inside the single binary (TLS + session cookie auth + CSRF protection + rate-limited login):

```bash
# Quick local/SSH-tunneled mode (generates random admin password + self-signed ECDSA cert):
./fastly-finder-linux-amd64 --web 127.0.0.1:8443

# With custom credentials and Certbot TLS cert (auto-reloads on renewal without restart):
FASTLY_FINDER_WEB_AUTH='admin:your-strong-password' \
  ./fastly-finder-linux-amd64 --web 0.0.0.0:8443 \
  --web-cert /etc/fastly-finder/tls/cert.pem \
  --web-key /etc/fastly-finder/tls/key.pem \
  --web-dir /var/lib/fastly-finder/scans
```

### 7. One-command Linux systemd service installer (with optional Let's Encrypt IP cert)
Install `fastly-finder` as an unprivileged `systemd` service with auto-generated credentials in `/etc/fastly-finder/env` and automatic scan storage in `/var/lib/fastly-finder/scans`:

```bash
# Self-signed HTTPS on port 8443:
curl -fsSL https://raw.githubusercontent.com/retro1878/fastly-finder/master/install.sh | sudo bash

# With a real Let's Encrypt short-lived IP certificate (6-day cert, auto-renewed by certbot.timer):
curl -fsSL https://raw.githubusercontent.com/retro1878/fastly-finder/master/install.sh | sudo bash -s -- --certbot
```

> Port `8443` stays open for the HTTPS dashboard while port `80` remains free for Certbot `--standalone` challenges and automatic renewals. On renewal, a Certbot deploy hook updates `/etc/fastly-finder/tls/` and `fastly-finder` hot-reloads the certificate automatically.

## Status Classifications

- `confirmed`: DNS matches Fastly (`*.fastly.net` / `*.fastlylb.net` / Fastly CIDR) and HTTP/edge probe sees Fastly headers (`X-Served-By: cache-...`, `Fastly-Debug-*`, `X-Timer`, `Via`) or a matching edge TLS cert.
- `fastly_dns_headers_hidden`: DNS points to Fastly, HTTP responded, but Fastly headers are stripped/hidden.
- `unknown_domain`: DNS points to Fastly, but Fastly returns `Fastly error: unknown domain` (unconfigured/dangling hostname).
- `dns_only_unreachable`: DNS points to Fastly, but HTTP/TLS probes timed out or were refused.
- `edge_configured_off_dns`: With `--probe-all`, public DNS points elsewhere, yet the Fastly edge IP recognizes the SNI/Host.

## Fastly Range Sources

Loads ranges in order: `--cidr-file` → 24h cache → `https://api.fastly.com/public-ip-list` → MISP `misp-warninglists` Fastly list → RIPEstat (`AS54113` / `AS394192`) → embedded fallback snapshot. Use `--include-bgp` to merge BGP prefixes and `--include-upcoming` for Fastly's Jan 11, 2027 ranges (`90.98.0.0/17`, `90.98.128.0/18`, `2a04:4e42::/31`, `2a04:4e44::/32`).
