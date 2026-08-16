# V2R-Subs

Automated V2Ray/Xray subscription pipeline: fetches, classifies, filters, and tests proxy nodes.

## Overview

This repository maintains a daily-updated collection of working V2Ray/Xray proxy nodes. The GitHub Actions workflow runs automatically every 24 hours, processing ~140K raw subscription nodes down to a curated set of healthy, low-latency proxies.

## Pipeline

```
config/links.yaml ──→ fetch_subs.py ──→ raw/              # Download subscriptions
                                          │
                                          ▼
                                    sort_subs.py ──→ subs/   # Classify by protocol, dedup, clean
                                          │
                                          ▼
                              fasttest_singbox.py ──→ subs/  # Filter dead servers, <1000ms latency

### Scripts

| Script | Purpose |
| `lib/fasttest_singbox.py` | Filters dead servers via TCP connect test, measures latency (median of 1 sample), removes nodes >1000ms, filters IPv6, overwrites `subs/` in-place. |
| `lib/fasttest_v2ray.py` | Same as above using v2ray-core approach (alternative engine for A/B comparison). |
| `lib/speedtest_singbox.py` | Offline speed testing through sing-box SOCKS5 proxies (curl bandwidth measurement). Not used in the workflow — available for manual use. |
### Filtering Rules

1. **IPv6 removal**: Nodes with IPv6 addresses are filtered out during parsing
2. **Dead server elimination**: TCP connect test with configurable timeout (default 3s)
3. **Latency filtering**: Nodes with median latency >1000ms are removed
4. **Protocol classification**: Nodes are grouped by protocol into separate `.txt` files

### Performance

- **Phase 1 (dead filter)**: TCP connect test (0.5s timeout) eliminates 60-70% of nodes
- **Throughput**: ~620-650 nodes/sec at concurrency 200
- **Full pipeline**: ~140K nodes processed in ~4 minutes on GitHub Actions (fetch + sort + fasttest + commit)

## Subs Structure

After processing, `subs/` contains one file per protocol:

```
subs/
├── hys.txt       # Hysteria2 nodes
├── socks5.txt    # SOCKS5 nodes
├── ss.txt        # Shadowsocks nodes
├── trojan.txt    # Trojan nodes
├── tuic.txt      # TUIC nodes
├── vless.txt     # VLESS nodes
└── vmess.txt     # VMess nodes
```
- `.gitignore` — Excludes `bin/`, `raw/`, `subs/`, `.cache/`

## Local Usage

```bash
# Install dependencies
pip install pyyaml

# Full pipeline
python3 lib/fetch_subs.py --workers 16
python3 lib/sort_subs.py
python3 lib/fasttest_singbox.py --concurrency 200 --timeout-connect 0.5 --timeout-latency 0.5 --samples 1 --max-latency 1000

# Or run individual scripts
python3 lib/fetch_subs.py --limit 10          # test with 10 URLs only
python3 lib/fasttest_singbox.py --help         # see all options
```

## GitHub Actions

The workflow runs daily at 00:00 UTC and on manual dispatch. It commits results back to the `subs/` directory.

## License

MIT License — see [LICENSE](LICENSE).
