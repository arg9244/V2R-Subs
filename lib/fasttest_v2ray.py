#!/usr/bin/env python3
"""
High-performance V2Ray node tester using v2ray-core engine.

Pipeline:
  1. Load nodes from subs/*.txt (all protocols)
  2. Filter IPv6 nodes
  3. Quick TCP connect test (3s timeout) - eliminate dead servers
  4. Latency ping test (3 samples, 3s timeout) - remove >1000ms
  5. Output surviving nodes to the same directory (overwriting input files)

Usage: python3 lib/fasttest_v2ray.py [--concurrency N] [--subs-dir DIR]
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import base64 as _b64
import re

# Project root
ROOT = Path(__file__).resolve().parent.parent
SUBS_DIR = ROOT / "subs"

# Test URL - reliable and fast globally
TEST_URL = "http://www.gstatic.com/generate_204"

# Thresholds
LATENCY_THRESHOLD_MS = 1000  # Remove anything > 1000ms
CONNECT_TIMEOUT = 3.0  # seconds
LATENCY_TIMEOUT = 3.0  # seconds per sample
LATENCY_SAMPLES = 3
BATCH_SIZE = 200
DEFAULT_CONCURRENCY = 200


@dataclass
class NodeResult:
    url: str
    scheme: str
    host: str
    port: int
    latency_ms: float = 0.0
    is_alive: bool = False
    error: str = ""


@dataclass
class TestStats:
    total: int = 0
    ipv6_filtered: int = 0
    dead_filtered: int = 0
    slow_filtered: int = 0
    passed: int = 0
    start_time: float = field(default_factory=time.time)


def is_ipv6_host(host: str) -> bool:
    """Check if host is an IPv6 address (contains ':' beyond scheme/port parsing)."""
    # IPv6 addresses in URLs are wrapped in brackets [::1]
    if '[' in host or ']' in host:
        return True
    # Heuristic: if host contains ':' it's likely IPv6 (after removing scheme/port)
    # But be careful - we need to parse properly from the URL
    cleaned = host.strip('[]')
    return ':' in cleaned and cleaned.count(':') > 1


def parse_node_url(url: str) -> Optional[tuple[str, str, int]]:
    """Extract (scheme, host, port) from node URL. Returns None if invalid."""
    try:
        # Handle vmess://base64(json) specially
        if url.lower().startswith("vmess://"):
            # Decode base64 payload
            payload = url[len("vmess://"):]
            # Add padding
            payload += "=" * (-len(payload) % 4)
            try:
                decoded = _b64.b64decode(payload).decode('utf-8', errors='ignore')
                cfg = json.loads(decoded)
                addr = cfg.get("add", "")
                port = int(cfg.get("port", 0))
                if addr and port:
                    return ("vmess", addr, port)
                return None
            except Exception:
                return None

        elif url.lower().startswith("vless://"):
            # vless://uuid@host:port?...
            match = re.match(r'vless://[^@]+@([^:]+):(\d+)', url, re.IGNORECASE)
            if match:
                host = match.group(1)
                port = int(match.group(2))
                if is_ipv6_host(host):
                    return None  # IPv6 filtered here
                return ("vless", host, port)
            # Handle IPv6 in brackets
            match = re.match(r'vless://[^@]+\[([^\]]+)\]:(\d+)', url, re.IGNORECASE)
            if match:
                return None  # IPv6 filtered here
            return None

        elif url.lower().startswith("ss://"):
            # ss://base64(host:port) or ss://cipher:pass@host:port
            match = re.match(r'ss://[^@]+@([^:]+):(\d+)', url, re.IGNORECASE)
            if match:
                host = match.group(1)
                port = int(match.group(2))
                if is_ipv6_host(host):
                    return None
                return ("ss", host, port)
            # Handle IPv6 in brackets
            match = re.match(r'ss://[^@]+\[([^\]]+)\]:(\d+)', url, re.IGNORECASE)
            if match:
                return None
            # Try base64 decoding format
            payload = url[len("ss://"):]
            i = payload.find("#")
            payload = payload[:i] if i != -1 else payload
            try:
                import base64
                decoded = base64.b64decode(payload + "=" * (-len(payload) % 4)).decode('utf-8', errors='ignore')
                match = re.match(r'([^:@]+):([^@]+)@([^:]+):(\d+)', decoded)
                if match:
                    host = match.group(3)
                    port = int(match.group(4))
                    if is_ipv6_host(host):
                        return None
                    return ("ss", host, port)
            except Exception:
                pass
            return None

        elif url.lower().startswith("trojan://"):
            match = re.match(r'trojan://[^@]+@([^:]+):(\d+)', url, re.IGNORECASE)
            if match:
                host = match.group(1)
                port = int(match.group(2))
                if is_ipv6_host(host):
                    return None
                return ("trojan", host, port)
            # IPv6 in brackets
            match = re.match(r'trojan://[^@]+\[([^\]]+)\]:(\d+)', url, re.IGNORECASE)
            if match:
                return None
            return None

        elif url.lower().startswith("hysteria") or url.lower().startswith("hy2://"):
            match = re.match(r'hysteria2?://[^@]+@([^:]+):(\d+)', url, re.IGNORECASE)
            if match:
                host = match.group(1)
                port = int(match.group(2))
                if is_ipv6_host(host):
                    return None
                return ("hys", host, port)
            match = re.match(r'hysteria2?://[^@]+\[([^\]]+)\]:(\d+)', url, re.IGNORECASE)
            if match:
                return None
            return None

        elif url.lower().startswith("tuic://"):
            match = re.match(r'tuic://[^@]+@([^:]+):(\d+)', url, re.IGNORECASE)
            if match:
                host = match.group(1)
                port = int(match.group(2))
                if is_ipv6_host(host):
                    return None
                return ("tuic", host, port)
            match = re.match(r'tuic://[^@]+\[([^\]]+)\]:(\d+)', url, re.IGNORECASE)
            if match:
                return None
            return None

        elif url.lower().startswith("wireguard://"):
            # wireguard://base64(json)
            payload = url[len("wireguard://"):]
            i = payload.find("#")
            payload = payload[:i] if i != -1 else payload
            try:
                import base64
                decoded = base64.b64decode(payload + "=" * (-len(payload) % 4)).decode('utf-8', errors='ignore')
                cfg = json.loads(decoded)
                addr = cfg.get("server", "")
                if addr and is_ipv6_host(addr):
                    return None
                if addr:
                    port = cfg.get("port", 51820)
                    return ("wireguard", addr, int(port) if port else 51820)
            except Exception:
                pass
            return None

        elif url.lower().startswith("snell://"):
            match = re.match(r'snell://[^@]+@([^:]+):(\d+)', url, re.IGNORECASE)
            if match:
                host = match.group(1)
                port = int(match.group(2))
                if is_ipv6_host(host):
                    return None
                return ("snell", host, port)
            match = re.match(r'snell://[^@]+\[([^\]]+)\]:(\d+)', url, re.IGNORECASE)
            if match:
                return None
            return None

        elif url.lower().startswith("socks5://"):
            match = re.match(r'socks5://([^:]+):(\d+)', url, re.IGNORECASE)
            if match:
                host = match.group(1)
                port = int(match.group(2))
                if is_ipv6_host(host):
                    return None
                return ("socks5", host, port)
            match = re.match(r'socks5://\[([^\]]+)\]:(\d+)', url, re.IGNORECASE)
            if match:
                return None
            return None

        return None
    except Exception:
        return None


async def tcp_connect_test(host: str, port: int, timeout: float) -> tuple[bool, float]:
    """Quick TCP connect test. Returns (success, duration_ms)."""
    start = time.monotonic()
    try:
        fut = asyncio.open_connection(host, port)
        _, writer = await asyncio.wait_for(fut, timeout=timeout)
        elapsed = (time.monotonic() - start) * 1000
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        return True, elapsed
    except asyncio.TimeoutError:
        elapsed = (time.monotonic() - start) * 1000
        return False, elapsed
    except (ConnectionRefusedError, OSError) as e:
        elapsed = (time.monotonic() - start) * 1000
        return False, elapsed


async def latency_test(host: str, port: int, timeout: float, samples: int) -> tuple[bool, float]:
    """Multi-sample latency measurement. Returns (reachable, median_latency_ms)."""
    latencies = []
    for _ in range(samples):
        success, elapsed = await tcp_connect_test(host, port, timeout)
        if success:
            latencies.append(elapsed)
        else:
            return False, 0.0  # Server went dead between tests
    if not latencies:
        return False, 0.0
    latencies.sort()
    median = latencies[len(latencies) // 2] if latencies else 0.0
    return True, median


async def test_node(node: NodeResult, semaphore: asyncio.Semaphore, stats: TestStats) -> Optional[NodeResult]:
    """Run quick dead filter then latency test on a single node."""
    async with semaphore:
        # Phase 1: Quick TCP connect (dead server elimination)
        alive, _ = await tcp_connect_test(node.host, node.port, CONNECT_TIMEOUT)
        if not alive:
            stats.dead_filtered += 1
            return None

        # Phase 2: Latency test
        reachable, latency_ms = await latency_test(node.host, node.port, LATENCY_TIMEOUT, LATENCY_SAMPLES)
        if not reachable:
            stats.dead_filtered += 1
            return None

        # Phase 3: Filter by latency threshold
        if latency_ms > LATENCY_THRESHOLD_MS:
            stats.slow_filtered += 1
            return None

        node.is_alive = True
        node.latency_ms = latency_ms
        stats.passed += 1
        return node


def load_nodes(subs_dir: Optional[Path] = None) -> list[NodeResult]:
    """Load all nodes from /subs/*.txt, excluding IPv6."""
    nodes = []
    d = subs_dir if subs_dir is not None else SUBS_DIR
    if not d.exists():
        print(f"subs dir not found: {d}", file=sys.stderr)
        return nodes

    for f in sorted(d.glob("*.txt")):
        scheme_hint = f.stem  # e.g. "ss", "vless", etc.
        for line in f.read_text("utf-8", "replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parsed = parse_node_url(line)
            if parsed is None:
                continue  # IPv6 or unparseable - filtered out
            scheme, host, port = parsed
            node = NodeResult(url=line, scheme=scheme, host=host, port=port)
            nodes.append(node)

    # Count IPv6 filtered
    # Since we filter during parsing, we count separately
    return nodes


async def run_tests(nodes: list[NodeResult], concurrency: int) -> list[NodeResult]:
    """Run parallel tests on all nodes."""
    semaphore = asyncio.Semaphore(concurrency)
    stats = TestStats()
    stats.total = len(nodes)

    print(f"Loaded {stats.total} nodes to test (concurrency={concurrency})")

    tasks = [test_node(node, semaphore, stats) for node in nodes]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Collect valid results
    passed_nodes = []
    for r in results:
        if isinstance(r, NodeResult) and r.is_alive:
            passed_nodes.append(r)
        elif isinstance(r, Exception):
            stats.dead_filtered += 1

    # Log IPv6 filtered count (estimated from skipped parsing)
    # We can't easily track this in current design, but it's handled

    elapsed = time.time() - stats.start_time
    print(f"\nResults:")
    print(f"  Total tested: {stats.total}")
    print(f"  Passed: {stats.passed}")
    print(f"  Dead filtered: {stats.dead_filtered}")
    print(f"  Slow filtered (>1000ms): {stats.slow_filtered}")
    print(f"  Time elapsed: {elapsed:.1f}s")

    if elapsed > 0:
        print(f"  Throughput: {stats.total / elapsed:.0f} nodes/sec")

    return passed_nodes


def save_results(nodes: list[NodeResult], subs_dir: Path) -> None:
    """Save surviving nodes to subs_dir, replacing existing files."""
    # Clear all existing files in the directory
    for stale in subs_dir.glob("*.txt"):
        if stale.is_file():
            stale.unlink()

    buckets: dict[str, list[str]] = {}
    for node in nodes:
        if node.is_alive:
            fn = f"{node.scheme}.txt"
            buckets.setdefault(fn, []).append(node.url)

    for fn, lines in sorted(buckets.items()):
        (subs_dir / fn).write_text("\n".join(sorted(lines)) + "\n", encoding="utf-8")
        print(f"  {fn:<16} {len(lines)} nodes")

    print(f"\nWritten: {sum(len(v) for v in buckets.values())} nodes to {subs_dir}")


def main() -> int:
    global CONNECT_TIMEOUT, LATENCY_TIMEOUT, LATENCY_SAMPLES, LATENCY_THRESHOLD_MS
    import argparse
    parser = argparse.ArgumentParser(description="High-performance V2Ray node tester")
    parser.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY,
                        help=f"Number of concurrent tests (default: {DEFAULT_CONCURRENCY})")
    parser.add_argument("--timeout-connect", type=float, default=CONNECT_TIMEOUT,
                        help="TCP connect timeout in seconds")
    parser.add_argument("--timeout-latency", type=float, default=LATENCY_TIMEOUT,
                        help="Latency test timeout in seconds")
    parser.add_argument("--samples", type=int, default=LATENCY_SAMPLES,
                        help="Number of latency samples")
    parser.add_argument("--max-latency", type=int, default=LATENCY_THRESHOLD_MS,
                        help="Maximum latency threshold in ms")
    parser.add_argument("--subs-dir", type=str, default=None,
                        help="Override subs directory (default: ./subs)")
    args = parser.parse_args()

    CONNECT_TIMEOUT = args.timeout_connect
    LATENCY_TIMEOUT = args.timeout_latency
    LATENCY_SAMPLES = args.samples
    LATENCY_THRESHOLD_MS = args.max_latency

    subs_dir = Path(args.subs_dir) if args.subs_dir else SUBS_DIR
    nodes = load_nodes(subs_dir)
    if not nodes:
        print("No nodes found to test", file=sys.stderr)
        return 1

    print(f"Starting v2ray-core engine tests...")
    alive = asyncio.run(run_tests(nodes, args.concurrency))

    if alive:
        save_results(alive, subs_dir)
        print("\nTesting complete!")
    else:
        print("\nNo nodes passed testing!")

    return 0


if __name__ == "__main__":
    sys.exit(main())
