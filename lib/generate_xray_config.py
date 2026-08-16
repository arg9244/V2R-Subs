#!/usr/bin/env python3
"""generate_xray_config — convert subs/*.txt node URLs into Xray JSON configs.

Mirrors the subs/ folder structure:
  - mix.json            — all nodes + leastPing LB
  - country/*.json      — nodes by country + leastPing LB
  - protocol/*.json     — nodes by protocol + leastPing LB
  - 1000/*.json         — chunks of 1000 + leastPing LB each

Each config has:
  - Listening inbound (socks5 + http) on 127.0.0.1:1080
  - One outbound per node (parsed from the raw URL)
  - A `freedom` direct outbound (fallback)
  - routing.balancers with strategy leastPing (HTTPing RTT-based load balancing)
  - Rules routing traffic into the balancer

Usage:
  python3 lib/generate_xray_config.py                    # default: reads subs/, writes xray/
  python3 lib/generate_xray_config.py --subs-dir subs --out-dir xray
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Ensure lib/ is on sys.path so parse_nodes is importable
sys.path.insert(0, str(Path(__file__).resolve().parent))

from parse_nodes import NodeConfig, load_all_nodes, load_nodes_from_file

ROOT = Path(__file__).resolve().parent.parent


def _node_to_xray_outbound(nc: NodeConfig) -> dict:
    """Convert a NodeConfig to a Xray outbound JSON object."""
    out: dict = {"tag": nc.tag}

    # --- Per-protocol settings (Xray uses flat settings objects) ---
    if nc.scheme == "vless":
        out["protocol"] = "vless"
        out["settings"] = {
            "address": nc.server,
            "port": nc.port,
            "id": nc.uuid,
            "tls": "tls" if nc.tls else "none",
        }
        if nc.flow and nc.flow != "none":
            out["settings"]["flow"] = nc.flow
        if nc.encryption:
            out["settings"]["encryption"] = nc.encryption

    elif nc.scheme == "vmess":
        out["protocol"] = "vmess"
        out["settings"] = {
            "address": nc.server,
            "port": nc.port,
            "id": nc.uuid,
            "security": nc.security or "auto",
            "level": 0,
        }

    elif nc.scheme == "ss":
        out["protocol"] = "shadowsocks"
        out["settings"] = {
            "address": nc.server,
            "port": nc.port,
            "method": nc.cipher,
            "password": nc.password,
            "level": 0,
        }

    elif nc.scheme == "trojan":
        out["protocol"] = "trojan"
        out["settings"] = {
            "address": nc.server,
            "port": nc.port,
            "password": nc.password,
            "level": 0,
        }

    elif nc.scheme in ("hysteria2", "hy2"):
        out["protocol"] = "hysteria2"
        out["settings"] = {
            "address": nc.server,
            "port": nc.port,
        }
        out["hysteriaSettings"] = {
            "auth": nc.password or nc.auth,
            "obfs": nc.obfs,
            "down Mbps": nc.down_mbps,
            "up Mbps": nc.up_mbps,
            "bandwidth": {"downMbps": nc.down_mbps or "200", "upMbps": nc.up_mbps or "50"},
        }
        # Clean up None/empty values
        if not out["hysteriaSettings"]["obfs"]:
            del out["hysteriaSettings"]["obfs"]
        if not out["hysteriaSettings"]["auth"]:
            del out["hysteriaSettings"]["auth"]
        out["hysteriaSettings"].pop("down Mbps", None)
        out["hysteriaSettings"].pop("up Mbps", None)

    elif nc.scheme == "hysteria":
        out["protocol"] = "hysteria"
        out["settings"] = {
            "address": nc.server,
            "port": nc.port,
            "protocol": "udp",
        }
        out["hysteriaSettings"] = {
            "auth": nc.auth,
            "obfs": nc.obfs,
            "recvBP": 200,
            "sendBP": 50,
            "bandwidth": {"rx":"200Mbps","tx":"50Mbps"},
            "network": "udp",
        }

    elif nc.scheme == "tuic":
        # Xray does NOT support TUIC — use VLESS over TCP/WS as fallback
        out["protocol"] = "vless"
        out["settings"] = {
            "address": nc.server,
            "port": nc.port,
            "id": nc.uuid,
            "tls": "tls" if nc.tls else "none",
        }

    elif nc.scheme == "socks5":
        out["protocol"] = "socks"
        out["settings"] = {
            "address": nc.server,
            "port": nc.port,
            "user": nc.username,
            "pass": nc.password,
            "level": 0,
        }

    else:
        # Unknown — emit freedom as a direct outbound
        out["protocol"] = "freedom"
        out["settings"] = {}
        return out

    # --- Stream settings (transport + TLS/xTLS) ---
    ss: dict = {}

    # TLS / xTLS / Reality
    if nc.tls or nc.reality:
        tls_settings: dict = {}
        if nc.sni:
            tls_settings["serverName"] = nc.sni
        if nc.alpn:
            tls_settings["alpn"] = {"alpn": nc.alpn}
        tls_settings["allowInsecure"] = nc.allow_insecure

        if nc.reality:
            tls_settings["reality"] = {"publicKey": nc.public_key}
            if nc.short_id:
                tls_settings["reality"]["shortId"] = nc.short_id

        ss["security"] = "reality" if nc.reality else "tls"
        ss["tlsSettings"] = tls_settings
    else:
        ss["security"] = "none"

    # Transport
    if nc.network:
        if nc.network in ("ws", "httpupgrade"):
            ws_opts: dict = {"path": nc.ws_path or "/"}
            if nc.ws_headers:
                ws_opts["headers"] = nc.ws_headers
            if nc.max_early_data > 0:
                ws_opts["maxEarlyData"] = nc.max_early_data
                ws_opts["earlyDataHeaderName"] = nc.early_data_header or "X-Real-Header"
            ss["network"] = "ws"
            ss["wsSettings"] = ws_opts
        elif nc.network == "http":
            http_opts = {"path": nc.http_path or "/", "headers": nc.http_headers or {}}
            ss["network"] = "http"
            ss["httpSettings"] = http_opts
        elif nc.network == "h2":
            ss["network"] = "h2"
            ss["http2Settings"] = {"host": [nc.h2_host or nc.sni]}
        elif nc.network == "grpc":
            ss["network"] = "grpc"
            ss["grpcSettings"] = {"serviceName": nc.grpc_service or ""}
        elif nc.network == "tcp":
            ss["network"] = "tcp"
        else:
            ss["network"] = nc.network

    if ss:
        out["streamSettings"] = ss

    # Mux (connection multiplexing)
    out["mux"] = {"enabled": True, "concurrency": -1}

    return out


def _build_balancer(node_tags: list[str], balancer_tag: str = "leastPing") -> dict:
    """Build the Xray routing.balancers entry for leastPing load balancing."""
    return {
        "tag": balancer_tag,
        "selector": node_tags,
        "strategy": {
            "type": "leastPing",
            "settings": {},
        },
    }


def _build_config(nodes: list[NodeConfig]) -> dict:
    """Build a complete Xray config with all nodes + leastPing balancer."""
    inbounds: list[dict] = [{
        "listen": "127.0.0.1",
        "port": 1080,
        "protocol": "socks",
        "settings": {"auth": "noauth", "udp": True},
        "tag": "socks-in",
    }, {
        "listen": "127.0.0.1",
        "port": 1081,
        "protocol": "http",
        "tags": ["http-in"],
    }]

    outbounds: list[dict] = []
    node_tags: list[str] = []

    for nc in nodes:
        ob = _node_to_xray_outbound(nc)
        outbounds.append(ob)
        node_tags.append(ob["tag"])

    # Direct/freedom outbound (fallback)
    outbounds.append({
        "protocol": "freedom",
        "name": "direct",
        "tag": "direct",
        "settings": {"domainStrategy": "UseIPv4"},
    })

    # DNS outbound
    outbounds.append({
        "protocol": "dns",
        "name": "dns-out",
        "tag": "dns-out",
        "settings": {"address": "1.1.1.1", "port": 53},
    })

    balancers = []
    if node_tags:
        balancers.append(_build_balancer(node_tags))

    config = {
        "log": {"loglevel": "warning"},
        "api": {
            "services": ["observer"],
            "listen": "127.0.0.1:1082",
            "protocol": "gRPC",
        },
        "dns": {
            "servers": [{"address": "1.1.1.1", "tag": "local_dns"},
                        {"address": "8.8.8.8", "tag": "remote_dns"}],
            "rules": [
                {"domain": ["dns.google", "one.one.one.one"], "server": "local_dns"},
            ],
            "final": "remote_dns",
        },
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"},
                {"type": "field", "domain": ["category-dns-dns", "dns.google", "one.one.one.one"], "outboundTag": "dns-out"},
            ],
            "balancers": balancers,
        },
        "observatory": {
            "enable": True,
            "subjects": ["leastPing"],
            "probeUrl": "https://connectivitycheck.gstatic.com/generate_204",
            "probe_intervals": 60,
            "pingConfig": {
                "destination": "https://connectivitycheck.gstatic.com/generate_204",
                "connectivity": "http",
                "interval": 300,
                "timeout": 5,
                "sampling": 10,
            },
        },
        "transport": {"tt": {"tcpSetting": {}, "tcp": True}},
        "policy": {
            "rules": [
                {"inboundTag": ["socks-in"], "outboundTag": "leastPing", "type": "logical"},
            ]
        },
        "stats": {},
        "vpn": True,
    }

    return config


def _write_config(config: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(config, indent=2, ensure_ascii=False), encoding="utf-8")


def generate(subs_dir: Path, out_dir: Path) -> int:
    """Generate Xray configs mirroring the subs/ layout."""
    if not subs_dir.exists():
        print(f"generate_xray: subs dir not found: {subs_dir}", file=sys.stderr)
        return 1

    count = 0

    # mix.json — ALL nodes
    all_nodes = load_all_nodes(subs_dir)
    cfg = _build_config(all_nodes)
    _write_config(cfg, out_dir / "mix.json")
    count += 1
    print(f"  xray/mix.json — {len(all_nodes)} nodes")

    # Protocol files (from subs/protocols/)
    proto_dir = subs_dir / "protocols"
    if proto_dir.is_dir():
        out_proto = out_dir / "protocol"
        for f in sorted(proto_dir.glob("*.txt")):
            nodes = load_nodes_from_file(f)
            cfg = _build_config(nodes)
            _write_config(cfg, out_proto / f"{f.stem}.json")
            count += 1
        print(f"  xray/protocol/ — {len(list(out_proto.glob('*.json')))} files")

    # Country files
    country_dir = subs_dir / "country"
    if country_dir.is_dir():
        out_country = out_dir / "country"
        for f in sorted(country_dir.glob("*.txt")):
            nodes = load_nodes_from_file(f)
            cfg = _build_config(nodes)
            _write_config(cfg, out_country / f"{f.stem}.json")
            count += 1
        print(f"  xray/country/ — {len(list(out_country.glob('*.json')))} files")

    # 1000-chunk files
    chunk_dir = subs_dir / "1000"
    if chunk_dir.is_dir():
        out_chunks = out_dir / "1000"
        for f in sorted(chunk_dir.glob("*.txt")):
            nodes = load_nodes_from_file(f)
            cfg = _build_config(nodes)
            _write_config(cfg, out_chunks / f"{f.stem}.json")
            count += 1
        print(f"  xray/1000/ — {len(list(out_chunks.glob('*.json')))} files")

    print(f"\nDone. {count} Xray config files written to {out_dir}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate Xray JSON configs from subs/*.txt node URLs"
    )
    parser.add_argument("--subs-dir", type=str, default=str(ROOT / "subs"),
                        help="Input subs directory (default: ./subs)")
    parser.add_argument("--out-dir", type=str, default=str(ROOT / "xray"),
                        help="Output directory for configs (default: ./xray)")
    args = parser.parse_args()

    subs_dir = Path(args.subs_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    return generate(subs_dir, out_dir)


if __name__ == "__main__":
    sys.exit(main())
