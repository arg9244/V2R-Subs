#!/usr/bin/env python3
"""parse_nodes — parse raw V2Ray node URLs into structured NodeConfig.

Shared parser used by all three core config generators:
  - lib/generate_singbox_config.py
  - lib/generate_xray_config.py
  - lib/generate_mihomo_config.py

Supports: vless, vmess, ss, trojan, hysteria2, hysteria, tuic, socks5

Each NodeConfig is a protocol-agnostic dataclass with all common fields
extracted from the URL. The generators map NodeConfig → core-specific format.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote
from typing import Optional


@dataclass
class NodeConfig:
    """Normalized node configuration extracted from a raw share-link URL."""

    # Identity
    tag: str = ""
    scheme: str = ""          # vless, vmess, ss, trojan, hysteria2, hysteria, tuic, socks5
    remark: str = ""

    # Server
    server: str = ""
    port: int = 0

    # Auth
    uuid: str = ""
    password: str = ""
    cipher: str = ""          # ss: cipher method (e.g. "chacha20-poly1305")
    security: str = ""        # vmess: "auto"|"aes-256-gcm"|"none"|etc.
    flow: str = ""
    encryption: str = ""   # vless: "none"|"auto"|etc.
    obfs: str = ""
    obfs_password: str = ""
    auth: str = ""            # hysteria: auth string

    # Transport / TLS (common across protocols)
    sni: str = ""
    alpn: list[str] = field(default_factory=list)
    tls: bool = False
    reality: bool = False
    public_key: str = ""      # Reality public key
    short_id: str = ""        # Reality short ID
    fingerprint: str = ""     # UTLS fingerprint (chrome, etc.)
    allow_insecure: bool = False

    # Transport settings
    network: str = ""         # tcp, ws, http, h2, grpc, xhttp, httpupgrade
    ws_path: str = ""
    ws_headers: dict[str, str] = field(default_factory=dict)
    grpc_service: str = ""
    http_path: str = ""
    http_headers: dict[str, str] = field(default_factory=dict)
    h2_path: str = ""
    h2_host: str = ""
    max_early_data: int = 0
    early_data_header: str = ""

    # TUIC
    congestion_control: str = ""
    udp_relay_mode: str = ""
    disable_sni: bool = False

    # Hysteria2
    down_mbps: str = ""
    up_mbps: str = ""
    ports: str = ""

    # SS plugin
    plugin: str = ""
    plugin_opts: dict[str, str] = field(default_factory=dict)

    # SOCKS5 / HTTP
    username: str = ""
    password: str = ""

    # Wireguard (if ever needed)
    wg_private_key: str = ""
    wg_public_key: str = ""
    wg_address: str = ""
    wg_endpoint: str = ""
    wg_pre_shared_key: str = ""
    wg_mtu: int = 0


def _b64decode_safe(payload: str) -> Optional[str]:
    """Base64-decode a URL-safe or standard payload, tolerating missing padding."""
    payload = payload.strip()
    pad = "=" * (-len(payload) % 4)
    for dec in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            return dec(payload + pad).decode("utf-8", errors="replace")
        except Exception:
            continue
    return None


def _is_ipv6_host(host: str) -> bool:
    cleaned = host.strip("[]")
    return ":" in cleaned and cleaned.count(":") > 1


def _parse_remarks(qs: dict[str, list[str]]) -> dict[str, str]:
    """Flatten query params to single-value strings (first occurrence)."""
    return {k: v[0] if v else "" for k, v in qs.items()}


def _safe_int(val: str, default: int = 0) -> int:
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


def parse_vless(url: str) -> Optional[NodeConfig]:
    """Parse vless://UUID@host:port?...#remark"""
    try:
        # Extract the main part and fragment
        frag = ""
        if "#" in url:
            main = url[:url.rindex("#")]
            frag = unquote(url[url.rindex("#") + 1:])
        else:
            main = url

        scheme_end = main.find("://")
        if scheme_end < 0:
            return None
        payload = main[scheme_end + 3:]

        # Split userinfo from host:port
        # vless://[user@]host:port
        at_idx = payload.rfind("@")
        if at_idx < 0:
            return None

        userinfo = payload[:at_idx]       # UUID or username:password
        hostinfo = payload[at_idx + 1:]   # host:port

        # Handle IPv6 in brackets
        if hostinfo.startswith("["):
            bracket_end = hostinfo.find("]")
            if bracket_end < 0:
                return None
            server = hostinfo[1:bracket_end]
            port = _safe_int(hostinfo[bracket_end + 1:].lstrip(":"))
            if _is_ipv6_host(server):
                return None  # IPv6 filtered per project rules
        else:
            parts = hostinfo.rsplit(":", 1)
            if len(parts) != 2:
                return None
            server, port = parts[0], _safe_int(parts[1])

        # Parse UUID (can contain : for username:password in vless)
        # VLESS URL: vless://uuid@host:port  OR vless://username:password@host:port
        # The UUID format is hex-dashes; username:password contains @
        uuid_or_user = userinfo
        if "@" not in uuid_or_user:
            # Standard: just UUID
            uuid = uuid_or_user
        else:
            # username:password format — treat as UUID field (Xray/V2Ray supports this)
            uuid = uuid_or_user.split("@")[0]

        # Parse query string
        qs = parse_qs(urlparse("vless://" + payload).query, keep_blank_values=True)
        params = _parse_remarks(qs)

        nc = NodeConfig(
            tag=f"vless_{server}_{port}",
            scheme="vless",
            remark=frag or params.get("remarks", ""),
            server=server,
            port=port,
            uuid=uuid,
            flow=params.get("flow", ""),
            encryption=params.get("encryption", ""),
            sni=params.get("sni", params.get("servername", "")),
        )

        # TLS
        security = params.get("security", "")
        if "tls" in security or "reality" in security:
            nc.tls = True
        if "reality" in security:
            nc.reality = True
            nc.public_key = params.get("pbk", "")
            nc.short_id = params.get("sid", "")

        # ALPN
        alpn = params.get("alpn", "")
        if alpn and alpn != "None":
            nc.alpn = [a.strip() for a in alpn.split(",") if a.strip()]

        # Fingerprint
        fp = params.get("fp", "")
        if fp and fp != "None":
            nc.fingerprint = fp

        # Allow insecure
        insecure = params.get("allowInsecure", "")
        nc.allow_insecure = insecure in ("1", "true")

        # Transport / network
        net = params.get("type", "tcp")
        nc.network = net

        if net == "ws" or net == "httpupgrade":
            nc.ws_path = params.get("path", "/")
            # Headers from query
            for k, v in qs.items():
                if k.startswith("header_") and v:
                    nc.ws_headers[k[len("header_"):]] = v[0]

            nc.max_early_data = _safe_int(params.get("max_early_data", "0"))
            nc.early_data_header = params.get("early_data_header_name", "")
        elif net == "h2":
            nc.h2_path = params.get("path", "/")
            nc.h2_host = params.get("host", "")
        elif net == "grpc":
            nc.grpc_service = params.get("serviceName", "")
        elif net == "xhttp":
            nc.http_path = params.get("path", "/")
            nc.http_headers = {"Host": params.get("host", "")}
        elif net == "http":
            nc.http_path = params.get("path", "/")

        return nc

    except Exception:
        return None


def parse_vmess(url: str) -> Optional[NodeConfig]:
    """Parse vmess://base64(json_object) or vmess://uuid@host:port"""
    try:
        payload = url[len("vmess://"):]
        # Strip fragment
        frag = ""
        if "#" in payload:
            frag = unquote(payload[payload.rindex("#") + 1:])
            payload = payload[:payload.rindex("#")]

        # Try base64 JSON first
        decoded = _b64decode_safe(payload)
        if decoded and decoded.strip().startswith("{"):
            try:
                cfg = json.loads(decoded)
            except json.JSONDecodeError:
                return None

            server = cfg.get("add", "")
            if _is_ipv6_host(server):
                return None
            port = _safe_int(str(cfg.get("port", 0)))

            nc = NodeConfig(
                tag=f"vmess_{server}_{port}",
                scheme="vmess",
                remark=frag or cfg.get("ps", ""),
                server=server,
                port=port,
                uuid=cfg.get("id", ""),
                security=cfg.get("scy", "auto"),
                flow=cfg.get("flow", ""),
            )

            # TLS
            if cfg.get("tls", "") == "tls":
                nc.tls = True
                nc.allow_insecure = str(cfg.get("allowInsecure", "")) == "1"
            nc.sni = cfg.get("sni", cfg.get("host", ""))
            nc.alpn = [a.strip() for a in cfg.get("alpn", "").split(",") if a.strip()] if cfg.get("alpn") else []
            fp = cfg.get("fp", "")
            if fp and fp != "None":
                nc.fingerprint = fp

            # Reality
            if cfg.get("security") == "reality" or cfg.get("tlstype") == "xtls-rprx-vision" or cfg.get("tlstype") == "reality":
                nc.reality = True
                nc.public_key = cfg.get("pbk", "")
                nc.short_id = cfg.get("sid", "")

            # Transport
            net = cfg.get("net", "tcp")
            nc.network = net
            if net in ("ws", "http", "httpupgrade"):
                nc.ws_path = cfg.get("path", "/")
                nc.ws_headers = {"Host": cfg.get("host", "")} if cfg.get("host") else {}
            elif net == "h2":
                nc.h2_path = cfg.get("path", "/")
                nc.h2_host = cfg.get("host", "")
            elif net == "grpc":
                nc.grpc_service = cfg.get("serviceName", "")

            return nc

        # URI-style vmess (rare, e.g. vmess://uuid@host:port)
        m = re.match(r'vmess://([^@]+)@([^:]+):(\d+)', url, re.IGNORECASE)
        if m:
            if _is_ipv6_host(m.group(2)):
                return None
            return NodeConfig(
                tag=f"vmess_{m.group(2)}_{m.group(3)}",
                scheme="vmess",
                remark=frag or m.group(1),
                server=m.group(2),
                port=_safe_int(m.group(3)),
                uuid=m.group(1),
                security="auto",
            )
        return None

    except Exception:
        return None


def _parse_ss_url(url: str) -> Optional[NodeConfig]:
    """Parse ss:// URL (handles base64 and plain formats)."""
    try:
        frag = ""
        body = url[len("ss://"):]
        if "#" in body:
            frag = unquote(body[body.rindex("#") + 1:])
            body = body[:body.rindex("#")]

        # Try standard format: ss://cipher:password@host:port
        m = re.match(r'([^@]+)@([^:]+):(\d+)', body, re.IGNORECASE)
        if m and ":" in m.group(1):
            cipher_pass = m.group(1)
            if ":" in cipher_pass:
                # Handle cipher:password that might contain base64-encoded password
                parts = cipher_pass.split(":", 1)
                cipher = parts[0]
                password = parts[1]
            else:
                cipher = cipher_pass
                password = ""
            host = m.group(2)
            if _is_ipv6_host(host):
                return None
            return NodeConfig(
                tag=f"ss_{host}_{m.group(3)}",
                scheme="ss",
                remark=frag,
                server=host,
                port=_safe_int(m.group(3)),
                cipher=cipher,
                password=password,
            )

        # Try base64 format: ss://base64(cipher:password@host:port)
        decoded = _b64decode_safe(body)
        if decoded:
            m = re.match(r'([^@]+)@([^:]+):(\d+)', decoded, re.IGNORECASE)
            if m and ":" in m.group(1):
                parts = m.group(1).split(":", 1)
                host = m.group(2)
                if _is_ipv6_host(host):
                    return None
                return NodeConfig(
                    tag=f"ss_{host}_{m.group(3)}",
                    scheme="ss",
                    remark=frag,
                    server=host,
                    port=_safe_int(m.group(3)),
                    cipher=parts[0],
                    password=parts[1],
                )
        return None

    except Exception:
        return None


def parse_trojan(url: str) -> Optional[NodeConfig]:
    """Parse trojan://password@host:port?...#remark"""
    try:
        frag = ""
        body = url[len("trojan://"):]
        if "#" in body:
            frag = unquote(body[body.rindex("#") + 1:])
            body = body[:body.rindex("#")]

        at_idx = body.rfind("@")
        if at_idx < 0:
            return None
        password = body[:at_idx]
        hostinfo = body[at_idx + 1:]

        # Handle IPv6
        if hostinfo.startswith("["):
            return None
        parts = hostinfo.rsplit(":", 1)
        if len(parts) != 2:
            return None
        server, port = parts[0], _safe_int(parts[1])
        if _is_ipv6_host(server):
            return None

        # Parse query
        qs = parse_qs(urlparse("trojan://" + body).query, keep_blank_values=True)
        params = _parse_remarks(qs)

        nc = NodeConfig(
            tag=f"trojan_{server}_{port}",
            scheme="trojan",
            remark=frag or params.get("remarks", ""),
            server=server,
            port=port,
            password=password,
            flow=params.get("flow", ""),
            sni=params.get("sni", ""),
            tls=True,
        )

        alpn = params.get("alpn", "")
        if alpn:
            nc.alpn = [a.strip() for a in alpn.split(",") if a.strip()]

        fp = params.get("fp", "")
        if fp and fp != "None":
            nc.fingerprint = fp

        nc.allow_insecure = params.get("allowInsecure", "") in ("1", "true")

        # Transport
        net = params.get("network", "")
        if net:
            nc.network = net
            if net == "ws":
                nc.ws_path = params.get("path", "/")
                nc.max_early_data = _safe_int(params.get("max_early_date", "0"))
            elif net == "grpc":
                nc.grpc_service = params.get("serviceName", "")
            elif net == "http":
                nc.http_path = params.get("path", "/")

        return nc

    except Exception:
        return None


def parse_hysteria(url: str) -> Optional[NodeConfig]:
    """Parse hysteria2:// or hysteria:// URL."""
    try:
        frag = ""
        body = url.split("://", 1)[1]
        if "#" in body:
            frag = unquote(body[body.rindex("#") + 1:])
            body = body[:body.rindex("#")]

        at_idx = body.rfind("@")
        # hysteria2://auth@host:port or hysteria2://user:pass@host:port
        if at_idx < 0:
            return None
        userinfo = body[:at_idx]
        hostinfo = body[at_idx + 1:]

        if hostinfo.startswith("["):
            return None
        parts = hostinfo.rsplit(":", 1)
        if len(parts) != 2:
            return None
        server, port = parts[0], _safe_int(parts[1])
        if _is_ipv6_host(server):
            return None

        qs = parse_qs(urlparse(url).query, keep_blank_values=True)
        params = _parse_remarks(qs)

        nc = NodeConfig(
            tag=f"hys_{server}_{port}",
            scheme="hysteria2",
            remark=frag,
            server=server,
            port=port,
            auth=userinfo,
            password=params.get("password", userinfo),
            sni=params.get("sni", params.get("peer", "")),
            obfs=params.get("obfs", ""),
        )

        nc.tls = True
        alpn = params.get("alpn", "")
        if alpn:
            nc.alpn = [a.strip() for a in alpn.split(",") if a.strip()]

        fp = params.get("fp", "")
        if fp and fp != "None":
            nc.fingerprint = fp

        nc.allow_insecure = params.get("insecure", "") == "1" or params.get("allowInsecure", "") == "1"
        nc.down_mbps = params.get("downmbps", params.get("down", ""))
        nc.up_mbps = params.get("upmbps", params.get("up", ""))

        # Hysteria2 realm mode
        if params.get("auth", ""):
            nc.auth = params.get("auth")

        return nc

    except Exception:
        return None


def parse_tuic(url: str) -> Optional[NodeConfig]:
    """Parse tuic://uuid:password@host:port?...#remark"""
    try:
        frag = ""
        body = url[len("tuic://"):]
        if "#" in body:
            frag = unquote(body[body.rindex("#") + 1:])
            body = body[:body.rindex("#")]

        at_idx = body.rfind("@")
        if at_idx < 0:
            return None
        userinfo = body[:at_idx]
        hostinfo = body[at_idx + 1:]

        if hostinfo.startswith("["):
            return None
        parts = hostinfo.rsplit(":", 1)
        if len(parts) != 2:
            return None
        server, port = parts[0], _safe_int(parts[1])
        if _is_ipv6_host(server):
            return None

        # userinfo = uuid:password
        if ":" in userinfo:
            uuid_val, password = userinfo.split(":", 1)
        else:
            uuid_val, password = userinfo, ""

        qs = parse_qs(urlparse(url).query, keep_blank_values=True)
        params = _parse_remarks(qs)

        nc = NodeConfig(
            tag=f"tuic_{server}_{port}",
            scheme="tuic",
            remark=frag,
            server=server,
            port=port,
            uuid=uuid_val,
            password=password,
            sni=params.get("sni", ""),
            alpn=[a.strip() for a in params.get("alpn", "").split(",") if a.strip()] if params.get("alpn") else [],
            tls=True,
            congestion_control=params.get("congestion_control", "bbr"),
            disable_sni=params.get("disable_sni", "0") == "1",
            udp_relay_mode=params.get("udp_relay_mode", ""),
        )

        fp = params.get("fp", "")
        if fp and fp != "None":
            nc.fingerprint = fp

        nc.allow_insecure = params.get("insecure", "") == "1" or params.get("allowInsecure", "") == "1"

        return nc

    except Exception:
        return None


def parse_socks5(url: str) -> Optional[NodeConfig]:
    """Parse socks5://user:pass@host:port"""
    try:
        parsed = urlparse(url)
        if parsed.scheme.lower() != "socks5":
            return None

        frag = unquote(parsed.fragment) if parsed.fragment else ""
        server = parsed.hostname
        if server and _is_ipv6_host(server):
            return None

        return NodeConfig(
            tag=f"socks5_{server}_{parsed.port or 0}",
            scheme="socks5",
            remark=frag,
            server=server or "",
            port=parsed.port or 0,
            username=parsed.username or "",
            password=parsed.password or "",
            tls=False,
        )

    except Exception:
        return None
# Scheme → parser dispatch
PARSERS = {
    "vless": parse_vless,
    "vmess": parse_vmess,
    "ss": _parse_ss_url,
    "socks5": parse_socks5,
    "trojan": parse_trojan,
    "hysteria2": parse_hysteria,
    "hy2": parse_hysteria,
    "tuic": parse_tuic,
}


def parse_node_url(url: str) -> Optional[NodeConfig]:
    """Parse any supported node URL into a NodeConfig, or None if unsupported/invalid.

    Returns None for IPv6 hosts (filtered per project rules).
    """
    url = url.strip()
    if not url or url.startswith("#"):
        return None

    for scheme in PARSERS:
        if url.lower().startswith(scheme + "://"):
            return PARSERS[scheme](url)

    return None


def load_nodes_from_file(path: Path) -> list[NodeConfig]:
    """Load and parse all nodes from a file (one URL per line)."""
    nodes: list[NodeConfig] = []
    if not path.is_file():
        return nodes

    for line in path.read_text("utf-8", "replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        nc = parse_node_url(line)
        if nc is not None:
            nodes.append(nc)

    return nodes


def load_all_nodes(subs_dir: Path) -> list[NodeConfig]:
    """Load all nodes from subs/*.txt (top-level files only, not subdirectories)."""
    nodes: list[NodeConfig] = []
    for f in sorted(subs_dir.glob("*.txt")):
        nodes.extend(load_nodes_from_file(f))
    return nodes


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 lib/parse_nodes.py <file.txt>", file=sys.stderr)
        sys.exit(1)
    path = Path(sys.argv[1])
    nodes = load_nodes_from_file(path)
    print(f"Parsed {len(nodes)} nodes from {path.name}")
    for nc in nodes[:5]:
        print(f"  [{nc.scheme}] {nc.server}:{nc.port} tag={nc.tag}")
