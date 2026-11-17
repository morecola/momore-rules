#!/usr/bin/env python3
"""
多源 Mihomo 分流规则自动聚合、父子域名树去重、CIDR 子网合并与 .mrs 编译工具。
参考 Loyalsoldier/clash-rules 与 VPSDance/ai-proxy-rules 架构设计。
零第三方 Python 依赖（仅使用标准库）。
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime
import ipaddress
import json
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
SOURCES_FILE = ROOT_DIR / "sources.json"
CUSTOM_DIR = ROOT_DIR / "custom"
DIST_DIR = ROOT_DIR / "dist"
RULES_OUT_DIR = DIST_DIR / "rules"

DOMAIN_CHARS_RE = re.compile(r"^[a-z0-9_*.-]+$")

VALID_CLASSICAL_TYPES = {
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "DOMAIN-WILDCARD",
    "DOMAIN-REGEX",
    "GEOSITE",
    "IP-CIDR",
    "IP-CIDR6",
    "IP-SUFFIX",
    "IP-ASN",
    "GEOIP",
    "SRC-GEOIP",
    "SRC-IP-ASN",
    "SRC-IP-CIDR",
    "SRC-IP-SUFFIX",
    "DST-PORT",
    "SRC-PORT",
    "IN-PORT",
    "IN-TYPE",
    "IN-USER",
    "IN-NAME",
    "PROCESS-PATH",
    "PROCESS-PATH-REGEX",
    "PROCESS-NAME",
    "PROCESS-NAME-REGEX",
    "UID",
    "NETWORK",
    "DSCP",
    "RULE-SET",
    "AND",
    "OR",
    "NOT",
    "SUB-RULE",
}

IP_RULE_TYPES = {"IP-CIDR", "IP-CIDR6", "IP-SUFFIX", "IP-ASN", "GEOIP"}


# ---------------------------------------------------------------------------
# 网络拉取层（带重试与备用镜像容灾）
# ---------------------------------------------------------------------------
def fetch_text(urls: list[str], timeout: int = 30, retries: int = 3) -> str:
    last_err: Exception | None = None
    headers = {"User-Agent": "mihomo-rules-aggregator/2.0"}
    for url in urls:
        for attempt in range(1, retries + 1):
            try:
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    if resp.status != 200:
                        raise RuntimeError(f"HTTP {resp.status}")
                    raw = resp.read()
                    if not raw:
                        raise RuntimeError("响应内容为空")
                    text = raw.decode("utf-8", errors="replace")
                    if text.lstrip().lower().startswith("<!doctype html"):
                        raise RuntimeError("返回了 HTML 错误页而非规则文本")
                    return text
            except Exception as exc:
                last_err = exc
                if attempt < retries:
                    time.sleep(1.5 * attempt)
    raise RuntimeError(f"拉取失败 {urls}: {last_err}")


# ---------------------------------------------------------------------------
# 通用行清洗
# ---------------------------------------------------------------------------
def clean_line(raw: str) -> str | None:
    line = raw.strip()
    if not line or line.startswith(("#", "//", ";", "!")):
        return None
    if line.startswith("[") and line.endswith("]"):
        return None
    if line.startswith("payload:"):
        return None
    if line in ("[]", "payload: []"):
        return None
    if line.startswith("-"):
        line = line[1:].strip()
    if not line or line.startswith("#"):
        return None
    # 剥离行内注释（要求 # 前有空白，避免误伤正则或特殊字符）
    line = re.sub(r"\s+#.*$", "", line).strip()
    if (line.startswith("'") and line.endswith("'")) or (
        line.startswith('"') and line.endswith('"')
    ):
        line = line[1:-1].strip()
    return line or None


def is_valid_domain(d: str) -> bool:
    d = d.strip().lower()
    if not d or len(d) > 253 or ".." in d:
        return False
    if d.startswith("-") or d.endswith("-"):
        return False
    return bool(DOMAIN_CHARS_RE.match(d))


# ---------------------------------------------------------------------------
# 1. 域名集合与「父子域名树去重」引擎
# ---------------------------------------------------------------------------
@dataclass
class DomainSet:
    suffixes: set[str] = field(default_factory=set)   # 对应 +.example.com（匹配自身及所有子域）
    exacts: set[str] = field(default_factory=set)     # 对应 example.com（仅精确匹配）
    wildcards: set[str] = field(default_factory=set)  # 对应含 * 的通配域名（如 +.stun.*.* / xbox.*.microsoft.com）
    raw_count: int = 0

    def add_suffix(self, domain: str) -> bool:
        d = domain.strip().lower().lstrip(".")
        if not is_valid_domain(d):
            return False
        if "*" in d:
            self.wildcards.add(f"+.{d}")
        else:
            self.suffixes.add(d)
        self.raw_count += 1
        return True

    def add_exact(self, domain: str) -> bool:
        d = domain.strip().lower().lstrip(".")
        if not is_valid_domain(d):
            return False
        if "*" in d:
            self.wildcards.add(d)
        else:
            self.exacts.add(d)
        self.raw_count += 1
        return True

    def ingest_text(self, text: str, source_name: str = "", strict: bool = False) -> None:
        """兼容 domain YAML / text list / classical YAML / AdBlock ||domain^ 四种上游格式提取域名"""
        for raw in text.splitlines():
            line = clean_line(raw)
            if not line:
                continue
            if line.startswith("@@"):
                if strict:
                    raise ValueError(f"[{source_name}] domain 规则集不支持 @@ 例外语法: {raw!r}")
                continue
            if line.startswith("||") and line.endswith("^"):
                dom = line[2:-1]
                if "/" not in dom and "$" not in dom:
                    if not self.add_suffix(dom) and strict:
                        raise ValueError(f"[{source_name}] 非法 AdBlock 域名后缀: {raw!r}")
                elif strict:
                    raise ValueError(f"[{source_name}] 不支持的复杂 AdBlock 规则: {raw!r}")
                continue
            if "," in line:
                parts = [p.strip() for p in line.split(",")]
                rtype = parts[0].upper()
                val = parts[1] if len(parts) > 1 else ""
                if rtype == "DOMAIN-SUFFIX":
                    if not self.add_suffix(val) and strict:
                        raise ValueError(f"[{source_name}] 非法域名后缀: {raw!r}")
                elif rtype in {"DOMAIN", "DOMAIN-WILDCARD"}:
                    if not self.add_exact(val) and strict:
                        raise ValueError(f"[{source_name}] 非法域名: {raw!r}")
                elif strict:
                    raise ValueError(f"[{source_name}] domain 规则集不支持类型 {rtype!r}: {raw!r}")
                # 非严格模式下忽略 DOMAIN-KEYWORD / IP-CIDR 等非 domain rule-set 支持的类型
                continue

            # 无逗号：处理 +.foo.com / .foo.com / *.foo.com / foo.com
            if line.startswith("+."):
                if not self.add_suffix(line[2:]) and strict:
                    raise ValueError(f"[{source_name}] 非法域名后缀: {raw!r}")
            elif line.startswith("."):
                if not self.add_suffix(line[1:]) and strict:
                    raise ValueError(f"[{source_name}] 非法域名后缀: {raw!r}")
            elif line.startswith("*."):
                # *.foo.com 仅匹配子域不匹配根域，保留通配写法
                if is_valid_domain(line):
                    self.wildcards.add(line.lower())
                    self.raw_count += 1
                elif strict:
                    raise ValueError(f"[{source_name}] 非法通配域名: {raw!r}")
            else:
                # 排除纯 IP / CIDR 行
                try:
                    ipaddress.ip_network(line, strict=False)
                    if strict:
                        raise ValueError(f"[{source_name}] domain 规则集不能包含 IP 网段: {raw!r}")
                    continue
                except ValueError as exc:
                    if strict and "domain 规则集不能包含 IP 网段" in str(exc):
                        raise
                if not self.add_exact(line) and strict:
                    raise ValueError(f"[{source_name}] 非法域名: {raw!r}")

    @staticmethod
    def _has_parent_in(domain: str, suffix_pool: set[str], include_self: bool) -> bool:
        parts = domain.split(".")
        start = 0 if include_self else 1
        for i in range(start, len(parts)):
            candidate = ".".join(parts[i:])
            if candidate in suffix_pool:
                return True
        return False

    def covers_suffix(self, suffix: str) -> bool:
        if suffix in self.exacts:
            return True
        return self._has_parent_in(suffix, self.suffixes, include_self=True)

    def covers_exact(self, domain: str) -> bool:
        if domain in self.exacts:
            return True
        return self._has_parent_in(domain, self.suffixes, include_self=True)

    def subtract(self, other: "DomainSet") -> None:
        """剔除已被 other 覆盖的域名（用于防污染与黑名单剔除）"""
        if not other.suffixes and not other.exacts and not other.wildcards:
            return
        self.suffixes = {s for s in self.suffixes if not other.covers_suffix(s)}
        self.exacts = {d for d in self.exacts if not other.covers_exact(d)}
        self.wildcards = {
            w
            for w in self.wildcards
            if w not in other.wildcards
            and not (
                (w.startswith("*.") or w.startswith("+."))
                and "*" not in w[2:]
                and other.covers_suffix(w[2:])
            )
        }

    def deduplicate(self) -> None:
        """父子域名树精简：若 +.google.com 存在，自动剪枝 +.mail.google.com 与 www.google.com"""
        self.suffixes = {
            s for s in self.suffixes if not self._has_parent_in(s, self.suffixes, include_self=False)
        }
        self.exacts = {
            d for d in self.exacts if not self._has_parent_in(d, self.suffixes, include_self=True)
        }
        self.wildcards = {
            w
            for w in self.wildcards
            if not (
                (w.startswith("*.") or w.startswith("+."))
                and "*" not in w[2:]
                and self._has_parent_in(w[2:], self.suffixes, include_self=True)
            )
        }

    def to_payload_list(self) -> list[str]:
        self.deduplicate()
        items: list[str] = []
        for s in sorted(self.suffixes):
            items.append(f"+.{s}")
        for w in sorted(self.wildcards):
            items.append(w)
        for d in sorted(self.exacts):
            items.append(d)
        return items


# ---------------------------------------------------------------------------
# 2. IP-CIDR 集合与「相邻/重叠子网聚合」引擎
# ---------------------------------------------------------------------------
def _exclude_networks(
    nets: list, excludes: list
) -> list:
    if not nets or not excludes:
        return nets
    collapsed_ex = list(ipaddress.collapse_addresses(excludes))
    current = list(ipaddress.collapse_addresses(nets))
    for ex in collapsed_ex:
        next_nets = []
        for net in current:
            if not net.overlaps(ex):
                next_nets.append(net)
            elif net.subnet_of(ex):
                continue
            else:
                next_nets.extend(net.address_exclude(ex))
        current = next_nets
    return current


@dataclass
class IPCIDRSet:
    v4: list[ipaddress.IPv4Network] = field(default_factory=list)
    v6: list[ipaddress.IPv6Network] = field(default_factory=list)
    raw_count: int = 0

    def add_cidr(self, token: str) -> bool:
        try:
            net = ipaddress.ip_network(token.strip(), strict=False)
        except ValueError:
            return False
        if isinstance(net, ipaddress.IPv4Network):
            self.v4.append(net)
        else:
            self.v6.append(net)
        self.raw_count += 1
        return True

    def ingest_text(self, text: str, source_name: str = "", strict: bool = False) -> None:
        for raw in text.splitlines():
            line = clean_line(raw)
            if not line:
                continue
            if "," in line:
                parts = [p.strip() for p in line.split(",")]
                rtype = parts[0].upper()
                if rtype in {"IP-CIDR", "IP-CIDR6"} and len(parts) >= 2:
                    if not self.add_cidr(parts[1]) and strict:
                        raise ValueError(f"[{source_name}] 非法 CIDR 网段: {raw!r}")
                elif strict:
                    raise ValueError(f"[{source_name}] ipcidr 规则集不支持类型 {rtype!r}: {raw!r}")
            else:
                if not self.add_cidr(line) and strict:
                    raise ValueError(f"[{source_name}] 非法 CIDR 网段: {raw!r}")

    def subtract(self, other: "IPCIDRSet") -> None:
        if other.v4:
            self.v4 = _exclude_networks(self.v4, other.v4)
        if other.v6:
            self.v6 = _exclude_networks(self.v6, other.v6)

    def to_payload_list(self) -> list[str]:
        collapsed_v4 = list(ipaddress.collapse_addresses(self.v4))
        collapsed_v6 = list(ipaddress.collapse_addresses(self.v6))
        return [str(n) for n in collapsed_v4] + [str(n) for n in collapsed_v6]


# ---------------------------------------------------------------------------
# 3. Classical 混合规则集合（支持域名树去重 + CIDR 聚合 + 自动补齐 no-resolve）
# ---------------------------------------------------------------------------
@dataclass
class ClassicalSet:
    domains: DomainSet = field(default_factory=DomainSet)
    ips: IPCIDRSet = field(default_factory=IPCIDRSet)
    other_rules: list[str] = field(default_factory=list)
    raw_count: int = 0

    def ingest_text(self, text: str, source_name: str = "", strict: bool = False) -> None:
        for raw in text.splitlines():
            line = clean_line(raw)
            if not line:
                continue

            if "," not in line:
                # 兼容混入的 domain / ipcidr 纯列表上游（如 MetaCubeX category-ai-!cn.yaml）
                if line.startswith("+."):
                    if not self.domains.add_suffix(line[2:]) and strict:
                        raise ValueError(f"[{source_name}] 非法域名后缀: {raw!r}")
                    self.raw_count += 1
                elif line.startswith("."):
                    if not self.domains.add_suffix(line[1:]) and strict:
                        raise ValueError(f"[{source_name}] 非法域名后缀: {raw!r}")
                    self.raw_count += 1
                else:
                    try:
                        ipaddress.ip_network(line, strict=False)
                        self.ips.add_cidr(line)
                        self.raw_count += 1
                        continue
                    except ValueError:
                        pass
                    if is_valid_domain(line):
                        self.domains.add_exact(line)
                        self.raw_count += 1
                    elif strict:
                        raise ValueError(f"[{source_name}] 无法识别的规则行: {raw!r}")
                continue

            first_comma = line.find(",")
            rtype = line[:first_comma].strip().upper()
            rest = line[first_comma + 1 :].strip()

            if rtype not in VALID_CLASSICAL_TYPES:
                if strict:
                    raise ValueError(f"[{source_name}] 不支持的规则类型 {rtype!r}: {raw!r}")
                continue

            # 第三方上游中的 IP-ASN / GEOIP / GEOSITE 会依赖额外的 ASN.mmdb / GeoIP.dat 数据库，默认跳过保持纯 .mrs 零外部数据库依赖
            if not strict and rtype in {"IP-ASN", "SRC-IP-ASN", "GEOIP", "SRC-GEOIP", "GEOSITE"}:
                continue

            if rtype in {
                "AND",
                "OR",
                "NOT",
                "SUB-RULE",
                "DOMAIN-REGEX",
                "PROCESS-PATH-REGEX",
                "PROCESS-NAME-REGEX",
            }:
                self.other_rules.append(f"{rtype},{rest}")
                self.raw_count += 1
                continue

            parts = [p.strip() for p in rest.split(",")]
            target = parts[0]
            if not target:
                if strict:
                    raise ValueError(f"[{source_name}] 规则目标为空: {raw!r}")
                continue

            if rtype == "DOMAIN-SUFFIX":
                if not self.domains.add_suffix(target):
                    if strict:
                        raise ValueError(f"[{source_name}] 非法域名后缀: {raw!r}")
                    continue
                self.raw_count += 1
            elif rtype in {"DOMAIN", "DOMAIN-WILDCARD"}:
                if not self.domains.add_exact(target):
                    if strict:
                        raise ValueError(f"[{source_name}] 非法域名: {raw!r}")
                    continue
                self.raw_count += 1
            elif rtype in {"IP-CIDR", "IP-CIDR6"}:
                if not self.ips.add_cidr(target):
                    if strict:
                        raise ValueError(f"[{source_name}] 非法 CIDR 网段: {raw!r}")
                    continue
                self.raw_count += 1
            elif rtype in IP_RULE_TYPES:
                # IP-ASN / GEOIP 等强制附带 no-resolve 避免前置规则触发本地 DNS 解析
                self.other_rules.append(f"{rtype},{target},no-resolve")
                self.raw_count += 1
            else:
                # DOMAIN-KEYWORD / PROCESS-NAME 等
                self.other_rules.append(f"{rtype},{target}")
                self.raw_count += 1

    def subtract(self, other: "ClassicalSet") -> None:
        self.domains.subtract(other.domains)
        self.ips.subtract(other.ips)
        other_set = set(other.other_rules)
        self.other_rules = [r for r in self.other_rules if r not in other_set]

    def to_payload_list(self) -> list[str]:
        self.domains.deduplicate()
        out: list[str] = []
        for s in sorted(self.domains.suffixes):
            out.append(f"DOMAIN-SUFFIX,{s}")
        for w in sorted(self.domains.wildcards):
            out.append(f"DOMAIN-WILDCARD,{w}")
        for d in sorted(self.domains.exacts):
            out.append(f"DOMAIN,{d}")

        # 保留并去重 KEYWORD / REGEX / PROCESS-NAME 等规则
        seen_other: set[str] = set()
        for r in self.other_rules:
            if r not in seen_other:
                seen_other.add(r)
                out.append(r)

        # 所有 IP 段聚合后统一附带 no-resolve，确保 Fake-IP 0.1ms 不触发本地 DNS 解析
        for cidr in self.ips.to_payload_list():
            prefix = "IP-CIDR6" if ":" in cidr else "IP-CIDR"
            out.append(f"{prefix},{cidr},no-resolve")
        return out


# ---------------------------------------------------------------------------
# YAML 序列化与 .mrs 编译
# ---------------------------------------------------------------------------
YAML_SPECIAL_CHARS = set(":#[]{}*+?&|!%@`'\"")


def render_yaml(payload: list[str], header_comment: str, empty_placeholder: str) -> str:
    effective = payload if payload else [empty_placeholder]
    lines = [f"# {header_comment}", "payload:"]
    for item in effective:
        if any(ch in YAML_SPECIAL_CHARS for ch in item):
            escaped = item.replace("'", "''")
            lines.append(f"  - '{escaped}'")
        else:
            lines.append(f"  - {item}")
    return "\n".join(lines) + "\n"


def compile_mrs(mihomo_bin: str, behavior: str, yaml_path: Path, mrs_path: Path) -> None:
    cmd = [mihomo_bin, "convert-ruleset", behavior, "yaml", str(yaml_path), str(mrs_path)]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0 or not mrs_path.exists() or mrs_path.stat().st_size == 0:
        raise RuntimeError(
            f"mihomo convert-ruleset 编译失败 ({yaml_path.name}): "
            f"code={res.returncode}, stderr={res.stderr.strip()}, stdout={res.stdout.strip()}"
        )


def format_size(num_bytes: int) -> str:
    if num_bytes < 1024:
        return f"{num_bytes} B"
    if num_bytes < 1024 * 1024:
        return f"{num_bytes / 1024:.1f} KB"
    return f"{num_bytes / (1024 * 1024):.2f} MB"


def read_custom_classical(filename: str) -> ClassicalSet:
    cset = ClassicalSet()
    path = CUSTOM_DIR / filename
    if path.exists():
        cset.ingest_text(path.read_text(encoding="utf-8"), source_name=f"custom/{filename}", strict=True)
    return cset


def toposort_section(
    section_cfg: dict[str, dict], prebuilt_names: set[str]
) -> list[tuple[str, dict]]:
    """按 exclude_sets 依赖关系进行拓扑排序，杜绝字典顺序导致的防污染漏剔除"""
    order: list[tuple[str, dict]] = []
    state: dict[str, int] = {}  # 0=unvisited, 1=visiting, 2=done

    def visit(name: str) -> None:
        st = state.get(name, 0)
        if st == 2:
            return
        if st == 1:
            raise ValueError(f"sources.json 中存在循环 exclude_sets 依赖: {name}")
        state[name] = 1
        cfg = section_cfg[name]
        for dep in cfg.get("exclude_sets", []):
            if dep in section_cfg:
                visit(dep)
            elif dep not in prebuilt_names:
                raise ValueError(
                    f"[{name}] exclude_sets 引用了未定义或尚未构建的规则集: {dep!r}"
                )
        state[name] = 2
        order.append((name, cfg))

    for key in section_cfg:
        visit(key)
    return order


# ---------------------------------------------------------------------------
# 主构建流水线
# ---------------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser(description="多源拉取、去重合并并编译 Mihomo 规则集")
    parser.add_argument(
        "--mihomo",
        default=shutil.which("mihomo") or "",
        help="mihomo 二进制路径（提供时自动将 domain/ipcidr 规则集编译为二进制 .mrs）",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="离线自检模式：仅校验本地 custom/ 与 sources.json 并验证去重逻辑，不联网拉取",
    )
    args = parser.parse_args()

    config = json.loads(SOURCES_FILE.read_text(encoding="utf-8"))
    RULES_OUT_DIR.mkdir(parents=True, exist_ok=True)

    # 1. 加载并严格校验本地 custom/ 规则
    custom_exclude = read_custom_classical("exclude.yaml")
    user_direct_cset = read_custom_classical("direct.yaml")
    user_direct_cset.subtract(custom_exclude)

    proxy_cset = read_custom_classical("proxy.yaml")
    proxy_cset.subtract(custom_exclude)
    proxy_cset.subtract(user_direct_cset)

    # 2. 并发拉取 sources.json 中定义的所有上游文本（含 exclude_upstreams，按 URL 去重）
    fetched_texts: dict[str, str] = {}
    if not args.dry_run:
        unique_upstreams: dict[str, dict] = {}
        for section in ("domain", "ipcidr", "classical"):
            for item_cfg in config.get(section, {}).values():
                for key in ("upstreams", "exclude_upstreams"):
                    for up in item_cfg.get(key, []):
                        url = up["url"]
                        if url not in unique_upstreams:
                            unique_upstreams[url] = dict(up)
                        elif up.get("required", False):
                            unique_upstreams[url]["required"] = True

        print(f"[INFO] 正在并发拉取 {len(unique_upstreams)} 个公开上游规则源...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
            future_map = {}
            for url, up in unique_upstreams.items():
                urls = [url]
                if up.get("fallback_url"):
                    urls.append(up["fallback_url"])
                future_map[url] = (up, pool.submit(fetch_text, urls))

            for url, (up, fut) in future_map.items():
                try:
                    fetched_texts[url] = fut.result()
                    print(f"  [FETCH OK] {up['name']}")
                except Exception as exc:
                    if up.get("required", True):
                        print(f"  [FATAL] 核心上游拉取失败 {up['name']}: {exc}", file=sys.stderr)
                        return 1
                    print(f"  [WARN] 补充上游拉取失败（已自动跳过）{up['name']}: {exc}", file=sys.stderr)

    # 3. 先构建 classical 规则集（direct / proxy / gemini / ai），以便后续给 domain 集合做防污染剔除
    direct_cset = ClassicalSet()
    direct_cfg = config.get("classical", {}).get("direct", {})
    for up in direct_cfg.get("upstreams", []):
        txt = fetched_texts.get(up["url"], "")
        if txt:
            direct_cset.ingest_text(txt, source_name=up["name"], strict=False)
    if direct_cfg.get("extra_rules"):
        direct_cset.ingest_text(
            "\n".join(direct_cfg["extra_rules"]),
            source_name="sources.json:direct.extra_rules",
            strict=True,
        )
    direct_cset.subtract(proxy_cset)
    direct_cset.ingest_text(
        "\n".join(user_direct_cset.to_payload_list()),
        source_name="custom/direct.yaml",
        strict=True,
    )
    direct_cset.subtract(custom_exclude)

    classical_sets: dict[str, ClassicalSet] = {
        "direct": direct_cset,
        "proxy": proxy_cset,
    }

    other_classical_cfg = {
        k: v for k, v in config.get("classical", {}).items() if k not in ("direct", "proxy")
    }
    for name, item_cfg in toposort_section(
        other_classical_cfg, set(classical_sets.keys())
    ):
        cset = ClassicalSet()
        for up in item_cfg.get("upstreams", []):
            txt = fetched_texts.get(up["url"], "")
            if txt:
                cset.ingest_text(txt, source_name=up["name"], strict=False)
        if item_cfg.get("extra_rules"):
            cset.ingest_text(
                "\n".join(item_cfg["extra_rules"]),
                source_name=f"sources.json:{name}.extra_rules",
                strict=True,
            )

        for ex_name in item_cfg.get("exclude_sets", []):
            cset.subtract(classical_sets[ex_name])

        if item_cfg.get("exclude_upstreams") or item_cfg.get("exclude_rules"):
            local_ex = ClassicalSet()
            for ex_up in item_cfg.get("exclude_upstreams", []):
                txt = fetched_texts.get(ex_up["url"], "")
                if txt:
                    local_ex.ingest_text(txt, source_name=ex_up["name"], strict=False)
            if item_cfg.get("exclude_rules"):
                local_ex.ingest_text(
                    "\n".join(item_cfg["exclude_rules"]),
                    source_name=f"sources.json:{name}.exclude_rules",
                    strict=True,
                )
            cset.subtract(local_ex)

        # 个人 custom/ 规则优先级高于上游剔除表，仅受全局 exclude/direct/proxy 约束
        if item_cfg.get("custom_file"):
            custom_path = CUSTOM_DIR / item_cfg["custom_file"]
            if custom_path.exists():
                cset.ingest_text(
                    custom_path.read_text(encoding="utf-8"),
                    source_name=f"custom/{item_cfg['custom_file']}",
                    strict=True,
                )

        cset.subtract(custom_exclude)
        for ex_name in item_cfg.get("exclude_sets", []):
            if ex_name in ("direct", "proxy"):
                cset.subtract(classical_sets[ex_name])

        classical_sets[name] = cset

    # 4. 按拓扑顺序构建所有 domain 规则集（确保被依赖集合先于依赖它的集合构建）
    domain_sets: dict[str, DomainSet] = {}
    for name, item_cfg in toposort_section(
        config.get("domain", {}), set(classical_sets.keys())
    ):
        dset = DomainSet()
        for up in item_cfg.get("upstreams", []):
            txt = fetched_texts.get(up["url"], "")
            if txt:
                dset.ingest_text(txt, source_name=up["name"], strict=False)
        if item_cfg.get("extra_rules"):
            dset.ingest_text(
                "\n".join(item_cfg["extra_rules"]),
                source_name=f"sources.json:{name}.extra_rules",
                strict=True,
            )

        for ex_name in item_cfg.get("exclude_sets", []):
            if ex_name in classical_sets:
                dset.subtract(classical_sets[ex_name].domains)
            if ex_name in domain_sets:
                dset.subtract(domain_sets[ex_name])

        if item_cfg.get("exclude_upstreams") or item_cfg.get("exclude_rules"):
            local_ex = DomainSet()
            for ex_up in item_cfg.get("exclude_upstreams", []):
                txt = fetched_texts.get(ex_up["url"], "")
                if txt:
                    local_ex.ingest_text(txt, source_name=ex_up["name"], strict=False)
            if item_cfg.get("exclude_rules"):
                local_ex.ingest_text(
                    "\n".join(item_cfg["exclude_rules"]),
                    source_name=f"sources.json:{name}.exclude_rules",
                    strict=True,
                )
            dset.subtract(local_ex)

        if item_cfg.get("custom_file"):
            custom_path = CUSTOM_DIR / item_cfg["custom_file"]
            if custom_path.exists():
                dset.ingest_text(
                    custom_path.read_text(encoding="utf-8"),
                    source_name=f"custom/{item_cfg['custom_file']}",
                    strict=True,
                )

        dset.subtract(custom_exclude.domains)
        for ex_name in item_cfg.get("exclude_sets", []):
            if ex_name in ("direct", "proxy"):
                dset.subtract(classical_sets[ex_name].domains)

        dset.deduplicate()
        domain_sets[name] = dset

    # 5. 构建所有 ipcidr 规则集（自动合并相邻/重叠子网并支持剔除）
    ip_sets: dict[str, IPCIDRSet] = {}
    prebuilt_for_ip = set(classical_sets.keys()) | set(domain_sets.keys())
    for name, item_cfg in toposort_section(config.get("ipcidr", {}), prebuilt_for_ip):
        iset = IPCIDRSet()
        for up in item_cfg.get("upstreams", []):
            txt = fetched_texts.get(up["url"], "")
            if txt:
                iset.ingest_text(txt, source_name=up["name"], strict=False)
        if item_cfg.get("extra_rules"):
            iset.ingest_text(
                "\n".join(item_cfg["extra_rules"]),
                source_name=f"sources.json:{name}.extra_rules",
                strict=True,
            )

        for ex_name in item_cfg.get("exclude_sets", []):
            if ex_name in classical_sets:
                iset.subtract(classical_sets[ex_name].ips)
            if ex_name in ip_sets:
                iset.subtract(ip_sets[ex_name])

        if item_cfg.get("exclude_upstreams") or item_cfg.get("exclude_rules"):
            local_ex = IPCIDRSet()
            for ex_up in item_cfg.get("exclude_upstreams", []):
                txt = fetched_texts.get(ex_up["url"], "")
                if txt:
                    local_ex.ingest_text(txt, source_name=ex_up["name"], strict=False)
            if item_cfg.get("exclude_rules"):
                local_ex.ingest_text(
                    "\n".join(item_cfg["exclude_rules"]),
                    source_name=f"sources.json:{name}.exclude_rules",
                    strict=True,
                )
            iset.subtract(local_ex)

        if item_cfg.get("custom_file"):
            custom_path = CUSTOM_DIR / item_cfg["custom_file"]
            if custom_path.exists():
                iset.ingest_text(
                    custom_path.read_text(encoding="utf-8"),
                    source_name=f"custom/{item_cfg['custom_file']}",
                    strict=True,
                )

        iset.subtract(custom_exclude.ips)
        for ex_name in item_cfg.get("exclude_sets", []):
            if ex_name in ("direct", "proxy"):
                iset.subtract(classical_sets[ex_name].ips)

        ip_sets[name] = iset

    # 6. 输出全部 YAML 文件，并在有 mihomo 内核时编译 .mrs 二进制文件
    stats_rows: list[str] = []

    print("[INFO] 正在写出构建产物...")
    for name, cset in classical_sets.items():
        payload = cset.to_payload_list()
        desc = (
            config.get("classical", {}).get(name, {}).get("description")
            or f"Custom {name} rules"
        )
        yaml_path = RULES_OUT_DIR / f"{name}.yaml"
        yaml_path.write_text(
            render_yaml(payload, f"{name}.yaml - {desc}", "DOMAIN,placeholder.invalid"),
            encoding="utf-8",
        )
        pruned = max(0, cset.raw_count - len(payload))
        stats_rows.append(
            f"| `{name}.yaml` | `classical` | {cset.raw_count} | **{len(payload)}** (-{pruned}) | {format_size(yaml_path.stat().st_size)} |"
        )
        print(f"  [YAML] {name}.yaml: 原始 {cset.raw_count} -> 去重后 {len(payload)}")

    for name, dset in domain_sets.items():
        payload = dset.to_payload_list()
        desc = config["domain"][name].get("description", name)
        yaml_path = RULES_OUT_DIR / f"{name}.yaml"
        yaml_path.write_text(
            render_yaml(payload, f"{name} - {desc}", "placeholder.invalid"),
            encoding="utf-8",
        )
        pruned = max(0, dset.raw_count - len(payload))
        size_str = format_size(yaml_path.stat().st_size)
        out_label = f"`{name}.yaml`"

        if args.mihomo:
            mrs_path = RULES_OUT_DIR / f"{name}.mrs"
            compile_mrs(args.mihomo, "domain", yaml_path, mrs_path)
            size_str = f"{format_size(mrs_path.stat().st_size)} (`.mrs`)"
            out_label = f"`{name}.mrs` / `.yaml`"
            print(f"  [MRS ] {name}.mrs: 原始 {dset.raw_count} -> 树去重后 {len(payload)} ({size_str})")
        else:
            print(f"  [YAML] {name}.yaml: 原始 {dset.raw_count} -> 树去重后 {len(payload)}")

        stats_rows.append(
            f"| {out_label} | `domain` | {dset.raw_count} | **{len(payload)}** (-{pruned}) | {size_str} |"
        )

    for name, iset in ip_sets.items():
        payload = iset.to_payload_list()
        desc = config["ipcidr"][name].get("description", name)
        yaml_path = RULES_OUT_DIR / f"{name}.yaml"
        yaml_path.write_text(
            render_yaml(payload, f"{name} - {desc}", "127.0.0.254/32"),
            encoding="utf-8",
        )
        pruned = max(0, iset.raw_count - len(payload))
        size_str = format_size(yaml_path.stat().st_size)
        out_label = f"`{name}.yaml`"

        if args.mihomo:
            mrs_path = RULES_OUT_DIR / f"{name}.mrs"
            compile_mrs(args.mihomo, "ipcidr", yaml_path, mrs_path)
            size_str = f"{format_size(mrs_path.stat().st_size)} (`.mrs`)"
            out_label = f"`{name}.mrs` / `.yaml`"
            print(f"  [MRS ] {name}.mrs: 原始 {iset.raw_count} -> 子网聚合后 {len(payload)} ({size_str})")
        else:
            print(f"  [YAML] {name}.yaml: 原始 {iset.raw_count} -> 子网聚合后 {len(payload)}")

        stats_rows.append(
            f"| {out_label} | `ipcidr` | {iset.raw_count} | **{len(payload)}** (-{pruned}) | {size_str} |"
        )

    # 7. 生成 release 分支统计看板 README.md
    tz_cn = datetime.timezone(datetime.timedelta(hours=8))
    now_str = datetime.datetime.now(tz_cn).strftime("%Y-%m-%d %H:%M:%S UTC+8")
    readme_lines = [
        "# Mihomo 多源去重规则集 (Auto-Generated Release Branch)",
        "",
        f"- **最近自动构建时间**: `{now_str}`",
        "- **上游数据源**: `MetaCubeX/meta-rules-dat` + `Loyalsoldier/clash-rules` + `VPSDance/ai-proxy-rules` + `TG-Twilight/AWAvenue-Ads-Rule` + `Cats-Team/AdRules` + `hagezi/dns-blocklists` + `anti-AD` (`dead-horse` 白名单) + `Aethersailor` + `DustinWin` + `SukkaW` + `gaoyifan/china-operator-ip` + `Hackl0us/GeoIP2-CN` + `blackmatrix7` + `uselibrary/PCDN` + `custom/` 个人规则",
        "- **去重算法**: 父子域名后缀树剪枝（`+.example.com` 自动剔除多余子域名，原生兼容 AdBlock `||domain^` 与多级通配符）+ IPv4/IPv6 相邻与重叠 CIDR 子网合并 + 拓扑依赖跨集合防污染剥离",
        "",
        "## 构建统计明细",
        "",
        "| 规则文件 | 类型 | 合并前总条数 | 去重后条数 (精简数) | 产物大小 |",
        "| :--- | :--- | ---: | ---: | ---: |",
        *stats_rows,
        "",
    ]
    (DIST_DIR / "README.md").write_text("\n".join(readme_lines), encoding="utf-8")
    print(f"[DONE] 全部构建完成 -> {DIST_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
