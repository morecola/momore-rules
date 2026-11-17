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
    if not line or line.startswith(("#", "//", ";")):
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
    wildcards: set[str] = field(default_factory=set)  # 对应含内部 * 的通配域名（如 xbox.*.microsoft.com）
    raw_count: int = 0

    def add_suffix(self, domain: str) -> None:
        d = domain.strip().lower().lstrip(".")
        if is_valid_domain(d) and "*" not in d:
            self.suffixes.add(d)
            self.raw_count += 1

    def add_exact(self, domain: str) -> None:
        d = domain.strip().lower().lstrip(".")
        if not is_valid_domain(d):
            return
        if "*" in d:
            self.wildcards.add(d)
        else:
            self.exacts.add(d)
        self.raw_count += 1

    def ingest_text(self, text: str) -> None:
        """兼容 domain YAML / text list / classical YAML 三种上游格式提取域名"""
        for raw in text.splitlines():
            line = clean_line(raw)
            if not line:
                continue
            if "," in line:
                parts = [p.strip() for p in line.split(",")]
                rtype = parts[0].upper()
                val = parts[1] if len(parts) > 1 else ""
                if rtype == "DOMAIN-SUFFIX":
                    self.add_suffix(val)
                elif rtype == "DOMAIN":
                    self.add_exact(val)
                elif rtype == "DOMAIN-WILDCARD":
                    self.add_exact(val)
                # 忽略 DOMAIN-KEYWORD / IP-CIDR 等非 domain rule-set 支持的类型
                continue

            # 无逗号：处理 +.foo.com / .foo.com / *.foo.com / foo.com
            if line.startswith("+."):
                self.add_suffix(line[2:])
            elif line.startswith("."):
                self.add_suffix(line[1:])
            elif line.startswith("*.") and "*" not in line[2:]:
                # *.foo.com 仅匹配子域不匹配根域，保留通配写法
                if is_valid_domain(line):
                    self.wildcards.add(line.lower())
                    self.raw_count += 1
            else:
                # 排除纯 IP / CIDR 行
                try:
                    ipaddress.ip_network(line, strict=False)
                    continue
                except ValueError:
                    pass
                self.add_exact(line)

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
            and not (w.startswith("*.") and other.covers_suffix(w[2:]))
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
                w.startswith("*.")
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
@dataclass
class IPCIDRSet:
    v4: list[ipaddress.IPv4Network] = field(default_factory=list)
    v6: list[ipaddress.IPv6Network] = field(default_factory=list)
    raw_count: int = 0

    def add_cidr(self, token: str) -> None:
        try:
            net = ipaddress.ip_network(token.strip(), strict=False)
        except ValueError:
            return
        if isinstance(net, ipaddress.IPv4Network):
            self.v4.append(net)
        else:
            self.v6.append(net)
        self.raw_count += 1

    def ingest_text(self, text: str) -> None:
        for raw in text.splitlines():
            line = clean_line(raw)
            if not line:
                continue
            if "," in line:
                parts = [p.strip() for p in line.split(",")]
                if parts[0].upper() in {"IP-CIDR", "IP-CIDR6"} and len(parts) >= 2:
                    self.add_cidr(parts[1])
            else:
                self.add_cidr(line)

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
                    self.domains.add_suffix(line[2:])
                    self.raw_count += 1
                elif line.startswith("."):
                    self.domains.add_suffix(line[1:])
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
                continue

            if rtype == "DOMAIN-SUFFIX":
                self.domains.add_suffix(target)
                self.raw_count += 1
            elif rtype == "DOMAIN":
                self.domains.add_exact(target)
                self.raw_count += 1
            elif rtype == "DOMAIN-WILDCARD":
                self.domains.add_exact(target)
                self.raw_count += 1
            elif rtype in {"IP-CIDR", "IP-CIDR6"}:
                self.ips.add_cidr(target)
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
    direct_cset = read_custom_classical("direct.yaml")
    direct_cset.subtract(custom_exclude)

    proxy_cset = read_custom_classical("proxy.yaml")
    proxy_cset.subtract(custom_exclude)
    proxy_cset.subtract(direct_cset)

    # 2. 并发拉取 sources.json 中定义的所有上游文本
    fetched_texts: dict[str, str] = {}
    if not args.dry_run:
        all_upstreams: list[dict] = []
        for section in ("domain", "ipcidr", "classical"):
            for item_cfg in config.get(section, {}).values():
                for up in item_cfg.get("upstreams", []):
                    all_upstreams.append(up)

        print(f"[INFO] 正在并发拉取 {len(all_upstreams)} 个公开上游规则源...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
            future_map = {}
            for up in all_upstreams:
                urls = [up["url"]]
                if up.get("fallback_url"):
                    urls.append(up["fallback_url"])
                future_map[up["url"]] = (up, pool.submit(fetch_text, urls))

            for url, (up, fut) in future_map.items():
                try:
                    fetched_texts[url] = fut.result()
                    print(f"  [FETCH OK] {up['name']}")
                except Exception as exc:
                    if up.get("required", True):
                        print(f"  [FATAL] 核心上游拉取失败 {up['name']}: {exc}", file=sys.stderr)
                        return 1
                    print(f"  [WARN] 补充上游拉取失败（已自动跳过）{up['name']}: {exc}", file=sys.stderr)

    # 3. 先构建 classical 规则集（direct / proxy / gemini / ai），以便后续给 cn 等做防污染剔除
    classical_sets: dict[str, ClassicalSet] = {
        "direct": direct_cset,
        "proxy": proxy_cset,
    }

    for name, item_cfg in config.get("classical", {}).items():
        cset = ClassicalSet()
        if item_cfg.get("custom_file"):
            custom_part = read_custom_classical(item_cfg["custom_file"])
            cset.ingest_text(
                "\n".join(custom_part.to_payload_list()),
                source_name=f"custom/{item_cfg['custom_file']}",
            )
            cset.raw_count = custom_part.raw_count

        for up in item_cfg.get("upstreams", []):
            txt = fetched_texts.get(up["url"], "")
            if txt:
                cset.ingest_text(txt, source_name=up["name"], strict=False)

        cset.subtract(custom_exclude)
        for ex_name in item_cfg.get("exclude_sets", []):
            if ex_name in classical_sets:
                cset.subtract(classical_sets[ex_name])

        classical_sets[name] = cset

    # 4. 构建所有 domain 规则集（先处理非 cn 集，最后处理 cn 以便剔除 google/gemini/ai 污染域名）
    domain_sets: dict[str, DomainSet] = {}
    domain_cfg_items = list(config.get("domain", {}).items())
    # 确保被依赖的集合（如 google、private）先于 cn 和 non-cn 构建
    domain_cfg_items.sort(key=lambda kv: 1 if kv[0] in {"non-cn", "cn"} else 0)

    for name, item_cfg in domain_cfg_items:
        dset = DomainSet()
        if item_cfg.get("custom_file"):
            custom_path = CUSTOM_DIR / item_cfg["custom_file"]
            if custom_path.exists():
                dset.ingest_text(custom_path.read_text(encoding="utf-8"))

        for up in item_cfg.get("upstreams", []):
            txt = fetched_texts.get(up["url"], "")
            if txt:
                dset.ingest_text(txt)

        dset.subtract(custom_exclude.domains)
        for ex_name in item_cfg.get("exclude_sets", []):
            if ex_name in classical_sets:
                dset.subtract(classical_sets[ex_name].domains)
            if ex_name in domain_sets:
                dset.subtract(domain_sets[ex_name])

        dset.deduplicate()
        domain_sets[name] = dset

    # 5. 构建所有 ipcidr 规则集（自动合并相邻/重叠子网）
    ip_sets: dict[str, IPCIDRSet] = {}
    for name, item_cfg in config.get("ipcidr", {}).items():
        iset = IPCIDRSet()
        if item_cfg.get("custom_file"):
            custom_path = CUSTOM_DIR / item_cfg["custom_file"]
            if custom_path.exists():
                iset.ingest_text(custom_path.read_text(encoding="utf-8"))

        for up in item_cfg.get("upstreams", []):
            txt = fetched_texts.get(up["url"], "")
            if txt:
                iset.ingest_text(txt)
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
        "- **上游数据源**: `MetaCubeX/meta-rules-dat` + `Loyalsoldier/clash-rules` + `VPSDance/ai-proxy-rules` + `TG-Twilight/AWAvenue-Ads-Rule` + `anti-AD` + `gaoyifan/china-operator-ip` + `Hackl0us/GeoIP2-CN` + `blackmatrix7/ios_rule_script` + `custom/` 个人规则",
        "- **去重算法**: 父子域名后缀树剪枝（`+.example.com` 自动剔除多余子域名）+ IPv4/IPv6 相邻与重叠 CIDR 子网合并 + 跨集合防污染剥离",
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
