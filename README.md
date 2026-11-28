# Mihomo 多源去重规则集 (Auto-Generated Release Branch)

- **最近自动构建时间**: `2026-11-28 10:49:22 UTC+8`
- **上游数据源**: `MetaCubeX/meta-rules-dat` + `Loyalsoldier/clash-rules` + `VPSDance/ai-proxy-rules` + `Aethersailor` + `DustinWin` + `SukkaW` + `gaoyifan/china-operator-ip` + `blackmatrix7` + `custom/` 个人规则（纯分流无去广告）
- **去重算法**: 父子域名后缀树剪枝（`+.example.com` 自动剔除多余子域名，原生兼容多级通配符）+ IPv4/IPv6 相邻与重叠 CIDR 子网合并 + 拓扑依赖跨集合防污染剥离

## 构建统计明细

| 规则文件 | 类型 | 合并前总条数 | 去重后条数 (精简数) | 产物大小 |
| :--- | :--- | ---: | ---: | ---: |
| `direct.yaml` | `classical` | 9 | **9** (-0) | 393 B |
| `proxy.yaml` | `classical` | 0 | **0** (-0) | 74 B |
| `gemini.yaml` | `classical` | 106 | **56** (-50) | 2.2 KB |
| `ai.yaml` | `classical` | 572 | **293** (-279) | 9.6 KB |
| `httpdns.mrs` / `.yaml` | `domain` | 75 | **53** (-22) | 827 B (`.mrs`) |
| `fakeip-filter.mrs` / `.yaml` | `domain` | 959 | **581** (-378) | 5.1 KB (`.mrs`) |
| `private.mrs` / `.yaml` | `domain` | 132 | **132** (-0) | 781 B (`.mrs`) |
| `google.mrs` / `.yaml` | `domain` | 1764 | **880** (-884) | 7.4 KB (`.mrs`) |
| `category-ntp.mrs` / `.yaml` | `domain` | 198 | **158** (-40) | 1.1 KB (`.mrs`) |
| `pt-tracker.mrs` / `.yaml` | `domain` | 676 | **601** (-75) | 6.0 KB (`.mrs`) |
| `games-cn.mrs` / `.yaml` | `domain` | 327 | **288** (-39) | 2.5 KB (`.mrs`) |
| `apple-cn.mrs` / `.yaml` | `domain` | 467 | **248** (-219) | 2.3 KB (`.mrs`) |
| `microsoft-cn.mrs` / `.yaml` | `domain` | 189 | **189** (-0) | 1.9 KB (`.mrs`) |
| `telegram.mrs` / `.yaml` | `domain` | 45 | **27** (-18) | 337 B (`.mrs`) |
| `apple.mrs` / `.yaml` | `domain` | 1668 | **1354** (-314) | 13.9 KB (`.mrs`) |
| `dev.mrs` / `.yaml` | `domain` | 801 | **641** (-160) | 6.3 KB (`.mrs`) |
| `scholar.mrs` / `.yaml` | `domain` | 697 | **491** (-206) | 4.9 KB (`.mrs`) |
| `microsoft.mrs` / `.yaml` | `domain` | 782 | **530** (-252) | 5.6 KB (`.mrs`) |
| `non-cn.mrs` / `.yaml` | `domain` | 32102 | **26800** (-5302) | 190.2 KB (`.mrs`) |
| `cn.mrs` / `.yaml` | `domain` | 6454 | **4650** (-1804) | 28.5 KB (`.mrs`) |
| `lanip.mrs` / `.yaml` | `ipcidr` | 56 | **28** (-28) | 236 B (`.mrs`) |
| `httpdns-ip.mrs` / `.yaml` | `ipcidr` | 41 | **41** (-0) | 276 B (`.mrs`) |
| `telegramip.mrs` / `.yaml` | `ipcidr` | 38 | **13** (-25) | 152 B (`.mrs`) |
| `cnip.mrs` / `.yaml` | `ipcidr` | 29154 | **9728** (-19426) | 37.2 KB (`.mrs`) |
