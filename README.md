# Mihomo 多源去重规则集 (Auto-Generated Release Branch)

- **最近自动构建时间**: `2026-11-21 09:36:58 UTC+8`
- **上游数据源**: `MetaCubeX/meta-rules-dat` + `Loyalsoldier/clash-rules` + `VPSDance/ai-proxy-rules` + `TG-Twilight/AWAvenue-Ads-Rule` + `Cats-Team/AdRules` + `hagezi/dns-blocklists` + `anti-AD` (`dead-horse` 白名单) + `Aethersailor` + `DustinWin` + `SukkaW` + `gaoyifan/china-operator-ip` + `Hackl0us/GeoIP2-CN` + `blackmatrix7` + `uselibrary/PCDN` + `custom/` 个人规则
- **去重算法**: 父子域名后缀树剪枝（`+.example.com` 自动剔除多余子域名，原生兼容 AdBlock `||domain^` 与多级通配符）+ IPv4/IPv6 相邻与重叠 CIDR 子网合并 + 拓扑依赖跨集合防污染剥离

## 构建统计明细

| 规则文件 | 类型 | 合并前总条数 | 去重后条数 (精简数) | 产物大小 |
| :--- | :--- | ---: | ---: | ---: |
| `direct.yaml` | `classical` | 9 | **9** (-0) | 393 B |
| `proxy.yaml` | `classical` | 0 | **0** (-0) | 74 B |
| `gemini.yaml` | `classical` | 68 | **59** (-9) | 2.3 KB |
| `ai.yaml` | `classical` | 570 | **317** (-253) | 10.4 KB |
| `pt-tracker.mrs` / `.yaml` | `domain` | 673 | **608** (-65) | 6.1 KB (`.mrs`) |
| `category-ads-all.mrs` / `.yaml` | `domain` | 658394 | **307108** (-351286) | 2.68 MB (`.mrs`) |
| `httpdns.mrs` / `.yaml` | `domain` | 75 | **53** (-22) | 827 B (`.mrs`) |
| `fakeip-filter.mrs` / `.yaml` | `domain` | 959 | **590** (-369) | 5.1 KB (`.mrs`) |
| `private.mrs` / `.yaml` | `domain` | 264 | **132** (-132) | 781 B (`.mrs`) |
| `category-ntp.mrs` / `.yaml` | `domain` | 198 | **169** (-29) | 1.1 KB (`.mrs`) |
| `games-cn.mrs` / `.yaml` | `domain` | 850 | **342** (-508) | 3.1 KB (`.mrs`) |
| `apple-cn.mrs` / `.yaml` | `domain` | 467 | **248** (-219) | 2.3 KB (`.mrs`) |
| `microsoft-cn.mrs` / `.yaml` | `domain` | 189 | **189** (-0) | 1.9 KB (`.mrs`) |
| `telegram.mrs` / `.yaml` | `domain` | 45 | **27** (-18) | 337 B (`.mrs`) |
| `google.mrs` / `.yaml` | `domain` | 1763 | **879** (-884) | 7.3 KB (`.mrs`) |
| `apple.mrs` / `.yaml` | `domain` | 1850 | **1584** (-266) | 16.1 KB (`.mrs`) |
| `dev.mrs` / `.yaml` | `domain` | 796 | **630** (-166) | 6.0 KB (`.mrs`) |
| `scholar.mrs` / `.yaml` | `domain` | 697 | **491** (-206) | 4.9 KB (`.mrs`) |
| `microsoft.mrs` / `.yaml` | `domain` | 1423 | **762** (-661) | 7.8 KB (`.mrs`) |
| `non-cn.mrs` / `.yaml` | `domain` | 59406 | **26901** (-32505) | 190.9 KB (`.mrs`) |
| `cn.mrs` / `.yaml` | `domain` | 9140 | **5589** (-3551) | 35.0 KB (`.mrs`) |
| `lanip.mrs` / `.yaml` | `ipcidr` | 56 | **28** (-28) | 236 B (`.mrs`) |
| `httpdns-ip.mrs` / `.yaml` | `ipcidr` | 41 | **41** (-0) | 276 B (`.mrs`) |
| `telegramip.mrs` / `.yaml` | `ipcidr` | 38 | **13** (-25) | 152 B (`.mrs`) |
| `cnip.mrs` / `.yaml` | `ipcidr` | 55677 | **11780** (-43897) | 49.2 KB (`.mrs`) |
