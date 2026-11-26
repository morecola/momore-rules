# Mihomo 多源分流规则自动聚合与去重仓库

参考 [`Loyalsoldier/clash-rules`](https://github.com/Loyalsoldier/clash-rules) 与 [`VPSDance/ai-proxy-rules`](https://github.com/VPSDance/ai-proxy-rules) 架构设计，**专注纯净分流（不含去广告规则）、针对实际在用的 24 个核心规则集**，每天自动从主流公开规则源并发拉取、跨格式归一化、父子域名树去重、IP 子网合并，并调用官方 Mihomo 内核编译出二进制 `.mrs` 规则集发布到独立的 `release` 分支。

---

## 核心特性

1. **多公开上游交叉互补（定义在 `sources.json`，纯分流零广告误杀）**
   - **HTTPDNS 与私有中继金丝雀拦截（`httpdns` / `httpdns-ip`）**：`MetaCubeX/category-httpdns-cn` + `blackmatrix7/BlockHttpDNS`（含专用 HTTPDNS IP 段）+ Apple Private Relay / Mozilla DoH 官方金丝雀域名（`mask.icloud.com`、`use-application-dns.net`），防国内 App 绕过 Fake-IP 且不误伤海外正常 DoH 与 Safari 验证
   - **Fake-IP 豁免（`fakeip-filter`）**：`MetaCubeX/category-stun` + `DustinWin/fakeip-filter` + `SukkaW/clash_fake_ip_filter` + 多级 STUN 通配符与本地面板（`yacd` / `metacubexd` / `zashboard`），并剔除广告源与海外代理站点误收条目
   - **CN IP 纯净 BGP 大陆网段（`cnip`）**：`MetaCubeX/geoip-cn` + `gaoyifan/china-operator-ip`（每日实测电信/联通/移动/教育网 BGP 路由 IPv4 & IPv6）+ `Loyalsoldier/cncidr`；剔除混入阿里云/腾讯云海外 HK/SG/JP/US 网段的污染源，确保海外云站点不误走直连
   - **CN Site 高纯度直连 + `cnip` IP 兜底**：`MetaCubeX/geolocation-cn` + `MetaCubeX/tld-cn` + `SukkaW/domestic` + `MetaCubeX/category-bank-cn` + `MetaCubeX/deepseek`（剔除 10 万条陈旧僵尸域名及 `China_Domain` 混入的海外 VPS/机场/外站 PT/泰国 `.in.th` 等污染项，长尾域名交由 `cnip` 按真实解析 IP 精准裁决）；内置国际厂商国内 CDN 直连（`jetbrains@cn`、`nvidia@cn`、`hf-mirror.com`、`apple-cn`、`microsoft-cn`、`games-cn` 纯净本土游戏 CDN 并剥离被墙 `steamusercontent.com` 社区图床与海外 Fastly/Google CDN、`pt-tracker` 剥离动漫花园等被墙公网站点），并将 22+ 国内大厂出海/海外云节点（`aliyun@!cn`、`tencent@!cn`、`bytedance@!cn`、`proximabeta.com`、`larksuite`、`aliexpress` 等）精准归入 `non-cn`
   - **AI、Google、Microsoft、Apple 与 Telegram 专项**：`VPSDance/ai-proxy-rules` + `MetaCubeX/category-ai-!cn` + `MetaCubeX/google-gemini` + `MetaCubeX/apple-intelligence`（自动剥离 Cloudflare Turnstile、Stripe、Auth0、IdenTrust CA、Envato、MSN/Office 等非 AI 公共基础设施，防止跨出口 IP 导致验证异常）；`Microsoft` 与 `Apple` 均采用纯净 `MetaCubeX` 上游并剥离国内直连子集，杜绝第三方上游混入全局 `akadns.net` / `edgesuite.net` 劫持；`Telegram` 域名 + 数据中心裸 IP 段双层覆盖
   - **零泄漏加密 DNS + 精准 ECS 兜底**：国内与直连出口全面升级为 IP 直连 DoH（`https://223.5.5.5/dns-query` + `https://1.12.12.12/dns-query`），开启 `direct-nameserver-follow-policy: true` 配合严格有序 `nameserver-policy`：`private` 局域网域名在 TUN 与混合端口下均走 `system` 解析，`apple` 默认直连优先走国内 DoH 命中本土 CDN，`pt-tracker` 与默认 `nameserver` 采用代理侧 Google DoH + 中国 ECS（`ecs=223.5.5.0/24&ecs-override=true`），兼顾防运营商/GFW DNS 污染、零 DNS 泄漏与长尾国内 CDN 命中 `cnip`
2. **三重深度去重与拓扑防污染算法（`scripts/sync.py`）**
   - **父子域名后缀树剪枝**：自动兼容 YAML / 纯文本 / Classical 四种格式及多级通配符（`+.stun.*.*`）；当存在 `+.google.com` 时自动剪枝多余子域名，且精确域名不会误删父级通配后缀。
   - **相邻与重叠 CIDR 子网聚合**：使用标准库 `ipaddress.collapse_addresses` 与 $O((N+M)\log(N+M))$ 扫描线差集算法合并/剔除 IPv4 / IPv6 网段，并对 `classical` 规则中的 IP 自动强制补齐 `,no-resolve`。
   - **拓扑依赖防污染剥离（支持 `exclude_sets` / `exclude_upstreams` / `exclude_rules` / `extra_rules`）**：
     - 自动将 `gemini`（Google AI）从 `ai` 中剥离，并从 `httpdns` 中保护 `direct`、`proxy`、`ai`、`gemini` 关键业务域名不被上游规则误伤。
     - 自动从大陆直连域名 `cn.mrs` 中剔除 `direct`、`proxy`、`google`、`gemini`、`ai`、`dev`、`scholar`、`telegram`、`httpdns`、`non-cn` 及污染顶级域（`.ms` / `.full`），配合分层有序 `nameserver-policy` 彻底杜绝国内 DNS 泄漏。
     - 自动从 `scholar` / `dev` 中剥离国内学术库（知网/万方/维普/北大法宝）与国内开发镜像；从 `apple` / `microsoft` 中剥离 `apple-cn` / `microsoft-cn`。
3. **官方内核原生编译 `.mrs` + 孤儿分支零体积膨胀**
   - GitHub Actions 每次构建时自动拉取最新官方 `mihomo` 二进制，执行 `mihomo convert-ruleset` 同时生成 `.mrs`（极致加载速度与低内存占用）与可读的 `.yaml`。
   - 构建产物强制覆盖推送到无历史记录的 `release` 孤儿分支，`main` 分支永远只有几十 KB，跑上十年仓库也不会膨胀。

---

## 目录结构

```text
.
├── .github/workflows/sync.yml  # GitHub Actions 每日定时 + Push 自动构建流水线
├── sources.json                # 【多源配置】24 个规则集对应的多上游地址与防污染剔除关系
├── custom/                     # 【日常维护】个人自定义最高优先级规则
│   ├── direct.yaml             # 个人直连规则（已内置 no.al、letcola.eu.org）
│   ├── proxy.yaml              # 个人代理补充规则
│   ├── fakeip-filter.yaml      # 个人 Fake-IP 豁免补充（含多级 STUN 通配与本地 Web 面板）
│   ├── cn.yaml                 # 个人国内直连域名补充（编译进 cn.mrs）
│   ├── cnip.yaml               # 个人国内 IP 网段补充（聚合编译进 cnip.mrs）
│   ├── ai.yaml                 # 个人 AI 补充规则（归入 🤖 AI 服务）
│   ├── google.yaml             # 个人 Google/Gemini 补充规则（归入 🔍 谷歌服务）
│   └── exclude.yaml            # 全局误杀剔除白名单（从所有规则集中强制移除）
├── scripts/sync.py             # 多源并发拉取、域名树剪枝、CIDR 合并与 .mrs 编译脚本
├── configs/                    # 【四套现成客户端配置】按需任选其一导入
│   ├── mihomo-residential.yaml     # 带家宽前置版 + GitHub Raw 规则源（11 策略组）
│   ├── mihomo-residential-cdn.yaml # 带家宽前置版 + jsDelivr CDN 加速源（11 策略组）
│   ├── mihomo-standard.yaml        # 标准无家宽版 + GitHub Raw 规则源（9 策略组）
│   └── mihomo-standard-cdn.yaml    # 标准无家宽版 + jsDelivr CDN 加速源（9 策略组）
└── mihomo-config.yaml          # 默认主配置模板（同 configs/mihomo-residential.yaml）
```

---

## 首次上传到 GitHub 教程（3 分钟完成）

### 第 1 步：在 GitHub 新建公开仓库
1. 打开 <https://github.com/new>
2. **Repository name** 填写例如 `momore-rules`
3. 选择 **Public**（公开仓库可免费无限使用 GitHub Actions 且客户端可直接拉取），**不要勾选** Add a README file，直接点击 **Create repository**。

### 第 2 步：推送本项目文件到 `main` 分支
在本项目目录执行以下命令：

```bash
git init -b main
git add .
git commit -m "init: multi-upstream mihomo rules builder"
git remote add origin https://github.com/morecola/momore-rules.git
git push -u origin main
```

> 也可以直接在新建的空仓库页面点击 **uploading an existing file**，把整个文件夹里的文件（注意包含隐藏目录 `.github/workflows/sync.yml`）拖拽上传并提交。

### 第 3 步：确认首次自动构建完成
1. 打开仓库顶部的 **Actions** 标签页。
2. 推送后会立即运行 `Sync & Build Mihomo Rules`（若网页拖拽未触发，点击左侧 `Sync & Build Mihomo Rules` -> 右侧 **Run workflow** 手动运行一次）。
3. 等待约 20~35 秒变成绿勾 ✅ 后，切换到仓库的 **`release` 分支**：
   - `release` 分支首页会自动生成一张**构建统计表**（展示每个规则集合并前总条数、去重剪枝条数与编译后 `.mrs` 体积）。
   - `rules/` 目录下已生成全部 24 个规则集文件（20 个 `.mrs` + 对应的 `.yaml`）。

### 第 4 步：按需选择配置文件填入节点并导入
`configs/` 目录下预置了 **4 套已绑定 `morecola/momore-rules` (`release` 分支) 的完整配置**，24 个规则集、防泄漏 DNS 与分流优先级完全一致，只需将 `proxies: []` 与 `__PROXY_NODES__` 替换为实际节点或 `proxy-providers` 订阅即可导入使用：

| 配置文件 | 家宽支持 | 规则拉取源 | 适用场景与节点过滤说明 |
| :--- | :---: | :---: | :--- |
| `configs/mihomo-residential.yaml` | 支持（11 组） | GitHub Raw | 含 `💻 前置节点` 与 `🏡 家宽优选`，适合拥有家宽落地节点的订阅（同根目录 `mihomo-config.yaml`） |
| `configs/mihomo-residential-cdn.yaml` | 支持（11 组） | jsDelivr CDN | 同上，规则地址全部替换为 `cdn.jsdelivr.net/gh/morecola/momore-rules@release/...` |
| `configs/mihomo-standard.yaml` | 无家宽（9 组） | GitHub Raw | 移除家宽与前置组；兼容带 `-` 的常规机场节点名（如 `HK-01`），仅过滤 `- \|`、家宽 `Big` 及流量/到期提示节点 |
| `configs/mihomo-standard-cdn.yaml` | 无家宽（9 组） | jsDelivr CDN | 标准无家宽版 + `cdn.jsdelivr.net` 加速规则源 |

---

## 日常维护指南

### 1. 增删个人规则（改 `custom/`）
直接在 GitHub 网页打开 `custom/` 下对应文件点击编辑保存，约 30 秒自动重编生效：
- 强制直连域名/IP -> `custom/direct.yaml`
- 强制代理网站 -> `custom/proxy.yaml`
- 自建 AI 镜像 / API 中转 -> `custom/ai.yaml`
- 上游误杀的域名 -> `custom/exclude.yaml`

> **语法提示**：每行写 `- 类型,值`（如 `- DOMAIN-SUFFIX,linux.do` 或 `- IP-CIDR,1.2.3.0/24,no-resolve`），**末尾不要带 `,DIRECT` 等策略名**。

### 2. 增删上游规则源（改 `sources.json`）
后续如果发现新的优秀公开规则库（无论是 `.yaml` 还是纯文本 `.txt`），只需往 `sources.json` 对应规则集的 `"upstreams"` 数组里追加一条 `{ "name": "...", "url": "...", "required": false }`，保存后即会自动纳入每日去重与编译流水线。
