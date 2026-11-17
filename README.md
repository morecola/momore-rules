# Mihomo 多源分流规则自动聚合与去重仓库

参考 [`Loyalsoldier/clash-rules`](https://github.com/Loyalsoldier/clash-rules) 与 [`VPSDance/ai-proxy-rules`](https://github.com/VPSDance/ai-proxy-rules) 架构设计，**仅针对你实际在用的 17 个规则集**，每天自动从四大主流公开规则源并发拉取、跨格式归一化、父子域名树去重、IP 子网合并，并调用官方 Mihomo 内核编译出二进制 `.mrs` 规则集发布到独立的 `release` 分支。

---

## 核心特性

1. **八大公开上游交叉互补（定义在 `sources.json`）**
   - **AdBlock 去广告**：`TG-Twilight/AWAvenue-Ads-Rule`（秋风广告规则，低误杀开屏/摇一摇拦截）+ `privacy-protection-tools/anti-AD` + `Loyalsoldier/reject` + `MetaCubeX/category-ads-all` + `blackmatrix7/AdvertisingLite`
   - **CN IP 大陆网段**：`gaoyifan/china-operator-ip`（每日实测电信/联通/移动/教育网 BGP 路由 IPv4 & IPv6）+ `Hackl0us/GeoIP2-CN`（`17mon/ipip.net` + 纯真 IP）+ `Loyalsoldier/cncidr` + `MetaCubeX/geoip-cn`
   - **CN Site 大陆域名**：`MetaCubeX/cn`（`v2fly` + `dnsmasq-china-list`）+ `Loyalsoldier/direct` + `blackmatrix7/China_Domain`
   - **AI 与分流专项**：`VPSDance/ai-proxy-rules`（海外 AI + Google AI）+ `blackmatrix7/ios_rule_script`（OpenAI / Claude / Copilot / Gemini / 学术 / 开发者）
2. **三重深度去重与防污染算法（`scripts/sync.py`）**
   - **父子域名后缀树剪枝**：例如同时存在 `+.google.com`、`+.mail.google.com`、`www.google.com` 时，自动剪枝多余子域名，仅保留根后缀 `+.google.com`。
   - **相邻与重叠 CIDR 子网聚合**：使用标准库 `ipaddress.collapse_addresses` 自动将 6 个国内 IP 源里重叠或相邻的 IPv4 / IPv6 网段合并为最少条数，并对 `classical` 规则中的 IP 自动强制补齐 `,no-resolve`。
   - **跨集合防污染剥离**：
     - 自动将 `gemini`（Google AI）从 `ai` 中剥离，确保 Gemini 与 Google 账号同走 `🔍 谷歌服务`，而 Codex / Claude / Cursor 等走 `🤖 AI 服务`。
     - 自动从大陆直连域名 `cn.mrs` 中剔除 `google`、`gemini`、`ai`、`dev`、`scholar` 及个人代理域名，彻底杜绝上游直连表混入海外 CDN 域名导致的国内 DNS 泄漏。
     - 自动从去广告 `category-ads-all.mrs` 中剔除 `direct`、`proxy` 与 `exclude` 中的域名，防止广告规则误杀正常业务。
3. **官方内核原生编译 `.mrs` + 孤儿分支零体积膨胀**
   - GitHub Actions 每次构建时自动拉取最新官方 `mihomo` 二进制，执行 `mihomo convert-ruleset` 同时生成 `.mrs`（极致加载速度与低内存占用）与可读的 `.yaml`。
   - 构建产物强制覆盖推送到无历史记录的 `release` 孤儿分支，`main` 分支永远只有几十 KB，跑上十年仓库也不会膨胀。

---

## 目录结构

```text
.
├── .github/workflows/sync.yml  # GitHub Actions 每日定时 + Push 自动构建流水线
├── sources.json                # 【多源配置】17 个规则集对应的多上游地址与防污染剔除关系
├── custom/                     # 【日常维护】个人自定义最高优先级规则
│   ├── direct.yaml             # 个人直连规则（已内置 no.al、letcola.eu.org）
│   ├── proxy.yaml              # 个人代理补充规则
│   ├── adblock.yaml            # 个人去广告补充域名（编译进 category-ads-all.mrs）
│   ├── cn.yaml                 # 个人国内直连域名补充（编译进 cn.mrs）
│   ├── cnip.yaml               # 个人国内 IP 网段补充（聚合编译进 cnip.mrs）
│   ├── ai.yaml                 # 个人 AI 补充规则（归入 🤖 AI 服务）
│   ├── google.yaml             # 个人 Google/Gemini 补充规则（归入 🔍 谷歌服务）
│   └── exclude.yaml            # 全局误杀剔除白名单（从广告及所有规则集中强制移除）
├── scripts/sync.py             # 多源并发拉取、域名树剪枝、CIDR 合并与 .mrs 编译脚本
└── mihomo-config.yaml          # 配套精简版 Mihomo 配置模板（极速防泄漏 DNS + 10 个核心策略组）
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
3. 等待约 25~40 秒变成绿勾 ✅ 后，切换到仓库的 **`release` 分支**：
   - `release` 分支首页会自动生成一张**构建统计表**（展示每个规则集合并前总条数、去重剪枝条数与编译后 `.mrs` 体积）。
   - `rules/` 目录下已生成全部 17 个规则集文件（13 个 `.mrs` + 对应的 `.yaml`）。

### 第 4 步：填入节点并导入 `mihomo-config.yaml`
`mihomo-config.yaml` 已预绑定至 `morecola/momore-rules` 的 `release` 分支，只需填入你的节点或 `proxy-providers` 即可直接使用：

- **GitHub Raw 地址**（更新最及时，`mihomo-config.yaml` 已默认配置通过 `🚀 手动选择` 代理拉取）：
  `https://raw.githubusercontent.com/morecola/momore-rules/release/rules/cn.mrs`
- **jsDelivr CDN 镜像地址**（备选）：
  `https://cdn.jsdelivr.net/gh/morecola/momore-rules@release/rules/cn.mrs`

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
