# 牛B WAF（NiuBWAF）部署文档

预编译包以 `v1.2.2` 为例。该版本内置 Coraza v3.8.1 和 OWASP CRS 4.25.2 LTS，使用 Go 1.26.11 和 `CGO_ENABLED=0` 构建 Linux AMD64 和 Windows x64 二进制。[发布页](https://github.com/IT-luo/NiuBWAF/releases/tag/v1.2.2)

| 部署方式 | 交付范围 |
|---|---|
| Linux x86_64 + systemd | GitHub Release 提供 `linux-amd64` 包和 SHA-256 校验文件 |
| Linux arm64 + systemd | 可从版本标签构建，部署前在目标架构验证 |
| Windows x64 原生 | GitHub Release 提供 `windows-amd64` ZIP，解压为控制台程序，常驻托管需使用 Windows 服务包装器 |
| Docker Compose | 仓库提供构建文件和非 root 运行配置，部署前验证目标环境和数据卷权限 |

---

## 1. 架构与端口速览

单二进制、单进程、单节点。检测引擎（Coraza+CRS）与反向代理、管理 API、控制台打包在一起；数据全部落在 `data/` 目录（SQLite + 情报缓存 + 证书 + 备份）。

| 端口 | 默认监听 | 用途 | 是否必须对外 |
|---|---|---|---|
| 8080 | `-proxy :8080` | 防护代理 HTTP（业务流量入口） | 是 |
| 8443 | `-tls :8443` | 防护代理 HTTPS（按站点 SNI 证书） | 是 |
| 9443 | `-admin 127.0.0.1:9443` | 管理控制台（**仅 HTTPS**） | 否，默认仅环回；远程仅运维网段或 SSH 隧道 |
| 80 | `-acme-http :80` | ACME HTTP-01 挑战（仅 `acme_enabled=on` 时启动） | 启用 ACME 时需公网可达 |

数据流：`客户端 → [可选前置 LB/CDN] → NiuBWAF(8080/8443) → 上游源站`。管理面与业务面端口分离，互不影响。

---

## 2. 部署前准备

### 2.1 硬件 / 系统

- Linux 单节点，使用 systemd 或 Docker Compose。先确认目标架构、访问路径与源站连通性。
- 试运行可以从 2 vCPU、2 GiB 内存起步，按真实请求体、上游时延和日志量压测调整。systemd 内存上限见 §5.3，测试方法见附录 D。
- 为 `data/` 中的日志、统计和备份预留磁盘空间。流量和保留时长决定实际占用，试运行期间观察增长量。
- 发布的静态二进制无需安装系统 SQLite 或 PCRE。

### 2.2 网络 / 防火墙
- 放行 8080/8443 给业务流量。
- 9443 默认仅监听环回；确需对外开放时仅放行运维 / 堡垒机网段（管理面含全部配置能力）。
- 若启用 ACME：域名需公网解析到本机，且 80（HTTP-01）或 443（TLS-ALPN-01）可被 Let's Encrypt 访问；**内网 / 无公网域名无法签发**。

### 2.3 证书准备（三选一）
1. **手动证书**：自备 PEM（fullchain + privkey），启动参数 `-cert/-key`（代理默认）与 `-admin-cert/-admin-key`（管理台），或在控制台按站点配置 SNI 证书。
2. **ACME 自动签发**：控制台「ACME 自动证书」启用（需公网域名，见 §9）。
3. **自签名（默认）**：未提供证书时自动生成 `data/default_cert.pem`、`data/admin_cert.pem`（SAN 仅含 localhost/niubwaf.local/127.0.0.1/::1）。**浏览器会告警，仅限内网 / 测试**；生产请换 1 或 2。

### 2.4 可选：GeoIP 库
- **ip2region（推荐）**：官方 `ip2region_v4.xdb`（旧名 `ip2region.xdb` 亦兼容）放到 `data/`，离线免费、无需注册；中国 IP 精确到省/市/运营商，仪表盘 Top 攻击 IP、攻击日志、情报页的城市展示优先用它。来源：github.com/lionsoul2014/ip2region 或 gitee.com/lionsoul/ip2region 的 `data/ip2region_v4.xdb`。
- 将 mmdb 格式的 GeoIP 数据库（自行获取并遵守数据源许可）放到 `data/geoip.mmdb`（国家）、`data/geoip_city.mmdb`（城市）、`geoip_asn.mmdb`（ASN）。海外 IP 城市与 ASN 依赖 mmdb；**地域访问控制策略仅认 mmdb 国家库（ISO 码）**，ip2region 只补城市展示。缺失时地理位置功能自动降级为不可用，不影响其他功能。
- IDC / Tor 情报内置基线并自动在线刷新（缓存 `data/idc_cache.json`、`data/tor_cache.json`），无需手动放置。

---

## 3. 获取构建产物

### 3.1 下载发布包（Linux x86_64）

从 [GitHub Releases](https://github.com/IT-luo/NiuBWAF/releases) 下载同一版本的 `niubwaf-<版本>-linux-amd64.tar.gz` 和 `SHA256SUMS`。以下以 `v1.2.2` 为例，在下载目录运行。成功时会报告压缩包 `OK`，并解压得到 `niubwaf`。

```bash
sha256sum -c --ignore-missing SHA256SUMS && tar -xzf niubwaf-v1.2.2-linux-amd64.tar.gz
```

### 3.2 从版本标签编译

进入仓库，在 Bash 中执行以下命令。Windows PowerShell 可用 `$env:CGO_ENABLED='0'`、`$env:GOOS='linux'` 和 `$env:GOARCH='amd64'` 设置环境变量，再执行其中的 `go build`。

```bash
git checkout v1.2.2
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o niubwaf .
# arm64 目标：GOARCH=arm64
```

在构建机检查二进制架构、链接类型和版本信息。保留提交哈希，便于后续复现。

```bash
file niubwaf
go version -m niubwaf
git rev-parse HEAD
```

### 3.3 Docker 构建（备选）

用待部署版本的 `Dockerfile` 和 `docker-compose.yml` 构建。当前源码可直接构建无 GeoIP 数据的镜像。需要 GeoIP 时把数据库放入运行时数据卷。若固定在旧标签 `v1.2.1`，该标签的 `Dockerfile` 仍要求 `data/geoip.mmdb`，可在本地构建副本里移除对应的 `COPY` 行。[Docker 部署](#6-docker-部署备选)

### 3.4 Windows x64 原生部署

从发布页下载同一版本的 `niubwaf-v1.2.2-windows-amd64.zip` 和 `SHA256SUMS`，在下载目录的 PowerShell 中执行。管理台默认仅绑定本机 HTTPS `9443`。

```powershell
$package = 'niubwaf-v1.2.2-windows-amd64.zip'
$expected = (Select-String -LiteralPath SHA256SUMS -Pattern ('^[0-9a-f]{64}  ' + [regex]::Escape($package) + '$')).Line -split '  '
if (-not $expected -or (Get-FileHash -LiteralPath $package -Algorithm SHA256).Hash -ne $expected[0]) {
    throw 'SHA-256 校验失败'
}
Expand-Archive -LiteralPath $package -DestinationPath '.\niubwaf-v1.2.2'
Set-Location '.\niubwaf-v1.2.2'
.\niubwaf.exe -proxy ':8080' -tls ':8443' -admin '127.0.0.1:9443' -data 'C:\NiuBWAF\data'
```

如需自行构建，在同一版本标签的仓库目录执行。

```powershell
$env:GOOS = 'windows'
$env:GOARCH = 'amd64'
$env:CGO_ENABLED = '0'
go build -trimpath -ldflags '-s -w' -o niubwaf.exe .
.\niubwaf.exe -proxy ':8080' -tls ':8443' -admin '127.0.0.1:9443' -data 'C:\NiuBWAF\data'
```

使用专用 NTFS 数据目录，以实际运行账号启动。程序会为数据目录、受管 SQLite 文件、生成的私钥、备份及 ACME 缓存检查或收紧 ACL，允许当前运行账号、SYSTEM 与 Administrators 访问。权限修复失败会中止启动，可由管理员为实际运行账号预配目录权限。通过启动参数引用的外部证书和私钥由部署者设置权限。

---

## 4. 目录布局

```
/opt/niubwaf/
├── niubwaf                 # 主程序（linux 静态二进制）
└── data/                   # -data 指向此处（默认 ./data）
    ├── niubwaf.db          # SQLite 主库（站点/日志/统计/设置/信誉/规则…）
    ├── niubwaf.db-wal/-shm # WAL 伴生文件
    ├── default_cert.pem / default_key.pem   # 代理默认自签名证书（自动生成）
    ├── admin_cert.pem / admin_key.pem       # 管理台自签名证书（自动生成）
    ├── ip2region_v4.xdb                       # 可选，中国省市+运营商（推荐）
    ├── geoip.mmdb / geoip_city.mmdb / geoip_asn.mmdb   # 可选，手动放置
    ├── idc_cache.json / tor_cache.json      # 情报缓存（自动）
    ├── acme/                                # ACME 签发缓存（启用后自动）
    └── backups/                             # 自动备份（0700，保留 7 份）
```

`data/` 保存应用状态。部署时还要单独保管 systemd unit 或 Compose 配置、环境变量配置以及通过启动参数引用的外部证书文件。

启动时会检查专用数据目录及受管密钥、数据库和备份。Linux 会收紧本地目录和现有敏感文件权限。数据根目录及受管状态文件应使用实际文件和目录。

---

## 5. systemd 部署（推荐）

### 5.1 创建运行用户与目录

```bash
id niubwaf >/dev/null 2>&1 || sudo useradd --system --user-group --no-create-home --shell /usr/sbin/nologin niubwaf
sudo install -d -m 0755 -o root -g root /opt/niubwaf
sudo install -d -m 0700 -o niubwaf -g niubwaf /opt/niubwaf/data
```

### 5.2 安装已校验的二进制

```bash
sudo install -m 0755 -o root -g root niubwaf /opt/niubwaf/niubwaf
```

可选 GeoIP 数据放在 `/opt/niubwaf/data/`。默认业务端口和管理端口允许普通用户监听。启用 ACME 的 `:80` 监听时，给服务配置 `CAP_NET_BIND_SERVICE`。

### 5.3 systemd unit
`/etc/systemd/system/niubwaf.service`：

```ini
[Unit]
Description=NiuBWAF Web Application Firewall
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=niubwaf
Group=niubwaf
WorkingDirectory=/opt/niubwaf
ExecStart=/opt/niubwaf/niubwaf -proxy :8080 -tls :8443 -admin 127.0.0.1:9443 -data /opt/niubwaf/data
Restart=always
RestartSec=3
# 自愈与资源约束：崩溃 3s 拉起；内存软/硬上限防单请求大_body_ 撑爆主机
MemoryHigh=768M
MemoryMax=1G
LimitNOFILE=65535
# 安全加固（可选）
NoNewPrivileges=true
ProtectSystem=full
ReadWritePaths=/opt/niubwaf/data
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

> `MemoryMax=1G` 是整个服务的内存兜底，按压测结果调整。常规请求体上限由 `body_inspect_kb` 与 `body_scan_kb` 共同决定。大上传按站点和精确路径配置，详见附录 C。
> 使用正式证书时在 `ExecStart` 追加 `-cert /path/fullchain.pem -key /path/privkey.pem -admin-cert … -admin-key …`。

### 5.4 启用并验证
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now niubwaf
systemctl status niubwaf            # active (running)
ss -ltn | grep -E '8080|8443|9443'  # 三个端口均在监听
journalctl -u niubwaf -f            # 观察启动日志：引擎就绪 / GeoIP / 情报源 / 备份
```

启动日志关键行（用于确认各子系统正常）：
- `引擎就绪（平衡/严格双模式）…`
- `GeoIP 已加载（…）` 或 `GeoIP 数据库未找到…`（后者=功能降级，非致命）
- `IP 情报源就绪（IDC CIDR n 条 / Tor 出口 n 个…）`
- `管理台使用自动生成的自签名证书…`（未配正式证书时）
- `数据库自动备份完成: backups/…`

---

## 6. Docker 部署（备选）

```bash
docker compose up -d --build
```

`docker-compose.yml` 要点：
- 业务端口映射 8080/8443；管理端口仅发布到主机环回地址 `127.0.0.1:9443`，远程运维请用 SSH 隧道或自行限定运维网段。
- 容器使用 UID/GID 10001 的非 root 用户运行。新命名卷会继承镜像内 `/app/data` 的所有权；**从旧 root 容器升级已有命名卷，或挂载宿主机目录时**，需先由管理员执行 `chown -R 10001:10001` 使数据目录可写，再启动新版本。
- 命名卷 `niubwaf-data → /app/data` 持久化状态。
- 正式证书：取消注释 `./certs:/app/certs:ro` 与 `command:` 覆盖块，把 `-cert/-key/-admin-cert/-admin-key` 指向 `/app/certs/…`。
- 需要 GeoIP 时把合法来源的数据文件放入运行时数据卷。当前构建将宿主机 `data/` 排除在镜像构建上下文之外。

升级镜像：`docker compose build && docker compose up -d`（卷内数据保留，schema 自动迁移）。

---

## 7. 首次启动与初始化

1. 本机浏览器打开 `https://127.0.0.1:9443`。远程运维建议使用 `ssh -L 9443:127.0.0.1:9443 user@host`；如显式改为监听其他地址，安全组必须只放行运维网段。自签名证书会告警，生产请配正式证书（§9）。
2. **没有固定默认口令**。首次启动日志会显示一次随机初始密码（Docker 用 `docker compose logs niubwaf` 查看）；也可在首次启动前通过 `NIUBWAF_ADMIN_PASSWORD` 设置符合强度要求的初始密码。首次登录强制改密，改密后所有旧会话失效。新口令要求 ≥8 位且同时含字母和数字、≠旧口令，且不能重新使用历史默认口令 `admin123`。**请立即改为强口令并妥善保存（系统不存明文，仅 PBKDF2 哈希，无法找回）。** 存量库若仍使用 `admin123`，启动时会自动轮换：优先采用环境变量，否则生成并记录一次性随机初始密码。
3. 打开「防护站点」并添加站点。填写业务域名、WAF 能访问的源站地址和防护模式。域名指向 WAF 前，确保回源地址可直接到达源站，避免同一个公网域名解析后又回到 WAF。保存后配置会热加载。
4. 从 WAF 所在机器发一个普通请求验证本机路由。把 `app.example.test` 换成实际站点域名。若已开启 HTTP 跳转，也可改用业务 HTTPS 入口验证。

   ```bash
   curl -sSi -H 'Host: app.example.test' http://127.0.0.1:8080/
   ```

5. 切换域名解析或端口转发后，从用户所在网络访问实际入口，检查证书、状态码和预期页面。外部及回源端口分别配置。例如公众访问 `:9020` 时，路由器的目标端口应指向 WAF 的 HTTPS 监听端口，再由 WAF 转发到源站。
6. 在支持接入验收的版本中，打开对应站点的「接入验收」。选择用户实际访问的协议、端口及可正常访问的 GET 路径，生成命令。要验证公网入口，请从站点所在局域网之外执行两条命令，回到控制台刷新结果。验收完成后核对 §8 的生产配置清单。

控制台写操作自动携带 CSRF 令牌。API 客户端先调用 `GET /api/csrf`，再为写请求添加 `X-NiuB-CSRF` 请求头。

接口限流在「自定义规则」中配置。选定站点，加入路径和请求方法条件，选择「接口限流（429）」并填写每秒请求数与突发容量。生效规则按优先级选择第一个匹配项，额度按客户端 IP、站点和规则分别计算。其他请求继续使用站点 CC 限额。通过管理 API 配置时，使用 `action: "rate_limit"`，`action_param` 填每秒速率或用逗号分隔的速率与突发容量。

「运行维护」显示实际加载的 CRS 版本、GeoIP 状态、巡检、备份和配置导入导出。Prometheus 可用 `niubwaf_rate_limited_total` 区分站点及接口限流，用 `niubwaf_upstream_queue_requests` 和 `niubwaf_upstream_queue_duration_seconds` 查看上游排队，用 `niubwaf_upstream_timeouts_total` 和 `niubwaf_overload_rejections_total` 区分超时与过载拒绝。

### 接入验收与请求诊断

- **已配置**表示站点启用。**已收到流量**表示该节点看到了发往此站点的请求。**入口已验收**表示两条验收请求均满足预期，普通请求经过现有防护流程并获得源站成功响应或重定向，验收拦截请求由 WAF 返回 `403`。
- 验收命令有效期为 5 分钟，两条命令各可使用一次。测试标记只用于当前节点和目标站点，验收拦截不会进入攻击排行榜。验证后可以用结果中的请求 ID 查处理过程。选择的执行位置由操作者提供，界面会标明内网或外部网络。两次请求都未到达时，核对 DNS、证书、端口转发和前置代理是否保留验证请求头。验收结果在本节点内存中最多保留 24 小时。
- 验收按节点实际收到的协议和 Host 端口匹配。端口转发应保留 Host 中的公网端口。若前置代理终止 TLS 并以 HTTP 转发请求，节点可以显示收到了业务流量，但无法按 HTTPS 入口完成这项验收。
- 在「攻击日志 → 请求诊断」输入拦截页或 `X-NiuB-WAF-Req-ID` 响应头中的请求 ID。可以区分 WAF 拦截、回源失败以及源站返回错误。`413` 会尽可能显示记录到的大小、检测上限和配置来源。客户端声明长度与实际读取长度分别标注。
- 近期诊断在当前节点按数量和时间保留，最长 15 分钟，服务重启后清空。请求头、查询参数和请求体原文不会写入诊断。超过近期窗口后，仍可用请求 ID 查询现有防护日志中的部分字段。

在 `v1.2.1` 等早期版本中，可添加一条站点专用的临时规则，精确匹配自选的随机请求头值，关闭影子模式并选择「拦截」。从同一外部客户端分别发普通请求和带该请求头的请求，核对正常回源、`403` 及 `X-NiuB-WAF: blocked`，完成后删除临时规则。

### 响应检测覆盖

启用站点的「响应内容检测」后，WAF 检查响应头，并在扫描上限内检查支持类型的 HTTP 正文，支持原始和 gzip 编码。超过上限时只检查正文前缀。流式响应、协议升级、分段下载和其他内容类型或编码只检查响应头。整体覆盖及失败原因可在「运行维护」和 Prometheus 的 `niubwaf_response_inspection_total` 中查看。

### API 契约

打开「防护站点 → API 契约」，上传 JSON 或 YAML 格式的 OpenAPI 3.0 / 3.1 文件，并设置校验的路径范围。文档中的路径使用 WAF 收到的完整路径，服务器地址只作为文档信息。契约使用单文件，内部引用可用。先选择「仅记录」，检查日志中的「API 契约」事件，再按站点打开拒绝模式。API 身份认证仍由站点或源站执行。

### 账号与审计采集

原有 `admin` 账号继续可用。管理员可新建独立账号并分配管理员、操作员或只读角色。操作员可维护规则、豁免、名单和 API 契约。临时密码首次登录需要修改，停用或重置账号会撤销其旧会话。

在「运行维护 → 审计日志采集」设置专用令牌。采集器携带 `Authorization: Bearer <令牌>` 拉取 `GET /audit/events?after_id=0&limit=200`。每行是一条 JSON 事件，收到一批后保存响应头 `X-NiuB-Audit-Next-ID` 并作为下一次的 `after_id`。采集间隔应保证在本地审计轮转前读取记录。

### Bot 来源与行为

在「安全设置 → Bot 来源和行为」启用 Googlebot、Bingbot 网段校验。WAF 在后台更新官方网段，有可用数据后按请求的实际客户端 IP 验证。可为启用了 Bot 防护的站点设置同一客户端 10 秒内允许访问的新路径数。重复访问同一路径只计一次，设为 0 时关闭行为判定。

---

## 8. 生产环境必做配置清单

| # | 配置项 | 位置 | 生产建议 | 说明 |
|---|---|---|---|---|
| 1 | 管理口令 | 首次登录强制 | 随机初始口令 + 强口令 | 无固定默认口令；改密撤销全部旧会话 |
| 2 | 管理台证书 | `-admin-cert/-admin-key` | 正式证书 | 否则自签名浏览器告警 |
| 3 | 代理证书 | `-cert/-key` 或控制台站点证书 或 ACME | 正式证书 | 按站点 SNI |
| 4 | `trusted_proxies` | 安全设置 | **留空**（默认忽略转发头）或仅填真实前置代理的 IP/CIDR | 公网入口必须清理客户端自带的身份头，并从连接来源重建可信转发头 |
| 5 | `log_retention_days` | 安全设置→日志保留 | 按合规（默认 30） | 6h 清理一次 |
| 6 | `semantic_mode` | 安全设置 | 先 `observe` 观察误报，再 `block` | 抗混淆语义引擎 |
| 7 | 信誉自动拉黑 | 安全设置（默认 on，阈值 30/24h） | 保持 on；重要业务 IP 加白名单 | 白名单优先；解封赦免一个窗口 |
| 8 | 动态防护 | 站点编辑→动态防护 | 默认 off；先 `observe` 再 `block` | 仅门禁写操作；GET/HEAD 豁免 |
| 9 | 告警通知 | 安全设置→告警 | 默认 off；按需接 webhook/钉钉/企微 | 阈值 50/60s/冷却 300s 起 |
| 10 | `metrics_token` | 安全设置→Prometheus | 设 token 或保持空（仅环回） | `/metrics` 在 9443 |
| 11 | 请求体检查上限 | 安全设置或站点上传策略 | 按真实业务请求体配置 | 通用上限取 `body_inspect_kb` 与 `body_scan_kb` 较小值，默认有效上限 16 KiB。较大上传可单独设置精确路径策略 |
| 12 | GeoIP 数据 | `data/` | ip2region_v4.xdb（中国城市展示）+ mmdb（地域策略/ASN/海外城市） | 缺失自动降级 |
| 13 | 9443 防火墙 | 主机/云安全组 | 仅运维网段 | 管理面高权限 |

---

## 9. 证书管理

- **手动**：启动参数或控制台站点证书（SNI）。站点证书优先于默认证书。
- **ACME**：控制台「ACME 自动证书」→ 启用、填域名（逗号分隔）与邮箱；`acme_staging` 默认 on（测试 CA，不触发速率限制），联调通过后切 off（生产 CA）。需公网域名 + 80/443 可达 Let's Encrypt；首次启用需重启以监听 :80（`-acme-http` 可改）。签发缓存于 `data/acme`，自动续期。**内网无法实际签发**，仅验证配置/回退不破坏代理。
- **回退顺序**：站点证书 → ACME → 默认自签名证书。

---

## 10. 备份与恢复

- **自动**：每 6 小时 `VACUUM INTO` 热备份到受限的 `data/backups/` 目录，保留最近 7 份；运行中可安全执行。
- **手动**：控制台「数据备份」→ 立即备份，或 `POST /api/backup`；列表 `GET /api/backups`。
- **备份范围**：热备份生成 SQLite 快照。`data/` 中的外部证书、GeoIP 文件、ACME 缓存，以及部署文件和外置证书需另行备份。站点证书等入库配置可能包含私钥，备份文件应按敏感数据管理。
- **恢复**：选择与目标程序版本兼容的备份。先在独立目录或测试实例中恢复并核对站点、证书和规则。正式恢复时停止服务，将现有数据库及 `-wal`、`-shm` 文件一起移到另一个备份目录。将已验证的快照复制为 `data/niubwaf.db`，确认运行用户有读写权限，再启动服务，重新执行 §7 外部验收。

---

## 11. systemd 升级与回滚

1. 在测试实例里从旧版本升级一次，检查发布说明和数据迁移。按 §10 保留升级前的数据库快照，再保存当前程序、部署配置和外部证书。单节点重启安排在维护窗口。
2. 按 §3 获取并校验目标版本，将新二进制传到服务器临时目录。在服务器上从该目录执行下面的替换步骤。备份文件名可以改为当前部署版本。

   ```bash
   sudo cp -p /opt/niubwaf/niubwaf /opt/niubwaf/niubwaf.before-upgrade &&
     sudo install -m 0755 -o root -g root niubwaf /opt/niubwaf/niubwaf.new &&
     sudo mv -f /opt/niubwaf/niubwaf.new /opt/niubwaf/niubwaf &&
     sudo systemctl restart niubwaf
   ```

3. 检查服务、日志和管理入口，然后按 §7 从外部重新验收一个真实站点。重新启动后需要重新登录管理台。

   ```bash
   systemctl is-active niubwaf
   sudo journalctl -u niubwaf -n 40 --no-pager
   curl -kfsS -o /dev/null -w '管理台 HTTP %{http_code}\n' https://127.0.0.1:9443/
   ```

   上例适用于默认环回地址和自签名管理证书。使用正式证书时，以正确主机名访问并启用证书校验。

4. 回滚时用保留的二进制替换当前文件并重启。如果新版本已执行旧程序无法读取的数据迁移，先停止服务，再按 §10 恢复升级前的快照，然后启动旧程序。数据库恢复以快照时间为准，需保留当前数据副本供核对。

Docker 升级前保留旧镜像标签和已验收的数据快照。回滚时切回旧镜像，并按版本兼容性判断是否恢复数据，重新创建容器时保留数据卷。

---

## 12. 运维与监控

- **日志**：`journalctl -u niubwaf -f`（systemd）或 `docker logs -f niubwaf`。
- **指标**：`GET https://<admin>:9443/metrics`（Prometheus 文本格式）。无 token 仅环回可抓；设 `metrics_token` 后需 `Authorization: Bearer <token>`。含请求量/时延直方图、攻击计数、上游健康、信誉封禁数、响应字节、Go 运行时。
- **上游健康**：`GET /api/upstreams`；控制台站点表绿/红点。
- **攻击日志/报表**：控制台「攻击日志」（筛选/导出 CSV/一键豁免误报）与「防护报告」。
- **实时大屏**：`/screen.html`（含全球攻击轨迹点阵地图与实时弧线）。
- **流量分析 / 安全态势**：控制台 `#/traffic`、`#/posture`；聚合数据来自 `GET /api/analytics?hours=6|24|72|168`（小时桶内存累加 + SQLite 保留 7 天）。
- **实时 QPS**：仪表盘与流量分析页的 QPS 面板、大屏地图角标；`GET /api/qps`（近 60 秒序列 + 5s 滚动均值 + 60s 峰值），SSE `/api/events` 每秒推送 `type=qps` 帧；秒级桶仅内存保留 120s，重启清零。
- **资源**：systemd `MemoryMax` 兜底；SQLite 连接池上限 8。

---

## 13. 故障排查

| 现象 | 原因 | 处理 |
|---|---|---|
| 管理台浏览器告警 | 自签名证书 SAN 不含服务器 IP | 配正式证书（§9）；内网可继续访问 |
| 登录后所有 API 403 `{must_change}` | 仍使用首次启动的初始口令 | 先改密（强制门禁） |
| 启动报 `引擎初始化失败` | CRS 嵌入资源损坏/二进制不完整 | 重新编译/上传完整二进制 |
| `GeoIP 数据库未找到` | 未放 mmdb | 放置 `data/geoip.mmdb`（可选，功能降级不致命） |
| 业务 502 | 上游不可达、证书不匹配或地址有误 | 检查站点源站地址和 TLS，再查看 `/api/upstreams`。现有主动探测收到 HTTP 响应即判定连接可用，业务健康还需用预期路径和状态码验证 |
| 状态为「防护中」，请求没有拦截记录 | 站点配置已启用，正常放行也可能没有拦截记录 | 按 §7 比对本机和外部入口，检查公网目标端口与测试规则 |
| 请求返回 403 | WAF 或源站可能返回 403 | 查看响应是否含 `X-NiuB-WAF: blocked`，并用拦截页的请求 ID 和时间核对攻击日志 |
| 大上传返回 413 | 超过 WAF 有效上限，或被前置代理、源站等环节拒绝 | 若有 WAF 拦截页，先看站点上传策略是否命中方法和路径，再核对通用检查上限。否则查前置代理与源站日志 |
| 请求返回 503 | 上游连接队列饱和、上传额度用尽，或业务端拒绝请求 | 对照 `Retry-After`、访问时间和过载指标，结合源站日志确定发生的位置 |
| `text/plain` POST 被 403（规则 920420） | 已启用内容类型白名单，该类型不在允许范围 | 按业务需要增补「允许的 Content-Type」，或让客户端使用站点已支持的格式 |
| 真实客户端 IP 显示为代理 IP | 前置 LB 未配 `trusted_proxies` | 安全设置填真实代理 CIDR（勿填 0.0.0.0/0） |
| 覆盖二进制报 `ETXTBSY` | 直接覆盖运行中文件 | 用 §11 的 `.new + mv` 流程 |
| ACME 签发失败 | 内网/域名未公网解析/80-443 不可达 | 确认公网可达；或改手动证书 |

---

## 14. 卸载

```bash
sudo systemctl disable --now niubwaf
sudo rm -f /etc/systemd/system/niubwaf.service && sudo systemctl daemon-reload
sudo rm -rf /opt/niubwaf        # 含 data/（先备份！）
# Docker: docker compose down -v   （-v 会删除数据卷，慎用）
```

---

## 附录 A：启动参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `-proxy` | `:8080` | 防护代理 HTTP 监听 |
| `-tls` | `:8443` | 防护代理 HTTPS 监听 |
| `-cert` / `-key` | 空 | 代理默认证书/私钥 PEM；留空自动生成自签名 |
| `-admin` | `127.0.0.1:9443` | 管理控制台监听（恒 HTTPS；远程运维建议 SSH 隧道） |
| `-admin-cert` / `-admin-key` | 空 | 管理台证书/私钥；留空自动生成自签名 |
| `-data` | `./data` | 数据目录 |
| `-acme-http` | `:80` | ACME HTTP-01 监听（仅 acme_enabled=on） |

## 附录 B：控制台设置项（`GET/PUT /api/settings`）

| 键 | 默认 | 取值/范围 | 说明 |
|---|---|---|---|
| `semantic_mode` | observe | off/observe/block | 语义抗混淆引擎 |
| `geoip_mode` / `geoip_countries` | off / 空 | off/block/allow + 国家码 | 地域访问控制 |
| `trusted_proxies` | 空 | IP/CIDR 逗号分隔；拒 0.0.0.0/0、::/0 | 真实客户端 IP 解析 |
| `log_retention_days` | 30 | ≥1 | 攻击日志保留 |
| `reputation_enabled` | on | on/off | 信誉自动拉黑总开关 |
| `rep_window` / `rep_threshold` | 24 / 30 | 1–168 h / 1–100000 | 评分窗口/阈值 |
| `rep_ban_ttl` / `rep_max_ttl` | 60 / 1440 | 1–10080 / 1–43200 min | 首封 TTL/上限 |
| `alert_enabled` | off | on/off | 告警推送 |
| `alert_threshold` / `alert_window` / `alert_cooldown` | 50 / 60 / 300 | 1–1e6 / 10–3600 / 10–86400 | 阈值/窗口/冷却 |
| `alert_webhook` / `alert_dingtalk` / `alert_wecom` | 空 | http(s) URL | 推送通道 |
| `acme_enabled` / `acme_staging` | off / on | on/off | ACME 开关/测试 CA |
| `acme_domains` / `acme_email` | 空 | 域名逗号分隔/邮箱 | ACME 签发目标 |
| `metrics_token` | 空 | 字符串 | Prometheus 抓取令牌 |
| `intel_provider` / `intel_api_key` / `intel_api_url` | off / 空 / 空 | `off` 或 `generic`，配 Bearer key 和含 `{ip}` 的 URL | 可选威胁情报服务 |
| `body_inspect_kb` | 2048 | 64–102400 | 请求体检查上限 |
| `body_scan_kb` | 16 | 16–1024 | 通用请求体完整送检上限（KiB） |
| `block_page` | 空 | HTML（占位符 {{REQ_ID}} 等） | 自定义拦截页 |

### 人机验证与凭据隔离

- 为 Bot、CC 或自定义规则启用人机验证前，在 Cloudflare Turnstile 创建允许对应业务域名的组件，并在启动环境设置 `NIUBWAF_TURNSTILE_SITE_KEY` 和 `NIUBWAF_TURNSTILE_SECRET_KEY`。Compose 会传入这两个变量。浏览器与 WAF 需要能访问 `challenges.cloudflare.com`。缺少密钥或服务验证失败时，请求保持拦截。
- 人机通行证绑定站点、客户端 IP 和触发规则，仅在同一用途下生效。CC 限流及动态令牌检查继续执行。动态令牌分别限制每个站点和每个客户端的未消费额度。
- 对外代理会删除管理会话 Cookie。站点启用 Basic Auth 时，WAF 验证并消耗认证头。管理控制台使用独立主机名能进一步隔离浏览器会话。
- 新攻击日志只写入 URL 路径。历史日志、CSV 与回放样本显示时隐藏查询串，回放仍可使用库内已有数据评估旧记录。新记录缺少查询串时，依赖完整 URL 或参数值的条件标记为不可判定。旧 SQLite 文件及已有备份中保存的数据仍需按保留策略处理。

## 附录 C：已知限制（生产评估用）

- **单节点**：无分布式集群/多活（P2 规划）；横向扩展需前置 LB 多实例各自独立 `data/`（配置不共享）。
- **日志查询**：CSV 按行导出。日志量大时，优先按完整域名、IP 等条件过滤，模糊包含查询的开销随数据量增加。
- **CRS 内容类型策略**：默认放行任意 Content-Type（920420 已默认豁免，请求体仍被检测）；配置 `allowed_content_types` 后进入严格白名单模式。
- **请求体完整检查**。通用上限取 `body_inspect_kb` 与 `body_scan_kb` 的较小值（默认 16 KiB，最高 1 MiB）。超限返回 413，非 identity 的 `Content-Encoding` 返回 415。上传客户端需要发送未压缩的请求，并按站点业务体积调整上限。
- **大文件上传策略**。管理员可在「防护站点 → 上传策略」为 `POST`、`PUT` 或 `PATCH` 的精确路径配置 1–64 MiB 请求体上限和 1–4 个大上传并发。例如 `POST /api/upload` 可设置 64 MiB、并发 2。上限按整个请求体计算，包含 multipart 表单边界及字段。匹配且经过 WAF 防护的请求仍完整送入 Coraza 进行 HTTP 请求检测，文件类型校验、文件内容安全扫描和磁盘配额由业务端负责。每个 WAF 进程对大请求同时使用 4 个处理槽及 128 MiB 在途请求体额度，额度不足返回 503 和 `Retry-After`。代理读取、检测和回源期间都占用额度，Coraza 可能使用系统临时目录。
- **上游连接池**。每个源站默认最多使用 256 条代理连接，共用源站的站点共享额度。可用启动参数 `-upstream-connections` 按源站容量调整。等待连接超过 1 秒返回 503 和 `Retry-After`。SSE 与 WebSocket 在连接存续期间占用额度。
- **ACME 需公网**：内网环境无法实际签发。
- **API 与 Bot 范围**：支持 OpenAPI 3.0 / 3.1 请求契约，以及 UA、搜索引擎来源校验和短窗口访问行为。TLS 指纹、GraphQL 专项检测和 BOLA 自动识别尚未提供，业务对象授权由应用执行。
- **日志保留与过载**：攻击日志按保留期自动清理，审计日志保留最新约 10000 条；极端超过攻击日志队列容量时仍会丢弃，但会写入限频告警，并通过 `/api/stats` 的 `dropped_attack_logs` 暴露累计丢弃数。

## 附录 D：容量测试与发布核对

### 在本机复现 HTTP 转发容量

在独立测试环境中使用与待发布版本一致的二进制、规则和资源限制。运行 `node test/upstream.js` 启动本机测试源站，然后在 WAF 中新建测试站点 `perf.example.test`，上游填 `http://127.0.0.1:8081`。使用平衡模式，记录是否开启接口限流、Bot 和响应检测，确保比较的各轮配置一致。

在安装了 [hey](https://github.com/rakyll/hey) 的同一主机运行以下命令。先验证业务通过 WAF 转发，再测直连源站和经过 WAF 的结果。所有命令仅请求本机的普通页面。

```bash
curl -fsS -H 'Host: perf.example.test' http://127.0.0.1:8080/ >/dev/null
hey -z 60s -c 32 -disable-redirects http://127.0.0.1:8081/
hey -z 60s -c 32 -disable-redirects -host perf.example.test http://127.0.0.1:8080/
```

记录 Git 标签和提交、CRS 版本、CPU、内存、系统、并发、测试持续时间、请求特征、QPS、P95/P99、状态码分布、超时和错误率。重复运行并区分预热与正式结果。若要评估生产容量，再加入实际的 HTTPS、上传、长连接及回源延迟，并测试预期高峰下的持续运行。单机普通 HTTP 结果只对应本节测试配置。

项目曾用 33,877 条标注流量评估旧规则集。二轮调优记录的检出率为 77.66%，误报率为 1.04%。当前版本的检测率和误报率需要使用固定的标注数据集重新测量。

### 每次发布前核对

- 从目标提交运行 `go test ./...`。构建对应架构的二进制，按 Release 约定打包并生成 `SHA256SUMS`，再从下载后的发布包复验哈希。
- 在干净环境完成安装、首次登录、首站接入和外部验收，记录测试了哪些架构和部署方式。
- 使用已有数据完成一次升级、程序回滚和从快照恢复，检查站点证书、规则和业务访问。
- 发布说明标明支持范围、兼容性变化、恢复步骤，以及实际验证过的性能条件；未完成的场景标明待验证。
