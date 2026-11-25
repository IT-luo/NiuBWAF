# 牛B WAF（NiuBWAF）部署文档

> 构建基线：Coraza v3.8.1、OWASP CRS 4.25.2 LTS、Go 1.26.11，纯 Go SQLite，`CGO_ENABLED=0` 静态二进制。
> 适用：Linux x86_64 / arm64 生产部署（systemd 推荐，Docker 备选）

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
- Linux（Ubuntu 20.04+ / Debian / CentOS 均可），systemd；内核无特殊要求。
- 建议 ≥ 2 vCPU / 2 GiB 内存（实验室 2 vCPU 实测正常流量 ~1500–2000 QPS）。内存上限由 systemd `MemoryMax` 约束（见 §5.3）。
- 磁盘：程序 ~25 MB；`data/` 视日志量增长（攻击日志 + 流量统计在 SQLite），建议 ≥ 10 GiB 并纳入备份。
- **无外部运行时依赖**：静态链接、无 CGO、不需要系统 SQLite / PCRE 等。

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

### 3.1 交叉编译（推荐）
在开发机（Windows/macOS/Linux 均可）从源码编译 Linux 静态二进制：

```bash
# 国内环境建议设置模块代理
export GOMODCACHE=$HOME/go/pkg/mod          # Windows: set GOMODCACHE=E:/go/go_workspace/pkg/mod
export GOPROXY=https://goproxy.cn,direct
export GOFLAGS=-mod=mod

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags="-s -w" -o niubwaf-linux .
# arm64 目标：GOARCH=arm64
```

校验为静态链接（应输出 `statically linked` 或 `not dynamically linked`）：
```bash
file niubwaf-linux
```

> `-trimpath -ldflags="-s -w"` 去除构建路径与符号表，减小体积并避免泄露路径。**必须 `CGO_ENABLED=0`**，否则依赖系统 libc 无法跨机运行。

### 3.2 Docker 构建（备选，未经生产验证）
仓库自带 `Dockerfile`（多阶段：golang:1.26.11-alpine 构建 → alpine:3.21 运行）与 `docker-compose.yml`。
注意：`Dockerfile` 中 `COPY data/geoip.mmdb /app/seed/geoip.mmdb` 要求仓库 `data/geoip.mmdb` 存在，否则构建失败；无该文件时先放一个占位或删掉该行（entrypoint 会在缺失时跳过种子拷贝）。

### 3.3 预编译二进制
仓库根目录的 `niubwaf-linux` 为某次构建产物。**生产请以 §3.1 重新编译**，确保与当前源码一致。

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

`data/` 是**唯一状态目录**：迁移、备份、恢复都只涉及它。程序本体无状态，可随意替换。

---

## 5. systemd 部署（推荐）

### 5.1 上传二进制
```bash
sudo mkdir -p /opt/niubwaf/data
sudo install -m 0755 niubwaf-linux /opt/niubwaf/niubwaf
# 可选：放置 GeoIP
# sudo cp ip2region_v4.xdb geoip*.mmdb /opt/niubwaf/data/
```

### 5.2 创建运行用户（可选但推荐）
```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin niubwaf
sudo chown -R niubwaf:niubwaf /opt/niubwaf
```
> 若以非 root 运行，需保证该用户可绑定 8080/8443/9443（均 >1024，无需特权）；启用 ACME 监听 :80 需 root 或 `CAP_NET_BIND_SERVICE`。

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

> `MemoryMax=1G` 与代码内「请求体检查上限（`body_inspect_kb`，默认 2048 KB）+ 响应缓冲上限」配合，约束单请求内存。若业务有超大上传且调大了 `body_inspect_kb`，请同步上调 `MemoryMax`。
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
- `entrypoint` 会在 `data/geoip.mmdb` 缺失时从镜像种子拷贝一份（若构建时带了种子）。

升级镜像：`docker compose build && docker compose up -d`（卷内数据保留，schema 自动迁移）。

---

## 7. 首次启动与初始化

1. 本机浏览器打开 `https://127.0.0.1:9443`。远程运维建议使用 `ssh -L 9443:127.0.0.1:9443 user@host`；如显式改为监听其他地址，安全组必须只放行运维网段。自签名证书会告警，生产请配正式证书（§9）。
2. **没有固定默认口令**。首次启动日志会显示一次随机初始密码（Docker 用 `docker compose logs niubwaf` 查看）；也可在首次启动前通过 `NIUBWAF_ADMIN_PASSWORD` 设置符合强度要求的初始密码。首次登录强制改密，改密后所有旧会话失效。新口令要求 ≥8 位且同时含字母和数字、≠旧口令，且不能重新使用历史默认口令 `admin123`。**请立即改为强口令并妥善保存（系统不存明文，仅 PBKDF2 哈希，无法找回）。** 存量库若仍使用 `admin123`，启动时会自动轮换：优先采用环境变量，否则生成并记录一次性随机初始密码。
3. 创建第一个站点：控制台「站点管理」→ 新建，填 域名（Host 匹配）、上游（可逗号分隔多个做负载均衡）、防护模式（平衡/严格）。保存即生效（热加载，无需重启）。控制台写操作自动携带 CSRF 令牌；API 客户端需先 `GET /api/csrf`，再为写请求添加 `X-NiuB-CSRF` 请求头。
4. 验证：`curl -sk -H "Host: <域名>" http://127.0.0.1:8080/` 应返回源站内容；带攻击样本（如 `/?id=1 UNION SELECT …`）应返回 403 拦截页。
5. 按需完成 §8 生产配置清单。

接口限流在「自定义规则」中配置。选定站点，加入路径和请求方法条件，选择「接口限流（429）」并填写每秒请求数与突发容量。生效规则按优先级选择第一个匹配项，额度按客户端 IP、站点和规则分别计算。其他请求继续使用站点 CC 限额。通过管理 API 配置时，使用 `action: "rate_limit"`，`action_param` 填每秒速率或用逗号分隔的速率与突发容量。

「运行维护」显示实际加载的 CRS 版本、GeoIP 状态、巡检、备份和配置导入导出。Prometheus 可用 `niubwaf_rate_limited_total` 区分站点及接口限流，用 `niubwaf_upstream_queue_requests` 和 `niubwaf_upstream_queue_duration_seconds` 查看上游排队，用 `niubwaf_upstream_timeouts_total` 和 `niubwaf_overload_rejections_total` 区分超时与过载拒绝。

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
| 4 | `trusted_proxies` | 安全设置 | **留空**（默认忽略 XFF）或仅填真实前置代理 CIDR | 填宽（如 `0.0.0.0/0`）会被拒绝；填错可被客户端伪造 XFF 绕过黑白名单/信誉/地域 |
| 5 | `log_retention_days` | 安全设置→日志保留 | 按合规（默认 30） | 6h 清理一次 |
| 6 | `semantic_mode` | 安全设置 | 先 `observe` 观察误报，再 `block` | 抗混淆语义引擎 |
| 7 | 信誉自动拉黑 | 安全设置（默认 on，阈值 30/24h） | 保持 on；重要业务 IP 加白名单 | 白名单优先；解封赦免一个窗口 |
| 8 | 动态防护 | 站点编辑→动态防护 | 默认 off；先 `observe` 再 `block` | 仅门禁写操作；GET/HEAD 豁免 |
| 9 | 告警通知 | 安全设置→告警 | 默认 off；按需接 webhook/钉钉/企微 | 阈值 50/60s/冷却 300s 起 |
| 10 | `metrics_token` | 安全设置→Prometheus | 设 token 或保持空（仅环回） | `/metrics` 在 9443 |
| 11 | `body_inspect_kb` | 安全设置→请求体检查上限 | 默认 2048 KB | 与 `body_scan_kb` 取较小值，超限返回 413 |
| 12 | GeoIP 数据 | `data/` | ip2region_v4.xdb（中国城市展示）+ mmdb（地域策略/ASN/海外城市） | 缺失自动降级 |
| 13 | 9443 防火墙 | 主机/云安全组 | 仅运维网段 | 管理面高权限 |

---

## 9. 证书管理

- **手动**：启动参数或控制台站点证书（SNI）。站点证书优先于默认证书。
- **ACME**：控制台「ACME 自动证书」→ 启用、填域名（逗号分隔）与邮箱；`acme_staging` 默认 on（测试 CA，不触发速率限制），联调通过后切 off（生产 CA）。需公网域名 + 80/443 可达 Let's Encrypt；首次启用需重启以监听 :80（`-acme-http` 可改）。签发缓存于 `data/acme`，自动续期。**内网无法实际签发**，仅验证配置/回退不破坏代理。
- **回退顺序**：站点证书 → ACME → 默认自签名证书。

---

## 10. 备份与恢复

- **自动**：每 6 小时 `VACUUM INTO` 热备份到 `data/backups/niubwaf-<时间戳>.db`（0700），保留最近 7 份；运行中可安全执行。
- **手动**：控制台「数据备份」→ 立即备份，或 `POST /api/backup`；列表 `GET /api/backups`。
- **恢复**：停止服务 → 用备份文件覆盖 `data/niubwaf.db`（同时删除残留 `-wal`/`-shm`）→ 启动服务。
- **备份范围**：仅 SQLite 数据库。**证书、mmdb、ACME 缓存不在备份内**，请另行纳入主机备份策略。

---

## 11. 升级 / 重新部署（热替换）

运行中的二进制被直接覆盖会报 `ETXTBSY`，因此采用「先传 .new 再 mv」：

```bash
# 1) 开发机交叉编译（§3.1）得到 niubwaf-linux
# 2) 上传为 .new
scp niubwaf-linux user@host:/opt/niubwaf/niubwaf.new
# 3) 服务器上原子替换 + 重启
ssh user@host 'sudo chmod +x /opt/niubwaf/niubwaf.new && \
               sudo mv -f /opt/niubwaf/niubwaf.new /opt/niubwaf/niubwaf && \
               sudo systemctl restart niubwaf'
# 4) 验证
systemctl is-active niubwaf
ss -ltn | grep -E '8080|8443|9443'
curl -sk https://127.0.0.1:9443/api/login -o /dev/null -w '%{http_code}\n'   # 401/200 均代表管理端存活
```

- **回滚**：替换前可先 `cp niubwaf niubwaf.bak`；回滚即 `mv -f niubwaf.bak niubwaf && systemctl restart`。
- **数据迁移自动**：启动时 `migrate()` 自动建表/加列/升级旧数据（如明文口令哈希化），无需手工 SQL。
- **配置/会话不丢**：设置与站点在 SQLite；会话为内存态，重启后需重新登录（属预期）。

Docker 环境升级见 §6 末。

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
| 业务 502 | 上游不可达/地址填错 | 检查站点 upstream、`/api/upstreams` 健康 |
| `text/plain` POST 被 403（规则 920420） | CRS 默认内容类型策略不含 text/plain | 属策略非 bug；经 `tx.allowed_request_content_type` 调优或让客户端改用 urlencoded/json |
| 真实客户端 IP 显示为代理 IP | 前置 LB 未配 `trusted_proxies` | 安全设置填真实代理 CIDR（勿填 0.0.0.0/0） |
| 覆盖二进制报 `ETXTBSY` | 直接覆盖运行中文件 | 用 §11 的 `.new + mv` 流程 |
| ACME 签发失败 | 内网/域名未公网解析/80-443 不可达 | 确认公网可达；或改手动证书 |
| 大上传被拦/内存高 | `body_inspect_kb` 与 `MemoryMax` 不匹配 | 按 §5.3 注同步调整 |

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
| `intel_provider` / `intel_api_key` / `intel_api_url` | off / 空 / 空 | off|generic + Bearer key + 含 `{ip}` 的 URL | 付费威胁情报 |
| `body_inspect_kb` | 2048 | 64–102400 | 请求体检查上限 |
| `block_page` | 空 | HTML（占位符 {{REQ_ID}} 等） | 自定义拦截页 |

### 人机验证与凭据隔离

- 为 Bot、CC 或自定义规则启用人机验证前，在 Cloudflare Turnstile 创建允许对应业务域名的组件，并在启动环境设置 `NIUBWAF_TURNSTILE_SITE_KEY` 和 `NIUBWAF_TURNSTILE_SECRET_KEY`。Compose 会传入这两个变量。浏览器与 WAF 需要能访问 `challenges.cloudflare.com`。缺少密钥或服务验证失败时，请求保持拦截。
- 人机通行证绑定站点、客户端 IP 和触发规则，仅在同一用途下生效。CC 限流及动态令牌检查继续执行。动态令牌分别限制每个站点和每个客户端的未消费额度。
- 对外代理会删除管理会话 Cookie。站点启用 Basic Auth 时，WAF 验证并消耗认证头。管理控制台使用独立主机名能进一步隔离浏览器会话。
- 新攻击日志只写入 URL 路径。历史日志、CSV 与回放样本显示时隐藏查询串，回放仍可使用库内已有数据评估旧记录。新记录缺少查询串时，依赖完整 URL 或参数值的条件标记为不可判定。旧 SQLite 文件及已有备份中保存的数据仍需按保留策略处理。

## 附录 C：已知限制（生产评估用）

- **单节点**：无分布式集群/多活（P2 规划）；横向扩展需前置 LB 多实例各自独立 `data/`（配置不共享）。
- **性能 backlog（未修，非阻塞）**：ScoreIPs 每 60s 全表 GROUP BY；QueryLogs 前导 `%` LIKE 不走索引；exportCSV 一次性载入内存；限流器全局互斥锁。中小流量无感，超大日志量需关注。
- **CRS 内容类型策略**：默认放行任意 Content-Type（920420 已默认豁免，请求体仍被检测）；配置 `allowed_content_types` 后进入严格白名单模式。
- **请求体完整检查**。通用上限取 `body_inspect_kb` 与 `body_scan_kb` 的较小值（默认 16 KiB，最高 1 MiB）。超限返回 413，非 identity 的 `Content-Encoding` 返回 415。上传客户端需要发送未压缩的请求，并按站点业务体积调整上限。
- **大文件上传策略**。管理员可在「防护站点 → 上传策略」为 `POST`、`PUT` 或 `PATCH` 的精确路径配置 1–64 MiB 请求体上限和 1–4 个大上传并发。例如 `POST /api/upload` 可设置 64 MiB、并发 2。上限按整个请求体计算，包含 multipart 表单边界及字段。匹配且经过 WAF 防护的请求仍完整送入 Coraza 进行 HTTP 请求检测，文件类型校验、文件内容安全扫描和磁盘配额由业务端负责。每个 WAF 进程对大请求同时使用 4 个处理槽及 128 MiB 在途请求体额度，额度不足返回 503 和 `Retry-After`。代理读取、检测和回源期间都占用额度，Coraza 可能使用系统临时目录。
- **上游连接池**。每个源站默认最多使用 256 条代理连接，共用源站的站点共享额度。可用启动参数 `-upstream-connections` 按源站容量调整。等待连接超过 1 秒返回 503 和 `Retry-After`。SSE 与 WebSocket 在连接存续期间占用额度。
- **ACME 需公网**：内网环境无法实际签发。
- **高级能力未含（P2）**：bot/TLS 指纹、API 安全（OpenAPI/BOLA/GraphQL）、ML 检测。
- **日志保留与过载**：攻击日志按保留期自动清理，审计日志保留最新约 10000 条；极端超过攻击日志队列容量时仍会丢弃，但会写入限频告警，并通过 `/api/stats` 的 `dropped_attack_logs` 暴露累计丢弃数。

## 附录 D：旧规则集的历史调优基线（33,877 样本公开基准）

用开源基准压测工具（33,877 条真实流量样本，658 黑 / 33,219 白）回归的调优结果：

| 指标 | 调优前（干净基线） | 一轮调优 | 二轮调优 |
|---|---|---|---|
| 检出率 | 76.29% | 81.31% | **77.66%** |
| 误报率 | 14.97% | 4.11% | **1.04%** |
| 准确率 | 84.86% | 95.61% | **98.55%** |
| 平均耗时 | — | 24.6 ms | **19.1 ms** |

二轮调优漏报 147 条，误报 345 条。以下为当时的调优手段，检测指标需按当前规则集重新测量。

1. **方法策略**：900003 允许 `PUT/PATCH/DELETE`，兼容常用 REST 操作。
2. **默认豁免低价值高噪声 CRS 规则**（对 3.4 万样本 TP≈0，等价攻击由其余规则/语义引擎覆盖）：942550、930120、932260、932370、932380、943110、921150、920450、941180、932230、933180、920270、933150、933120、932130、942190、942540、942140、942290、920470；920420 仅在未配置 `allowed_content_types` 时豁免。豁免以 `ctl:ruleRemoveById` 注入，站点级规则调优仍可进一步增删。
3. **932235 语义复核熔断**：该规则宽匹配（FP 434 / TP 37），单独命中时须语义引擎 100203 代码注入复核确认才拦截，否则记观察日志放行——误报与检出兼得。
4. **语义引擎增强**（规则 100200–100203）：JS 转义还原（`\xNN`/`\uNNNN`/八进制）、双层与截断 base64 还原（含 base64url）、SELECT…FROM / INSERT INTO 结构识别、括号属性访问 XSS、LFI/SSRF（危险协议、敏感系统文件、云元数据）与代码注入（PHP/JSP 标签、webshell 函数、Struts OGNL）检测。生产建议将 `semantic_mode` 设为 `block`。
5. **自有规则 100001 精修**：命令词后要求分隔符/路径符，消除 `;cat=` 类广告像素误报。
6. **请求体不按客户端 Content-Type 旁路**：文本与二进制声明使用相同的 CRS/语义检测流程，避免伪造 `application/octet-stream` 等类型绕过正文检测；送检性能由 `body_scan_kb` 上限约束。
7. **送检上限默认 16 KiB**（`body_scan_kb`，范围 16–1024 KiB）。请求体完整送检，超过上限即拒绝。CRS 同时拦截超过 Coraza 参数上限的请求。

**压测注意**：基准压测工具从单一 IP 发送全部样本，IP 信誉自动拉黑（默认开启，阈值 30）会在数十个攻击样本后封禁该 IP，导致后续白样本被连带拦截、误报率虚高（曾观测 26%+）。评估内容检测能力时应临时关闭 `reputation_enabled` 或调高 `rep_threshold`；生产环境中对持续攻击源自动封禁属预期行为。
