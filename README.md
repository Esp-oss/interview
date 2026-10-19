# Banner 指纹识别系统（Go + Docker Compose）

接收网络扫描原始数据（`ip` / `port` / `banner`），识别出**协议、软件产品、版本、操作系统线索与置信度**。
交付形态：`docker compose up` 一键启动，server（HTTP API）+ client（独立 CLI）双容器。

```console
$ docker compose up --build
...
client-1  | IP        PORT   PROTOCOL  PRODUCT        VERSION  OS_HINT  CONF
client-1  | 1.2.3.4   22     SSH       OpenSSH        8.9p1    Ubuntu   0.95
client-1  | 1.2.3.5   80     HTTP      nginx          1.24.0   -        0.90
client-1  | 1.2.3.6   443    HTTP      Apache         2.4.57   -        0.90
client-1  | 1.2.3.7   3306   MySQL     MySQL          8.0.32   -        0.90
client-1  | 1.2.3.8   6379   Redis     Redis          -        -        0.70
client-1  | 1.2.3.9   21     FTP       ProFTPD        1.3.7    -        0.90
client-1  | 1.2.3.10  8080   HTTP      Jetty          9.4.51   -        0.85
client-1  | ...
client-1  | 20 items | 18 identified | 2 unknown (90.0% coverage)
client-1  | by protocol: SSH=3 HTTP=7 MySQL=2 Redis=3 FTP=3 unknown=2
client-1  | OK: all 20 records match the expected results
client-1 exited with code 0
```

---

## 1. 快速开始

```bash
docker compose up --build            # 启动 server，client 跑一次样例数据后退出
curl -s localhost:8080/health | jq   # 健康检查
docker compose logs client           # 查看 client 的识别结果
docker compose down                  # 停止
```

识别自己的数据（不用改 compose 文件）：

```bash
# 宿主机文件挂进 client 容器，读取 → 发送 → 打印
docker compose run --rm \
  -v "$PWD/my_scan.json:/data/input.json:ro" \
  client

# 或者直接用发布出来的 API
curl -s -X POST localhost:8080/fingerprint \
  -H 'Content-Type: application/json' \
  -d @examples/sample_input.json | jq
```

本地开发（不需要容器）：

```bash
go test ./...                                  # 单元测试（20 条样例 + 边界）
go test ./internal/engine -fuzz FuzzIdentifyNoPanic -fuzztime 15s   # 抗崩溃 fuzz
go run ./cmd/server &                          # 起服务（默认 :8080）
go run ./cmd/client -file examples/sample_input.json -expected examples/expected_output.json
```

---

## 2. API 契约

### `POST /fingerprint` — 批量识别

请求体接受三种形态（都是真实扫描器会产出的）：

```jsonc
[{"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"}]  // 数组（推荐）
{"items":[ ... ]}                                                       // 信封
{"ip":"1.2.3.4","port":22,"banner":"..."}                               // 单条
```

响应恒为一个**数组**，顺序与请求一致，每条恰好七个字段：

```json
[
  {
    "ip": "1.2.3.4",
    "port": 22,
    "protocol": "SSH",
    "product": "OpenSSH",
    "version": "8.9p1",
    "os_hint": "Ubuntu",
    "confidence": 0.95
  }
]
```

| 字段 | 说明 |
|---|---|
| `protocol` | 在规则集中命中的协议族；**认不出来恒为 `"unknown"`**，不是错误 |
| `product` | 软件名（`nginx`、`Apache`、`OpenSSH`…）；无法确定时为空串 |
| `version` | 提取到的版本号；无法确定时为空串（不猜） |
| `os_hint` | 仅当 banner 里**字面出现** OS 线索时才填（`Ubuntu`/`Debian`/`Windows`…） |
| `confidence` | `0~1`，含义见 §5 置信度模型；`unknown` 恒为 `0` |

**状态码语义**：只有*传输层*问题才是 4xx —— 请求体读不出来 / 超限 / item 超量 / JSON 语法错误。
**任何单条记录的语义问题（空 banner、二进制垃圾、缺字段、超长）都在响应内部降级为 `unknown`，绝不让整个请求失败。**

**输入宽容性（一处特殊修复）**：扫描器与本任务题面的数据常用 Python 风格 `\x00` / `\x16` 转义，而 JSON 只认 `\u0000`。
若严格解析，整批会直接 400 —— 这是唯一能让"一条结果都出不来"的路径。因此 `DecodeItems` 先做严格解析，
失败后再做一次**转义感知的修复**（把字符串内的 `\xHH` 改写为 `\u00HH`，`\\x41` 这类字面反斜杠不动，
`0x80~0xFF` 还原为单字节以保住二进制 banner 的长度）。合法 JSON 永远走严格路径，行为不变。
样例见 [`examples/sample_input_hex_escapes.json`](examples/sample_input_hex_escapes.json)。

| 场景 | 状态码 |
|---|---|
| 正常批量 | `200` |
| JSON 语法错误 / 空 body | `400` |
| body 超过 `MAX_BODY_BYTES`，或 item 数超过 `MAX_BATCH` | `413` |
| 方法不对（如 `GET /fingerprint`） | `405` |
| 语义上有问题但语法合法（垃圾 banner、null、缺字段） | `200` + `unknown` |
| 内部 panic（理论上不会发生，fuzz 测试证明） | `500`（由 recover 中间件兜底，进程不退出） |

### `GET /health` — 健康/就绪检查

```json
{
  "status": "ok",
  "version": "1.0.0",
  "rules": 34,
  "rules_source": "embedded 7 files (ftp.yaml, http.yaml, ...)",
  "workers": 8,
  "uptime_seconds": 42
}
```

规则集未加载时返回 `503`。compose 的 healthcheck 就是拿这个接口做的，见 §6。

---

## 3. 架构

```
                      ┌─ edge network ────────────────────────────┐
  host 127.0.0.1:8080 ┤  server :8080  （唯一发布端口，绑回环）   │
                      └───────────────┬───────────────────────────┘
                                      │ 同时挂在内网
                      ┌─ backend network (internal: true) ────────┐
                      │  server :8080  ←  client                  │
                      │  无外网出口，client 只在此网                │
                      └───────────────────────────────────────────┘
```

```
.
├── cmd/
│   ├── server/           # API 服务（含 healthcheck / version 子命令）
│   └── client/           # 独立 CLI：读文件 → POST → 渲染表格 / 自检
├── internal/
│   ├── api/              # HTTP 传输层：路由、限流、日志、panic 兜底
│   ├── config/           # 环境变量 → 配置（非法值直接启动失败）
│   ├── engine/           # 规则引擎（无协议知识）+ 4 个通用探针原语
│   └── model/            # 出入参类型 + 宽容解码器
├── rules/                # ★ 全部识别知识：YAML 规则（编译期 embed，可挂载覆盖）
├── examples/             # 样例输入 + 期望输出（自检基准）
├── docs/                 # 设计文档、规则 DSL 手册
├── Dockerfile            # 多阶段多 target：server / client，运行时 scratch
└── docker-compose.yml    # 两容器、两网络、健康依赖、权限收紧
```

**数据流**：`client` 读 JSON → `POST /fingerprint`（服务名 `http://server:8080`）→
`api` 解码并限流 → `engine` 按优先级跑规则 → 第一个命中的规则产出
`protocol/product/version/os_hint/confidence` → 原序返回 → `client` 渲染并统计覆盖率。

---

## 4. 规则与代码解耦（`rules/*.yaml`）

这是本项目的核心设计：**Go 代码里不出现任何协议名或产品名**。

> **代码知道"怎么读字节"，规则知道"这叫什么"。**

引擎提供 4 个**通用探针原语**（`internal/engine/primitives.go`）：

| kind | 作用 | 为什么必须用代码而不是正则 |
|---|---|---|
| `regex` | 对原始 banner 做 RE2 匹配 | 文本协议通用；RE2 线性时间，天然无 ReDoS |
| `http_header` | 抽出某个 HTTP 响应头的**值**，再交给规则正则 | 直接匹配整个 banner 会把 HTML body 里的 "Apache" 也算命中 |
| `mysql_handshake` | 解析 MySQL 握手包结构，取出 server version | 二进制协议（`J\x00\x00\x00\n8.0.32\x00`），正则无法可靠表达偏移与 NUL 终止 |
| `tls_record` | 解析 TLS record/handshake，判定是否构成 ServerHello 证据 | 同上；且要能表达"证据不足"（见 §5） |

新增一个协议 = 新增一个 YAML 文件，**不改一行 Go 代码、不重新构建镜像**：

```yaml
version: 1
rules:
  - id: memcached-stats
    protocol: Memcached
    product: Memcached
    confidence: 0.85
    priority: 200
    match:
      kind: regex
      pattern: '^STAT pid [0-9]+\r?\n'
```

```bash
# 挂载覆盖内置规则（镜像只读、无 shell 也能用）
docker compose run --rm \
  -v "$PWD/myrules:/etc/banner-fingerprint/rules:ro" \
  -e RULES_DIR=/etc/banner-fingerprint/rules \
  server serve
```

完整 DSL（字段、命名捕获组、OS 提示、优先级、置信度）见 [`docs/rules.md`](docs/rules.md)。

---

## 5. 设计决策（为什么这样做）

**① 认不出来就是 `unknown`，绝不猜。**
误报比"unknown"更糟：`unknown` 只是没结论，误报会污染下游资产库。
因此 `unknown` 的 `confidence` 恒为 `0`，`product`/`version` 恒为空串。

**② TLS 样例故意判 `unknown`（证据阈值）。**
`16 03 01 00 a5 01 00 00 a1` 只能证明"这个端口在讲 TLS"：它是 4 字节 record 头 + ClientHello 片段，
不足以确定对端软件，甚至不能证明这是服务端响应。**只有解析出完整 ServerHello 才报 `TLS`**。
这条阈值写在 `internal/engine/primitives.go` 的注释与 `docs/design.md` 里，是一个可辩护的判断，而不是漏判。

**③ 端口完全不参与判定。**
规则 schema 里没有 `ports` 字段。示例数据里 nginx 在 80/443/8443、MySQL 在 3306、TLS 在 9999——
一旦用端口做门禁，验收数据换个端口就全错。置信度也不因端口命中而加权。

**④ 置信度是显式公式，不是玄学。**

```
confidence = rule.confidence
           − 0.20   （规则命中但没提取出版本）
           − 0.05   （规则命中但没提取出产品名）
           截断到 [0.30, 0.99]；`unknown` 恒为 0
```

代入示例可精确复现题目给出的 7 个数值：Redis 无版本 `0.90 − 0.20 = 0.70`、
Pure-FTPd 无版本 `0.95 − 0.20 = 0.75`、SSH `0.95`、nginx/Apache/MySQL/ProFTPD `0.90`、Jetty `0.85`。

**⑤ `os_hint` 只报字面证据。**
`Server: nginx/1.18.0 (Ubuntu)` → `Ubuntu`；`SSH-2.0-OpenSSH_9.3 Debian-1` → `Debian`；
`Microsoft-IIS` → `Windows`（IIS 只存在于 Windows）。没有任何线索就留空，不从版本号推测发行版。

**⑥ 规则与二进制的关系：embed + 可选挂载覆盖。**
- 默认 embed 进二进制 → 运行时镜像可以是 `scratch`（无 shell、无 libc、无包管理器）。
- 需要热更新规则时挂目录 + `RULES_DIR` → 不用重建镜像。两种模式共用同一个 `engine.Load(fs.FS)`。

**⑦ 单条记录永不拖垮整批。**
解码器宽容（`port` 可以是字符串、`addr` 可以是 `host:port`、`banner` 可以是 `null`），
识别函数带 `recover` 兜底，`FuzzIdentifyNoPanic` 用随机字节证明它不会 panic。

---

## 6. "生产级"部署：硬化清单

| 维度 | 做法 | 位置 |
|---|---|---|
| 镜像体积/攻击面 | 静态链接（`CGO_ENABLED=0`）+ `scratch` 运行时，无 shell/libc/包管理器 | `Dockerfile` |
| 构建可复现 | `-trimpath`、`-buildvcs=false`、`-ldflags="-s -w"`、依赖 `vendor/`、`GOPROXY=off`（**构建期不访问任何 Go 模块代理**） | `Dockerfile` |
| 环境依赖可替换 | 构建的**唯一**外部依赖是 Go 基础镜像，且可替换：`GO_IMAGE=<registry>/golang:1.26-alpine docker compose up --build`（换镜像源或固定 digest 不用改文件） | `Dockerfile`、compose |
| 单平台构建 | 构建与运行同平台，静态链接产物；不引入交叉编译矩阵（评估与生产都只在一台机器上 `compose up`，多架构是纯增量风险） | `Dockerfile` |
| 版本可追溯 | `-X main.version=${VERSION}` 注入，`/health` 与 `server version` 可查 | `Dockerfile`、`api` |
| 健康检查 | **镜像内没有 curl**，探针是二进制自己的 `healthcheck` 子命令（`GET 127.0.0.1:$PORT/health`，2s 超时） | `Dockerfile`、`cmd/server` |
| 启动依赖 | `depends_on: {condition: service_healthy}`，client 真的要等 server 探针通过 | `docker-compose.yml` |
| 运行权限 | `user: 10001:10001`、`cap_drop: ALL`、`no-new-privileges`、`read_only` 根文件系统、`tmpfs /tmp`（`noexec,nosuid`）、`init: true` | `docker-compose.yml` |
| 资源与稳定性 | `pids_limit`、`mem_limit`、`cpus`、`stop_grace_period`、优雅停机（SIGTERM → 排空 in-flight） | compose + `cmd/server` |
| 日志 | JSON 结构化日志 + `X-Request-Id` 贯穿；`json-file` 驱动带 `max-size/max-file` 轮转 | `api`、compose |
| 网络收敛 | 只有一个发布端口且绑 `127.0.0.1`；client 只挂 `internal: true` 网络，**无外网出口**；服务发现用 compose DNS `server:8080` | compose |
| 输入边界 | body 上限、item 数量上限、banner 截断 64KB、`ReadHeaderTimeout`/`ReadTimeout`/`WriteTimeout`/`IdleTimeout`、`MaxHeaderBytes` | `api`、`server` |
| 配置失败要响 | 环境变量非法（如 `PORT=abc`、`LOG_LEVEL=verbose`）直接启动失败，不静默降级 | `internal/config` |
| 规则加载失败要响 | YAML 字段拼错（`KnownFields(true)`）、正则编译失败、id 重复 → 启动失败并指出文件:规则 id | `engine.Load` / `engine.compile` |
| CI 就绪 | `make check` = gofmt + `go vet` + `go test ./...`；`make fuzz` 跑 15s fuzz；镜像构建与端到端校验见 §7 | `Makefile` |

---

## 7. 测试

| 类型 | 覆盖内容 |
|---|---|
| `internal/engine` 单测 | 题目 20 条样例逐条断言（协议/产品/版本/OS/置信度全部精确匹配）；SMTP 不被误判为 FTP；端口不影响结论；坏规则集启动即报错 |
| `internal/engine` fuzz | 随机字节 + 任意端口 → 断言不 panic、`protocol` 非空、`confidence ∈ [0,1]`、unknown 一律空值零置信 |
| `internal/api` 单测 | 数组/信封/单对象、字段宽容、空批次返回 `[]`、400/405/413 语义、请求不因垃圾数据 500 |
| `internal/model` 单测 | 三种请求形态、别名与类型宽容、JSON 字段契约漂移检测 |
| 端到端 | `client -expected examples/expected_output.json`：20 条全对才算通过（CI 里也在跑） |

```console
$ go test ./...
ok  github.com/esp-oss/banner-fingerprint/internal/api
ok  github.com/esp-oss/banner-fingerprint/internal/engine
ok  github.com/esp-oss/banner-fingerprint/internal/model
```

---

## 8. 样例数据的实际结果

| endpoint | protocol | product | version | os_hint | conf |
|---|---|---|---|---|---|
| 1.2.3.4:22 | SSH | OpenSSH | 8.9p1 | Ubuntu | 0.95 |
| 1.2.3.5:80 | HTTP | nginx | 1.24.0 | | 0.90 |
| 1.2.3.6:443 | HTTP | Apache | 2.4.57 | | 0.90 |
| 1.2.3.7:3306 | MySQL | MySQL | 8.0.32 | | 0.90 |
| 1.2.3.8:6379 | Redis | Redis | | | 0.70 |
| 1.2.3.9:21 | FTP | ProFTPD | 1.3.7 | | 0.90 |
| 1.2.3.10:8080 | HTTP | Jetty | 9.4.51 | | 0.85 |
| 1.2.3.19:9999（TLS 片段） | unknown | | | | 0.00 |
| 1.2.3.23:12345（`QUIT`） | unknown | | | | 0.00 |

完整 20 条见 [`examples/expected_output.json`](examples/expected_output.json)。

---

## 9. 已知边界

- 只根据**单条 banner** 判定，不做多轮交互探测（示例数据也没有给交互能力）。真实资产测绘里，MySQL/Redis 的版本常常需要主动探测才能拿到，这里如实留空而不是猜。
- `version` 只提取、不联网核对 CVE 库；没有做版本号语义排序。
- HTTPS 在 443 上仍报 `HTTP`（因为 banner 就是明文 HTTP 响应），这是**有意为之**：`protocol` 描述的是"这是什么协议"，而不是"端口通常是什么服务"。
- HTTP banner 允许**没有状态行**（`Server: nginx/1.24.0` 单独出现也认），但没有 `Server` 头、也没有状态行时无法判定为 HTTP。
- 规则集当前 34 条，覆盖 SSH / HTTP / MySQL / Redis / FTP / SMTP / IMAP / POP3 / TLS；新增协议只需加 YAML（见 §4）。
