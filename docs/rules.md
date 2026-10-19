# 规则 DSL 手册

规则文件是**全部**识别知识所在：协议名、产品名、版本模式、OS 线索、置信度。
`internal/engine` 里没有任何协议名；`rules/*.yaml` 里没有任何字节偏移。

- 文件位置：`rules/*.yaml`（编译期 `go:embed` 进二进制）
- 运行时覆盖：设置 `RULES_DIR=/some/dir`，该目录下的 `*.yaml` **替换**内置规则集（不合并）
- 加载是严格的：字段名拼错、正则编译失败、id 重复、`version != 1` 都会让服务**启动失败**并指出 `文件:规则id`

## 1. 文件结构

```yaml
version: 1          # 必需，当前只支持 1
rules:
  - id: ssh-openssh
    protocol: SSH
    product: OpenSSH
    confidence: 0.95
    priority: 200
    match:
      kind: regex
      pattern: '^SSH-(?:[0-9]+\.[0-9]+)-(?P<product>OpenSSH)[-_](?P<version>[^\s]+)'
    os_patterns:
      - {pattern: 'Ubuntu', value: Ubuntu}
    note: '给人看的说明，不参与匹配'
```

## 2. 字段

| 字段 | 必需 | 说明 |
|---|---|---|
| `id` | ✔ | 全局唯一，稳定标识；错误信息用它定位 |
| `protocol` | ✔ | 命中后输出的协议族名（`SSH` / `HTTP` / `MySQL` / …）。**这是唯一出现协议名的地方** |
| `product` | | 默认产品名；若正则里有 `(?P<product>…)` 捕获组，捕获值优先 |
| `confidence` | ✔ | 该规则**完整命中**（产品与版本都拿到）时的分数，`(0,1]` |
| `priority` | | 整数，越大越先评估；同优先级按 id 字典序。**首个命中即返回** |
| `match` | ✔ | 匹配指令，见 §3 |
| `os_patterns` | | `[{pattern, value}]`，字面命中即作为 `os_hint`；自上而下首个命中生效 |
| `note` | | 注释，加载时忽略 |

## 3. `match`：四个通用探针原语

```yaml
match:
  kind: regex | http_header | mysql_handshake | tls_record
  pattern: '<RE2 正则>'
  header: Server        # 仅 http_header 用，缺省 Server
```

### `regex`
对**原始 banner** 做匹配。RE2 语法（无回溯、线性时间、无 ReDoS 风险），支持 `\x00` 等字节转义。

### `http_header`
先抽出指定 HTTP 响应头的**值**（大小写不敏感、容忍 `\r\n` 与 `\n`、只在头部块内查找），再让 `pattern` 匹配该值。
用途：避免把 HTML body 里的产品名当成指纹。

接受两种捕获形态，行为一致：

```text
HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nDate: ...   ← 完整响应（按状态行定位）
Server: nginx/1.24.0\r\nDate: ...                      ← 状态行被 scanner 截掉
```

第二种只在前导行**结构上都是 `Name: value`** 时才成立，因此纯文本里出现 `Server: nginx` 不会被当成 HTTP；
头部块在第一个空行或第一个非头部行结束，所以响应体里即使有 `Server:` 也不会被当作证据。

```yaml
match:
  kind: http_header
  header: Server
  pattern: '^(?i:nginx)(?:/(?P<version>[^\s(]+))?(?:\s|$)'
```

### `mysql_handshake`
解析 MySQL 初始握手包（`3 字节长度 + 1 字节序号 + 0x0a + NUL 结尾版本串`），把**版本串**交给 `pattern`。
对截断 / 缺包头的 banner 有兜底扫描；返回的不是版本形态的串就不算命中。

```yaml
match:
  kind: mysql_handshake
  pattern: '^(?P<version>[0-9]+\.[0-9]+\.[0-9]+)'
```

### `tls_record`
只有当 banner 里存在**完整 ServerHello**（record type `0x16`、handshake type `0x02`、长度足够）时才产出证据，
值是归一化版本标签（`TLS1.2` 等）。裸的 `16 03 01 …` 会话片段**不**产出证据 → 结果是 `unknown`。

```yaml
match:
  kind: tls_record
  pattern: '^(?P<version>TLS1\.[0-3]|SSL3\.0)$'
```

## 4. 命名捕获组

| 组名 | 含义 |
|---|---|
| `(?P<version>…)` | 版本号。**没有捕获到 → 置信度 −0.20** |
| `(?P<product>…)` | 产品名，覆盖规则级 `product`。**最终产品名为空 → 置信度 −0.05** |
| 其它组 | 允许，仅作正则结构用途（如 `(?P<protover>)`） |

## 5. 置信度

```
score = rule.confidence
      − 0.20  （未提取到 version）
      − 0.05  （未确定 product）
      截断到 [0.30, 0.99]；完全未命中 → protocol="unknown", confidence=0
```

因此 `confidence` 应当填"产品与版本都确认时"的分数。例：

| 规则 | base | 命中时的实际情况 | 最终 |
|---|---|---|---|
| `ssh-openssh` | 0.95 | 产品+版本 | 0.95 |
| `redis-error` | 0.90 | 产品命中，Redis 无版本 | **0.70** |
| `ftp-pureftpd` | 0.95 | 产品命中，问候语常无版本 | **0.75** |
| `http-generic` | 0.80 | 只有协议，无产品无版本 | 0.55 |

## 6. 编写一张新规则（检查表）

1. `id` 用 `协议-产品` 小写短横线风格，全局唯一。
2. 选 `kind`：文本 → `regex`；HTTP `Server` 头 → `http_header`；二进制结构 → 对应原语。
3. 正则**锚定开头**（`^`），避免在长 banner 中间随意命中。
4. 版本用 `(?P<version>…)` 捕获；产品名若能从 banner 直接取，用 `(?P<product>…)`。
5. `priority` 要高于同类兜底规则（本项目约定：具体产品 190–200，协议兜底 ≤ 20）。
6. `confidence` 按"完整命中"打分，公式会自动扣减缺失项。
7. 有 OS 线索才写 `os_patterns`，**不要用版本号推测发行版**。
8. 跑 `go test ./...`：`TestIdentifyCorpus` 会保护既有 20 条样例不被新规则破坏
   （典型回归：新加的宽松规则抢走了 nginx 的 banner）。

## 7. 内置规则一览

| 文件 | 覆盖 |
|---|---|
| `ssh.yaml` | OpenSSH（含发行版注释）、通用 SSH 实现 |
| `http.yaml` | nginx / OpenResty / Apache / Jetty / Apache-Coyote / IIS / Caddy / lighttpd / gunicorn / Cloudflare、HTTP 协议兜底 |
| `mysql.yaml` | MySQL 握手包、MariaDB（`5.5.5-` 兼容前缀） |
| `redis.yaml` | `-ERR`/`-NOAUTH`/`-WRONGTYPE`… 、`+PONG`、`+OK`、`$`/`*`/`:` RESP 帧 |
| `ftp.yaml` | ProFTPD / vsFTPd / Pure-FTPd / FileZilla / Microsoft FTP、FTP 兜底 |
| `mail.yaml` | Postfix / Exim / Exchange、SMTP / IMAP / POP3（优先级高于 FTP 兜底，防止 220 撞车） |
| `tls.yaml` | 完整 ServerHello → `TLS` |
