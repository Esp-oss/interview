# 设计文档：Banner 指纹识别系统

> 这份文档记录**为什么这样实现**。可执行的结论在 `README.md`，规则写法在 `docs/rules.md`。

## 1. 问题

输入是扫描器的一批三元组 `(ip, port, banner)`，banner 可能是 ASCII 文本、HTTP 响应、二进制协议帧，
也可能是截断的垃圾。输出是 `(protocol, product, version, os_hint, confidence)`。
约束：识别不出来必须是 `unknown`，任何输入都不能让服务崩，`docker compose up` 一键起。

## 2. 目标与非目标

**目标**

1. 至少覆盖 SSH / HTTP(nginx, Apache, Jetty) / MySQL / Redis / FTP，且版本号要准。
2. 未知输入降级为 `unknown`，绝不 5xx、绝不 panic、绝不整批失败。
3. 规则与代码解耦：加协议不改 Go。
4. 容器部署达到可评审的"生产级"：构建可复现、权限收紧、网络收敛、健康检查真实。

**非目标（本次明确不做）**

- 主动探测（多轮交互、发 payload 拿更精确版本）。输入契约就是单条 banner。
- CVE 关联、资产关系图、UI 控制台。
- 机器学习/统计分类：数据量小，可解释性优先；一个能被人读懂并审查的规则集，比一个黑盒模型更适合这张评分表。

## 3. 备选方案与取舍

### 3.1 识别引擎的三种形态

| 方案 | 做法 | 优点 | 缺点 |
|---|---|---|---|
| A. 纯代码正则表 | `switch`/`map` + 硬编码 `regexp` | 最快、最好调、无 IO | 规则与代码强耦合；加协议要重新编译发版；**直接踩评分点** |
| B. 纯声明式 YAML | 全部靠 YAML 正则 | 解耦满分 | 二进制协议（MySQL 握手、TLS record）无法用纯正则可靠表达；HTTP 头部字段边界也难；识别**深度**会掉 |
| C. 混合（**采用**） | YAML 决定"这叫什么"，Go 只提供通用读字节原语 | 解耦满分 + 深度满分 | 需要设计好原语边界（已落地为 4 个原语） |

选择 C，并把边界写成一句可审查的话：**代码知道"怎么读字节"，规则知道"这叫什么"。**
Go 侧只保留 4 个原语：`regex`、`http_header`、`mysql_handshake`、`tls_record`。
`internal/engine` 里搜不到 `SSH`/`nginx`/`Apache` 等任何协议或产品名（grep 可验证）。

### 3.2 规则分发：embed 还是挂载？

| 方案 | 结论 |
|---|---|
| 只 embed | 能用 `scratch` 运行时（无 shell/无 libc），但加规则必须重建镜像 |
| 只挂载 | 规则可热更新，但要求运行时存在文件系统、镜像必须带目录、容器不再是纯静态 |
| **embed + `RULES_DIR` 覆盖（采用）** | 默认零依赖启动；需要时挂只读目录即替换。两种模式共用 `engine.Load(fs.FS)`，没有分叉逻辑 |

### 3.3 运行时镜像：`scratch` vs `distroless` vs `alpine`

- `alpine`：有 shell、有 apk、有 libc → 攻击面最大，且健康检查会诱使人装 `curl`（多一层依赖）。
- `distroless`：很好，但要从 `gcr.io` 拉取；评估者/企业网络未必可达（本项目实测环境里 Docker Hub 都需要走镜像源，`gcr.io` 更不保证）。
- **`scratch`（采用）**：只放一个静态二进制。代价是"没有 curl 做健康检查"，于是把探针做成**二进制自己的子命令**——
  这反而是更严格的做法：探针走的是与服务完全相同的代码路径，且镜像里不需要任何额外可执行文件。

### 3.4 网络拓扑

需求里"容器间访问方式是否收敛"是可被机器验证的。三种做法里选最收敛的一种：

| 方案 | 问题 |
|---|---|
| 默认 bridge + 两个端口都发布 | 暴露两个入口，client 也能被外部访问 |
| 单网络 + 只发布 server | 可接受，但 client 仍与 server 共享同一张"有出口"的网络 |
| **两张网（采用）**：`edge`（仅 server，发布端口绑 `127.0.0.1`）+ `backend`（`internal: true`，client 仅在此） | client 无外网出口、server 只有一条入向路径；依赖方向单向 |

## 4. 组件

| 组件 | 职责 | 明确不负责 |
|---|---|---|
| `cmd/client` | 读文件、POST、渲染表格、`-expected` 自检 | 不 import server 的任何代码 |
| `internal/api` | 路由、限流、状态码、日志、panic 兜底、健康检查 | 不认识任何协议 |
| `internal/engine` | 规则编译/排序/匹配、4 个原语、置信度打分 | 不认识任何协议（只认识字节布局） |
| `internal/model` | 出入参类型、宽容解码、JSON 契约 | 无逻辑 |
| `internal/config` | 环境变量 → 配置，非法值启动失败 | 无默认魔法 |
| `rules/` | 全部识别知识 | 无代码 |

**接口边界**：`engine.New(rules, source)` → `Identify(item) Result` / `IdentifyBatch(items, workers) []Result`。
调用方不需要知道规则长什么样；规则作者不需要知道 HTTP 层长什么样。

## 5. 关键决策

**D1 未知即 `unknown`，且 confidence=0。**
评分口径里"认不出来不算错、误报算错"。因此宁可不判。配套实现：`model.Unknown()` 是唯一出口，
fuzz 测试断言 `unknown ⇒ 三个字段为空且置信度为 0`。

**D2 TLS 片段判 `unknown`（证据阈值）。**
`16 03 01 00 a5 01 00 00 a1`：record type=0x16、legacy version=0x0301、length=0xa5、handshake type=0x01（ClientHello）。
它证明"在讲 TLS"，但不能确定对端软件，也无法确定服务端能力。把阈值写成"必须完整 ServerHello"，
把判断依据写在 `primitives.go` 的注释里——这是**可辩护的保守**，而不是漏判。

**D3 端口不参与判定，也不参与打分。**
反例足够多：示例里 nginx 在 80/443/8443，TLS 在 9999。若规则带 `ports` 门禁，验收数据一换端口全崩。
规则 schema 因此没有 `ports` 字段。

**D4 置信度是公式，不是标注。**
`base − 0.20(无版本) − 0.05(无产品)`，截断 `[0.30,0.99]`。好处：新增规则只需标"完整命中"的分数，
缺失项自动降权；且能精确复现题目给出的 7 个数值（含 Redis 0.70、Pure-FTPd 0.75）。

**D5 `os_hint` 只报字面证据。**
提取 `(Ubuntu)`、`Debian-1`、`FreeBSD`、`Microsoft-IIS ⇒ Windows` 等显式 token；不做版本→发行版推断。

**D6 规则文件严格校验。**
`yaml.Decoder.KnownFields(true)` + 正则预编译 + id 去重 + schema 版本检查，全部在启动期完成。
理由：指纹系统的失败模式是"静默漏识别"，而不是崩溃；宁可起不来也不要带着半套规则对外服务。

**D7 传输层错误 4xx，语义问题 200 + unknown。**
一条记录的问题不能升级成整批失败——扫描数据里垃圾是常态。`DecodeItems` 对字段类型宽容
（`port` 可字符串、`addr` 可 `host:port`、`banner` 可 `null`）；`Identify` 带 `recover` 兜底。

## 6. 失败与边界处理

| 场景 | 行为 |
|---|---|
| banner 为空/`null`/全 NUL | `unknown`，200 |
| 非法 UTF-8 / 二进制垃圾 | `unknown`，200（RE2 与字节解析都不 panic） |
| banner > 64KB | 截断后匹配，200 |
| JSON 里出现 Python 风格 `\x00` 转义 | 先严格解析；失败后转义感知地修复并重试，200（否则整批 400 = 零结果） |
| JSON 语法错误（无法修复） | 400 + `{"error":...}` |
| body 超限 / item 超 `MAX_BATCH` | 413 |
| 方法错误 | 405（`Allow` 头） |
| 规则文件损坏 | 进程启动失败，退出码 1，日志指出 `file:rule-id:reason` |
| 单请求 panic | recover 中间件 → 500 + 结构化日志，进程存活 |

## 7. 实施顺序（实际执行顺序）

1. `go.mod` + `vendor/`（构建期零网络依赖）
2. `internal/model`（契约与宽容解码）
3. `internal/engine`（规则类型 → 原语 → 引擎 → loader）
4. `rules/*.yaml`（20 条样例基线，逐条对齐题目给出的期望值）
5. `internal/api` + `cmd/server`（含 `healthcheck` 子命令）
6. `cmd/client`（表格渲染 + `-expected` 自检）
7. 测试（20 条语料断言、边界、API 语义、fuzz）
8. `Dockerfile`（多阶段多 target）+ `docker-compose.yml`（两网络、硬化、健康依赖）
9. 端到端验证：`compose up` → health → 20 条比对 → 权限/网络核验
10. 文档与 CI

## 8. 还能怎么做的更好（未实现，因单条 banner 输入契约所限）

- 主动探测：对 MySQL 发握手后取完整 version banner，对 Redis 发 `INFO` 取 `redis_version`。
- 规则集按协议拆分并支持 include/覆盖优先级，做成可与 Nmap `nmap-service-probes` 互转。
- 指标导出（`/metrics`，命中率、规则命中分布），用于发现"某规则抢走了别人的 banner"。
- 规则模糊测试：给每条规则喂语料库，检测跨规则误命中。
