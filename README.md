# proctrace

实时查看一个进程及其全部子进程打开了哪些文件；面向 AI agent 场景，可按
**工作区白名单 + 敏感路径黑名单**标记未授权文件访问，并告警访问受保护进程。

- **macOS + Linux**，Python 3.9+，唯一运行时依赖 `psutil`
- **无 root 也能用**：普通用户即可观察自己有权读取的进程
- **Agent 文件审计**：工作区外的文件、`~/.ssh`/`.env`/浏览器数据等敏感路径会标红告警
- **可选内核事件流**：macOS `eslogger` / Linux `fanotify`，补齐轮询漏掉的短命 open（Linux 还能到 read/write）
- **网络与数据库**：连接元数据、Unix socket、数据库端口分类、SQLite/DuckDB 文件读写
- **SQL 级审计**：PostgreSQL/MySQL 审计日志 + SQLite shim；SQL 自动脱敏、风险分级
- **实时 TUI**：进程树 + 当前文件/网络 + 事件流，键盘过滤/暂停/导出
- **JSONL / 一次性快照**：方便接入日志、脚本或其它 UI
- **性能可控**：FD 扫描和子进程发现分离，默认每 1 秒才重新发现进程树；
  1 个进程 / 40 个 fd 的实测扫描约 1.8ms（详见"性能"）

> 重要：路径审计和 `protected` 都是**告警**，不是强制拦截；proctrace 不会读取文件内容，
> 只看“哪个进程打开了哪个路径、以什么模式打开”。macOS 无特权模式下无法观测
> `task_for_pid`/Mach 内存访问，详见"能力矩阵"。

---

## 作为 DeepSeek Harness 插件

本目录同时是一个 **Host-only DSH bundle**：`package.json` 中的
`dsh.bundle.patch` 指向 `cordis.patch.yml`，安装后会在 DSH 中注册 `proctrace`
工具。它只使用 Node 内置模块，不导入 DSH 客户端包，也不需要重新构建 Web UI。

在对话中可以让 agent：

- `start`：启动监控；不传 `pid`/`name` 时默认监控 **当前 DSH Host 及其子进程**，
  因此 bash 等工具启动的 agent 子进程会进入进程树。
- `status`：查看监控状态、事件计数和完整 JSONL 日志路径。
- `events`：读取内存环形缓冲区中的最近事件，支持 `important_only`。
- `stop`：停止监控；插件卸载时也会自动停止自己启动的所有监控。
- `protect_names` / `exclude_names`：启动时可配置受保护进程名和排除进程名（glob）。

推荐显式传 `workspace`（授权工作区绝对路径）；否则使用目标进程的 cwd。默认启用
`audit`/`network`/`database`，`kernel` 需要 root（macOS 还需要 Full Disk Access）
且默认关闭。事件不会持久化在 DSH 内，但每个监控都会写一份
`$TMPDIR/dsh-proctrace/<monitor-id>.jsonl`。

安装/更新（先克隆到本机，再让 DSH 的 `plugin_manager` 链接这个目录）：

```bash
git clone https://github.com/tiansy9981/dsh-proctrace.git
# 通过 DSH 的 plugin_manager：action=install_bundle
# target=/absolute/path/to/dsh-proctrace
```

插件没有独立侧边栏面板；结果通过对话中的工具卡片展示。完整参数、限制和验证方式见
[`docs/DETAIL.md`](docs/DETAIL.md)。

---

## 快速开始

```bash
git clone https://github.com/tiansy9981/dsh-proctrace.git
cd dsh-proctrace
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
./proctrace doctor                 # 检查平台、权限、后端、TTY
./proctrace watch --pid 1234       # 实时 TUI，含子进程
./proctrace watch --name 'python*' # 按进程名选择；多个匹配选最新启动的
./proctrace watch --pid 1234 --interval 0.2 --all-types

# 网络连接 + 数据库端点/文件
./proctrace watch --pid 1234 --network --database

# 内核事件流（需要 root；macOS 还需要终端 Full Disk Access）
sudo ./proctrace watch --pid 1234 --kernel --network --database

# 启动并审计新 agent；SQLite SQL 需要此模式
./proctrace run --audit --workspace /absolute/project \
  --db-audit sqlite:/tmp/proctrace-sqlite.sock -- claude

# 读取 PostgreSQL / MySQL 审计日志
./proctrace watch --pid 1234 \
  --db-audit postgresql:/var/log/postgresql/postgresql-16-main.log \
  --db-audit mysql:/var/lib/mysql/general.log \
  --log audit.jsonl
```

面向 AI agent（Claude Code / Codex CLI / 自建 agent 等）：

```bash
# 按进程名选择；自动包含它启动的 node/python 子进程
./proctrace watch --name 'claude' --audit --workspace ~/projects/my-app --interval 0.2

# 按命令行正则选择，适合 python -m my_agent 这类入口
./proctrace watch --cmdline 'codex|my_agent' --audit --workspace . --interval 0.2
```

`--name` 匹配的是进程名（comm），不一定等于 agent 的品牌名；找不到时用
`--cmdline` 搜索完整命令行。启用 `--audit` 后，目标进程打开工作区外的文件，
或打开 `~/.ssh`、`.env`、浏览器 profile 等敏感路径时，会产生红色 `VIOLATION`
事件；TUI 中按 `v` 可以直接查看选中进程当前打开的文件，违规项同样标红。

不进入 TUI，直接输出事件（适合管道/日志）：

```bash
./proctrace watch --pid 1234 --no-tui
./proctrace watch --pid 1234 --no-tui --json
./proctrace watch --pid 1234 --duration 10 --json --log events.jsonl
```

一次性快照：

```bash
./proctrace snapshot --pid 1234
./proctrace snapshot --pid 1234 --json > snapshot.json
```

生成配置文件：

```bash
./proctrace init --path proctrace.json
# 或者使用 agent 审计模板：
cp examples/agent-audit.json proctrace.json
```

手动安装（如果 `.venv` 不存在）：

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/pip install -e .
./scripts/build_shim.sh          # SQLite SQL 级监控需要
# 或者不建 venv：
python3 -m pip install 'psutil>=5.9,<8'
PYTHONPATH=src python3 -m proctrace doctor
```

`./proctrace` 是一个很薄的 shell 启动器：优先使用 `.venv`，没有则回退到
`python3`，并检查 `psutil` 是否可导入。

---

## TUI 按键

| 按键 | 作用 |
| --- | --- |
| `q` | 退出 |
| `space` | 暂停 / 恢复扫描 |
| `↑` `↓` / `k` `j` | 选择进程 |
| `Enter` | 只看选中 PID 的事件 |
| `Esc` | 清除过滤条件 |
| `f` | 过滤循环：all → opens → alerts |
| `/` | 文本过滤（路径、进程名、详情） |
| `[` `]` | 向前 / 向后滚动事件历史 |
| `c` | 清空事件列表（不影响监控） |
| `e` | 导出当前快照 JSON 到当前目录 |
| `v` | 在事件流 / 选中进程的当前文件列表之间切换 |
| `n` | 在事件流 / 选中进程的网络连接之间切换 |
| `a` | 显示/隐藏 socket、pipe、anon fd |
| `+` `-` | 加快 / 放慢轮询 |
| `?` | 帮助 |

TUI 是纯 ANSI + `termios` 实现，不依赖 ncurses。原因：macOS 13 自带
Python 3.9 的 `curses` 在 `initscr()` 后可能直接 SIGSEGV；换用 ANSI
渲染后既避开该问题，也让 macOS/Linux 行为一致。

一个实际帧（110×24，已去除 ANSI 颜色码）：

```text
proctrace  LIVE/AUDIT  target=claude 67884  backend=macos-libproc  0.20s
procs=1    fds=2    events=2     alerts=1    scan=16.9ms (max 16.9)  filter=all
PID     PPID   NAME                   FD |TIME      PID    PROCESS          EVENT  DETAIL
67884   67882    Python                2 |20:07:02 67884  Python         OPEN   4    ...ptpreview/outside.txt
                                         |20:07:02 67884  Python         VIOL outside  ...preview/outside.txt
                                         |
                                         |
                                         |
                                         |
                                         |
                                         |
                                         |
                                         |
                                         |
                                         |
                                         |
                                         |
                                         |
                                         |
                                         |
                                         |
                                         |
q quit  space pause  v files  n net  f filter  / search  enter pid  [ ] scroll  c clear  e export  a types  …
audit=on workspace=/tmp/ptpreview/ws deny_rules=0 outside=on
```

---

## 配置

自动搜索顺序：

1. `--config PATH`
2. `$PROCTRACE_CONFIG`
3. `./proctrace.json`
4. `~/.config/proctrace/config.json`

JSON 格式（不支持注释；`_comment` 字段会被忽略）：

```json
{
  "interval": 0.5,
  "tree_refresh": 1.0,
  "policy_refresh": 2.0,
  "max_events": 5000,
  "max_processes": 2048,
  "show_initial": false,
  "show_nonfile": false,
  "protected": [
    {"pid": 1234},
    {"name": "1Password"},
    {"name": "ssh-agent"},
    {"exe": "/usr/bin/security", "uid": 501},
    {"cmdline": "python.*secret"}
  ],
  "exclude": [
    {"name": "WindowServer"},
    {"name": "kernel_task"}
  ],
  "audit": {
    "enabled": true,
    "workspaces": ["/Users/me/projects/my-app"],
    "allow_paths": ["~/scratch/**"],
    "deny_paths": ["~/.zsh_history"],
    "ignore_paths": [],
    "outside_workspace": true,
    "use_defaults": true,
    "include_stdio": false
  },
  "network": {
    "enabled": true,
    "include_unix": true,
    "db_ports": {},
    "ignore_ports": []
  },
  "database": {
    "enabled": true,
    "sqlite_suffixes": [".db", ".sqlite", ".sqlite3", ".duckdb"]
  },
  "kernel": {
    "enabled": false,
    "mark_paths": ["/"],
    "include_writes": true
  },
  "db_audit": {
    "enabled": true,
    "from_start": false,
    "sources": [
      {"system": "postgresql", "path": "/var/log/postgresql/postgresql-16-main.log"},
      {"system": "mysql", "path": "/var/lib/mysql/general.log"}
    ],
    "sensitive_tables": ["users", "credentials", "tokens", "secrets"]
  }
}
```

### 规则语义

每条 `protected` / `exclude` 规则内部的字段是 **AND**：

- `pid`：精确 PID
- `create_time`：只能和 `pid` 一起使用；用于防止 PID 复用误判
- `name`：进程名 glob（`*`、`?`、`[]`），大小写敏感
- `exe`：可执行文件完整路径 glob
- `cmdline`：对 `" ".join(cmdline)` 做 Python 正则搜索
- `uid`：真实 UID

`protected` 的进程会被标记为 `P`，并且 **proctrace 不会去枚举它的 fd**
（避免监控工具本身去打开受保护进程）。它的子进程仍会被监控。
`exclude` 的进程及其整棵子树都不会被扫描，适合排除噪音进程。

### 内核事件流（可选，高精度）

轮询永远可能漏掉短命 open；`--kernel` 打开平台内核后端：

- **macOS**：Apple 自带 `eslogger`（EndpointSecurity）采集 `open` / `close` / `write`（没有 read 事件）。
  需要 `sudo`，且终端或运行进程在“系统设置 → 隐私与安全性 → 完全磁盘访问权限”
  中被授权。eslogger 是 Apple 的调试工具，不是稳定 API，输出 schema 可能随系统变化。
- **Linux**：fanotify 采集 `open` / `read` / `close` / `write`，需要 root；
  默认标记 `/`，可用 `--kernel-mark /path` 指定，若目标工作区在独立挂载点需额外标记。
- 内核事件流会**抑制重复的轮询文件事件**；如果 eslogger 退出或 fanotify 失败，
  会自动回退到轮询（可能重新出现漏报）。
- 事件仍按**当前已知进程树 PID**过滤；在 `tree_refresh` 之前出现并退出的极短子进程
  可能漏掉。要覆盖这种 fork/exec 竞赛，需要订阅 ESF fork/exec 事件或使用 eBPF
  cgroup 过滤，当前版本没有做。
- 当前文件列表仍由轮询维护，所以“当前打开的文件”不是内核快照；事件流才是。
- 网络连接仍然通过 psutil 轮询，因为 macOS ESF 没有公开的 IP 网络事件；
  Linux 的内核网络采集尚未接入。
- 这些后端在当前环境没有 root，**未做真实内核运行验证**；只有解析器和集成测试，
  首次使用请先用一个短命 `cat`/SQLite 进程验证。
- `sudo` 后 `HOME` 可能变成 root 的家目录；配置/工作区/日志请使用**绝对路径**，
  或者用 `sudo -E` 保留环境（是否允许取决于 sudoers）。

### 文件路径审计（AI agent 场景）

`audit` 段启用后，每个新打开的普通文件都会按以下优先级判断：

1. `ignore_paths`：命中则完全忽略；
2. `deny_paths`：命中则 `denied_path`；
3. 是否在任一 `workspaces` 内：是则允许；
4. `allow_paths`：命中则允许（例如系统库、缓存）；
5. `outside_workspace=true` 且以上都不匹配：`outside_workspace`。

`use_defaults=true` 会内置一组放行规则（`/usr`、`/System`、`/Library`、
临时目录、`~/.cache` 等）和敏感规则（`~/.ssh`、`~/.aws`、`~/.gnupg`、
浏览器 profile、`.env`、`*.pem`、agent 凭证等）。规则源码在
[src/proctrace/pathpolicy.py](src/proctrace/pathpolicy.py)，可以按需增删。

几个容易踩的点：

- **默认工作区是目标进程的 cwd**。GUI agent 的 cwd 可能是 `/`，这时请显式传
  `--workspace`；检测到 `/` 或 home 时会给出 warning。
- `--workspace .` 按**当前 shell 的 cwd**展开，不是按目标进程 cwd。
- `deny_paths` 优先于 workspace 和 `allow_paths`；如果要放行一个敏感文件，
  请用 `ignore_paths` 或 `use_defaults=false`。
- `--no-default-audit-paths` 关闭内置放行/敏感规则，只按你给的规则判断；
  适合测试或严格白名单。
- 路径会做 `~`/环境变量展开和 `realpath` 归一化；符号链接按最终路径判断。
- 只有普通文件/目录参与路径审计；socket、pipe、anon fd 不参与。
- 默认忽略 fd 0/1/2（stdin/stdout/stderr），避免把启动器重定向的日志当成 agent
  的越权访问；需要时加 `--audit-stdio`。
- 只覆盖**目标进程树**。被 launchd/IDE/XPC 拉起的独立进程如果 reparent 到树外，
  需要单独用 `--pid`/`--name` 监控，或改用系统级事件采集。

### 网络与数据库

网络监控（`--network`）是**连接元数据**，不是 payload：

- 每个被监控 PID 的 TCP/UDP/Unix socket；
- 本地/远端地址、端口、状态、fd；
- 常见数据库端口自动标记（PostgreSQL/MySQL/Redis/MongoDB/MSSQL/Oracle/
  ClickHouse/Elasticsearch 等），可用 `--db-port 5432:postgresql` 扩展；
- 不会解密 TLS，也不会读取请求/响应内容。

`--database` 会同时启用网络连接监控（用于识别 DB 端口/Unix socket），
并提供两类可核验的事件：

1. **`db_connect` / `db_close`**：到数据库端口的连接；同一路径的 TCP 连接
   不代表 SQL 语义。
2. **`db_file`**：SQLite / DuckDB 等本地文件的打开和读/写操作。Linux 内核模式
   可以从 fanotify 的 `FAN_ACCESS`/`FAN_CLOSE_WRITE` 区分 read/write；macOS 的
   libproc 通常拿不到 mode，只能标为 `unknown`。

**SQL 语句级（SELECT/INSERT/UPDATE）不在内核能力范围内。** 要拿到语句级事件，
必须接入数据库自身的审计/general log（PostgreSQL `pgaudit`、MySQL general log）
或部署数据库代理。本版本通过下一节的 `db_audit` 读取这些日志，并对 SQL 脱敏、
分级；不会从网络流量里猜 SQL。

### 数据库审计日志接入（SQL 级）

仅靠文件/网络事件看不到 SQL；`db_audit` 直接读取数据库审计日志，并输出
**脱敏后的 SQL + 操作类型 + 风险等级 + 客户端端点**：

```bash
# PostgreSQL log_statement=all / pgaudit、MySQL general log
./proctrace watch --pid <PID> \
  --db-audit postgresql:/var/log/postgresql/postgresql-16-main.log \
  --db-audit mysql:/var/lib/mysql/general.log \
  --log audit.jsonl

# 从日志开头回放（默认只看新行）
./proctrace watch ... --db-audit-from-start
```

日志要求：PostgreSQL 设置 `log_statement=all`（或启用 `pgaudit`），MySQL 设置
`general_log=ON`；日志需要对运行 proctrace 的用户可读。PostgreSQL 建议在
`log_line_prefix` 中加 `%r`（客户端 host:port），用于把 SQL 关联到 agent PID。

日志事件形如：

```json
{"kind":"db_query","pid":4242,"service":"postgresql","severity":"high",
 "reason":"destructive_ddl",
 "db":{"system":"postgresql","operation":"DROP","risk":"high","reason":"destructive_ddl",
       "sql":"DROP TABLE users","database":"prod","db_user":"app",
       "client_host":"10.0.0.5","client_port":54321,"agent_pid":4242}}
```

关联方式：PostgreSQL 的 `log_line_prefix` 使用 `%r`（客户端 host:port）时，可以和
`--network` 捕获的客户端连接精确匹配到 agent PID；MySQL 只有 host 时，仅在唯一
匹配时关联，否则 `agent_pid` 为空但仍然记录。审计文件可能包含**其它客户端**的
SQL；只关心 AI agent 时，在日志消费端过滤 `db.agent_pid != null`。

**SQLite** 没有服务端审计日志。项目提供可选的 SQLite shim：

```bash
./scripts/build_shim.sh
./proctrace run \
  --db-audit sqlite:/tmp/proctrace-sqlite.sock \
  --audit --workspace /absolute/project -- claude
```

`run` 会把 `DYLD_INSERT_LIBRARIES`（macOS）或 `LD_PRELOAD`（Linux）和 socket
路径注入子进程；shim 在 `sqlite3_open_v2` 后注册 `SQLITE_TRACE_STMT`，把 SQL
发到 proctrace 的 Unix datagram socket，不落盘原始 SQL。SIP/hardened runtime
可能阻止注入，此时只能退回 SQLite 文件级 `db_file` 事件。

`run` 默认在监控退出时终止子进程；要保留子进程用 `--keep-child`。TUI 模式下
子进程 stdout/stderr 默认丢弃，用 `--child-log FILE` 保存；`--no-tui` 时继承
终端输出。

**交互式 agent（Claude Code/Codex CLI）** 不要让 TUI 和它的终端 UI 抢 stdin；
推荐让 agent 保留终端、事件只写审计日志：

```bash
./proctrace run --no-tui --quiet --log audit.jsonl --log-only \
  --db-audit sqlite:/tmp/proctrace-sqlite.sock \
  --audit --workspace /absolute/project -- claude
```

这样 agent 的交互界面正常显示，proctrace 只把文件/网络/DB 事件写入
`audit.jsonl`。

**脱敏**：字符串、数字、dollar-quoted 字面量会被替换为 `?`；注释被移除。日志
不会包含业务数据值，但仍会保留表名、列名和 SQL 结构。SQL 原文来自数据库自身
审计日志（或 SQLite shim），proctrace 只保存脱敏副本；DB 侧的原始日志仍需按
数据库的审计/保留策略管理。风险规则包括
`DROP/TRUNCATE/ALTER`、无 `WHERE` 的 `DELETE/UPDATE`、`COPY ... TO`、
`INTO OUTFILE`、`xp_cmdshell`、敏感表访问等；规则在
[src/proctrace/db_audit.py](src/proctrace/db_audit.py)。

`protected` 告警只针对被监控进程访问受保护进程的行为：

| 检测方式 | Linux | macOS |
| --- | --- | --- |
| 打开 `/proc/<protected_pid>/mem`、`maps`、`environ` 等 procfs 伪文件 | ✅ | —（无 procfs） |
| `pidfd_open`：从 `/proc/<pid>/fdinfo` 的 `Pid:` 字段识别 | ✅（内核支持时） | — |
| `ptrace` 附加：读受保护进程的 `TracerPid` | ✅ | ❌ 无特权不可见 |
| `task_for_pid` / Mach `vm_read` | — | ❌ 需要 EndpointSecurity |
| `process_vm_readv` / `process_vm_writev` | ❌ 需要 eBPF（未实现） | — |

macOS 上 `protected` 仍有意义：它会阻止 proctrace 扫描该进程的 fd，并可在 TUI
中标记；但**不能**在不引入 EndpointSecurity（需要 Apple entitlement、root 和
代码签名）的前提下对 `task_for_pid` 告警。README 不会把这一点藏起来。

Linux 上还有一个容易误解的边界：`/proc/<pid>/fd/<n>`、`exe`、`cwd`、`root/...`
都是**符号链接**。目标进程打开它们后，`/proc/<target>/fd` 的 `readlink` 会解析到
最终文件，proctrace 看不到"它来自哪个受保护进程"。因此上表只承诺可观测的
procfs 伪文件；要覆盖符号链接解析前的一次性 `openat`，需要内核事件流（Linux
fanotify/eBPF 或 macOS ESF）。

`exclude` 和 `protected` 都可以在命令行追加：

```bash
./proctrace watch --pid 1234 \
  --protect 5678 \
  --protect-name '1Password' \
  --exclude-name 'WindowServer'
```

---

## 工作方式与兼容性

### 后端

| | Linux | macOS |
| --- | --- | --- |
| FD 枚举 | `/proc/<pid>/fd` + `readlink` | `libproc`（经 psutil `open_files()`） |
| 新建 fd 的 mode | `/proc/<pid>/fdinfo` 的 `flags` | libproc 不提供时为空 |
| 子进程发现 | psutil | psutil |
| 特殊 fd | socket/pipe/anon 可识别 | 主要返回普通 vnode 文件 |
| 权限 | 同用户或 root | 同用户或 root；受 SIP 限制的系统进程不可见 |

- Linux 需要挂载 `/proc`；`hidepid=2` 会限制普通用户可见性。
- macOS 已在 13.7.8 / Apple Silicon 上验证；Linux 代码路径包含 procfs 单测，
  但未在真机上跑集成测试。
- 不支持 Windows。Windows 需要 ETW/驱动级方案，和当前 polling 模型差异较大。

### "实时"的边界（对 AI agent 尤其重要）

默认模式是**轮询**：

- 每 `interval`（0.5s）扫描一次已知 PID 的 fd 表；
- 每 `tree_refresh`（1s）重新发现一次子进程；
- 生命周期短于一个轮询周期的 open/read/close 可能完全看不到；
- 无 root 时把 `--interval` 调到 `0.1`–`0.2` 只能降低漏报率，不能根治。

启用 `--kernel` 后，文件事件来自内核（macOS eslogger / Linux fanotify），
短命 open/read/close 不再依赖 fd 轮询。但：

- **需要 root**；macOS 还需要 Full Disk Access。
- **网络仍是 psutil 轮询**；macOS ESF 不提供 IP 网络事件，Linux 内核网络采集
  尚未接入。
- **数据库 SQL 语句级仍不可见**；内核只能看到 DB 连接/SQLite 文件 I/O。
- 当前环境没有 root，内核后端**未做真实运行验证**；首次使用请用短命 `cat`
  或 SQLite 进程验证，并查看 `doctor`/启动 warning。
- macOS 的 libproc 通常不返回 fd 读写模式，因此无内核模式下 violation 只能
  说明“打开了”；Linux `/proc/<pid>/fdinfo` 可以区分。

`proctrace` **不会读取文件内容**，只判断路径、fd 和打开模式；需要“是否读了某个
文件”的强证据时，应使用 `--kernel`（Linux `FAN_ACCESS` 可到 read 事件；macOS
eslogger 只有 open + fflag，仍有语义差距）或数据库/应用层审计。

### PID 复用

所有进程状态都带 `create_time`。PID 被复用时旧状态会被丢弃并重新建立，
不会把新进程的文件错误地算到旧进程头上。`protected` 规则如果写了
`create_time`，也会校验它。

---

## 性能

在本机（macOS 13.7.8，Apple Silicon，Python 3.9）用 `Monitor.poll()` 实测：

| 场景 | 单次扫描 |
| --- | --- |
| 1 个进程，40 个 fd | 约 **1.8ms** 平均 |
| 21 个进程，20 个 fd | 约 **4ms** 平均 |
| 同上，重新发现进程树的那一次 | 约 **17ms**（每 1s 一次） |

按默认 0.5s 间隔，21 个进程约占单核 **2–3%**；1 个进程通常低于 1%。
Linux procfs 的 fd 枚举一般更快，主要开销同样来自进程树发现。

可调参数：

- `--interval 0.5`：fd 扫描间隔；审计 agent 建议 0.2
- `--tree-refresh 1.0`：子进程发现间隔；审计 agent 建议 0.5
- `--max-processes 2048`：进程树上限，防止误监控 `launchd`/大型构建树时失控
- `--no-children`：只监控目标本身
- `exclude`：排除高噪音子树，直接减少扫描量
- `--all-types` 只影响显示，不影响采集

TUI 只保留 `max_events` 条事件；`--log` 是写入文件的 JSONL，不受该上限影响。

---

## 输出格式

### 逐行模式

```text
21:27:51.553 OPEN     43484 Python           fd=4  r   /private/tmp/app/gamma.txt
21:27:53.108 EXIT     43486 Python               扫描时进程已退出
21:28:01.002 ALERT    43484 Python           -> 5678 1Password via=procfs /proc/5678/mem
```

非普通文件默认不显示；`--all-types` 会显示 `socket:[...]`、`pipe:[...]`、
`anon_inode:[...]` 等。

### JSONL

每行一个事件：

```json
{"ts":1794403671.55375,"time":"2026-11-11T21:27:51.553","kind":"open","pid":43484,"name":"Python","ppid":43480,"fd":4,"path":"/private/tmp/app/gamma.txt","file_kind":"file"}
```

`kind` 取值：`open`、`change`、`close`、`read`、`write`、`alert`、`violation`、
`net_open`、`net_change`、`net_close`、`db_connect`、`db_change`、`db_close`、
`db_file`、`db_query`、`process_start`、`process_exit`、`warn`。

路径审计事件额外包含 `reason`（`denied_path` / `outside_workspace`）：

```json
{"kind":"violation","pid":43484,"name":"node","fd":12,"path":"/Users/me/.ssh/id_rsa","mode":"r","reason":"denied_path"}
{"kind":"db_connect","pid":43484,"name":"node","service":"postgresql","net":{"proto":"tcp","local":"10.0.0.5:51234","remote":"10.0.0.9:5432","status":"ESTABLISHED"}}
{"kind":"db_file","pid":43484,"name":"node","fd":20,"path":"/project/app.sqlite","mode":"rw","service":"sqlite","reason":"read_write"}
```

告警事件额外包含：

```json
{"kind":"alert","pid":43484,"victim_pid":5678,"victim_name":"1Password","via":"procfs","path":"/proc/5678/mem"}
```

### 快照

`snapshot --json` 输出一个对象，包含 `target_pid`、`backend`、
`capabilities`、`stats`、`processes[].files[]` 和 `alerts[]`。
适合直接 `jq` 或喂给其它面板。

---

## 退出码

| 码 | 含义 |
| --- | --- |
| `0` | 正常结束（包括 `--duration` 到期、目标退出） |
| `2` | 配置/目标/后端错误 |
| `130` | 被 Ctrl-C 中断 |

---

## 测试

```bash
PYTHONPATH=src .venv/bin/python -m pytest -q
node --test tests/plugin.test.mjs
```

当前覆盖：配置解析、规则 AND/glob/regex、PID 复用、fd diff、初始基线、
真实进程 fd 枚举、Linux procfs 假文件树、pidfd、`TracerPid`、受保护路径告警、
工作区/敏感路径审计、CLI 的 `doctor`/`init`/`snapshot`/`watch`，以及 DSH 插件的
`start`/`events`/`stop` 端到端闭环。

Linux-only 的保护/fanotify 测试在 macOS 上会自动 skip。内核后端需要 root，当前
环境无法做真实内核运行验证；网络/DB/解析器/CLI 集成路径已覆盖。SQLite shim 的
端到端测试会实际注入 Python 子进程并检查 SQL 事件。

---

## 目录

```text
src/proctrace/
  cli.py        命令行、配置合并、逐行/JSONL/快照
  engine.py     进程树、fd diff、告警、统计
  collector.py  Linux procfs / macOS libproc 采集器
  policy.py     protected/exclude 规则
  pathpolicy.py 工作区/敏感路径审计
  network.py    网络连接与 DB 端口分类
  database.py   SQLite/DuckDB 文件分类
  db_audit.py   PG/MySQL 日志、SQL 脱敏、风险规则
  kernel.py     eslogger / fanotify 事件源
  tui.py        ANSI 全屏 TUI
  render.py     文本/JSON 渲染
  config.py     JSON 配置
  target.py     目标进程选择
tests/          单测 + 本机集成测试 + DSH 插件测试
shim/           SQLite LD_PRELOAD / DYLD interposer
scripts/        build_shim.sh
examples/       示例配置
index.js        DSH Host 工具（proctrace 工具）
cordis.patch.yml DSH bundle 注册行
locale/         插件标题/描述（中/英）
docs/           插件详情页
icon.svg        插件图标
```

## 后续可以做什么

- Linux：eBPF 采集 `process_vm_readv`/`pidfd_getfd` 和网络事件（当前只有
  fanotify 文件事件 + psutil 网络轮询）
- macOS：自定义 EndpointSecurity 客户端（`ES_EVENT_TYPE_NOTIFY_PTRACE` 等），
  需要 entitlement 与签名；当前只使用 Apple 自带 eslogger
- Linux：eBPF 网络事件与 cgroup 过滤，覆盖短命连接/极短子进程
- 可选的 Windows ETW 后端

这些都没有包含在当前版本里，以避免给出"看起来支持、实际观测不到"的安全承诺。
