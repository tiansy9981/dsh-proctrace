# ProcTrace for DeepSeek Harness

ProcTrace 是一个 Host-only DSH 插件，把 `proctrace` 的进程树监控能力注册为
`proctrace` 工具。它不依赖 Web 客户端构建，也不引入额外 npm 依赖；插件被激活后，
可以直接在对话中让 agent 启动监控、读取事件、查看状态和停止监控。

## 能做什么

- 监控一个目标进程及其全部子进程打开的文件，按工作区白名单和敏感路径黑名单产生
  `violation` 告警。
- 监控 TCP/UDP/Unix 连接，标记 PostgreSQL、MySQL、Redis、MongoDB 等数据库端口。
- 监控 SQLite/DuckDB 文件的打开和读写，产生 `db_file` 事件。
- 默认目标是 **当前 DSH Host 进程**，因此 agent 通过 bash 等工具启动的子进程会进入
  监控范围；也可以指定 `pid` 或用 `name` 匹配其它进程。
- 事件保存在插件内存的环形缓冲区中，默认 500 条；同时写入
  `$TMPDIR/dsh-proctrace/<monitor-id>.jsonl`，便于后续排查。

## 在对话中使用

工具名为 `proctrace`，参数 `action` 有四个值：

| action | 作用 |
|---|---|
| `start` | 启动监控。不传 `pid`/`name` 时监控当前 DSH Host 及其子进程。 |
| `status` | 查看当前进程内所有监控的状态、事件计数和日志路径。 |
| `events` | 读取最近的缓冲事件，可用 `limit`、`important_only` 过滤。 |
| `stop` | 停止指定监控；不传 `monitor_id` 时停止所有运行中的监控。 |

常用参数：

- `workspace`：授权工作区。建议显式传入项目绝对路径；否则使用目标进程的 cwd。
- `interval`：轮询间隔，默认 `0.5` 秒，最小 `0.1`。
- `network` / `database` / `audit`：默认都为 `true`。
- `protect_names`：受保护进程名 glob 列表；访问这些进程会触发告警（仅告警，不阻断）。
- `exclude_names`：从监控树中排除的进程名 glob 列表。
- `kernel`：启用内核事件后端，默认 `false`；macOS 需要 root + Full Disk Access，
  Linux 需要 root + fanotify 权限。
- `duration`：到时自动停止（秒）。
- `important_only`：只返回 violation、alert 和高/中风险事件。

典型对话：

> 用 proctrace 监控当前 DSH 进程，工作区设为 `/Users/me/project`，然后每 30 秒
> 汇总一次高风险的路径访问和数据库连接。

> 查看 proctrace 最近的 20 条事件，只要重要的。

> 停止所有 proctrace 监控。

## 安装与依赖

插件通过 DSH 的 `plugin_manager` 以本地目录 bundle 安装，`package.json` 中的
`dsh.bundle.patch` 会插入 `@local/dsh-proctrace` 这一行。`index.js` 只使用 Node
内置模块，不导入 DSH 包；Python 侧仍由同目录的 `./proctrace` 启动。

项目副本已带 `.venv`（`psutil`、`pytest`）。如果把插件打包到没有 `.venv` 的环境，
需要先执行：

```bash
cd <plugin-dir>
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

也可以用 `DSH_PROCTRACE_BIN` 或插件配置的 `executable` 指向另一个 `proctrace`
可执行文件。可选配置：

```yaml
config:
  executable: /absolute/path/to/proctrace
  maxEvents: 500
  interval: 0.5
  maxStderr: 4000
```

插件配置没有声明 Schemastery schema；上面的键由插件自己读取，非法数值会退回默认值。

## 工作原理

插件为每个监控启动一个子进程：

```text
proctrace watch --no-tui --json --quiet --audit --network --database \
  --pid <pid> --log <tmp>/<id>.jsonl
```

它逐行解析 stdout 的 JSONL，维护计数和环形缓冲区；`--log` 保留完整 JSONL 供
`events` 之外的人工检查。停止时先发 `SIGTERM`，1.5 秒后仍未退出则 `SIGKILL`。
插件卸载时会停止自己启动的所有监控。

默认监控 DSH Host 会让插件看到其他会话/工具产生的文件访问；如果只想审计某个
agent 子进程，在启动时传入它的 `pid`。监控自身产生的 `proctrace` 子进程事件会被
过滤，避免自噪声。

## 限制

- **只告警，不拦截**。ProcTrace 不阻止文件打开，也不修改目标进程行为。
- **轮询会漏掉短命 open**。默认后端是 psutil/libproc 轮询；短于轮询间隔的打开可能
  看不到。`kernel` 后端可减少漏报，但需要 root，且当前环境未验证。
- **不读取文件内容**。只记录路径、fd、模式和审计原因；SQL 文本只有 SQLite shim
  或 PostgreSQL/MySQL 审计日志路径才会出现，而本插件没有启用 SQL shim。
- **数据库事件是文件/连接元数据**，不是 SQL 级审计。
- **macOS 无 root 时**看不到 `task_for_pid`/Mach 内存访问；受保护进程的告警也是
  尽力而为。
- 事件在插件内存中，DSH 重启或插件卸载后不保留；完整记录看 `log_path` 的 JSONL。
- 没有独立侧边栏面板；宿主是对话中的工具结果。需要面板时应另做 client 插件。
- 默认目标是整个 DSH Host 进程树，不是单个 agent 会话；需要更细粒度时显式传
  `pid` 或在目标 agent 启动时用 `proctrace run`。

## 验证

```bash
# 在 dsh-proctrace 仓库根目录执行
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
PYTHONPATH=src .venv/bin/python -m pytest -q
node --test tests/plugin.test.mjs
```

第一条验证 Python 监控器（本机预期 66 passed, 2 skipped）；第二条用 mock Cordis
context 启动真实 `proctrace watch`，验证 `start`/`events`/`stop` 闭环。
