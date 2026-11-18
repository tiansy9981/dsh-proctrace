/**
 * ProcTrace host plugin for DeepSeek Harness.
 *
 * The plugin owns a small number of `proctrace watch` child processes and
 * exposes their JSONL event streams as a normal DSH tool. Keeping the tool
 * host-only means it works without a Web UI build and without importing DSH
 * packages from this linked local checkout.
 */

import { spawn } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { accessSync, constants, existsSync, mkdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, isAbsolute, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

export const inject = ['tools']

const ROOT = dirname(fileURLToPath(import.meta.url))
const DEFAULT_EXECUTABLE = join(ROOT, 'proctrace')
const TOOL_NAME = 'proctrace'
const ACTIONS = new Set(['start', 'status', 'events', 'stop'])
const MAX_MONITORS = 20

/** Normalize the optional row config without requiring a Schemastery schema. */
function normalizeConfig(config) {
  const source = config && typeof config === 'object' && !Array.isArray(config) ? config : {}
  return {
    executable: typeof source.executable === 'string' && source.executable.trim()
      ? source.executable.trim()
      : undefined,
    cwd: typeof source.cwd === 'string' && source.cwd.trim() ? source.cwd.trim() : undefined,
    maxEvents: clampInteger(source.maxEvents, 50, 5000, 500),
    interval: clampNumber(source.interval, 0.1, 10, 0.5),
    maxStderr: clampInteger(source.maxStderr, 500, 20000, 4000),
  }
}

function clampInteger(value, min, max, fallback) {
  const number = typeof value === 'number' ? value : Number(value)
  if (!Number.isFinite(number)) return fallback
  return Math.min(max, Math.max(min, Math.trunc(number)))
}

function clampNumber(value, min, max, fallback) {
  const number = typeof value === 'number' ? value : Number(value)
  if (!Number.isFinite(number)) return fallback
  return Math.min(max, Math.max(min, number))
}

function resolveExecutable(configured) {
  const value = configured || process.env.DSH_PROCTRACE_BIN || DEFAULT_EXECUTABLE
  const full = isAbsolute(value) ? value : resolve(ROOT, value)
  if (!existsSync(full)) {
    throw new Error(`proctrace executable not found: ${full}. Run the plugin from its copied project directory or set DSH_PROCTRACE_BIN.`)
  }
  try {
    accessSync(full, constants.X_OK)
  } catch {
    throw new Error(`proctrace executable is not runnable: ${full}`)
  }
  return full
}

function integerArg(value, name, min, max) {
  const number = typeof value === 'number' ? value : (typeof value === 'string' && value.trim() ? Number(value) : NaN)
  if (!Number.isInteger(number) || number < min || number > max) {
    throw new Error(`${name} must be an integer between ${min} and ${max}`)
  }
  return number
}

function numberArg(value, name, min, max) {
  const number = typeof value === 'number' ? value : (typeof value === 'string' && value.trim() ? Number(value) : NaN)
  if (!Number.isFinite(number) || number < min || number > max) {
    throw new Error(`${name} must be a number between ${min} and ${max}`)
  }
  return number
}

function booleanArg(value, name) {
  if (value === undefined) return undefined
  if (typeof value !== 'boolean') throw new Error(`${name} must be a boolean`)
  return value
}

function stringArg(value, name) {
  if (value === undefined) return undefined
  if (typeof value !== 'string' || !value.trim()) throw new Error(`${name} must be a non-empty string`)
  return value.trim()
}

function stringListArg(value, name, maxItems = 50) {
  if (value === undefined) return []
  if (!Array.isArray(value)) throw new Error(`${name} must be an array of strings`)
  if (value.length > maxItems) throw new Error(`${name} must contain at most ${maxItems} entries`)
  return value.map((entry, index) => stringArg(entry, `${name}[${index}]`))
}

/** Validate the model-supplied arguments because this definition is registered directly. */
function validateInput(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('arguments must be an object')
  const action = raw.action
  if (!ACTIONS.has(action)) throw new Error(`action must be one of: ${[...ACTIONS].join(', ')}`)

  const pid = raw.pid === undefined ? undefined : integerArg(raw.pid, 'pid', 1, 2 ** 31 - 1)
  const name = stringArg(raw.name, 'name')
  if (pid !== undefined && name !== undefined) throw new Error('pid and name are mutually exclusive')

  const workspace = stringArg(raw.workspace, 'workspace')
  const monitorId = stringArg(raw.monitor_id, 'monitor_id')
  const input = {
    action,
    pid,
    name,
    workspace: workspace === undefined ? undefined : (isAbsolute(workspace) ? workspace : resolve(process.cwd(), workspace)),
    monitorId,
    interval: raw.interval === undefined ? undefined : numberArg(raw.interval, 'interval', 0.1, 10),
    duration: raw.duration === undefined ? undefined : numberArg(raw.duration, 'duration', 1, 86400),
    limit: raw.limit === undefined ? 50 : integerArg(raw.limit, 'limit', 1, 200),
    importantOnly: booleanArg(raw.important_only, 'important_only') === true,
    network: booleanArg(raw.network, 'network'),
    database: booleanArg(raw.database, 'database'),
    audit: booleanArg(raw.audit, 'audit'),
    kernel: booleanArg(raw.kernel, 'kernel'),
    protectNames: stringListArg(raw.protect_names, 'protect_names'),
    excludeNames: stringListArg(raw.exclude_names, 'exclude_names'),
    newMonitor: booleanArg(raw.new_monitor, 'new_monitor') === true,
  }
  return input
}

function isRunningStatus(status) {
  return status === 'running' || status === 'stopping'
}

function formatTime(value) {
  if (typeof value === 'string' && value.length >= 19) return value.slice(11, 19)
  if (typeof value === 'number' && Number.isFinite(value)) {
    const date = new Date(value * 1000)
    return Number.isNaN(date.getTime()) ? '-' : date.toISOString().slice(11, 19)
  }
  return '-'
}

function short(value, width) {
  const text = String(value ?? '-').replace(/\s+/g, ' ')
  return text.length > width ? `${text.slice(0, Math.max(1, width - 1))}…` : text
}

function truncate(value, width) {
  const text = String(value ?? '').replace(/\s+/g, ' ')
  return text.length > width ? `${text.slice(0, Math.max(1, width - 1))}…` : text
}

function eventDetail(event) {
  if (event.kind === 'db_query') {
    const db = event.db && typeof event.db === 'object' ? event.db : {}
    const risk = db.risk || event.severity || '?'
    return `${db.system || event.service || 'db'} ${db.operation || '?'} risk=${risk} ${truncate(db.sql || event.detail || '', 170)}`
  }
  if (event.kind && (event.kind.startsWith('net_') || event.kind.startsWith('db_connect') || event.kind.startsWith('db_change') || event.kind.startsWith('db_close'))) {
    const net = event.net && typeof event.net === 'object' ? event.net : {}
    return `${net.proto || '?'} ${net.local || '-'} -> ${net.remote || '-'} ${net.service || ''}`.trim()
  }
  if (event.kind === 'alert') {
    return `victim ${event.victim_pid || '?'} ${event.victim_name || ''} via=${event.via || '?'} ${event.path || ''}`.trim()
  }
  if (event.kind === 'violation') return `${event.path || '-'} reason=${event.reason || '?'}`
  if (event.kind === 'db_file') {
    const db = event.db && typeof event.db === 'object' ? event.db : {}
    return `${event.path || '-'} ${event.mode || '?'} ${db.system || ''}`.trim()
  }
  return event.path || event.detail || event.reason || ''
}

function eventLine(event) {
  const kind = short(String(event.kind || '?').toUpperCase(), 9).padEnd(9)
  const severity = event.severity ? ` ${event.severity}` : ''
  return `${formatTime(event.time || event.ts)} ${kind} pid=${event.pid ?? '-'} ${short(event.name, 14)}${severity} ${eventDetail(event)}`
}

function monitorSummary(monitor) {
  const summary = {
    id: monitor.id,
    status: monitor.status,
    target: monitor.target,
    interval: monitor.interval,
    audit: monitor.audit,
    network: monitor.network,
    database: monitor.database,
    kernel: monitor.kernel,
    protect_names: monitor.protectNames,
    exclude_names: monitor.excludeNames,
    started_at: monitor.startedAt,
    event_count: monitor.eventCount,
    counts: monitor.counts,
    log_path: monitor.logPath,
    monitor_pid: monitor.child?.pid,
  }
  if (monitor.pid !== undefined) summary.pid = monitor.pid
  if (monitor.name !== undefined) summary.name = monitor.name
  if (monitor.endedAt !== undefined) summary.ended_at = monitor.endedAt
  if (monitor.lastEventAt !== undefined) summary.last_event_at = monitor.lastEventAt
  if (monitor.error) summary.error = monitor.error
  if (monitor.stderrTail) summary.stderr_tail = monitor.stderrTail
  return summary
}

function renderMonitorRow(monitor) {
  const counts = monitor.counts || {}
  return `${short(monitor.id, 10).padEnd(10)} ${short(monitor.status, 8).padEnd(8)} ${short(monitor.target, 26).padEnd(26)} events=${String(monitor.event_count ?? 0).padStart(5)} violations=${String(counts.violations ?? 0).padStart(3)}`
}

function render(_args, value) {
  const lines = []
  if (value.message) lines.push(String(value.message))
  if (value.monitor) {
    lines.push('Monitor:')
    lines.push(renderMonitorRow(value.monitor))
    lines.push(`log: ${value.monitor.log_path}`)
    if (value.monitor.stderr_tail) lines.push(`stderr tail: ${value.monitor.stderr_tail}`)
  }
  if (Array.isArray(value.monitors)) {
    if (value.monitors.length === 0) lines.push('No monitors have been started in this DSH process.')
    else {
      lines.push('Monitors:')
      lines.push('id         status   target                     events violations')
      for (const monitor of value.monitors) lines.push(renderMonitorRow(monitor))
    }
  }
  if (Array.isArray(value.events)) {
    if (value.events.length === 0) lines.push(`No matching events yet (buffered=${value.total_buffered ?? 0}).`)
    else {
      lines.push(`Events (${value.events.length} shown, ${value.total_buffered ?? value.events.length} buffered):`)
      lines.push('time     kind      target')
      for (const event of value.events) lines.push(eventLine(event))
    }
  }
  if (value.counts && value.counts.kinds) {
    const kinds = Object.entries(value.counts.kinds).sort((a, b) => b[1] - a[1])
    if (kinds.length) lines.push(`Buffered kinds: ${kinds.map(([kind, count]) => `${kind}=${count}`).join(', ')}`)
  }
  return [{ type: 'text', text: lines.join('\n') || 'No data.' }]
}

/**
 * Mount the host plugin.
 * @param {object} ctx Cordis context with the tools service.
 * @param {object} [config] Optional row config: executable, cwd, maxEvents, interval, maxStderr.
 */
export function apply(ctx, config) {
  const settings = normalizeConfig(config)
  const monitors = new Map()
  let disposed = false

  if (!ctx || !ctx.tools || typeof ctx.tools.register !== 'function') {
    throw new Error('ProcTrace requires the DSH tools service')
  }

  const cleanup = () => {
    disposed = true
    const active = [...monitors.values()].filter(monitor => isRunningStatus(monitor.status))
    return Promise.allSettled(active.map(monitor => stopMonitor(monitor, 'plugin disposed')))
  }
  if (typeof ctx.effect === 'function') ctx.effect(() => cleanup)
  else if (typeof ctx.on === 'function') ctx.on('dispose', cleanup)

  function notifyExit(monitor) {
    const waiters = monitor.waiters.splice(0)
    for (const waiter of waiters) waiter()
  }

  function consumeStdout(monitor, chunk) {
    monitor.stdoutBuffer += chunk
    if (monitor.stdoutBuffer.length > 1024 * 1024) {
      monitor.stdoutBuffer = monitor.stdoutBuffer.slice(-256 * 1024)
      monitor.parseErrors += 1
    }
    let newline
    while ((newline = monitor.stdoutBuffer.indexOf('\n')) >= 0) {
      const line = monitor.stdoutBuffer.slice(0, newline).trim()
      monitor.stdoutBuffer = monitor.stdoutBuffer.slice(newline + 1)
      if (!line) continue
      let event
      try {
        event = JSON.parse(line)
      } catch {
        monitor.parseErrors += 1
        continue
      }
      if (!event || typeof event !== 'object' || typeof event.kind !== 'string') continue
      // The monitor process is a child of the DSH host, so monitoring the host
      // also observes proctrace itself. Drop only the monitor's own events.
      if (event.pid !== undefined && event.pid === monitor.child?.pid) continue
      monitor.eventCount += 1
      monitor.lastEventAt = event.time || new Date().toISOString()
      monitor.events.push(event)
      if (monitor.events.length > settings.maxEvents) monitor.events.shift()
      monitor.counts.kinds[event.kind] = (monitor.counts.kinds[event.kind] || 0) + 1
      if (event.severity) monitor.counts.severities[event.severity] = (monitor.counts.severities[event.severity] || 0) + 1
      if (event.kind === 'violation') monitor.counts.violations += 1
      if (event.kind === 'alert') monitor.counts.alerts += 1
      if (event.kind === 'db_query' && (event.severity === 'high' || event.severity === 'medium')) {
        monitor.counts.important_db_queries += 1
      }
    }
  }

  function consumeStderr(monitor, chunk) {
    monitor.stderrTail = `${monitor.stderrTail}${chunk}`.slice(-settings.maxStderr)
  }

  async function start(input, exec) {
    const pid = input.pid ?? (input.name === undefined ? process.pid : undefined)
    const name = input.name
    if (pid !== undefined) {
      try {
        process.kill(pid, 0)
      } catch (error) {
        if (error?.code === 'ESRCH') throw new Error(`target process ${pid} does not exist`)
      }
    }
    if (pid !== undefined && name !== undefined) throw new Error('pid and name are mutually exclusive')

    const target = pid !== undefined ? `pid ${pid}` : `name ${name}`
    const targetKey = `${pid !== undefined ? `pid:${pid}` : `name:${name}`}|protect:${input.protectNames.join(',')}|exclude:${input.excludeNames.join(',')}`
    if (!input.newMonitor) {
      const existing = [...monitors.values()].find(monitor => monitor.targetKey === targetKey && isRunningStatus(monitor.status))
      if (existing) return { ok: true, message: `Monitor ${existing.id} is already watching ${target}.`, monitor: monitorSummary(existing) }
    }

    const activeCount = [...monitors.values()].filter(monitor => isRunningStatus(monitor.status)).length
    if (activeCount >= MAX_MONITORS) throw new Error(`at most ${MAX_MONITORS} monitors may run at once`)

    const executable = resolveExecutable(settings.executable)
    const id = `pt-${Date.now().toString(36)}-${randomBytes(3).toString('hex')}`
    const logDir = join(tmpdir(), 'dsh-proctrace')
    mkdirSync(logDir, { recursive: true })
    const logPath = join(logDir, `${id}.jsonl`)
    const interval = input.interval ?? settings.interval
    const audit = input.audit !== false
    const network = input.network !== false
    const database = input.database !== false
    const kernel = input.kernel === true
    const cliArgs = ['watch', '--no-tui', '--json', '--quiet', '--log', logPath, '--interval', String(interval)]
    if (pid !== undefined) cliArgs.push('--pid', String(pid))
    else cliArgs.push('--name', name)
    if (audit) cliArgs.push('--audit')
    if (input.workspace) cliArgs.push('--workspace', input.workspace)
    if (network) cliArgs.push('--network')
    if (database) cliArgs.push('--database')
    if (kernel) cliArgs.push('--kernel')
    for (const pattern of input.protectNames) cliArgs.push('--protect-name', pattern)
    for (const pattern of input.excludeNames) cliArgs.push('--exclude-name', pattern)
    if (input.duration !== undefined) cliArgs.push('--duration', String(input.duration))

    const monitor = {
      id,
      target,
      targetKey,
      pid,
      name,
      interval,
      audit,
      network,
      database,
      kernel,
      protectNames: input.protectNames,
      excludeNames: input.excludeNames,
      status: 'starting',
      startedAt: new Date().toISOString(),
      endedAt: undefined,
      lastEventAt: undefined,
      eventCount: 0,
      counts: { kinds: {}, severities: {}, violations: 0, alerts: 0, important_db_queries: 0 },
      events: [],
      stdoutBuffer: '',
      stderrTail: '',
      parseErrors: 0,
      logPath,
      child: undefined,
      waiters: [],
      stopRequested: false,
      error: undefined,
    }

    const child = spawn(executable, cliArgs, {
      cwd: settings.cwd || process.cwd(),
      env: { ...process.env, PYTHONUNBUFFERED: '1' },
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    monitor.child = child
    child.stdout?.setEncoding('utf8')
    child.stderr?.setEncoding('utf8')
    child.stdout?.on('data', chunk => consumeStdout(monitor, chunk))
    child.stderr?.on('data', chunk => consumeStderr(monitor, chunk))
    child.once('error', error => {
      monitor.status = 'failed'
      monitor.error = error instanceof Error ? error.message : String(error)
      monitor.endedAt = new Date().toISOString()
      notifyExit(monitor)
    })
    child.once('exit', (code, signal) => {
      monitor.endedAt = new Date().toISOString()
      monitor.exitCode = code
      monitor.signal = signal
      monitor.status = monitor.stopRequested ? 'stopped' : (code === 0 ? 'stopped' : 'failed')
      if (monitor.status === 'failed' && !monitor.error) {
        monitor.error = `proctrace exited with code ${code}${signal ? ` (${signal})` : ''}`
      }
      notifyExit(monitor)
    })

    await new Promise((resolveStart, rejectStart) => {
      const timeout = setTimeout(() => {
        try { child.kill('SIGKILL') } catch {}
        rejectStart(new Error('proctrace did not start within 5 seconds'))
      }, 5000)
      child.once('spawn', () => {
        clearTimeout(timeout)
        resolveStart()
      })
      child.once('error', error => {
        clearTimeout(timeout)
        rejectStart(error)
      })
    }).catch(async error => {
      await stopMonitor(monitor, 'start failed').catch(() => {})
      monitors.delete(id)
      throw error
    })

    monitor.status = 'running'
    monitors.set(id, monitor)
    pruneMonitors()
    if (exec?.signal?.aborted) {
      await stopMonitor(monitor, 'cancelled')
      throw new Error('cancelled')
    }

    const flags = [audit ? 'audit' : null, network ? 'network' : null, database ? 'database' : null, kernel ? 'kernel' : null].filter(Boolean)
    return {
      ok: true,
      message: `Started ${id} on ${target}; interval=${interval}s; ${flags.length ? flags.join(', ') : 'file events only'}.`,
      monitor: monitorSummary(monitor),
    }
  }

  function pruneMonitors() {
    if (monitors.size < MAX_MONITORS) return
    const stopped = [...monitors.values()]
      .filter(monitor => monitor.status === 'stopped' || monitor.status === 'failed')
      .sort((a, b) => String(a.endedAt).localeCompare(String(b.endedAt)))
    while (monitors.size >= MAX_MONITORS && stopped.length > 0) {
      const oldest = stopped.shift()
      monitors.delete(oldest.id)
    }
  }

  function selectMonitor(id) {
    if (id) {
      const monitor = monitors.get(id)
      if (!monitor) throw new Error(`unknown monitor id: ${id}`)
      return { monitor, ambiguous: false }
    }
    const active = [...monitors.values()].filter(monitor => isRunningStatus(monitor.status))
    if (active.length === 0) {
      const latest = [...monitors.values()].sort((a, b) => String(b.startedAt).localeCompare(String(a.startedAt)))[0]
      if (latest) return { monitor: latest, ambiguous: false }
      throw new Error('no monitor has been started in this DSH process')
    }
    if (active.length === 1) return { monitor: active[0], ambiguous: false }
    active.sort((a, b) => String(b.startedAt).localeCompare(String(a.startedAt)))
    return { monitor: active[0], ambiguous: true }
  }

  function status(input) {
    const selected = input.monitorId ? [selectMonitor(input.monitorId).monitor] : [...monitors.values()]
    return { ok: true, monitors: selected.map(monitorSummary) }
  }

  function events(input) {
    const { monitor, ambiguous } = selectMonitor(input.monitorId)
    let events = monitor.events
    if (input.importantOnly) {
      events = events.filter(event => event.kind === 'violation' || event.kind === 'alert'
        || event.severity === 'high' || event.severity === 'medium'
        || (event.kind === 'db_query' && (event.db?.risk === 'high' || event.db?.risk === 'medium')))
    }
    const selected = events.slice(-input.limit)
    const result = {
      ok: true,
      monitor_id: monitor.id,
      events: selected,
      total_buffered: monitor.events.length,
      counts: monitor.counts,
      running: isRunningStatus(monitor.status),
      log_path: monitor.logPath,
    }
    if (ambiguous) {
      result.message = `Multiple monitors are active; showing the newest (${monitor.id}).`
    }
    return result
  }

  async function stop(input) {
    const targets = input.monitorId
      ? [selectMonitor(input.monitorId).monitor]
      : [...monitors.values()].filter(monitor => isRunningStatus(monitor.status))
    if (targets.length === 0) return { ok: true, message: 'No running monitors.', stopped: [] }
    await Promise.all(targets.map(monitor => stopMonitor(monitor, 'requested')))
    return {
      ok: true,
      message: `Stopped ${targets.length} monitor${targets.length === 1 ? '' : 's'}.`,
      stopped: targets.map(monitorSummary),
    }
  }

  async function stopMonitor(monitor, reason) {
    if (!monitor.child || monitor.status === 'stopped' || monitor.status === 'failed') return
    if (monitor.status === 'stopping') return waitForExit(monitor, 2500)
    monitor.stopRequested = true
    monitor.stopReason = reason
    monitor.status = 'stopping'
    try { monitor.child.kill('SIGTERM') } catch {}
    const killTimer = setTimeout(() => {
      try { monitor.child.kill('SIGKILL') } catch {}
    }, 1500)
    try {
      await waitForExit(monitor, 2500)
    } finally {
      clearTimeout(killTimer)
    }
  }

  function waitForExit(monitor, timeoutMs) {
    if (monitor.status === 'stopped' || monitor.status === 'failed' || monitor.status === 'starting') return Promise.resolve(true)
    return new Promise(resolveExit => {
      let settled = false
      const waiter = () => settle(true)
      const settle = exited => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        monitor.waiters = monitor.waiters.filter(candidate => candidate !== waiter)
        resolveExit(exited)
      }
      const timer = setTimeout(() => settle(false), timeoutMs)
      monitor.waiters.push(waiter)
      // The child may have exited between the status check above and the
      // waiter push. Re-check after registering so that exit is never missed.
      if (monitor.status === 'stopped' || monitor.status === 'failed') settle(true)
    })
  }

  const tool = {
    name: TOOL_NAME,
    description: 'Monitor file, network, and database activity of a process tree for AI security auditing. Start a monitor for the current DSH process by default, then read important events or stop it.',
    parameters: {
      type: 'object',
      additionalProperties: false,
      properties: {
        action: {
          type: 'string',
          enum: ['start', 'status', 'events', 'stop'],
          description: 'start a monitor, inspect monitor status, read buffered events, or stop monitoring.',
        },
        pid: {
          type: 'integer',
          minimum: 1,
          description: 'Target PID. Defaults to the current DSH host process, which includes agent tool subprocesses.',
        },
        name: {
          type: 'string',
          description: 'Process-name glob alternative to pid; the newest matching process is monitored.',
        },
        workspace: {
          type: 'string',
          description: 'Authorized workspace path for file auditing. Defaults to the target process cwd; relative paths resolve from the DSH working directory.',
        },
        interval: {
          type: 'number',
          minimum: 0.1,
          maximum: 10,
          description: 'Polling interval in seconds. Defaults to 0.5.',
        },
        duration: {
          type: 'number',
          minimum: 1,
          maximum: 86400,
          description: 'Automatically stop after this many seconds. Omit to run until stopped.',
        },
        monitor_id: {
          type: 'string',
          description: 'Monitor id returned by start; required only when several monitors are active.',
        },
        limit: {
          type: 'integer',
          minimum: 1,
          maximum: 200,
          description: 'Maximum events to return. Defaults to 50.',
        },
        important_only: {
          type: 'boolean',
          description: 'Only return violations, alerts, and high/medium severity events.',
        },
        network: {
          type: 'boolean',
          description: 'Monitor network connections. Defaults to true.',
        },
        database: {
          type: 'boolean',
          description: 'Monitor database files and database port connections. Defaults to true.',
        },
        audit: {
          type: 'boolean',
          description: 'Enable workspace and sensitive-path auditing. Defaults to true.',
        },
        kernel: {
          type: 'boolean',
          description: 'Use the kernel event backend (macOS eslogger or Linux fanotify); requires root and Full Disk Access on macOS. Defaults to false.',
        },
        protect_names: {
          type: 'array',
          items: { type: 'string' },
          maxItems: 50,
          description: 'Process-name globs that are protected: accessing their process/files raises an alert. Alert-only, never blocks.',
        },
        exclude_names: {
          type: 'array',
          items: { type: 'string' },
          maxItems: 50,
          description: 'Process-name globs whose subtrees are excluded from monitoring.',
        },
        new_monitor: {
          type: 'boolean',
          description: 'Start another monitor even if an equivalent one is running.',
        },
      },
      required: ['action'],
    },
    output: {
      schema: {
        type: 'object',
        properties: {
          ok: { type: 'boolean' },
          message: { type: 'string' },
          monitor: { type: 'object' },
          monitors: { type: 'array', items: { type: 'object' } },
          stopped: { type: 'array', items: { type: 'object' } },
          events: { type: 'array', items: { type: 'object' } },
          counts: { type: 'object' },
          monitor_id: { type: 'string' },
          total_buffered: { type: 'integer' },
          running: { type: 'boolean' },
          log_path: { type: 'string' },
        },
      },
      render,
    },
    async execute(raw, exec) {
      try {
        const input = validateInput(raw)
        if (exec?.signal?.aborted) throw new Error('cancelled')
        switch (input.action) {
          case 'start': return await start(input, exec)
          case 'status': return status(input)
          case 'events': return events(input)
          case 'stop': return await stop(input)
          default: throw new Error(`unsupported action: ${input.action}`)
        }
      } catch (error) {
        return { ok: false, message: error instanceof Error ? error.message : String(error) }
      }
    },
  }

  return ctx.tools.register(tool)
}
