import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { mkdtemp, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { once } from 'node:events'
import test from 'node:test'

import { apply } from '../index.js'

function mockContext() {
  const tools = []
  const disposers = []
  return {
    tools: {
      register(definition) {
        tools.push(definition)
        return () => {}
      },
    },
    effect(effect) {
      disposers.push(effect())
      return () => {}
    },
    toolsList: tools,
    disposers,
  }
}

async function waitFor(predicate, timeoutMs = 12000) {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    const value = await predicate()
    if (value) return value
    await new Promise(resolve => setTimeout(resolve, 250))
  }
  return undefined
}

test('registers one proctrace tool with a strict action schema', async () => {
  const ctx = mockContext()
  apply(ctx, { maxEvents: 50 })
  assert.equal(ctx.toolsList.length, 1)
  const tool = ctx.toolsList[0]
  assert.equal(tool.name, 'proctrace')
  assert.deepEqual(tool.parameters.required, ['action'])
  assert.deepEqual(tool.parameters.properties.action.enum, ['start', 'status', 'events', 'stop'])
  assert.equal(tool.parameters.properties.protect_names.type, 'array')
  assert.equal(tool.parameters.properties.exclude_names.type, 'array')
  assert.equal(typeof tool.output.render, 'function')

  const invalid = await tool.execute({ action: 'nope' }, {})
  assert.equal(invalid.ok, false)
  assert.match(invalid.message, /action must be one of/)
})

test('starts a real monitor, buffers a file open, and stops it', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'dsh-proctrace-test-'))
  const probe = join(dir, 'probe.txt')
  await writeFile(probe, 'proctrace plugin integration probe\n')

  const target = spawn(process.execPath, ['-e', `
    const fs = require('node:fs')
    setTimeout(() => {
      const fd = fs.openSync(${JSON.stringify(probe)}, 'r')
      fs.readFileSync(fd)
      setInterval(() => {}, 1000)
    }, 700)
  `], { cwd: dir, stdio: ['ignore', 'ignore', 'ignore'] })
  await once(target, 'spawn')
  t.after(() => {
    try { target.kill('SIGKILL') } catch {}
  })

  const ctx = mockContext()
  apply(ctx, { maxEvents: 100 })
  const tool = ctx.toolsList[0]

  const started = await tool.execute({
    action: 'start',
    pid: target.pid,
    workspace: dir,
    interval: 0.2,
    network: false,
    database: false,
  }, {})
  assert.equal(started.ok, true, started.message)
  const monitorId = started.monitor.id
  assert.match(monitorId, /^pt-/)

  const matching = await waitFor(async () => {
    const result = await tool.execute({ action: 'events', monitor_id: monitorId, limit: 100 }, {})
    return result.events?.find(event => event.path === probe || event.path === `${probe}` || String(event.path).endsWith('/probe.txt'))
  })
  assert.ok(matching, 'expected a file event for the probe path')
  assert.ok(['open', 'change', 'read'].includes(matching.kind), `unexpected kind: ${matching.kind}`)

  const stopped = await tool.execute({ action: 'stop', monitor_id: monitorId }, {})
  assert.equal(stopped.ok, true)
  assert.equal(stopped.stopped[0].status, 'stopped')

  const status = await tool.execute({ action: 'status' }, {})
  assert.equal(status.monitors.length, 1)
  assert.equal(status.monitors[0].status, 'stopped')
})
