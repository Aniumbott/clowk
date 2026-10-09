// Tests for the clowk mod (hooks/register.js). Run with:  claude plugin test .
// `clowk rewrite` itself is tested in Python (tests/test_rewrite.py); here its output is stubbed,
// and what is under test is what the mod does with it -- above all, that every failure drops.
import { expect, test } from 'claude-code/testing'

const KEY = 'sk_' + 'live_4eC39HqLyjWDarjtT1zdp7dc'
const POINTER = '[assistant: $NAME is a credential clowk holds.]'

function session(on) {
  on('session.cwd', () => ({ value: '/work' }))
  on('session.id', () => ({ value: 'sess-1' }))
  on('ui.status', () => ({ value: undefined }))
  // Whatever reaches the end of the chain is what the model would get.
  on('prompt.submit', ($, e) => ({ text: e.text, context: e.context }))
}

function detector(on, answer, seen = []) {
  on('process.run', ($, e) => {
    seen.push(e)
    return typeof answer === 'function' ? answer(e) : answer
  })
}

const replaced = { value: { exitCode: 0, stderr: '', stdout: JSON.stringify(
  { text: 'charge it with $STRIPE_SECRET_KEY', names: ['STRIPE_SECRET_KEY'], pointer: POINTER }) } }

test('a credential is replaced by its name before the prompt goes on', async ($, on) => {
  session(on)
  detector(on, replaced)
  const out = await $.prompt.submit({ text: 'charge it with ' + KEY })
  expect(out.text).toBe('charge it with $STRIPE_SECRET_KEY')
  expect(out.text).not.toContain(KEY)
})

test('the prompt reaches the detector on stdin, never in argv', async ($, on) => {
  const seen = []
  session(on)
  detector(on, replaced, seen)
  await $.prompt.submit({ text: 'charge it with ' + KEY })
  expect(seen.length).toBe(1)
  expect(seen[0].argv).toEqual(['clowk', 'rewrite'])
  expect(JSON.stringify(seen[0].argv)).not.toContain(KEY)
  expect(JSON.parse(seen[0].init.stdin)).toEqual({ prompt: 'charge it with ' + KEY, cwd: '/work', session_id: 'sess-1' })
})

test('the skill pointer goes to the model as context, not into the text', async ($, on) => {
  session(on)
  detector(on, replaced)
  const out = await $.prompt.submit({ text: 'charge it with ' + KEY })
  expect(out.context).toEqual([POINTER])
  expect(out.text).not.toContain('[assistant:')
})

test('a clean prompt goes on untouched', async ($, on) => {
  session(on)
  detector(on, { value: { exitCode: 0, stderr: '', stdout: JSON.stringify({ text: 'refactor it', names: [], pointer: null }) } })
  const out = await $.prompt.submit({ text: 'refactor it' })
  expect(out.text).toBe('refactor it')
  expect(out.context).toBeUndefined()
})

test('unclowk goes through without asking the detector', async ($, on) => {
  const seen = []
  session(on)
  detector(on, replaced, seen)
  const out = await $.prompt.submit({ text: 'unclowk ' + KEY })
  expect(out.text).toBe('unclowk ' + KEY)
  expect(seen.length).toBe(0)
})

test('clowk missing from PATH drops the prompt', async ($, on) => {
  session(on)
  on('process.run', () => ({ deny: 'spawn clowk ENOENT' }))
  const out = await $.prompt.submit({ text: 'charge it with ' + KEY })
  expect(out.drop).toBeDefined()
  expect(out.drop).toContain('unclowk')
  expect(out.text).toBeUndefined()
})

test('a non-zero exit drops the prompt', async ($, on) => {
  session(on)
  detector(on, { value: { exitCode: 1, stdout: '', stderr: 'clowk rewrite: ValueError' } })
  const out = await $.prompt.submit({ text: 'charge it with ' + KEY })
  expect(out.drop).toBeDefined()
})

test('output that is not the expected JSON drops the prompt', async ($, on) => {
  session(on)
  detector(on, { value: { exitCode: 0, stdout: 'Traceback (most recent call last):', stderr: '' } })
  const out = await $.prompt.submit({ text: 'charge it with ' + KEY })
  expect(out.drop).toBeDefined()
})

test('JSON of the wrong shape drops the prompt', async ($, on) => {
  session(on)
  detector(on, { value: { exitCode: 0, stdout: JSON.stringify({ names: ['X'] }), stderr: '' } })
  const out = await $.prompt.submit({ text: 'charge it with ' + KEY })
  expect(out.drop).toBeDefined()
})

test('a clowk too old to know `rewrite` steps aside for the old settings hook', async ($, on) => {
  session(on)
  detector(on, { value: { exitCode: 1, stdout: '', stderr: 'Unknown command, or wrong number of arguments. Run `clowk help`.\n' } })
  const out = await $.prompt.submit({ text: 'charge it with ' + KEY })
  // Passed on unchanged: the old package's settings hook, beneath, blocks it the old way.
  expect(out.text).toBe('charge it with ' + KEY)
  expect(out.drop).toBeUndefined()
})

const ROW = (text) => ({
  plugin: 'clowk', component: 'UserMessage', surface: 'terminal', viewport: { columns: 100, rows: 30 },
  props: { text, origin: { kind: 'user' }, isExpanded: true },
})

test('the rewritten message row shows the name in teal and says the value stayed', async ($, on) => {
  session(on)
  detector(on, replaced)
  on('ui.render', () => ({ type: 'Text', props: {}, children: ['drawn by Claude Code'] }))
  await $.prompt.submit({ text: 'charge it with ' + KEY })
  const ui = await $.ui.mount(ROW('charge it with $STRIPE_SECRET_KEY'))
  // The line is Claude Code's prompt glyph and the text, with the name a teal span inside it.
  const line = await ui.find({ type: 'Text', text: /^❯ charge it with / })
  expect(line.props.backgroundColor).toBe('userMessageBackground')
  expect(line).toBeDefined()
  expect(JSON.stringify(line.children)).toContain('{"type":"Text","props":{"color":"#14b8a6","bold":true},"children":["$STRIPE_SECRET_KEY"]}')
  expect(await ui.find({ type: 'Text', text: /stayed on this machine/ })).toBeDefined()
})

test('a message clowk did not touch is drawn as Claude Code draws it', async ($, on) => {
  session(on)
  detector(on, replaced)
  on('ui.render', () => ({ type: 'Text', props: {}, children: ['drawn by Claude Code'] }))
  const ui = await $.ui.mount(ROW('refactor the parser'))
  expect(await ui.find({ type: 'Text', text: /stayed on this machine/ })).toBeUndefined()
  expect(await ui.find({ type: 'Text', text: 'drawn by Claude Code' })).toBeDefined()
})

test('a subagent hand-back or task notice goes on without asking the detector', async ($, on) => {
  const seen = []
  session(on)
  detector(on, replaced, seen)
  for (const kind of ['peer', 'task-notification']) {
    const out = await $.prompt.submit({ text: 'report: ' + KEY, origin: { kind } })
    expect(out.text).toBe('report: ' + KEY)
  }
  expect(seen.length).toBe(0)
})

test('what a person typed is checked whatever surface it came from', async ($, on) => {
  const seen = []
  session(on)
  detector(on, replaced, seen)
  for (const kind of ['composer', 'bridge', 'sdk', 'channel']) {
    await $.prompt.submit({ text: 'charge it with ' + KEY, origin: { kind } })
  }
  expect(seen.length).toBe(4)
})

const BASH_RAN = (stdout) => () => ({ result: { stdout, stderr: '', interrupted: false } })

test('a credential a command prints reaches the model as its name', async ($, on) => {
  session(on)
  detector(on, ($e) => {
    const text = JSON.parse($e.init.stdin).prompt.split(KEY).join('$STRIPE_SECRET_KEY')
    return { value: { exitCode: 0, stderr: '', stdout: JSON.stringify({ text, names: ['STRIPE_SECRET_KEY'], pointer: null }) } }
  })
  on('tool.call', BASH_RAN('STRIPE_KEY=' + KEY + '\n'))
  const out = await $.tool.call({ tool: 'Bash', command: 'printenv' })
  expect(out.result.stdout).toBe('STRIPE_KEY=$STRIPE_SECRET_KEY\n')
  expect(out.result.stderr).toBe('')
  expect(JSON.stringify(out)).not.toContain(KEY)
})

test('clean command output is handed over as it was', async ($, on) => {
  session(on)
  detector(on, ($e) => ({ value: { exitCode: 0, stderr: '', stdout: JSON.stringify({ text: JSON.parse($e.init.stdin).prompt, names: [], pointer: null }) } }))
  on('tool.call', BASH_RAN('hello\n'))
  const out = await $.tool.call({ tool: 'Bash', command: 'echo hello' })
  expect(out.result.stdout).toBe('hello\n')
})

test('a Read is never scrubbed, so a file read back and written out keeps its values', async ($, on) => {
  const seen = []
  session(on)
  detector(on, replaced, seen)
  on('tool.call', () => ({ result: { type: 'text', file: { filePath: '/w/.env', content: 'K=' + KEY } } }))
  const out = await $.tool.call({ tool: 'Read', file_path: '/w/.env' })
  expect(JSON.stringify(out)).toContain(KEY)
  expect(seen.length).toBe(0)
})

test('output clowk cannot check is withheld', async ($, on) => {
  session(on)
  on('process.run', () => ({ deny: 'spawn clowk ENOENT' }))
  on('tool.call', BASH_RAN('STRIPE_KEY=' + KEY))
  const out = await $.tool.call({ tool: 'Bash', command: 'printenv' })
  expect(out.deny).toContain('withheld')
})

test('session start says whether the guard is armed', async ($, on) => {
  const shown = []
  on('session.cwd', () => ({ value: '/work' }))
  on('session.id', () => ({ value: 'sess-1' }))
  on('ui.status', ($, e) => { shown.push(e.text); return { value: undefined } })
  on('session.start', () => ({ cwd: '/work' }))
  detector(on, { value: { exitCode: 1, stdout: '', stderr: 'Unknown command, or wrong number of arguments.' } })
  await $.session.start({ surface: 'terminal', isInteractive: true, cwd: '/work' })
  expect(shown.length).toBe(1)
  expect(shown[0]).toContain('clowk update')
})

test('an armed guard puts nothing on the status line', async ($, on) => {
  const shown = []
  on('session.cwd', () => ({ value: '/work' }))
  on('session.id', () => ({ value: 'sess-1' }))
  on('ui.status', ($, e) => { shown.push(e.text); return { value: undefined } })
  on('session.start', () => ({ cwd: '/work' }))
  detector(on, { value: { exitCode: 0, stderr: '', stdout: JSON.stringify({ text: '', names: [], pointer: null }) } })
  await $.session.start({ surface: 'terminal', isInteractive: true, cwd: '/work' })
  expect(shown).toEqual([undefined])
})
