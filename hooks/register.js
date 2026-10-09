// clowk as a Claude Code mod (Claude Code v2.1.287+).
//
// A settings hook can only block a prompt, which is why clowk's flow everywhere else is block,
// copy a rewrite to the clipboard, repaste. A mod's `prompt.submit` can REWRITE it, so here the
// credential is replaced by its $NAME in place and the prompt goes on: nothing to repaste. The same
// goes for what a command prints: `tool.call` scrubs a command's output before the model reads it.
//
// Detection and filing stay in Python (`clowk rewrite`), so there is one detector and one vault
// writer. Text goes to it on stdin, never in argv, where `ps` would show it. ~85 ms a call, measured
// (interpreter start plus compiling the ruleset) -- small next to a model turn, so there is no
// JavaScript pre-filter that could disagree with the detector and let something through.
//
// Fails CLOSED. A mod hook that throws or times out is skipped by default, which would send the
// credential, so every failure -- clowk missing, a non-zero exit, output that isn't the JSON it
// should be, a timeout -- ends in a refusal, and `.catch` refuses for anything that escapes.
// `unclowk` at the start of a message is the deliberate way through, checked here so it works even
// when Python can't run.
//
// One failure is not closed: a clowk too old to know `rewrite`. The plugin and the Python package
// update separately, so that skew is ordinary, and the old package's settings hooks are still
// registered and still block. So the mod steps aside, the old block-and-repaste flow handles it,
// and the status line says to run `clowk update`.
//
// The settings hooks `clowk setup` registers stay as the backstop. They run beneath the mod chain
// and see the rewritten text, so they pass it; they still block when the mod isn't running
// (--bare, --safe-mode, a policy that refuses user mods, a crashed plugin worker).

const BYPASS = /^\s*unclowk/i
// Turns Claude Code starts on the model's behalf: a subagent's hand-back, a background task's
// notice, another session's message. Whatever credential is in one came out of a model or a tool,
// so the model has had it already; rewriting only files junk in the vault, and Claude Code stores a
// peer hand-back as delivered anyway (measured, 2.1.295). The settings hook skips the same turns by
// their `source: "system"`. What a person wrote -- the composer, Remote Control, the SDK, a channel,
// a schedule -- is checked.
const MACHINE_AUTHORED = new Set([
  'task-notification', 'peer', 'peer-send-message', 'projects-relay', 'coordinator', 'observer', 'observer-activity',
])
// Read is left out on purpose: an agent edits what it reads, and a file read back with `$NAME` in it
// and written out whole would replace the real value with the name.
const SCRUBBED_TOOLS = ['Bash', 'BashOutput', 'Grep', 'WebFetch', 'WebSearch']
const DETECT_TIMEOUT_MS = 20000
// Joins a tool result's strings for one detector call. A NUL never appears in a credential, so no
// finding can span two of them.
const SEP = '\n\u0000clowk\u0000\n'

const UNSENT = 'clowk could not check this message for credentials, so it was not sent. '
const FIX = {
  missing: 'Is `clowk` installed and on your PATH? Run `clowk setup` to check. ',
  broken: 'Run `clowk setup` to check the install. ',
}
const OVERRIDE = 'To send this message unchecked, start it with  unclowk'
const WITHHELD = 'clowk could not check this output for credentials, so it was withheld. Run `clowk setup` to check the install.'
// Claude Code draws a plugin's status line as a notice -- "⚠ clowk: <text>" -- so it is only used
// when something needs doing. An armed guard says nothing there; the note under a rewritten message
// is where it shows itself.
const STATUS = {
  ok: undefined,
  old: 'older than its plugin, so credentials are blocked, not rewritten · run `clowk update`',
  missing: 'not found on PATH, so messages are held back · install clowk, or start a message with unclowk',
}
const TEAL = '#14b8a6'

class TooOld extends Error {}

// Module state: it resets on a reload, and a resumed session's old rows simply draw plainly.
const rewrote = new Map()   // rewritten prompt -> the names put into it, for the message row

export function register(on) {
  on('session.start', async ($, e, next) => {
    const started = await next(e)
    $.ui.status(STATUS[await health($)])
    return started
  })
  on('prompt.submit', guard).catch(async ($, e, next) => {
    // Already passed on: that result stands, and nothing runs twice.
    if (next.called) return next(e)
    return { drop: UNSENT + FIX.broken + OVERRIDE + ' (' + next.error.kind + ')' }
  })
  // Anything that escapes scrub withholds the output rather than handing it over unchecked.
  on('tool.call', { tool: SCRUBBED_TOOLS }, scrub).catch(async () => ({ deny: WITHHELD }))
  on('tool.call', { tool: /^mcp__/ }, scrub).catch(async () => ({ deny: WITHHELD }))
  // Claude Code's row, redrawn with the $NAMEs in teal, and one line under it saying what happened.
  // A rewrite that happens silently reads like magic, or like a bug.
  on('ui.render', { component: 'UserMessage' }, async ($, e, next) => {
    const names = rewrote.get(e.props.text)
    if (!names) return next(e)
    const { Box, Text } = $.ui.resolve(e)
    return Box({ flexDirection: 'column', children: [message(Box, Text, e.props.text, names), note(Box, Text, names)] })
  })
}

async function guard($, e, next) {
  if (BYPASS.test(e.text) || MACHINE_AUTHORED.has(e.origin?.kind)) return next(e)
  let result
  try {
    result = await detect($, e.text)
  } catch (err) {
    if (err instanceof TooOld) return next(e)   // the old settings hook handles it
    return { drop: UNSENT + (err.missing ? FIX.missing : FIX.broken) + OVERRIDE }
  }
  if (result.names.length === 0) return next(e)
  rewrote.set(result.text, result.names)
  // The pointer is for the model only: the user's message stays what they typed, minus the value.
  if (!result.pointer) return next({ ...e, text: result.text })
  return next({ ...e, text: result.text, context: [...(e.context ?? []), result.pointer] })
}

async function scrub($, e, next) {
  const ran = await next(e)
  if (!ran || ran.deny || ran.result === undefined) return ran
  const leaves = []
  collect(ran.result, leaves)
  if (leaves.length === 0) return ran
  let result
  try {
    result = await detect($, leaves.join(SEP))
  } catch (err) {
    if (err instanceof TooOld) return ran
    return { deny: WITHHELD }
  }
  if (result.names.length === 0) return ran
  const parts = result.text.split(SEP)
  if (parts.length !== leaves.length) return { deny: WITHHELD }
  const scrubbed = { result: replace(ran.result, parts, { i: 0 }) }
  return result.pointer ? { ...scrubbed, context: [result.pointer] } : scrubbed
}

// `clowk rewrite` on one text. Throws TooOld, or an Error with `missing` set when clowk can't start.
async function detect($, text) {
  let run
  try {
    run = await $.process.run(['clowk', 'rewrite'], {
      stdin: JSON.stringify({ prompt: text, cwd: await $.session.cwd(), session_id: await $.session.id() }),
      timeoutMs: DETECT_TIMEOUT_MS,
    })
  } catch (err) {
    throw Object.assign(new Error('clowk did not run'), { missing: true })
  }
  if (run.exitCode !== 0) {
    if (run.stderr.includes('Unknown command')) throw new TooOld('clowk has no rewrite')
    throw new Error('clowk rewrite failed')
  }
  const result = JSON.parse(run.stdout)
  if (typeof result.text !== 'string' || !Array.isArray(result.names)) throw new Error('unexpected output')
  return result
}

async function health($) {
  try {
    await detect($, '')
    return 'ok'
  } catch (err) {
    return err instanceof TooOld ? 'old' : 'missing'
  }
}

function collect(value, leaves) {
  if (typeof value === 'string') leaves.push(value)
  else if (Array.isArray(value)) value.forEach((v) => collect(v, leaves))
  else if (value && typeof value === 'object') Object.values(value).forEach((v) => collect(v, leaves))
}

// Rebuilds `value` with its strings, in `collect` order, taken from `parts`. Never mutates.
function replace(value, parts, at) {
  if (typeof value === 'string') return parts[at.i++]
  if (Array.isArray(value)) return value.map((v) => replace(v, parts, at))
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, replace(v, parts, at)]))
  }
  return value
}

function message(Box, Text, text, names) {
  const pattern = new RegExp('(\\$(?:' + names.map(escapeRe).join('|') + ')(?![A-Za-z0-9_]))')
  const lines = text.split('\n').map((line, i) => Text({
    children: [i === 0 ? '❯ ' : '  ', ...line.split(pattern).map((part, j) =>
      j % 2 === 1 ? Text({ color: TEAL, bold: true, children: [part] }) : part)],
  }))
  return Box({ flexDirection: 'column', children: lines })
}

function note(Box, Text, names) {
  return Box({
    flexDirection: 'row',
    paddingLeft: 2,
    children: [
      Text({ color: TEAL, bold: true, children: ['🔒 clowk  '] }),
      Text({ color: TEAL, children: [names.map((n) => '$' + n).join(', ')] }),
      Text({ dimColor: true, children: [' stayed on this machine · the model gets the name, never the value'] }),
    ],
  })
}

function escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}
