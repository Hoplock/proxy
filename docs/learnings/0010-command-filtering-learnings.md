# 0010 — Command filtering & policy actions — Learnings

## Summary
- What shipped: command policy. `internal/filter` is the pure engine for D12's
  two exec tiers plus the interactive tier; `internal/filter/inspect` attaches
  it to 0009's pipeline as two inspectors on the `session` channel; the proxy
  builds one engine per connection from `route.Filter` and layers the
  inspectors into a per-session registry. No contract change (`api/` untouched).
- Key packages/files: `internal/filter/{doc,engine,pattern,restricted,argv,
  audit}.go` (+ `engine_test.go`, `restricted_test.go`, `tiers_test.go`,
  `audit_test.go`); `internal/filter/inspect/{doc,exec,interactive,register}.go`
  (+ tests); `internal/channel/{inspector,pipeline,registry}.go`;
  `internal/proxy/{session,channel,feedback}.go` + `filter_test.go`;
  `internal/control/contract.go` (one exported method); `docs/PLAN.md` §3, §6.2,
  §6.3; `README.md`.
- **Three tiers, and the exact words** (PLAN §6.3, D12) — these words are the
  same in the code, the docs, and the audit record, deliberately:

  | Tier (`tier=`) | Guarantee (`guarantee=`) | What it does |
  | --- | --- | --- |
  | `restricted_exec` | `enforcement` | Parses argv, default-deny against named executables + argument shapes, refuses anything it cannot parse into exactly one vector |
  | `filtered_exec` | `guardrail` | Ordered rule list, anchored glob against the whole exec string, first match wins, mode decides the rest |
  | `interactive` | `audit_signal` | Reassembles lines from keystrokes, **reports only**: never denies, never ends a session, never writes to the stream |
- **Audit event shape 0011 consumes** — `filter.AuditEvent`, event name
  `command.policy`, `priority: immediate` (D8) on every one. JSON fields:
  `event, priority, timestamp, session_id, channel_id, channel_type, request,
  tier, guarantee, action, outcome, enforced, command, matched, rule_index,
  detail, inspector`. `outcome` ∈ `allowed|warned|blocked|killed|observed`;
  `enforced=false` + `outcome=observed` is exactly the interactive tier.
  Delivered today through `filter.LogSink(logf)` as one line per event
  (`filter: priority=immediate event=command.policy …`); 0011 changes **where**
  they go, not what the fields are called.
- Key types: `filter.{Engine,New,Decision,Tier,Guarantee,AuditEvent,Sink,
  SinkFunc,LogSink,DiscardSink,ParseArgv,ParseError}`;
  `inspect.{Options,Exec,NewExec,Interactive,NewInteractive,Register,ExecName,
  InteractiveName,SessionChannel}`; `channel.{ActionTerminate,Terminate,
  TerminateWithDetail,Warn,Decision.Notice,Decision.CommandFailure,
  Decision.Terminates,Decision.AsCommandFailure,Info.ChannelID,Registry.Clone}`;
  `control.FilterPolicy.Validate` (exported wrapper over the existing rules).
- Policy inputs (all from the authorize response, none from `config.yaml` —
  **this phase adds no config keys**): `filter_policy.mode`
  (`whitelist|blacklist`, required), `filter_policy.rules[]`
  (`match`/`action`/`message`), `filter_policy.exec_mode`
  (`filtered`|`restricted`, absent = `filtered`),
  `filter_policy.restricted_exec.commands[]`.
- Decisions made/affected: D12 (implemented), D5/D5a, D2, D8, PLAN §4.3/§6.2/
  §6.3. No decision changed; PLAN §3, §6.2 and §6.3 gained implementation
  detail in this PR.
- Gotchas: `FilterRule.Match` is an **anchored glob**, not a substring — a
  substring match would make the guardrail appear to stop `sh -c '…'`, which is
  the promise D12 says it must not make. Restricted exec refuses `*`/`?`/`~`
  outside single quotes even though they are inert to the parser, because sshd
  hands the exec string to the target's login shell. A blocked command replies
  **true** to the exec request and reports the refusal as the channel's own
  failure (stderr + exit 254); the request-axis denial from 0009 still replies
  false, and the difference is what was refused.
- What the NEXT session must know: 0011 consumes `filter.AuditEvent` — take the
  struct, keep the field names, and replace `filter.LogSink` with a sink that
  routes `priority: immediate` to `POST /v1/logs/priority`. Anything registering
  an inspector whose knowledge is per connection uses
  `channel.Registry.Clone()` in `session.commandInspectors`, not the
  proxy-wide registry.

## Details

### Where each piece lives, and why the package split is load-bearing
`internal/filter` holds no SSH types at all. That is not tidiness: the tier this
product sells as a security boundary has to be testable directly against the
strings an attacker sends, without an SSH handshake in the way, and every
adversarial case in `restricted_test.go` is one line as a result.
`internal/filter/inspect` is the SSH-facing half — where a command is found in
the protocol, what the user is told, what the audit record says — and decides
nothing about policy.

### The engine
`filter.New(control.FilterPolicy)` compiles a policy or refuses it, validating
through `control.FilterPolicy.Validate()` (newly exported; the wire rules and
the engine's rules must not drift apart). A policy that does not compile fails
the session **closed** as an outage: there is no reading of "the policy could
not be understood" that permits a command. This is why two proxy tests that
built an authorize response without `filter_policy.mode` had to be corrected —
those responses were invalid per the contract, and the REST client would have
rejected them; only the test fake let them through.

`Engine.Filters()` reports whether a policy can ever say no. A blacklist with no
rules cannot, so `session.commandInspectors` registers nothing for it and the
session stays on 0009's straight-copy path. `TestASessionWithNothingToFilter…`
holds that.

`Decision.Reportable()` is the single predicate for "worth an audit event": a
rule matched, or the action is not `allow_and_log`. An unmatched command under a
blacklist is therefore silent here — logging every command is session capture,
which is 0011's job, not command policy's.

### Matching semantics (the contract left them to us)
`FilterRule.Match` is matched against the **whole** command (trimmed), with `*`
for any run of bytes and `?` for one, case-sensitive, `/` not special. The
anchoring is the important half: substring matching would block
`sh -c 'cat /etc/shadow'` under a `cat /etc/shadow` rule, and a guardrail that
appears to catch the shell wrapper is worse than no guardrail — the estate is
then sold a boundary it does not have. `TestTheShellWrapperCrossesTheGuardrail…`
(in `internal/filter` and again end-to-end in `internal/proxy`) asserts the
wrapper **reaches the target** under the guardrail and **does not** under the
boundary. Neither half may be softened.

### The parser (`ParseArgv`)
POSIX-ish word splitting with quote removal, and a refusal for everything else:
any control byte, NUL anywhere (single quotes included), invalid UTF-8, an
unterminated quote, `$`/backquote/backslash inside double quotes, and every one
of `; | & < > ( ) { } $ \` \ * ? [ ] ~ # !` outside quotes. The globbing
characters are refused even though the parser would treat them as literals: the
target's sshd runs an exec command through the user's login shell, so a `*` the
proxy approved as a literal is a `*` the target expands, and "the command that
runs is the argv that was approved" would be nearly-true instead of true. A
policy that wants a literal glob writes it `'*'`, which both we and the shell
reduce to the same thing.

### The exec inspector's presentation
| Action | Request reply | User sees | Channel |
| --- | --- | --- | --- |
| `allow_and_log` | relayed | nothing | runs |
| `warn_and_continue` | relayed | `Hoplock Proxy: Warning: this command is flagged by policy and has been recorded.` + operator message | runs |
| `block_command` (and every restricted-exec denial) | `true` | `Access denied. That command was blocked by policy.` + operator message | stderr, exit 254, closed |
| `kill_session` | `true` | `Hoplock Proxy: This session has been terminated by policy.` + operator message | whole session ends |

Answering the exec request `true` and then failing the channel is deliberate and
is the one place command policy differs from 0009's request axis: an SSH client
that gets a false reply prints its own generic "command failed" and stops
reading, which loses the sentence PLAN §4.3 requires. `failChannel` already made
this argument for setup failures; `Decision.CommandFailure` carries it for
command policy, and a request the session may never make (axis 2) still gets the
protocol-level refusal, because there the *request* is what was refused.

Nothing user-visible names the pattern, the mode, the permitted executables, or
even which tier decided. `TestTheUserLearnsThatPolicyStoppedThemAndNothingElse`
asserts the absence directly, which is the only way an absence stays true.

### The interactive tier
`Interactive` marks a channel when it sees `shell` or `pty-req` (which is why
`channel.Info` gained `ChannelID` — an inspector needs to correlate a request
with the stream that follows on the same channel), then wraps only the
client→target, non-stderr stream. The wrapper hands every byte on unchanged and
reassembles lines out of a copy: `\r`/`\n` end a line, backspace/DEL delete a
rune, `^U`/`^C` abandon it, ANSI escape sequences (`ESC [ … final`, `ESC O x`)
are skipped, other control bytes are dropped, and a line over 4096 bytes is
abandoned rather than truncated (half a command matched against a pattern is a
false report).

It never enforces — not even `kill_session`. That is a deliberate reading of
0009's stream contract ("policy is decided at open and request time and never
per byte") and of §6.3's "audit signal": an inspector that ended sessions off a
signal defeated by the left-arrow key would be enforcement in the one place the
plan says there is none. A `kill_session` rule matched on this tier is recorded
with `action=kill_session, enforced=false, outcome=observed` — the operator sees
what their policy would have done. If a future phase wants interactive
enforcement, D12 already says where it belongs: restricted exec, or 0015/0016's
target-side enforcement points.

An exec channel's stdin is never scanned, so a piped file does not arrive in the
security feed as a series of commands.

### Changes to 0009's pipeline
Additive, and each one paid for by this phase's requirements:
- `ActionTerminate` + `Terminate`/`TerminateWithDetail` — `kill_session` needs a
  decision that refuses the event *and* ends the session, while session teardown
  stays the transport's (`session.kill`, the same path a revocation takes).
  `Denied()` returns true for it, so no existing caller can read it as a yes.
- `Decision.Notice` + `Warn(notice, detail)` — warn-and-continue is the one
  shape 0009 had no vocabulary for: the event proceeds and the user is told.
- `Decision.CommandFailure` + `AsCommandFailure()` — see the presentation table.
- `Info.ChannelID`, assigned per channel by the pipeline — correlation and the
  audit record.
- `Registry.Clone()` — a per-session inspector layer, because a policy fetched
  per connection (D2) cannot live in the proxy-wide registry.

### Testing notes
- Engine: both modes, all four actions, per-rule actions, first-match-wins,
  mode defaults, both degenerate lists, and the compile refusals.
- Restricted: approved shapes, every denial class, and a parse table covering
  quoting, NUL (including inside single quotes), invalid UTF-8, unterminated
  quotes, substitution, redirection, newlines, globs, tildes and backslashes.
- Proxy integration (`internal/proxy/filter_test.go`): one test per policy
  sentence through a real SSH client — blacklist block, whitelist default, warn,
  kill, restricted allow+deny, the bypass test, the interactive tier (the echo
  from the stand-in target is the proof the stream was untouched), and the
  pass-through path for a policy that filters nothing.

### Follow-ups (no new prompts added)
- 0011 replaces `filter.LogSink` with the real priority path; the event struct
  is ready for it.
- `Engine.Interactive` under `exec_mode: restricted` reports every line the
  boundary would not have permitted. On a route that permits both a shell and a
  restricted-exec policy that is a lot of events — which is itself the signal,
  since D12 says such a route has no boundary. If it proves noisy in the field,
  0011's shipper is the place to sample it, not the engine.
