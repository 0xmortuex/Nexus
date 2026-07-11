# Test notes

Development happens on Linux, where the WPF app compiles (`EnableWindowsTargeting`)
but cannot run. Each stage is verified three ways: a clean `dotnet build`
(warnings are errors), `dotnet test` on the pure-logic Core library, and the
growing manual checklist in `manual-test-checklist.md` for the first run on a
real Windows machine.

## Stage 1 — Core process engine

`dotnet build`: clean, 0 warnings. `dotnet test`: 15/15 passed.

Covered by automated tests (run on Linux):
- `GetLogicalProcessorInformationEx` buffer parsing against synthetic buffers with
  winnt.h layout: hybrid P+E cores (i7-12700K-like), homogeneous SMT, SMT-off,
  truncated and empty buffers, records of irrelevant relationship types.
- P-core/E-core/physical-core/custom affinity mask derivation, including the
  "custom mask selects zero valid CPUs → treat as unrestricted" edge.
- `GetSystemCpuSetInformation` parsing and the merge of CPU set IDs onto logical CPUs.
- Rules JSON round-trip (all fields, enums as strings), unknown-property tolerance,
  corrupt-file recovery (renamed `.bad`, defaults returned), atomic write leaves no
  temp file, case-insensitive and extension-tolerant rule lookup, persistence across
  repository instances.

Not testable off-Windows (deferred to the manual checklist):
- The actual P/Invoke calls (`SetPriorityClass`, `SetProcessAffinityMask`,
  `SetProcessDefaultCpuSets`, `NtSetInformationProcess` IO priority,
  `SetProcessInformation` memory priority/EcoQoS, working-set trim).
- WMI `Win32_ProcessStartTrace` event delivery and the automatic failover to the
  polling watcher.

Design note: every mutating call goes through `ProcessApi`, which checks the
never-touch list first, never throws, and returns `false` + an error string that
callers log. The topology parsers are pure functions over `byte[]` specifically so
their offset arithmetic is testable here.

## Stage 2 — ProBalance (dynamic restraint)

`dotnet build`: clean, 0 warnings. `dotnet test`: 28/28 passed (13 new).

Covered by automated tests — the engine is a pure state machine, so all timing
behavior runs on a fake clock:
- No restraint until total load exceeds the enter threshold for the full sustain
  window; a dip below the threshold restarts the clock (brief spikes are immune).
- Foreground process, built-in exempt list, and user exclusions (case/extension
  insensitive) are never restrained.
- Restore requires the calm window (load ≤ exit threshold for ReleaseMs) AND the
  minimum restraint duration; becoming the foreground app restores immediately;
  process exit yields a forget-only action (no API call on a dead PID).
- Optional per-process sustain window filters single-sample CPU spikes.
- Simultaneous-restraint cap enforced.
- Disabling ProBalance restores every restrained process on the next tick.
- Anti-flap: 120 s of fast oscillation across the hysteresis dead zone produces
  zero actions; slow 30 s on/off cycles stay bounded at ≤ 1 restrain/restore pair
  per cycle with restrains always balanced by restores.

Not testable off-Windows (deferred to the manual checklist):
- `NtQuerySystemInformation` sampling accuracy (per-core %, per-process %,
  image-name pointer translation in the pinned buffer) — verify against Task
  Manager on the first Windows run.
- `GetForegroundWindow` PID resolution; actual priority save/restore round-trip.

## Stage 3 — Process Lasso parity features

`dotnet build`: clean, 0 warnings. `dotnet test`: 46/46 passed (18 new).

Covered by automated tests:
- Instance limits: newest instances selected for kill (start-time then PID
  ordering), case-insensitive matching, under-limit/disabled/zero-limit no-ops.
- Watchdog: fires only after the full sustained breach; dropping below the
  threshold resets the clock; per-(rule, pid) cooldown blocks immediate
  retriggers; CPU and RAM thresholds are OR-ed (RAM breach fires even with idle
  CPU).
- IdleSaver state machine: enters Power Saver exactly once at the idle threshold,
  restores exactly once on input, suppression (game mode) both blocks entry and
  forces exit, disabling while active exits cleanly.
- SmartTrim: selects only background processes over the RAM threshold (foreground,
  exempt, and system pseudo-PIDs skipped), honors the pass interval and the
  per-process cooldown, disabled = selects nothing.
- powercfg output parsing: GUID extraction from `/duplicatescheme` and localized
  (French) `/getactivescheme` output, `/list` scheme enumeration, no-GUID → null.

Not testable off-Windows (deferred to the manual checklist):
- powercfg execution itself (plan cloning, CPMINCORES write, plan switching).
- `GetLastInputInfo` idle math on a live session (including tick wraparound).
- `SetThreadExecutionState` behavior (verify the PC doesn't sleep with Keep Awake
  on; the flag is asserted from a dedicated thread and re-asserted hourly).
- Kill/restart of real processes and access-denied handling for elevated targets.

## Stage 4 — Game Mode

`dotnet build`: clean, 0 warnings. `dotnet test`: 60/60 passed (14 new).

Covered by automated tests:
- Game detection: borderless/exclusive fullscreen (caption-less window covering the
  monitor ±2 px) detected; windowed and maximized-with-caption apps rejected; known
  non-games (browsers, players, OBS, launchers, PowerPoint) rejected even when
  fullscreen; user game list wins even windowed; user ignore list beats the game
  list; partial coverage on ultrawide rejected; protected processes never count.
- Intended-state journal: persists across instances (crash simulation via fresh
  object over the same file), first mutation record per PID wins (originals are
  never overwritten by later demotions), previous power plan is never overwritten,
  clear leaves nothing pending. Journal writes are flushed to disk before the
  corresponding mutation is applied (write-ahead).

Not testable off-Windows (deferred to the manual checklist):
- Live foreground polling (GetWindowRect / GetWindowLongPtr / GetMonitorInfo).
- End-to-end enter/exit: priority + P-core pinning of a real game, hog demotion
  with EcoQoS, power plan switch, wuauserv stop/start, and full revert on exit.
- Crash recovery on a real machine: kill Nexus mid-game-mode, relaunch, verify
  every change is rolled back.

## Stage 5 — Tweaks, debloat, cleaner, startup manager

`dotnet build`: clean, 0 warnings. `dotnet test`: 73/73 passed (13 new).

Covered by automated tests:
- Catalog integrity ("no decorative toggles" enforced by test): every tweak has a
  non-empty description, at least one registry op or command, undo args on every
  command, rooted HKEY_ paths, known value kinds, unique IDs; per-adapter tweaks
  carry the {adapter} placeholder; descriptions must not contain hype words.
- Cleaner path safety: deletion allowed only strictly under target roots —
  `..` traversal, same-prefix sibling dirs (C:\Temp2 vs C:\Temp), and the root
  itself are all rejected; thumbnail target is pattern-scoped to thumbcache_*.db.
- Tweak state store: applied tweaks persist with captured originals (including
  Existed=false), re-apply replaces instead of duplicating, first service-start
  original wins (SysMain toggled twice still restores the true value), disabled
  scheduled tasks dedupe case-insensitively and round-trip.

Not testable off-Windows (deferred to the manual checklist):
- Actual registry writes/captures/restores (verify a tweak → undo → regedit diff).
- reg.exe export backups, System Restore point creation (and its 24 h throttle
  warning path), powercfg /hibernate off|on.
- Service stop + start-type changes, schtasks disable/enable, Remove-AppxPackage.
- StartupApproved byte format interop with Task Manager's Startup page.
- Real cache sizes/deletions with in-use file skipping.
