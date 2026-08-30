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

## Stage 6 — WPF UI

`dotnet build`: clean, 0 warnings. `dotnet test`: 73/73 passed (UI has no
Linux-runnable logic; view models are thin adapters over the tested services).

Notes for the first Windows run:
- The theme restyles Button/TabItem templates; verify no white-on-white areas.
- Chart controls are custom OnRender code — verify the sparkline and per-core
  bars actually draw (an empty rect means the Values binding broke).
- The WinForms global usings were removed project-wide (`<Using Remove=…>`);
  TrayIconService is the only WinForms consumer and fully qualifies its types.

## Stage 7 — Hardening & ship

`dotnet build -c Release`: clean. `dotnet test`: 73/73.
`dotnet publish src/Nexus.App -c Release -r win-x64 --self-contained
-p:PublishSingleFile=true` → single 66 MB Nexus.exe (compression on); the
embedded manifest was verified present in the apphost (`requireAdministrator`
and `PerMonitorV2` both found in the binary).

P/Invoke audit: all DllImports live in `Interop/NativeMethods.cs` (internal);
every call site is wrapped — ProcessApi (WithHandle + never-touch check),
CpuTopologyProvider, SystemSampler (guarded by ProBalanceService.Tick),
ForegroundInfo, ForegroundMonitor, IdleSaverService, KeepAwakeService all
catch-and-log. No raw P/Invoke escapes to feature code, so the planned
InteropGuard helper had no call sites and was deliberately not added.

Safety review: kills route through EnforcementService.TryKill or the Processes
tab, both gated on ProcessSafety.IsProtected; priority/affinity/EcoQoS/trim all
route through ProcessApi which re-checks the never-touch list; ProBalance and
SmartTrim additionally use the restraint-exempt list (shell, audio, self).

Final verification on Windows: `docs/manual-test-checklist.md` (7 sections,
covers every feature including the Game Mode crash test and anti-cheat
never-touch verification).

## Parity pass — Lasso Pro + Hone premium gap closure

`dotnet build`: clean. `dotnet test`: 75/75 (2 new persistence cases).
Single-file publish re-verified (66 MB).

Added to close remaining gaps (see `docs/parity-matrix.md` for the full accounting):
- **CPU Limiter** (Lasso Pro) — `CpuLimiterService`, hard % cap via Job Object CPU
  rate control; wired to the Processes context menu and to `ProcessRule.CpuLimitPct`.
- **Foreground boosting** (Lasso) — `ForegroundBoostService`, raises the focused
  app to AboveNormal and restores on blur; only touches Normal-priority processes.
- **Keep-awake-while-running + auto-restart** (Lasso Pro) — `RuleLifecycleService`
  with a `KillTracker` so Nexus-initiated kills never trigger a restart, plus a
  3-restarts-per-5-min crash-loop backoff.
- **Standby-list purge** (Hone/ISLC) — `StandbyListService` via
  `NtSetSystemInformation` + SeProfileSingleProcessPrivilege; manual + auto-below-threshold.
- **DNS benchmark & switch** (Hone premium) — `DnsService`, ICMP-timed public
  resolvers, per-adapter apply with captured-original undo (DHCP vs static).
- Four gaming tweaks: Windows Game Mode, fullscreen-optimizations off,
  global power-throttling off, Sticky Keys shortcut off.

Automated coverage for the new work is limited to what's pure (rule field
round-trip, DNS backup-state round-trip); the Job Object cap, standby purge,
foreground boost timing, and netsh DNS changes are interop and are in the manual
checklist. Deliberately NOT built (documented in the parity matrix): in-game FPS
overlay (anti-cheat hazard), hardware temperature monitoring (needs a
blocklisted kernel driver), "AI" auto-tuning (wrapper over existing tweaks).

## Stage 8 — Sentinel (advisory security) and the measurement layer

`dotnet build`: clean, 0 warnings (warnings are errors). `dotnet test`: 355/355.
Single-file publish re-verified — and it now produces **two** binaries,
`Nexus.exe` (63 MB) plus `Nexus.Scanner.exe` (11.6 MB, self-contained and
trimmed), with the publish failing outright if the scanner is absent.

### Covered by automated tests (run anywhere)

Everything in `Nexus.Core` is pure and testable off-Windows, and the security
work was deliberately shaped so that the parts worth getting right live there:

- **Verdict fusion** — weights, per-source diminishing returns, the per-source cap
  that forces corroboration, clean-vs-unknown coverage, signal ordering, and the
  rule that a user-trusted file never raises an alert.
- **Consent** — single-use, target-bound, action-bound, expiring, and concurrent
  redemption. These tests are the enforcement of "Sentinel never acts on its own";
  if they pass, the property holds by construction rather than by review.
- **Quarantine journal** — write-ahead ordering, crash-recoverable states, the
  refusal to restore something that was never moved.
- **PE parsing** — every prefix of a valid file, 300 randomly mutated files, and
  the integer-overflow case that a naive bounds check lets through.
- **Archive inspection** — real ZIPs built in memory, including an 8 MB zip bomb,
  traversal in both slash directions, drive-absolute and bare `..`, nested
  archives, entry-count overflow, and traversal false-positives (`my..file.txt`).
- **Script analysis** — obfuscation, defence tampering, download-and-run, and
  UTF-16 decoding, which is the case that silently fails and takes every keyword
  check with it.
- **Ransomware detection** — canary handling, uniform-extension renames, ransom
  notes, cooldown, window pruning, and the negative cases that matter most: a
  document burst alone, a build-output burst, and a bulk photo rename must all
  stay quiet.
- **Latency statistics** — the headline test is that two runs of an *unchanged*
  system report "no measurable difference". If that ever reports an improvement,
  every performance claim the app makes is worthless.
- **Throttle analysis** — power-plan vs firmware attribution, hybrid CPUs, and the
  requirement that a firmware limit is never presented as fixable.
- **Verdict cache** — stamp invalidation on size, timestamp, path and ruleset
  change, plus index consistency across eviction.

### Needs a real Windows machine (see `manual-test-checklist.md` §8–10)

Everything that talks to the OS, which is most of the App layer:
WinVerifyTrust results, the WMI behaviour watcher, autorun enumeration, Defender
queries, `GetExtendedTcpTable`, FileSystemWatcher behaviour under load, canary
planting, the latency probe against real hardware, and quarantine file moves.

Three of those were spot-verified during development rather than left entirely to
the checklist: the scanner worker end-to-end (including on the published, trimmed
binary), the Defender query shape — which is how the non-elevated placeholder
behaviour was found — and the TCP table P/Invoke, cross-checked against `netstat`
because a port byte-order bug is silently wrong rather than obviously broken.

### Not testable here, and why

`SentinelResetService`, `RansomwareGuardService` and `ScheduledScanService` live in
`Nexus.App`, which the test project does not reference (it references `Core` only,
so the suite stays runnable off-Windows). Their logic was kept as thin as possible
for that reason — the decisions live in Core, these classes are plumbing. The one
that genuinely deserves a test and cannot have one here is the restore-defaults
ordering, which is why it is the first item in checklist §10 and the only one
flagged as touching user data.
