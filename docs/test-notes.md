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
