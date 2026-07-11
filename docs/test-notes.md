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
