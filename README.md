# Nexus

A Windows game/system optimizer in the spirit of Process Lasso + Hone:
persistent per-process rules, ProBalance-style dynamic restraint, watchdog and
instance-limit enforcement, power-plan automation, a crash-safe Game Mode, and a
set of honest system tweaks with mandatory backups and working undo.

**Requirements:** Windows 10/11 x64, administrator (the app manifest enforces it).

## Features

- **Process engine** — per-exe rules for priority, CPU affinity / CPU sets
  (P-core, E-core, physical-core aware on hybrid CPUs), IO priority, memory
  priority, EcoQoS efficiency mode, working-set trim; applied the instant a
  process launches (WMI event trace with polling failover).
- **ProBalance** — when total CPU load stays above the threshold, background
  hogs are temporarily lowered to BelowNormal and restored when load subsides
  or they come to the foreground. Hysteresis on both edges; every event logged.
- **Enforcement** — instance-count limits, disallowed-process termination,
  per-exe watchdogs (CPU/RAM over threshold for N seconds → lower / trim /
  restart / kill).
- **Power** — "Nexus Performance" plan cloned from Ultimate Performance with
  core parking disabled; IdleSaver drops to Power Saver when you're away;
  Keep Awake toggle.
- **Game Mode** — fullscreen/borderless auto-detection plus a user game list;
  boosts the game, demotes hogs, switches power plan, optionally pauses Windows
  Update — all journaled to disk first, so even a crash restores every change
  on the next start.
- **Tweaks — measure before trusting** — curated registry tweaks with honest
  one-line descriptions, a System Restore point plus mandatory .reg backups
  before anything is written, and per-tweak undo. Disable-only debloat
  (services + telemetry tasks), an Appx removal checklist (nothing pre-checked),
  a cache cleaner with size preview, and an enable/disable-only startup manager.
- **UI** — dark WPF app with Dashboard, Processes, Game Mode, Tweaks, Log, and
  Settings tabs; tray icon with quick toggles; start-with-Windows via an
  elevated scheduled task; a "Restore all defaults" button that undoes
  everything Nexus ever changed.

Every switch in the UI calls a real Windows API — there are no decorative
toggles, and the tweak descriptions do not promise FPS.

## Building

.NET 8 SDK (a Microsoft build — the Ubuntu/source-build SDK lacks the
WindowsDesktop targets). Builds on Windows or cross-compiles from Linux:

```
dotnet build                # EnableWindowsTargeting is set in Directory.Build.props
dotnet test                 # pure-logic tests, run anywhere
dotnet publish src/Nexus.App -c Release -r win-x64 --self-contained -p:PublishSingleFile=true
```

The publish output is a single `Nexus.exe`. See `docs/manual-test-checklist.md`
for the first-run verification list and `docs/test-notes.md` for what is covered
by the automated tests versus what needs a live Windows machine.

## Safety

- A hard-coded never-touch list (csrss, lsass, audiodg, Defender, EasyAntiCheat,
  BattlEye, Vanguard, FACEIT…) is checked before *every* mutation, not just kills.
- Game Mode writes a write-ahead journal (`intended-state.json`) before each
  change; crash recovery reverts it on the next start.
- Tweaks refuse to apply if their registry backup fails.
- Debloat disables — it never deletes services or tasks.
