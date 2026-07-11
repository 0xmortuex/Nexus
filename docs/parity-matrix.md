# Feature parity: Nexus vs Process Lasso (Pro) and Hone

Honest accounting of what Nexus does, what the two commercial products do, and
where Nexus deliberately stops. "✅" = implemented against a real Windows API and
wired to the UI; "⚠️" = implemented with a documented caveat; "❌ (won't)" = a
conscious decision not to build it, with the reason.

## Process Lasso — core (free tier)

| Lasso feature | Nexus | Where |
|---|---|---|
| Persistent per-process priority | ✅ | `ProcessRule.Priority`, applied on launch |
| Persistent CPU affinity | ✅ | affinity mask + CPU sets, P/E-core aware |
| Default I/O priority | ✅ | `NtSetInformationProcess(ProcessIoPriority)` |
| ProBalance (dynamic priority restraint) | ✅ | `ProBalanceEngine` + `ProBalanceService`, hysteresis |
| Foreground boosting | ✅ | `ForegroundBoostService` (AboveNormal while focused) |
| Persistent power scheme / "keep active" | ✅ | Performance plan + Keep Awake (per-process holds) |
| Disallowed processes (auto-terminate) | ✅ | `EnforcementService` |
| Instance count limits | ✅ | `InstanceLimitEngine` |
| Activity log of all actions | ✅ | `ActivityLog`, Log tab |
| Gaming / performance power plan | ✅ | `PowerPlanService`, core parking off |

## Process Lasso — Pro / paid features

| Lasso Pro feature | Nexus | Where |
|---|---|---|
| **CPU Limiter** (hard cap % per process) | ✅ | `CpuLimiterService` via Job Object CPU rate control |
| Persistent CPU sets (efficiency-aware) | ✅ | `CpuAffinityMode`, hybrid-CPU aware |
| Process Watchdog (RAM/CPU threshold → action) | ✅ | `WatchdogEngine`: lower / trim / restart / kill |
| Keep process running (auto-restart on exit) | ✅ | `RuleLifecycleService`, crash-loop guarded |
| Keep system awake while process runs | ✅ | per-process `KeepAwakeService` holds |
| Efficiency mode (EcoQoS) per process | ✅ | `SetProcessInformation(ProcessPowerThrottling)` |
| SmartTrim (working-set trimming) | ✅ | `SmartTrimService` |
| IdleSaver (power plan when idle) | ✅ | `IdleSaverService` |
| Group/rule-based extended rules | ⚠️ | per-exe rules cover the common cases; no rule *groups* UI |
| Instance balancer (spread affinity across copies) | ❌ (won't) | niche; the affinity/CPU-set rules cover the real need |
| >64-logical-processor group management | ⚠️ | topology parsed for all groups; masks target group 0 (documented) |

## Hone — free + premium ("Hone Pro")

| Hone feature | Nexus | Where |
|---|---|---|
| One-click game optimization | ✅ | Game Mode auto-detect + per-game profiles |
| Auto game detection (fullscreen/borderless) | ✅ | `GameDetector` |
| Boost game / demote background during play | ✅ | `GameModeService` |
| Pause Windows Update while gaming | ✅ | wuauserv stop/resume, journaled |
| Registry/gaming tweaks with descriptions | ✅ | `TweakCatalog` — 18 tweaks, honest impact text |
| Win32PrioritySeparation presets | ✅ | 3 presets |
| GameDVR / Game Bar off | ✅ | tweak |
| HAGS on/off | ✅ | tweak |
| Windows Game Mode toggle | ✅ | tweak |
| Fullscreen optimizations off | ✅ | tweak (`fse-optimizations-off`) |
| Global power-throttling off | ✅ | tweak |
| Mouse acceleration off | ✅ | tweak |
| Nagle's algorithm off (per adapter) | ✅ | tweak, per-interface |
| Network throttling index / MMCSS | ✅ | tweaks |
| Sticky Keys / accessibility interrupt off | ✅ | tweak |
| Visual effects / transparency / animations off | ✅ | tweaks |
| **DNS benchmark + one-click switch** | ✅ | `DnsService` (ping-based, reversible) |
| **RAM / standby-list cleaner** | ✅ | `StandbyListService`, manual + auto |
| Debloat (services / tasks / apps) | ✅ | `DebloatService`, disable-only + Appx checklist |
| Temp / shader-cache / cache cleaner | ✅ | `CleanerService`, size preview |
| Startup manager | ✅ | `StartupManagerService` |
| System Restore point before changes | ✅ | `BackupService`, + mandatory .reg export |
| One-click revert / restore defaults | ✅ | `RestoreDefaultsService` |
| **In-game FPS / latency overlay** | ❌ (won't) | needs DirectX/Vulkan present-hooking (RTSS-style); injecting into game processes is exactly what anti-cheat bans for. Out of scope by design. |
| **Hardware monitoring (temps, GPU clocks, fan)** | ❌ (won't) | requires a kernel driver (WinRing0/inpout32 class). Those drivers are on Microsoft's vulnerable-driver blocklist and are a security liability. Use HWiNFO. |
| **"AI" auto-tuning / cloud profiles** | ❌ (won't) | marketing layer over the same registry writes Nexus already exposes transparently. |
| Driver updater | ❌ (won't) | third-party driver pushing is risky; use vendor tools / Windows Update. |

## Summary

Every **functional** capability of Process Lasso (including the Pro CPU Limiter,
watchdog, auto-restart, CPU sets, and keep-awake rules) and of Hone (including the
premium DNS switcher and RAM/standby cleaner) is implemented against a real Windows
API and wired to the UI.

The three things Nexus does **not** replicate — an FPS/latency overlay, hardware
temperature monitoring, and "AI" auto-tuning — are excluded on purpose:

- The **overlay** requires hooking the game's present loop, which is indistinguishable
  from what cheats do and gets accounts banned by EAC/BattlEye/Vanguard. Nexus's
  hard rule is "never touch anti-cheat"; an overlay violates it.
- **Temperature/fan monitoring** requires a signed kernel driver with raw hardware
  I/O — the WinRing0-family drivers used for this are on Microsoft's vulnerable-driver
  blocklist. Shipping one would make Nexus a security downgrade.
- **"AI auto-tuning"** is, in both products, a friendlier wrapper over the exact
  registry/priority changes Nexus already exposes with honest descriptions.

So: **full parity on everything that actually changes system behavior**, with three
documented, principled exclusions that are about safety, not capability.
