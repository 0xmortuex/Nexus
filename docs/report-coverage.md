# Coverage of the "Advanced System Optimization Architectures" report

Every mechanism the report describes, mapped to what Nexus implements. "✅" = real
Windows API/registry mechanism, wired to the UI, reversible. "⚠️" = implemented
with an honest caveat. "❌ (won't)" = deliberately excluded, with the reason.

## Dynamic process management & CPU scheduling
| Report mechanism | Status | Where |
|---|---|---|
| Heuristic priority modulation (lower background under load) | ✅ | `ProBalanceEngine` |
| Priority class table (Idle…Realtime) | ✅ | `ProcessPriority`, Processes menu |
| Persistent affinity masking + topology awareness | ✅ | `ProcessRule`, `CpuTopology` (P/E, SMT, CCD-agnostic mask) |
| CPU Sets (soft affinity) vs hard affinity | ✅ | `CpuAffinityMode`, `UseCpuSets` |
| **Processor Group Extender (>64 cores)** | ❌ (won't) | Requires injecting a thread-reassignment shim into the target process (DLL injection / thread hooking). That is exactly what anti-cheat bans, and it violates Nexus's never-inject rule. Documented limitation: masks target group 0. |
| Dynamic CPU limiter (hard throttle) | ✅ | `CpuLimiterService` — Job Object CPU rate control (strictly better than the report's affinity-shuffle method: kernel-enforced, no crash risk) |
| **Instance Balancer** | ✅ | `InstanceBalancerEngine` + `InstanceBalancerService` |

## API-level power / EcoQoS
| Report mechanism | Status | Where |
|---|---|---|
| EcoQoS on background (`SetProcessInformation` / `ProcessPowerThrottling`) | ✅ | `ProcessApi.TrySetEfficiencyMode` |
| `PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION` on background | ✅ | set together with EXECUTION_SPEED when enabling efficiency mode |
| Disable EcoQoS on foreground game | ✅ | Game Mode forces it off for the game |
| Watchdog rules (RAM/CPU threshold → action) | ✅ | `WatchdogEngine` |
| Power-plan automation (Ultimate/Highest Perf on game, revert on exit) | ✅ | `PowerPlanService`, Game Mode |

## Anti-cheat-safe priority (IFEO)
| Report mechanism | Status | Where |
|---|---|---|
| Registry-enforced priority via Image File Execution Options | ✅ | `IfeoService` — `PerfOptions\CpuPriorityClass/IoPriority/PagePriority`. Kernel applies it at process creation, before anti-cheat self-protection. Nexus never touches the anti-cheat process itself. In the Processes menu as "Launch priority (survives anti-cheat)". |

## Memory subsystem
| Report mechanism | Status | Where |
|---|---|---|
| Standby-list purge when free RAM low | ✅ | `StandbyListService` (`NtSetSystemInformation` MemoryPurgeStandbyList) |
| `EmptyWorkingSet` on processes | ✅ | `ProcessApi.TryTrimWorkingSet` + `SmartTrimService` |
| Disable Prefetch / SuperFetch | ✅ | tweak `prefetch-superfetch-off` (⚠️ honest note: helps HDDs, not SSDs) |

## Hardware interrupts / DPC latency
| Report mechanism | Status | Where |
|---|---|---|
| IRQ affinity (pin device interrupts to a core) | ✅ | `InterruptTuningService.SetIrqAffinity` (`Affinity Policy\DevicePolicy` + `AssignmentSetOverride`) |
| Core isolation from interrupts | ⚠️ | achieved indirectly by pinning device IRQs away from the game's cores; no dedicated "isolate core N" toggle |
| MSI / MSI-X mode enable | ✅ | `InterruptTuningService.SetMsi` (`MessageSignaledInterruptProperties\MSISupported`) |

## Timer facilities & kernel sync
| Report mechanism | Status | Where |
|---|---|---|
| HPET vs TSC (`useplatformclock`) | ✅ | `BootTimerService` `useplatformclock-off` (+ its undo) |
| `disabledynamictick` | ✅ | `BootTimerService` `dynamictick-off` |
| `tscsyncpolicy enhanced` | ✅ | `BootTimerService` `tsc-sync-enhanced` |
| System timer resolution (`NtSetTimerResolution` 0.5 ms) | ✅ | `TimerResolutionService`, held + re-asserted (per-process since Win10 2004) |

## MMCSS
| Report mechanism | Status | Where |
|---|---|---|
| `SystemResponsiveness` → 0 | ✅ | tweak `mmcss-responsiveness-max` (also a milder `=10` variant) |
| Games task tuning (GPU Priority 8, Priority 6, Scheduling Category High…) | ✅ | tweak `mmcss-gaming` |

## Network stack
| Report mechanism | Status | Where |
|---|---|---|
| Nagle off (`TcpAckFrequency`, `TCPNoDelay`, `TcpDelAckTicks`) | ✅ | tweak `nagle-off` (per adapter, all three values) |
| `NetworkThrottlingIndex` = ffffffff | ✅ | tweak `network-throttling-off` |
| NIC advanced props (Interrupt Moderation / Flow Control / EEE off) | ✅ | `NicTuningService`, Latency tab |
| Low-latency DNS (Cloudflare/Quad9) with benchmark | ✅ | `DnsService` |

## Graphics subsystem
| Report mechanism | Status | Where |
|---|---|---|
| HAGS on/off | ✅ | tweaks `hags-on` / `hags-off` |
| GPU preemption disable | ✅ | tweak `gpu-preemption-off` |
| Shader cache size increase | ⚠️ vendor | vendor-specific registry (NVIDIA/AMD). The vendor-neutral cache path is exposed via the cleaner; forcing a 10 GB shader cache needs the NVIDIA/AMD control panel or NVAPI/ADL — see exclusions. |
| Threaded optimization / Max pre-rendered frames / surface format | ❌ (won't) | NVIDIA/AMD proprietary driver settings (NVAPI / `.nip` profiles / ADL). Shipping a bundled profile editor is fragile and driver-version-specific; use the vendor control panel. Nexus does not fake having changed them. |
| Resizable BAR / Above-4G / CSM | ❌ (can't) | UEFI/firmware settings. Software can detect ReBAR state but cannot enable it; Nexus would only be able to *report* it, so it is documented rather than shown as a toggle. |

## OS debloat & quantum
| Report mechanism | Status | Where |
|---|---|---|
| Disable telemetry/search/GameDVR services | ✅ | `DebloatService` |
| Core parking off + min processor state 100% | ✅ | `PowerPlanService` (CPMINCORES 100 + PROCTHROTTLEMIN 100); tweak `core-parking-unhide` reveals the manual slider |
| `Win32PrioritySeparation` presets (0x26 / 0x2A / …) | ✅ | tweaks `priosep-*` (incl. the 0x2A throughput preset) |

## Deliberate exclusions (summary)
1. **Processor Group Extender** — needs in-process thread injection; anti-cheat hazard, breaks Nexus's never-inject guarantee.
2. **NVIDIA/AMD driver settings** (threaded optimization, pre-rendered frames, forced shader-cache size, surface format) — proprietary vendor APIs / profile formats; belong in the vendor control panel. Nexus refuses to pretend it changed a GPU setting it cannot verify.
3. **Resizable BAR / UEFI options** — firmware settings no user-mode app can write; would be report-only.
4. **In-game FPS/latency overlay** and **hardware temperature monitoring** — excluded earlier for anti-cheat (present-hooking) and vulnerable-kernel-driver reasons respectively (see `parity-matrix.md`).

Everything else in the report is implemented against a real, documented mechanism,
is reversible, and is described honestly (no "massive FPS boost" language — several
of these are explicitly labelled as measure-before-trusting or hardware-dependent).
