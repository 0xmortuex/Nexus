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
| **Suggested optimizations (home-screen recommendations)** | ✅ | `SuggestionEngine` + `SuggestionService`, on the Dashboard |
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

---

# Feature parity: Sentinel vs mainstream antivirus

Same accounting, applied to the security module. "✅" = implemented and wired to
the UI; "⚠️" = implemented with a documented caveat; "❌ (can't)" = blocked by a
gate this project cannot pass; "❌ (won't)" = a conscious decision not to build it.

## Detection

| AV capability | Sentinel | Where / why |
|---|---|---|
| On-demand file scanning | ✅ | `SentinelService.ScanFileAsync`, Security tab |
| Folder / full-disk scanning | ✅ | `ScanFolderAsync` and `ScanEverythingAsync`, streaming verdicts as they are produced |
| Scheduled scanning | ✅ | quick check every 6h; optional weekly full scan that waits for real idle and yields the moment you return |
| Scanning running processes | ✅ | `ScanRunningProgramsAsync` — closes the gap where behaviour monitoring only sees processes as they *start* |
| Removable-drive scanning on insert | ✅ | `RemovableDriveWatcherService`, capped at 20,000 files and says so |
| Right-click "Scan with Nexus" | ✅ | `ShellIntegrationService` (HKCU only) + a named pipe to the running instance |
| Scan history and exportable report | ✅ | `ScanHistory` — an empty findings list cannot otherwise be told apart from nothing having run |
| Hash reputation (known-good / known-bad) | ✅ | `ReputationService`. Known-good is built from the machine's own validly-signed binaries; known-bad takes a MalwareBazaar export. Online lookup deliberately not wired in |
| Authenticode signature verification | ✅ | `AuthenticodeVerifier` over WinVerifyTrust, including catalog-signed files — without that step most of Windows reads as unsigned |
| PE structure heuristics | ✅ | `PeHeuristics`: entropy, W+X sections, import capability groups, packer names, entry-point sanity |
| Byte-pattern signatures | ✅ | `PatternEngine`, `assets/patterns.txt` |
| YARA rules | ⚠️ | `YaraEngine` over YARA-X, implemented and tested. Not bundled: the DLL is ~21 MB and rule sets carry licences. Drop both in and it activates — see docs/sentinel.md |
| ML / PE classifier | ❌ (won't) | reimplementing EMBER's feature extractor invites a silent train/inference mismatch, and the fusion cap means a single source can never be decisive anyway. See docs/sentinel.md |
| Behaviour monitoring | ✅ | `BehaviorEngine` — masquerading, LOLBins, document-spawned shells, encoded command lines. Fed by an ETW kernel session, so a process that starts and exits in milliseconds is still seen; falls back to the WMI watcher (one-second polling) if ETW cannot start |
| Startup / persistence audit | ✅ | Run keys, startup folders, services, IFEO, Winlogon, AppInit_DLLs, WMI subscriptions, scheduled tasks |
| Ransomware behaviour detection | ⚠️ | shadow-copy deletion, backup deletion and recovery-disabling are detected and reported — but reported only, after the fact |
| Script obfuscation analysis | ✅ | `ScriptAnalyzer`: PowerShell/batch/VBScript/JScript/HTA, UTF-16 aware |
| Live script inspection (AMSI) | ❌ (not yet) | in-memory scripts need an AMSI provider DLL and an Authenticode certificate; files on disk are covered |
| Archive inspection | ✅ | ZIP, 7z, RAR, tar, gzip, bzip2 and xz, detected by magic bytes. Archives inside archives are opened two levels deep, spending one budget shared across every level so nesting cannot multiply the limits; deeper ones are reported as unopened. Password-protected archives are reported as unread rather than as clean |
| Ransomware canaries + mass-change detection | ✅ | `RansomwareGuardService` + `MassChangeDetector` |
| Network connection monitoring | ✅ | `NetworkMonitorService` via GetExtendedTcpTable, sampled every 10s into a `ConnectionHistory` while protection is on, so a connection that opens and closes between looks is still recorded. Kept in memory only |
| Antivirus health / exclusion auditing | ✅ | `DefenderHealthService` — reports on Defender rather than replacing it. Nexus audits its own exclusions to the same standard |
| Security posture check (firewall, UAC, SmartScreen) | ✅ | `SecurityPostureAudit` — also Secure Boot, drive encryption and update age. "Could not read" is never reported as "switched off" |
| Browser extension auditing | ⚠️ | `BrowserExtensionAudit` over Chrome, Edge, Brave, Vivaldi and Opera, with capabilities in plain language. Firefox stores extensions differently and is not read |
| Host file / DNS / proxy hijack check | ✅ | `SystemIntegrityAudit` — nothing else in the module would notice these, since no program is running |
| Rootkit scanning | ❌ (can't) | requires kernel visibility |
| Email / web / phishing filtering | ❌ (won't) | suite bloat, not protection. The browser and mail client already do this better |
| Firewall, VPN, password manager | ❌ (won't) | same |

## Response

| AV capability | Sentinel | Where / why |
|---|---|---|
| Explaining *why* something was flagged | ✅ | every verdict carries its signals and a score out of 100 — the module's whole point |
| Quarantine with restore | ✅ | `QuarantineService` + write-ahead journal; moves, never deletes |
| User allowlist | ✅ | `TrustStore`, keyed on content hash so edits revoke trust |
| Exclusions (folders, file types) | ✅ | `ExclusionList` with a picker. Nothing is refused for being too broad, but the warning sits on the row it concerns, and an excluded file is reported as skipped rather than clean |
| Real-time on-access blocking | ❌ (can't) | needs a filesystem minifilter driver: Microsoft altitude allocation, EV certificate, attestation signing |
| Blocking an execution | ❌ (can't, and won't) | needs the same driver. Also the explicit design choice: Sentinel reports and leaves the decision to you |
| Automatic quarantine / removal | ❌ (won't) | every destructive action requires a `UserConsent` token minted in a click handler. This is enforced by the type system, not by policy |
| Self-protection against tampering | ❌ (can't) | needs kernel object callbacks |
| Registering as the system antivirus | ❌ (can't) | needs Microsoft Virus Initiative membership: an established company with independent lab certification |
| Replacing Microsoft Defender | ❌ (won't) | follows from the above, and would be a security downgrade. Run both |

## Summary

Sentinel implements the **detection and explanation** half of an antivirus against
real Windows APIs, and deliberately implements none of the **enforcement** half.

The exclusions split cleanly in two:

- **Can't**: everything requiring a signed kernel driver or Microsoft Virus
  Initiative membership — on-access blocking, self-protection, rootkit scanning,
  PPL, replacing Defender. These are commercial and organisational gates, not
  engineering ones.
- **Won't**: automatic action, and the suite bloat (VPN, password manager, web
  filtering) that ships alongside mainstream AV without improving detection.

The "can't" list is exactly the set of things that exist to let software *block*.
Because Sentinel reports instead, none of them are on its critical path — the
design turns the project's hardest constraint into its defining feature.
