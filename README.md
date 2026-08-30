# Nexus

A Windows game/system optimizer in the spirit of Process Lasso + Hone:
persistent per-process rules, ProBalance-style dynamic restraint, watchdog and
instance-limit enforcement, power-plan automation, a crash-safe Game Mode, and a
set of honest system tweaks with mandatory backups and working undo — plus
**Sentinel**, an advisory security module that finds malware and tells you about
it instead of deciding for you.

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
- **Measure before trusting, made executable** — a latency probe that measures how
  punctually Windows wakes a thread, saved baselines, and an A/B comparison that
  uses a bootstrap confidence interval and is allowed to answer "no measurable
  difference" — which, for most tweaks, is the truth. Plus throttle detection that
  separates a ceiling your power plan is enforcing (fixable) from one the firmware
  is enforcing because of heat or power delivery (not fixable, and it says so).
- **Sentinel — security that reports, never decides** — on-demand file scanning,
  a startup/persistence audit (Run keys, tasks, services, IFEO, WMI subscriptions,
  Winlogon, AppInit_DLLs), Authenticode verification, PE structure heuristics,
  byte-pattern signatures, local hash reputation, and live behaviour monitoring
  (masquerading system binaries, living-off-the-land command lines, documents
  spawning shells), ransomware canaries with mass-change detection, script
  obfuscation analysis, ZIP inspection, per-process network connections, and
  Microsoft Defender health including exclusion auditing. New downloads are checked
  as they land, and the folders where files actually arrive are re-checked on a
  schedule that never runs while a game is active. Optional YARA-X support activates
  when you supply the library and rules. Every finding shows its reasons and a score
  out of 100.
  Nothing is ever blocked, moved or deleted without a click on that exact file.
  See `docs/sentinel.md`.
- **UI** — dark WPF app with Dashboard, Processes, Game Mode, Tweaks, Security,
  Log, and Settings tabs; tray icon with quick toggles; start-with-Windows via an
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

The publish output is `Nexus.exe` plus `Nexus.Scanner.exe` and an `assets/`
folder. The scanner is a separate *process* on purpose — it parses hostile files,
and Nexus runs elevated — so it is a second binary rather than a second assembly.
Both must sit in the same folder; the publish fails rather than shipping without
the scanner, because a silently disabled engine reports "unknown" about
everything it should have caught. See `docs/manual-test-checklist.md`
for the first-run verification list and `docs/test-notes.md` for what is covered
by the automated tests versus what needs a live Windows machine.

## Safety

- A hard-coded never-touch list (csrss, lsass, audiodg, Defender, EasyAntiCheat,
  BattlEye, Vanguard, FACEIT…) is checked before *every* mutation, not just kills.
- Sentinel never acts on its own, and this is enforced by the type system: every
  destructive path requires a single-use `UserConsent` token bound to one file and
  one action, minted only inside a click handler. It also refuses — regardless of
  consent — to move anything out of Windows or Program Files.
- Sentinel parses hostile files in a separate, restartable worker process, never
  inside the elevated UI process.
- Sentinel reports Nexus's own scheduled task and IFEO keys in its startup audit
  rather than hiding them.
- Keep Microsoft Defender on. Sentinel is a second opinion, not a replacement.
- Game Mode writes a write-ahead journal (`intended-state.json`) before each
  change; crash recovery reverts it on the next start.
- Tweaks refuse to apply if their registry backup fails.
- Debloat disables — it never deletes services or tasks.

## What this costs

Nothing, and nothing it depends on costs anything either.

| | |
|---|---|
| Nexus | MIT, this repository |
| .NET 8 SDK | free |
| YARA-X *(optional)* | BSD-3, free download from VirusTotal |
| YARA rule sets *(optional)* | free; several are MIT — see NOTICE.md |
| MalwareBazaar hash list *(optional)* | CC0, free, no account |
| Known-good baseline | generated on your own machine |
| CI | GitHub Actions, free for public repositories |

There is exactly one thing money would buy, and it is worth being straight about
rather than leaving it as an implied upgrade path.

### The SmartScreen warning

Nexus is not code-signed, so the first time anyone runs it Windows says *"Windows
protected your PC"* and they have to click **More info → Run anyway**. A code-signing
certificate is the only thing that removes that, it costs a few hundred pounds a
year, and there is no free equivalent — SmartScreen reputation is tied to a
certificate, so an unsigned build never accrues any no matter how many people
download it.

What is free is letting people verify the file instead of trusting the warning:
releases are built by a public GitHub Actions workflow from a tagged commit and ship
a `SHA256SUMS.txt`, so anyone can confirm the binary matches what the workflow built
from source they can read.

That is a weaker guarantee than a signature and it is stated as one. It does not
affect anything Nexus actually does.

### What staying free rules out

Only things that were already out of reach and are documented as such in
`docs/parity-matrix.md`: an AMSI provider for in-memory script inspection (scripts
*on disk* are already covered), a kernel driver for real-time blocking, and
registering as the system antivirus. The last two need Microsoft Virus Initiative
membership, which needs a company and independent lab certification — those were
never a question of money.

None of it changes the design. Sentinel reports rather than blocks by choice, and
every capability that choice gives up is one that needed a signed driver anyway.

## License

MIT — see [LICENSE](LICENSE).

Detection data is kept separate from the code on purpose. The byte-pattern rules
shipped in `assets/` are Nexus's own; the known-good baseline is generated on your
machine and never leaves it. If you add third-party rule sets or hash feeds, check
their licences — several widely used YARA rule collections are GPL, which would
constrain how you redistribute a build that bundles them.
