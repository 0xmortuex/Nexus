# Nexus — manual test checklist (first run on Windows)

Built and unit-tested on Linux; this checklist is the required first-run
verification on a real Windows 10/11 machine. Work through it top to bottom —
items marked **[hybrid]** need a P/E-core CPU (Intel 12th gen+), items marked
**[win11]** need Windows 11.

## 0. Install & launch
- [ ] `dotnet publish src/Nexus.App -c Release -r win-x64 --self-contained -p:PublishSingleFile=true`
      produces `Nexus.exe`, `Nexus.Scanner.exe` and an `assets/` folder. The publish
      FAILS rather than shipping without the scanner.
- [ ] Launching triggers a UAC elevation prompt (manifest requireAdministrator).
- [ ] Denying elevation → app does not start. Accepting → main window opens, dark theme.
- [ ] Launching a second instance shows "already running" and exits.
- [ ] `%APPDATA%\Nexus\` is created with settings.json + logs\activity-*.log.
- [ ] SmartScreen: unsigned exe → "Windows protected your PC" → More info → Run
      anyway. Expected and unavoidable without a paid certificate; the README says
      so plainly and releases ship SHA256SUMS.txt so users can verify instead.

## 1. Core engine / rules
- [ ] Dashboard shows CPU %, RAM, per-core bars matching Task Manager (±2 %).
- [ ] **[hybrid]** Dashboard reports "hybrid: P+E"; E-core bars are green; log shows
      correct P-core/E-core masks (cross-check with Task Manager → CPU → Logical processors).
- [ ] Processes tab lists processes with live CPU/RAM; filter box works.
- [ ] Right-click → Set priority (now) → High: verify in Task Manager → Details.
- [ ] Right-click → Set priority (always) on notepad.exe → close and relaunch notepad →
      priority is re-applied within ~1 s (WMI) — check the Log tab entry.
- [ ] Kill the WMI service (`net stop winmgmt`) → log shows fallback to polling; rules still apply (slower).
- [ ] Right-click → Restrict cores → P-cores only **[hybrid]**: Task Manager → Details →
      Set affinity shows restriction (hard mask mode) or use `Get-Process | % ProcessorAffinity`.
- [ ] IO priority: set Low on a copying process → verify with Process Explorer (I/O Priority column).
- [ ] Efficiency mode on **[win11]**: leaf icon appears in Task Manager for the target process.
- [ ] Trim working set: RAM (MB) column drops sharply, then regrows as pages fault back.
- [ ] Rules survive app restart (rules.json).
- [ ] Attempting any action on csrss.exe/audiodg.exe is refused with a log entry ("never-touch").

## 2. ProBalance
- [ ] Run a CPU burner (e.g. `prime95` or a `while(true)` PowerShell loop × cores) in the background.
- [ ] After ~2 s of >85 % load, the burner is restrained to BelowNormal; Log records
      the event with timestamp and reason; Dashboard shows it under "Currently restrained".
- [ ] Click into the burner window (make it foreground) → instantly restored.
- [ ] Stop the load → after release window + min restraint, priority restored.
- [ ] Add the burner to exclusions in Settings → it is never restrained again.
- [ ] Toggle ProBalance off in the tray while something is restrained → restored immediately.
- [ ] Foreground app is never restrained no matter how much CPU it uses.

## 3. Lasso parity features
- [ ] Instance limit 1 on notepad.exe → open two notepads → the newer one is killed, log entry.
- [ ] Disallowed list: add calc.exe → launching it dies instantly, log entry.
- [ ] Watchdog: rule "notepad.exe RAM > 100 MB for 5 s → kill" → open a huge file → killed.
- [ ] Watchdog restart action: relaunches the exe (note: command-line args are not preserved — logged).
- [ ] Performance Mode from tray: `powercfg /list` shows "Nexus Performance" active;
      `powercfg /q <guid> SUB_PROCESSOR CPMINCORES` shows 100/100 (core parking off).
- [ ] Toggle Performance Mode off → previous plan restored.
- [ ] IdleSaver: set 1 min, don't touch input → Power Saver activates; move mouse →
      previous plan restored within 15 s. Not triggered while a game runs.
- [ ] SmartTrim: enable with 100 MB threshold → within the interval, background hogs
      are trimmed (log lists MB); the foreground app is never trimmed.
- [ ] Keep Awake on → `powercfg /requests` lists Nexus under SYSTEM/DISPLAY; machine
      does not sleep past its timeout. Off → request disappears.

## 3b. Parity features (Lasso Pro + Hone premium)
- [ ] CPU Limiter: right-click a CPU burner → Limit CPU to 25% → its CPU% in the list
      and Task Manager settles near 25 % across all cores; Remove CPU limit → returns to full.
- [ ] CPU limit via rule: set `CpuLimitPct` in a rule → relaunch the exe → capped on start.
- [ ] Foreground boosting (Settings → General): enable → click between two Normal-priority
      apps → the focused one shows AboveNormal in Task Manager, the other returns to Normal.
      A process you manually set to High is NOT downgraded.
- [ ] Keep-awake-while-running rule: mark a rule → launch it → `powercfg /requests` lists
      Nexus; close it → request clears.
- [ ] Auto-restart rule: mark "restart if exited" → kill the process yourself → it relaunches.
      Kill it via Nexus (disallowed/instance/watchdog) → it does NOT relaunch. Kill it 4×
      quickly → backoff message after the 3rd, no more relaunches for 5 min.
- [ ] Standby purge (Memory & Network tab): note "Cached" in Task Manager → Purge → Cached drops.
- [ ] Auto-purge: enable with a high threshold → when free RAM dips below it, log shows an auto-purge.
- [ ] DNS benchmark: click Benchmark → resolvers listed by latency (or "no ICMP reply" on
      ICMP-blocked networks); "Use" on one → `ipconfig /all` shows it on every adapter;
      Restore previous DNS → back to the original (DHCP or prior static).
- [ ] New tweaks apply/undo cleanly: Windows Game Mode, fullscreen-optimizations off,
      power-throttling off (PowerThrottlingOff=1), Sticky Keys off (Flags=506).

## 3c. Suggested optimizations (Hone-style recommendations)
- [ ] Dashboard → "Suggested optimizations" lists items derived from real state
      (e.g. if GameDVR is on, it suggests turning it off; if DiagTrack runs, suggests disabling).
- [ ] On a fresh machine the list is non-empty; each item shows a plain-language reason.
- [ ] Click Apply on a tweak suggestion → the tweak applies (check the Tweaks tab shows it
      as applied) and the item drops off the suggestion list on re-scan.
- [ ] Apply a "Disable DiagTrack" suggestion → service disabled; item disappears.
- [ ] Enable-feature suggestions (ProBalance/Game Mode/perf plan) flip the corresponding setting.
- [ ] The hybrid-CPU hint appears only on a P/E-core CPU with no game profiles, and has no
      Apply button (guidance only).
- [ ] After applying everything, the panel shows "Your system already matches Nexus's recommendations."
- [ ] Everything applied via suggestions is still reversible from its normal tab / Restore All.

## 3d. Latency & hardware (report mechanisms)
- [ ] IFEO launch priority: Processes → right-click a game → Launch priority → High.
      Regedit shows HKLM\...\Image File Execution Options\<exe>\PerfOptions\CpuPriorityClass=3.
      Relaunch the game → it starts at High even under an anti-cheat that blocks live
      SetPriorityClass. Remove launch priority → key gone.
- [ ] Instance balancer: add an exe to BalancedProcesses, open 2+ copies → each copy's
      affinity (Task Manager → Details → Set affinity) covers a distinct core range.
- [ ] Timer resolution (Latency tab): enable → status shows ≈0.50 ms; `powercfg /energy`
      or ClockRes confirms 0.5 ms. Disable → returns toward 15.6 ms when nothing else holds it.
- [ ] Boot timers: Apply "let Windows use TSC" → `bcdedit` no longer lists useplatformclock;
      Undo → useplatformclock Yes. Same for dynamictick/tscsyncpolicy. Reboot to feel effect.
- [ ] Interrupt tuning: Scan devices → GPU/NIC/storage listed with MSI state. Toggle MSI on
      a NIC → regedit MSISupported=1 under that device's Interrupt Management. Pin IRQ→CPU 2
      → AssignmentSetOverride + DevicePolicy=4 written. Clear (empty box + Set) → values gone.
      Verify after reboot with an MSI-utility / Resource Monitor that IRQ is negative (MSI).
- [ ] NIC latency: Apply → Get-NetAdapterAdvancedProperty shows *InterruptModeration/
      *FlowControl/*EEE = 0 on adapters that expose them; unsupported ones skipped, no crash.
- [ ] New tweaks apply/undo: GPU preemption off (EnablePreemption=0), Prefetch/SuperFetch off,
      SystemResponsiveness=0, Win32PrioritySeparation=0x2A, core-parking-unhide reveals the
      slider in Power Options → Processor power management.

## 4. Game Mode
- [ ] Launch any fullscreen/borderless game (or a fullscreen video player NOT on the
      denylist to test detection logic) → Game Mode activates: log shows priority High,
      **[hybrid]** P-core CPU sets, hog demotion, power plan switch.
- [ ] `intended-state.json` is non-empty while in Game Mode.
- [ ] Alt-tab away → Game Mode stays active (exit is on process exit, not focus loss).
- [ ] Quit the game → everything reverts (priorities, power plan, journal cleared).
- [ ] Pause Windows Update enabled → wuauserv stops on entry (`sc query wuauserv`), starts on exit.
- [ ] CRASH TEST: while in Game Mode, kill Nexus via Task Manager → relaunch Nexus →
      startup log shows "previous session ended unexpectedly… reverted"; power plan and
      priorities are back; intended-state.json is empty.
- [ ] Add a windowed game by exe name → it triggers Game Mode despite being windowed.
- [ ] Chrome fullscreen (F11 + video) does NOT trigger Game Mode (denylist).
- [ ] Ignore list beats game list.

## 5. Tweaks — measure before trusting
- [ ] Applying any tweak creates `%APPDATA%\Nexus\backups\registry\<timestamp>-<id>\*.reg`
      and (once per session) attempts a System Restore point — check
      `Get-ComputerRestorePoint` or the log's 24 h-throttle warning.
- [ ] Make the backup fail (deny write access to the backup dir) → tweak REFUSES to apply.
- [ ] GameDVR off: apply → regedit shows GameDVR_Enabled=0 → Undo → original values back
      (including values that did not exist before being deleted again).
- [ ] Win32PrioritySeparation presets write 0x26/0x2/0x18 respectively.
- [ ] HAGS on/off **[win11 + supported GPU]**: HwSchMode=2/1, "reboot required" shown.
- [ ] Mouse accel off: Enhance pointer precision unchecks in Control Panel after sign-out.
- [ ] Nagle off: TcpAckFrequency=1 + TCPNoDelay=1 appear under every interface GUID; Undo removes
      them (they did not exist → deleted).
- [ ] Hibernation off: hiberfil.sys gone; Undo (`/hibernate on`) brings it back.
- [ ] Debloat service DiagTrack: Disable → service stopped + start type 4; Re-enable →
      original start type restored (check regedit Start value).
- [ ] SysMain shows the warning dialog before disabling.
- [ ] Telemetry tasks: Disable → `schtasks /query` shows Disabled; Re-enable works.
- [ ] Appx removal: nothing pre-checked; removing a checked app shows the one-way warning,
      then `Get-AppxPackage` no longer lists it.
- [ ] Cleaner: Scan shows plausible sizes (compare D3DSCache folder size manually);
      Clean only deletes checked targets; in-use files skipped without errors;
      thumbnails: only thumbcache_*.db files are touched in the Explorer dir.
- [ ] Startup manager lists the same Run-key entries as Task Manager → Startup;
      disabling one here shows Disabled there (StartupApproved interop) and vice versa.
- [ ] Startup scheduled tasks list only logon-triggered tasks; toggling works.

## 6. UI / tray
- [ ] All six tabs render in dark theme; no white flash areas.
- [ ] Dashboard graphs scroll (60 s window) and match Task Manager trends.
- [ ] Log tab updates live and the filter works; every action taken above appears in
      plain language.
- [ ] Tray icon: double-click opens the window; context menu checkmarks reflect real
      state (ProBalance from settings, Performance Mode from the ACTIVE power plan).
- [ ] Closing the window minimizes to tray; engines keep running (watch log file grow).
- [ ] Tray → Exit fully quits, restores restrained processes, removes the tray icon.
- [ ] Start with Windows: enable → `schtasks /query /tn "Nexus Optimizer"` exists with
      Highest run level; reboot → Nexus starts elevated without a UAC prompt; disable → task gone.

## 7. Hardening
- [ ] "Restore ALL defaults": applies every undo (tweaks, services, tasks), clears rules
      and game profiles, deletes the Nexus power plan, disables autostart — verify each.
- [ ] While a game is boosted, Restore All also exits Game Mode and reverts it.
- [ ] Run a game protected by EasyAntiCheat/BattlEye/Vanguard: Nexus never touches the
      anti-cheat processes (grep the log for "never-touch" refusals; no game kicks).
- [ ] Kill wmiprvse mid-session → watcher fails over to polling without crashing.
- [ ] Leave running 24 h: no unbounded memory growth (log ring is capped, sampler reuses buffers).

## 8. Sentinel (security module)

Nothing in this section can be verified on a build machine — it needs real Windows,
a real registry, and real signed binaries. Automated coverage stops at the pure
logic; everything below is the part that talks to the OS.

### Scanning
- [ ] Security tab renders; the "Nexus reports, it does not decide" banner is visible.
- [ ] `Nexus.Scanner.exe` sits next to `Nexus.exe` after publish. Run
      `Nexus.Scanner.exe --self-test` → prints "PE structure,byte patterns".
- [ ] Scan `C:\Windows\System32` → signed Microsoft binaries come back **Trusted**,
      not Unknown. (If they come back Unknown, WinVerifyTrust is failing — check the
      app is elevated and `wintrust.dll` resolves.)
- [ ] Create an EICAR test file (the standard 68-byte string) → scan reports it as
      "Worth a look" or higher, quoting the EICAR rule, and **nothing is moved**.
      Defender will likely quarantine the file first; that is expected.
- [ ] Rename a `.txt` to `.exe` → reported as "named like a program but its contents
      are not a Windows executable".
- [ ] Scan a large folder (50k+ files) → the UI stays responsive, progress updates,
      and "Stop" actually stops.
- [ ] Kill `Nexus.Scanner.exe` mid-scan → the host restarts it and the scan continues.
      After 5 kills, file scanning disables itself with a log message and the rest of
      the app keeps working.

### Startup audit
- [ ] "Check startup items" completes without an unhandled exception on a machine with
      third-party software installed.
- [ ] Nexus's own scheduled task and any IFEO `PerfOptions` keys it wrote appear in the
      results, marked as created by Nexus, scoring zero.
- [ ] Winlogon `Shell` / `Userinit` at their Windows defaults are **not** flagged.
- [ ] Unquoted service paths with spaces resolve to the right executable.
- [ ] A machine with no WMI event subscriptions reports none rather than erroring.

### Behaviour monitoring
- [ ] `certutil -hashfile <file> SHA256` → **not** flagged (ordinary use).
- [ ] `certutil -urlcache -split -f http://example.com/x` → flagged, and nothing is
      blocked or killed.
- [ ] Copy `cmd.exe` to `%TEMP%\svchost.exe` and run it → flagged as masquerading.
- [ ] A Word document that spawns a shell → flagged as document-spawned shell.
- [ ] Gaming session: no behaviour alerts fire on anti-cheat processes, and no
      measurable frame-time impact from the WMI watcher.

### Consent and quarantine
- [ ] Quarantine a file in a normal folder → moved, restorable, original path preserved.
- [ ] Try to quarantine something under `C:\Windows` → refused with an explanation,
      **even after confirming**.
- [ ] Try to quarantine an anti-cheat binary → refused (never-touch list).
- [ ] Quarantine, then kill Nexus mid-move (a hard power-off is the real test) → on the
      next start, reconciliation reports where the file ended up and prefers leaving
      the original untouched.
- [ ] Restore a quarantined file → back at its original path, byte-identical.
- [ ] Trust a file, then modify its bytes → no longer trusted (trust is hash-keyed).
- [ ] Leave the app idle overnight with monitoring on → no unbounded growth in the
      behaviour engine's process map (capped at 4096).

## 8a. Behaviour monitoring (ETW)

Confirmed on real elevated runs: the session starts, stops, and restarts on the same
instance; twelve process events arrived with every path resolved; no findings were
raised; and `logman query -ets` showed no leaked session afterwards. These steps
re-check it after changes and cover what only shows up in the running app.

- [ ] With protection on, Security → Protection shows **Behaviour monitoring** as
      "Watching every process launch, including very short-lived ones (ETW)". If it
      instead says it is using the WMI watcher, ETW did not start — the Log tab says
      why, and everything below is expected to fail.
- [ ] The Log records "Behaviour monitoring is using ETW" at startup.
- [ ] Run `cmd /c "powershell -nop -w hidden -enc SQBFAFgA"` from a shortcut. It exits
      in well under a second. A finding appears naming the encoded command line — this
      is precisely the case the WMI watcher misses.
- [ ] Turn protection off from the Security tab, then on again. ETW restarts cleanly
      and the status still reports ETW (a session that failed to release would show
      the WMI fallback instead).
- [ ] Kill Nexus from Task Manager, then start it again. It still reports ETW: the
      stale session left by the kill is cleared by name at startup. Confirm with
      `logman query -ets` that only one `NexusSentinelProcessWatch` session exists.
- [ ] Exit Nexus normally and confirm `logman query -ets` no longer lists it. An ETW
      session outlives the process that made it, so a leak here is a real one.

## 8a2. Network record

- [ ] With protection on for a minute or two, Security → Network record → "Show what
      has connected" lists processes and endpoints, most recently active first.
- [ ] The same program talking to the same endpoint appears **once**, not once per
      socket, and "seen N times" grows by one per ten seconds rather than in jumps.
- [ ] Open a browser tab, wait, close it. The endpoint stays in the list afterwards —
      that is the whole point; a snapshot would have lost it.
- [ ] "Clear" empties the list.
- [ ] Turn protection off: sampling stops (the list stops growing). Turn it back on:
      it resumes.
- [ ] Restart Nexus. The list is empty again — this is deliberate, nothing about where
      the machine has been is written to disk. Confirm no file under `%APPDATA%\Nexus`
      contains a remote address.

## 8b. Scan modes and the things that produce false positives

The point of this section is the *absence* of findings. Every check here was a real
false positive on a real machine at some point, and each one is now a regression test
as well as a manual step.

- [ ] **Scan folder** on a web project containing `node_modules` and a `.next` build:
      finishes with **zero** findings. Minified bundles, `typescript.js` and `core-js`
      polyfills must not be flagged. (This once produced 1,988 findings.)
- [ ] **Scan folder** on `C:\Windows\System32`: zero findings, and opening any result
      detail shows Windows files as **signed by Microsoft**, not "no digital
      signature". Catalog-signed files are the whole point of this check.
- [ ] **Scan folder** on Nexus's own build output: zero findings. A .NET assembly with
      embedded resources must not read as "packed".
- [ ] **Check running programs**: completes, reports how many distinct programs it
      looked at, and flags nothing on a clean machine. Processes it cannot open are
      skipped silently — the Log must NOT fill with warnings about system processes.
- [ ] **Full scan**: starts, the status line names the folder it is currently reading
      and updates as it moves. Stop works. The run appears in the scan history marked
      as stopped early.
- [ ] Plant a test script containing `IEX (New-Object Net.WebClient).DownloadString(...)`
      plus a Run-key write. Scanning it reports **LikelyMalicious**, and nothing about
      the file is changed. This is the control: if the checks above pass but this one
      does not, the tool has been quieted into uselessness.

## 8c. Archives

- [ ] Put the test script from above inside `.zip`, `.7z`, `.tar.gz` and `.tar.bz2`
      (7-Zip and `tar` both do this). Each one reports the same findings, named for the
      entry they came from.
- [ ] Create a password-protected `.7z` with encrypted headers (`-mhe=on`). Nexus
      reports it as **password-protected**, not as corrupt, and does not imply it is
      clean.
- [ ] A `.zip` renamed to `.txt` is still recognised — format comes from the bytes.
- [ ] Put the dropper `.zip` inside another `.zip`. The findings are still reported,
      and name the path through both archives.
- [ ] Mix formats: a `.zip` containing a `.7z` containing the dropper. Still found.
- [ ] Nest four archives deep. Nexus reports the inner one as **not opened** and says
      its contents have not been cleared — it must never go quiet instead.

## 8d. Exclusions, right-click and USB

- [ ] Security → "Files Nexus skips" → Browse → pick a folder → "Skip this". It
      appears in the list. Rescanning that folder reports files as **skipped**, never
      as clean.
- [ ] Exclude a whole drive (e.g. `C:\`). It is accepted — Nexus does not argue — but
      an amber warning appears on that row saying scanning is effectively off.
- [ ] "Scan it again" removes the exclusion.
- [ ] Settings → tick "Add Scan with Nexus to the right-click menu". Right-click any
      file in Explorer → "Scan with Nexus" → the existing Nexus window comes forward,
      switches to Security, and reports on that file — **without** a second instance
      starting and without an "already running" dialog.
- [ ] Right-click a folder and a drive: both offer the entry.
- [ ] Untick the setting → the entry disappears from all three menus. Check
      `HKCU\Software\Classes\*\shell` no longer contains `Nexus.ScanWithNexus`.
- [ ] Tools → Restore Defaults also removes the entry.
- [ ] Plug in a USB stick with protection on: the Log records that it was looked at,
      and the drive stays fully usable throughout. Unplug and replug → scanned again.
- [ ] A stick already plugged in when Nexus starts is NOT rescanned on every launch.

## 8e. Settings, posture and extensions

- [ ] "Check Windows security settings": reports firewall, UAC, SmartScreen, Secure
      Boot, encryption and update age. On a normally configured machine it finds
      nothing. Turn the Windows firewall off for the public profile → it is reported
      as Moderate, and the wording describes *configuration*, not infection.
- [ ] Anything Nexus cannot read must be silently absent, never reported as "off".
- [ ] "Check browser extensions": lists extensions from every Chromium browser
      installed, each with real names (never a 32-character id) and plain-language
      capabilities. Ordinary store extensions raise no alert even when they can read
      every site.
- [ ] "Check network settings": hosts file, proxy and DNS. A DNS server Nexus itself
      set from the Tools tab is not reported as a hijack.

## 8f. Scan history

- [ ] Every scan above appears in the history with its type, file count and duration.
- [ ] A scan you stopped is recorded as stopped early, not as completed.
- [ ] "Save report…" writes a readable text file listing every run and stating that
      nothing was changed.
- [ ] "Clear history" empties it, and it stays empty after a restart.

## 8g. Scheduled full scan

- [ ] Settings → "Run a full scan every week when the machine is idle" is **off** by
      default.
- [ ] Switch it on and restart. The Log states the interval and the idle requirement.
- [ ] It does not start while you are using the machine, and does not start while a
      game is running.

## 9. Measurement and phase-2 detection

### Latency measurement
- [ ] "Capture baseline" completes in a few seconds and reports a median in the
      sub-millisecond to low-millisecond range on an idle desktop.
- [ ] "Measure and compare" immediately after, with nothing changed → **no measurable
      difference**. If this reports an improvement on an unchanged system, the
      comparison is broken and nothing else in this section can be trusted.
- [ ] Set the power plan to Power Saver, then compare → a detectable regression.
- [ ] Start a heavy background compile, then compare → a detectable regression.
- [ ] "Stop" during a run leaves the previous baseline untouched.
- [ ] Baselines survive an app restart.

### Throttle detection
- [ ] "Check CPU speed limits" on a desktop at defaults → reports running at rated speed.
- [ ] Set the power plan's maximum processor state to 50% → reported as **caused by
      the power plan** and described as fixable.
- [ ] On a laptop under sustained load until it heats up → reported as firmware/thermal
      and explicitly **not** fixable in software. Nexus must not imply it can raise it.

### Ransomware watch
- [ ] On first start, hidden tripwire files appear in Documents/Pictures/Desktop.
- [ ] Delete one by hand → an alert appears, and the file is replanted.
- [ ] Modify a tripwire file in a text editor → immediate alert, nothing is blocked.
- [ ] Unzip a large archive of documents → **no** alert (burst rule alone must not fire).
- [ ] Run a backup or sync of your Documents folder → **no** alert.
- [ ] Rename 10+ documents to a `.locked` extension → alert naming that extension.
- [ ] Create a file named `HOW_TO_DECRYPT.txt` → alert.
- [ ] After an alert, further activity stays quiet for the 5-minute cooldown.
- [ ] Copy several thousand files at once → the watcher survives the buffer overflow
      and logs that events were dropped rather than dying silently.

### Scripts and archives
- [ ] Scan a real PowerShell module from a trusted vendor → no obfuscation findings.
- [ ] Scan a UTF-16 encoded `.ps1` → keywords still detected (this is the case that
      silently fails if decoding is wrong).
- [ ] Scan a ZIP containing a script with `-EncodedCommand` → findings name the entry
      inside the archive.
- [ ] Scan a zip bomb (e.g. a highly compressible 1 GB file) → reported, and Nexus does
      not allocate gigabytes or hang.
- [ ] Scan a password-protected ZIP → does not crash; entries are skipped.

### Defender health
- [ ] Elevated: exclusions are listed. Non-elevated: reports that they could not be
      read, **not** that there are none.
- [ ] Add `Add-MpPreference -ExclusionPath C:\` then re-check → flagged as a broad
      exclusion. Remove it afterwards.
- [ ] Turn real-time protection off briefly → flagged as strong evidence. Turn it back on.

### Network
- [ ] "Check connections" returns a count close to `netstat -ano | find "ESTABLISHED"`.
- [ ] Run a portable tool from `%TEMP%` that makes a connection → flagged.
- [ ] Normal browsing produces no findings (it must not flag ordinary HTTPS).

## 10. Integration and reset

### Restore all defaults (this one touches user data)
- [ ] Quarantine a file, then click "Restore ALL defaults" → the file is **put back at
      its original path**, not deleted and not left orphaned in the quarantine folder.
      This is the single most important check in this document: getting it wrong
      destroys data the user explicitly asked to be kept safe.
- [ ] Quarantine a file, make its original folder unwritable, then restore defaults →
      the failure is reported, and the journal entry is **kept** so the file is still
      findable rather than stranded under a random name.
- [ ] After restore defaults, the hidden tripwire files are gone from Documents,
      Pictures, Videos, Music and Desktop.
- [ ] After restore defaults, the trusted-file list and saved baselines are empty.
- [ ] Restore defaults on a machine where Sentinel never ran → completes without error.

### Settings
- [ ] Turn off "Ransomware watch", restart → no tripwire files are planted, and the
      existing ones are removed.
- [ ] Turn off "Watch process launches", restart → no WMI subscription is created
      (check with `Get-WmiObject -Namespace root\subscription -Class __EventFilter`).
- [ ] Turn off "Check new downloads", restart → downloading a program raises nothing.
- [ ] With everything off, the rest of Nexus still works normally.

### Downloads
- [ ] Download a large installer in Chrome/Edge → it is checked once, **after** the
      `.crdownload` rename completes, not while partially written.
- [ ] Download something unremarkable → nothing is logged. Silence on ordinary files
      is the requirement; a notification per download would train the user to ignore it.
- [ ] Download an EICAR test file → a warning appears and the file is **not** moved.

### Suggestions and dashboard
- [ ] With the power plan capped to 50%, the Suggestions list shows the throttle
      **above** the registry tweaks.
- [ ] On a thermally throttled laptop, the firmware suggestion appears as a hint with
      **no Apply button**.
- [ ] Turn Defender's real-time protection off → it appears in Suggestions and on the
      Dashboard security panel. Turn it back on afterwards.
- [ ] The Dashboard security panel is separate from the optimization ring, and a
      machine with findings does not show a high optimization score as reassurance.

## 11. Final surfaces

### Protection status
- [ ] All five components report On with sensible detail on a healthy machine.
- [ ] Turn a feature off in Settings, restart -> it reads "Turned off in Settings",
      NOT "could not start". The two must never look the same.
- [ ] Rename `Nexus.Scanner.exe`, restart -> "File scanning" reads Off with a reason,
      and the rest of the module still works.
- [ ] With no hash lists in `assets/`, "Hash reputation" reads Off and says why.

### Trusted files
- [ ] Trust a finding -> it appears in the trusted list with the right name and time.
- [ ] "Stop trusting" removes it, and the file is reported again on the next scan.
- [ ] Modify a trusted file -> it disappears from the effective allowlist (trust is
      keyed on content), and it is reported again.

### Ransomware dismissal
- [ ] Trigger an alert (edit a tripwire), press "That was me", then trigger it again
      -> a fresh alert appears rather than being swallowed by the cooldown.

### Connections
- [ ] "Check connections" fills the list, grouped by program, and the count roughly
      matches `netstat -ano | find "ESTABLISHED"`.

### Scan performance
- [ ] Scan a folder containing a git repository -> `.git` is skipped and the scan
      finishes in seconds rather than minutes.
- [ ] Scan the same folder twice -> the second pass is markedly faster (cache), and
      still shows the findings rather than going silent.

### Tray
- [ ] Tray menu shows the security state and opens the Security tab when clicked.
- [ ] A likely-malicious finding raises one balloon; an Unknown file raises none.

### Wizard
- [ ] First run reaches the Security step before Apply, and unchecking the ransomware
      option means no tripwire files are ever written.

## 12. Known-good baseline

- [ ] Before building: scan `C:\Windows\System32` → signed Microsoft binaries come
      back **Unknown**, and "Hash reputation" reads Off. That is the gap this fixes.
- [ ] "Build baseline from this PC" reports progress and the window stays responsive.
      Expect roughly 30,000 files and two to five minutes.
- [ ] "Stop" mid-build leaves any previous baseline untouched.
- [ ] Afterwards `%APPDATA%\Nexus\security\known-good-local.txt` exists, opens with a
      `#` header naming its provenance and date, and holds ~20–40k hashes.
- [ ] Restart Nexus → the log reports the loaded count and "Hash reputation" reads On.
- [ ] Re-scan System32 → those binaries now come back **Trusted** or **Clean** instead
      of Unknown.
- [ ] **The one that matters:** put an unsigned binary of your own into Program Files,
      rebuild the baseline, and confirm its hash is **NOT** in the file. The entire
      safety of building an allowlist from the local machine rests on only
      validly-signed files being recorded.
- [ ] Corrupt a line in the middle of the file → Nexus still loads the rest and logs a
      sane count, rather than discarding the whole list.
- [ ] Restore Defaults → the file is gone and reputation reads Off again.

## 13. Optional YARA

Only if you have added `yara_x_capi.dll` and rules; skip otherwise.

- [ ] Without the DLL: `Nexus.Scanner.exe --self-test` lists four engines and no YARA,
      and everything else still works. A missing optional engine must never degrade
      the rest.
- [ ] With the DLL and `assets/yara/nexus-selftest.yar`: the self-test lists YARA.
- [ ] Scan a file containing the EICAR marker -> reports `yara-Nexus_SelfTest_Eicar`
      alongside the byte-pattern hit. Both engines should fire; they are independent.
- [ ] Scan an ordinary signed Windows binary → reports NOTHING from YARA. The
      shipped self-test rules must not match ordinary files; a bundled rule that
      fires on everything is worse than shipping no rules at all.
- [ ] Put a deliberately broken rule in `assets/yara/` -> the worker writes a compile
      error to standard error and reports YARA unavailable, rather than silently
      scanning with no rules.
- [ ] Add a large third-party rule set and scan a folder -> no crashes, and scanning
      stays responsive. If a single file trips the five-second rule timeout it is
      reported as `yara-timeout` rather than being silently skipped.
- [ ] Leave it running through a long scan -> no growth in the worker's memory beyond
      the file being scanned (the callback delegate is pinned; a leak here would show
      as steady growth).
