# Nexus — manual test checklist (first run on Windows)

Built and unit-tested on Linux; this checklist is the required first-run
verification on a real Windows 10/11 machine. Work through it top to bottom —
items marked **[hybrid]** need a P/E-core CPU (Intel 12th gen+), items marked
**[win11]** need Windows 11.

## 0. Install & launch
- [ ] `dotnet publish src/Nexus.App -c Release -r win-x64 --self-contained -p:PublishSingleFile=true`
      produces a single `Nexus.exe`.
- [ ] Launching triggers a UAC elevation prompt (manifest requireAdministrator).
- [ ] Denying elevation → app does not start. Accepting → main window opens, dark theme.
- [ ] Launching a second instance shows "already running" and exits.
- [ ] `%APPDATA%\Nexus\` is created with settings.json + logs\activity-*.log.
- [ ] SmartScreen note: unsigned exe → "More info → Run anyway" is expected; document for users.

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
