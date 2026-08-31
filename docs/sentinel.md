# Nexus Sentinel — the advisory security module

Sentinel is the security half of Nexus. It looks for malware and reports what it
finds. It does not block, delete, or quarantine anything on its own.

That constraint is the design, not a limitation to be fixed later.

## Why advisory

A blocking antivirus needs things this project cannot get:

| Capability | What it needs | Status |
|---|---|---|
| Real-time on-access blocking | A filesystem minifilter driver: an altitude allocation from Microsoft, an EV certificate, Partner Center attestation signing | Out of reach |
| Self-protection | Kernel object callbacks — same driver requirements | Out of reach |
| `Microsoft-Windows-Threat-Intelligence` ETW | The consuming process must run as PPL-antimalware, which needs an ELAM driver signed under the Microsoft Virus Initiative | Out of reach |
| Registering as *the* antivirus (and turning Defender off) | Microsoft Virus Initiative membership: an established company that has passed independent lab certification | Out of reach |

Every one of those gates exists to let software *block*. An advisory tool needs
none of them, which is why this one can actually be built and shipped.

**Keep Microsoft Defender on.** Sentinel is a second opinion and a visibility
layer. It is not a replacement, it cannot legally register as one, and it should
not try.

## How "it never acts on its own" is enforced

Not by discipline — by types.

`UserConsent` is a token that is single-use, bound to one file's identity, bound
to one action name, and expires after five minutes. Every destructive path in the
codebase requires one, and the only place in Nexus that constructs one is
`SecurityViewModel`, inside a click handler, immediately after a confirmation
dialog. A scanning loop cannot mint one, and a token minted for one file cannot be
replayed against another.

On top of that, `QuarantineService` keeps a list of refusals that no consent can
override: it will not move a file out of `C:\Windows` or `Program Files`, and it
will not touch anything on the optimizer's never-touch list. A security tool that
can be talked into deleting a system binary is a more effective wrecking ball than
most malware, and "the user clicked yes" is not a good enough reason.

## How a verdict is reached

Six signal sources feed one fusion step:

| Source | What it looks at |
|---|---|
| `Reputation` | Local known-good / known-bad SHA-256 lists |
| `CodeSignature` | Authenticode state via WinVerifyTrust |
| `StaticRules` | PE structure heuristics, byte-pattern signatures |
| `Behavior` | Process launches, ransomware-shaped file activity, live connections |
| `Persistence` | Run keys, tasks, services, IFEO, WMI, Winlogon, AppInit, Defender health |

Each signal carries a weight (Informational 0, Weak 8, Moderate 20, Strong 35,
Decisive 100) and a plain-language explanation shown verbatim to the user.

Two rules shape the scoring, both aimed at not crying wolf:

1. **Diminishing returns per source.** A source's strongest signal counts fully,
   each additional one counts half, and the source is capped at 60 points. Forty
   pattern hits on one packer are one opinion, not forty.
2. **Corroboration required.** That 60-point cap sits below the 75-point malicious
   threshold, so no single non-decisive engine can condemn a file alone. Only an
   exact known-bad hash gets to do that unaided. This is enforced by a test.

`Unknown` is a first-class verdict and is *not* an accusation. A file nobody could
analyse comes back unknown rather than clean — engines that did not run are not
counted toward coverage.

## Ransomware watch

Hidden canary files are planted in Documents, Pictures, Videos, Music and Desktop.
Nothing on the machine knows they exist, so nothing legitimate opens them — anything
that rewrites one is walking the filesystem indiscriminately, and that is worth
interrupting the user for immediately.

Alongside them, `MassChangeDetector` watches for the shape of an encryption run.
The ordinary burst rule is deliberately conservative and cannot alert on its own,
because backup tools, sync clients, game updaters and unzipping all produce bursts.
The sharp evidence is the stuff with no innocent version: a canary touched, many
files renamed to one new non-document extension, or a ransom-note filename appearing.

Both hot-path tallies (distinct paths, extension counts) are maintained incrementally
rather than recomputed. This code runs on every filesystem change on the machine, and
the obvious implementations are quadratic exactly during the flood of events an
encryption run produces — which is the worst possible moment to fall behind.

It reports. It does not suspend or kill the process: that cannot be done reliably
from user mode, and half-blocking an encryption run is worse than describing it
clearly.

## Reporting on Microsoft Defender

Nexus cannot register as the system antivirus and should not try. What it does
instead is watch the defence the machine actually relies on: whether real-time
protection is on, whether definitions are current, whether tamper protection is
enabled, and — most usefully — what has been excluded from scanning.

Adding a broad exclusion is a standard early step for malware that intends to stay,
it persists, and it is invisible unless you go looking. Nexus lists exclusions and
flags the ones broad enough to be holes. It does not remove them: silently editing
another security product's configuration is exactly the behaviour this module
refuses to have.

One subtlety worth knowing: `Get-MpPreference` substitutes a placeholder string for
the exclusion lists when the caller is not elevated. Nexus detects that placeholder
and reports "could not be read" rather than letting an unreadable list look like an
empty one.

## Scripts and archives

`ScriptAnalyzer` reads PowerShell, batch, VBScript, JScript and HTA. Scripts are
where most real intrusions execute, and unlike a compiled binary the evidence is in
plain text — which is why interesting samples work so hard to stop being plain text.
So the strongest signals are not "this calls something dangerous" but "this has been
deliberately mangled": base64 payloads, character-code assembly, escape obfuscation,
constructed code passed to `Invoke-Expression`.

Two categories are graded harder than obfuscation because they have no innocent
reading: turning off or carving holes in the machine's defences, and allocating
executable memory to run bytes out of.

UTF-16 is decoded properly. Reading a UTF-16 script as UTF-8 turns it into noise
that every keyword check then silently misses.

### JavaScript is graded differently, and why

Those obfuscation rules apply to PowerShell, batch and VBScript. They do **not**
score JavaScript or HTML, because measuring them on a real project showed they have
no discriminating power there.

The measurement: an ordinary Next.js project, 18,889 files. Under the original rules
1,988 of them came out as findings, several at 68/100 — "looks malicious". Not one
was. `jquery.min.js` was flagged because minifiers emit `String.fromCharCode`.
`typescript.js` was flagged because a lexer calls it on nearly every line.
`core-js` polyfills were flagged because they construct an `ActiveXObject("htmlfile")`
to detect Internet Explorer. The rules were right about what they saw and wrong about
what it meant: in a language whose entire ecosystem is generated, bundled and
transpiled, "this text was not written by hand" describes almost everything.

What is scored in a web script is the Windows Script Host surface that actually does
something — `WScript.Shell`, `Scripting.FileSystemObject`, `ADODB.Stream`,
`Shell.Application`. No browser can call those, so a `.js` file that does is meant to
be run by Windows, which is how script-based malware arrives. `ActiveXObject` and
`MSXML2.XMLHTTP` are deliberately *not* scored, because Internet Explorer-era web code
uses both.

Everything the obfuscation rules noticed is still recorded and still shown when a
finding is opened. It is just worth zero points, so it cannot turn an ordinary file
into an alert on its own.

The cost of this is real and worth stating: a malicious npm package that shells out
via `child_process` will not be caught by static analysis here, because legitimate
build tooling does the same thing constantly. That is a genuine gap, accepted
knowingly. The alternative — a thousand findings a developer learns to dismiss — is
not a safer tool, only a louder one.

`ArchiveStaticEngine` looks inside ZIP, 7z, RAR, tar, gzip, bzip2 and xz, because that
is how most malware arrives and a scanner that stops at the container reports
"unknown" on the files it most needs an opinion about. Malware moved off ZIP for
exactly that reason.

Format is decided by magic bytes, never by extension — a file named `.txt` is still a
7z archive if it starts like one. Two readers are needed: 7z and RAR want random
access to their central directory, while a `.tar.gz` is a compressed stream wrapping
another archive and only the forward-only reader will take it. Both feed the same
limit checks, so the entry cap, expansion cap, traversal check and zip-bomb ratio
apply identically to every format. The limits are not reimplemented per format; that
is how one copy quietly ends up missing a check.

Archives inside archives are opened, two levels deep. Putting the payload in a second
archive is the oldest way past a scanner that stops at the container, and reporting
"there is an archive in here" left the obvious case unexamined.

The recursion is bounded twice: by depth, and by a single budget shared across every
level. Sharing the budget is what makes it safe — a fresh allowance per level would
let ten nested archives multiply the expansion ceiling tenfold, turning the zip-bomb
defence into a zip-bomb amplifier. Anything too deep, or reached after the budget is
spent, is reported as unopened, because unexamined is not the same as clean.

Findings name the whole path to the payload: "Inside the archive, test.7z: inside the
archive, dropper.ps1: this script downloads something from the internet and runs it".

A password-protected archive is reported as password-protected, not as corrupt. The
difference matters: encrypting an attachment so the scanner cannot read it, and
putting the password in the message beside it, is the oldest working delivery method
there is. Nexus says it could not look inside, which is not the same as saying there
is nothing there. Every limit exists because the archive is attacker-controlled: entry
count, total expansion, per-entry size, and compression ratio are all capped, path
traversal entries are flagged, nothing is written to disk, and nested archives are
reported rather than opened. Findings are rewritten to name the entry they came from.

## Scan modes

| Mode | Covers | Triggered by |
|---|---|---|
| Quick check | Downloads, temp, startup folders | Button, and every 6 hours |
| Scan folder | One folder, recursively | Button, or right-click a folder |
| Scan one file | One file | Right-click a file |
| Full scan | Every fixed drive | Button, and optionally weekly when idle |
| Running programs | The file behind every running process | Button |
| USB check | A removable drive, capped at 20,000 files | The drive being plugged in |
| Startup items | Run keys, services, scheduled tasks | Button |
| Network settings | Hosts file, proxy, DNS | Button |
| Windows security settings | Firewall, UAC, SmartScreen, Secure Boot, encryption, update age | Button |
| Browser extensions | Chrome, Edge, Brave, Vivaldi, Opera | Button |

The scheduled full scan is off unless asked for, unlike every other watch here.
Nexus's other half exists to keep the machine responsive, and a surprise full scan
chewing the disk is the behaviour it was built to prevent. Switched on, it waits for
ten minutes of genuine idle, never competes with a game, and pauses the moment input
comes back — checked every 200 files, so returning to the machine costs a second
rather than the rest of the scan.

Checking running programs exists because behaviour monitoring only ever sees a
process as it *starts*. Everything already running when Nexus was installed has never
been looked at, which is exactly where something that meant to stay would be sitting.
It reads the files behind those processes; it does not read process memory or touch
anything that is running.

Removable and network drives are left out of the full scan deliberately. A full scan
that silently pulls a terabyte across a VPN is not a feature, and a USB drive is
better looked at when it is plugged in — which is the moment before something on it
gets double-clicked.

The USB watch polls rather than subscribing to `WM_DEVICECHANGE`. That message needs
a window handle, and Nexus can be running with only a tray icon, so the tidier
approach would stop working exactly when the window is closed.

## Signatures, including the ones Windows keeps elsewhere

Most of Windows carries no signature inside the file. System binaries are signed in
bulk through catalog (`.cat`) files, and asking `WinVerifyTrust` about the file alone
answers "no signature" for `notepad.exe`, `svchost.exe` and `kernel32.dll` alike.

Nexus checks the catalogs when a file has no embedded signature of its own. Without
that step the strongest exoneration in the module — a valid Microsoft signature —
never fired for the operating system, and every scan of a Windows folder reported
thousands of files as unsigned. A scan of System32 (5,452 files) now produces no
findings at all.

## Watching the network

`GetExtendedTcpTable` answers "what is connected right now". A connection that opens
and closes between two looks therefore never happened, as far as Nexus is concerned,
and a great deal of what is worth seeing is exactly that short: a beacon checking in,
a downloader fetching a payload. Pressing a button in the UI was never going to catch
one.

So while protection is on, the table is sampled every ten seconds and the results are
kept. The call is a kernel table copy rather than a scan, which is what makes that
affordable to run all day. The rules themselves did not change — a program running
from a temp folder while connected was always worth reporting — but sampling is what
gives them a chance to fire.

Findings are identified by a hash of their own content rather than by a fixed name.
Without that, the first network finding of the session would have deduplicated every
later one out of existence, because they would all have shared an identity.

**Held in memory only.** Writing every address this machine has contacted into a file
would build a browsing history on the user's disk, and creating that record is a
bigger risk to them than the one it helps with. It lives as long as the session.

One thing measurement corrected here: a program commonly holds several simultaneous
sockets to the same endpoint, and counting each row as a sighting made the "seen N
times" figure meaningless — six samples of a browser reported it as seen 156 times,
which reads as persistence and is really parallelism. Sightings are counted per
sample.

## Watching processes start

Behaviour monitoring is fed by an ETW kernel session, and falls back to a WMI watcher
when ETW cannot start.

The difference is not academic. WMI delivers process-creation events on a one-second
polling window, so a process that starts and exits inside that window is never seen
at all — and that is the normal shape of the thing worth catching. A dropper that
spawns `cmd /c powershell -enc …` and exits lives for milliseconds. ETW delivers the
event as the kernel creates the process and misses nothing.

Neither can **intercept**. The event arrives as the process starts, not before, so
this stays a reporting pipeline; blocking an execution needs a kernel driver.

The Security tab names which watcher is running, because "behaviour monitoring: on"
otherwise means two materially different things and the user cannot tell which they
have.

ETW needs administrator rights, which Nexus has. It can still fail — policy can
disable it, another tool can hold the session — and a crash leaves the session behind,
so a stale one is cleared by name at every start. Without that, one hard kill would
cost the feature until the machine was rebooted.

**On verification:** the fallback path is tested — unelevated, `TryStart` returns false
cleanly, nothing throws, and the log explains the downgrade. The ETW path itself could
not be exercised on the machine this was written on, because starting a kernel session
requires elevation and the development shell does not have it. What *was* confirmed is
that the library loads and reaches the real session call from a single-file
self-contained build, which is the shipping configuration. The manual checklist has a
step for confirming the rest, and until someone runs it the honest statement is that
this half is unproven rather than proven.

## Checking the checks

`tools/Nexus.Sweep` runs this scoring over a real folder and prints what would be
reported. It exists because unit tests kept passing while the product was wrong.

Every false positive of consequence in this module was written with a plausible
rationale, covered by a test that agreed with it, and only fell over when pointed at
an actual disk. Exempting minified JavaScript from the obfuscation rules looked
correct and fixed almost nothing, because `typescript.js` is not minified and a lexer
calls `String.fromCharCode` on every line. The future-timestamp rule fired on nearly
every modern DLL. A .NET assembly with dense embedded resources was called "packed",
and that only surfaced when a new dependency happened to include one.

A test proves a rule does what its author meant. The sweep proves what the rule does
to the machine it is installed on, which is a different question and the one that
matters.

```
dotnet run --project tools/Nexus.Sweep -- "C:\Users\me\Downloads"
dotnet run --project tools/Nexus.Sweep -- --running
```

It exits non-zero when anything is flagged, so it can gate a release. The expected
result on a folder of ordinary software is zero. Current baselines on the development
machine:

| Target | Files | Reported |
|---|---|---|
| A Next.js project with `node_modules` | 18,917 | 0 |
| `C:\Windows\System32` | 6,911 | 0 |
| Programs running right now | 44 | 0 |
| A folder of planted droppers, plain and archived | 11 | 10 |

The sweep drives the real `Nexus.Scanner.exe` over the same protocol the product
uses, so archives, byte patterns and YARA are measured too. Compiling its engines in
instead would let the tool drift from what actually ships — reporting confidently on
behaviour the product does not have.

The last row is the control. Without it, "zero findings" only proves the tool has
been quieted, not that it is right.

## Scan history

Every scan is recorded: when, what, how many files, how many findings, and whether it
finished or was stopped. The last hundred are kept, and the whole thing exports as
plain text — plain text because what people actually do with a scan report is paste it
somewhere while asking for help.

This exists because an empty findings list is ambiguous. "500,000 files, nothing
flagged" and "nothing has run in three weeks" look identical from the findings list
alone, and only one of them is reassuring.

## When scanning happens

Four triggers, in rough order of how much they matter:

1. **On arrival.** New programs and archives landing in Downloads are checked as
   they appear. This is the one moment a warning changes what happens next —
   before the thing is double-clicked. Browsers write to a temporary name and
   rename on completion, so the rename is the event acted on, and the file is
   retried until the writer lets go of it.
2. **On a schedule.** Every six hours, the folders where new files actually
   arrive: Downloads, temp, the startup locations, Desktop. Deliberately not a
   full-disk scan — that takes hours, finds nothing extra, and gets cancelled.
   It never starts while Game Mode is active and abandons a scan in progress the
   moment a game launches.
3. **On demand.** A folder, or the quick check, from the Security tab.
4. **Continuously, for behaviour.** Process launches and file activity, which are
   not scans at all.

Repeat work is skipped through a cache keyed on path, size and last-write time,
so a rescan does not re-read and re-hash unchanged files. Machine-generated trees
(`.git`, `node_modules`, `obj`, `WinSxS`) are skipped entirely: enormous, and not
how anything gets executed.

## What the user can see and undo

A security tool that accumulates state the user cannot inspect is one they end up
distrusting. So:

- **Protection status** lists each component and whether it is genuinely running,
  distinguishing "turned off in Settings" from "tried to start and failed". Several
  of these can fail for ordinary reasons — WMI unavailable, a redirected Documents
  folder, the worker missing — and a module that looks enabled while silently doing
  nothing is worse than one honestly switched off.
- **Trusted files** are listed with a one-click revoke. Trusting something is a
  lasting decision made in a hurry from a dialog; an allowlist that can only grow
  is not acceptable in a security tool.
- **Quarantine** lists every held file with its original path and the reason.
- **"That was me"** resets the ransomware watch after an expected burst, because
  the alternative — after one false alarm from a backup restore — is that the user
  turns the whole feature off.
- **Restore all defaults** puts quarantined files back, removes the tripwire files,
  and clears the trust store, verdict cache and saved baselines.

## Turning YARA on

YARA is what a byte-pattern engine cannot be: conditions over PE structure, string
sets, wildcards, regular expressions, file-size guards. Nexus's own `PatternEngine`
does only literal bytes and says so — this is the step up.

It is implemented and tested, and needs two things dropped in beside `Nexus.exe`:

1. **The engine.** Download the YARA-X C API package from
   <https://github.com/VirusTotal/yara-x/releases> (`yara-x-capi-*-x86_64-pc-windows-msvc.zip`)
   and put `yara_x_capi.dll` next to `Nexus.exe`. BSD-3-Clause, compatible with MIT.
2. **Rules.** Any `.yar` or `.yara` file under `assets/yara/`. Nexus ships one
   self-test rule file of its own; see NOTICE.md for rule sets and their licences.

Verify it took: `Nexus.Scanner.exe --self-test` should list `YARA`, and scanning a
file containing the EICAR marker should report `yara-Nexus_SelfTest_Eicar`. If the
library loaded but rules did not compile, the worker writes the reason to standard
error rather than silently switching the engine off.

The shipped self-test rule matches only the EICAR marker, deliberately. An earlier
version also carried a rule matching any PE file, to demonstrate that structural
conditions work — and since every YARA hit is weighted Moderate, which clears the
alert threshold on its own, that rule reported every unsigned executable on the
machine. Bundled rules that fire on ordinary files are worse than shipping none.

Nexus binds the C API directly rather than through a community wrapper package.
In a security tool the supply chain is part of the threat model, and each wrapper is
one more party whose build you are trusting inside the process that parses hostile
files.

YARA hits are weighted **Moderate**, not Strong. Rule quality varies enormously
between collections, a hit is one opinion from one source, and the fusion engine's
per-source cap already prevents a noisy rule set condemning a file on its own — so
the weighting assumes nothing about whose rules are loaded.

Because Sentinel reports rather than blocks, it can afford broader and noisier rule
sets than an enforcing product could. A false positive costs a line in a report, not
a deleted file.

## Process isolation

All hostile-file parsing runs in `Nexus.Scanner.exe`, a separate process.

Nexus runs elevated. Every consequential remote-code-execution bug in a mainstream
antivirus has been in its file parsers, and a parser bug in an elevated process is
a full machine compromise. So the parsers live in a child process that is killed
and restarted on any timeout, crash, or protocol desync, with a restart cap so a
reproducible crash becomes a reported fault instead of a respawn loop.

Only `ScanRequest` / `ScanResponse` cross the boundary: text and enums. Nothing
the worker sends is used as a path to act on, a command, or an instruction. An
unparseable enum value from the worker degrades to `Informational` rather than
throwing.

## Identity: hash, not file name

The optimizer matches rules by exe name. That is a fine shortcut when the worst
case is a mis-prioritised process. It is not fine when deciding what to trust —
malware named `csrss.exe` would inherit the real one's exemption.

Security identity is the full path plus the SHA-256 of the contents, and trust
decisions are keyed on the hash alone, so replacing a trusted file's bytes revokes
its trust automatically. `BehaviorEngine` also flags any system image name running
from outside its expected directory.

## Nexus audits itself

The startup audit finds and reports Nexus's own scheduled task and its own IFEO
`PerfOptions` keys, marked as its own rather than filtered out. A security tool
that hides its own footprint teaches the user to trust a blind spot — and Nexus
writes exactly the kind of registry keys a user should be able to see and
recognise.

## Hash reputation, and why the baseline is built locally

Sentinel needs known-good data to say "clean" at all. Without it, reputation never
counts as an engine consulted, and since `Clean` requires three engines, **every
ordinary file comes back "unknown"** — including signed Windows binaries.

The obvious source is NIST's NSRL, and it is impractical: the full reference set is
tens of gigabytes, against a 63 MB application.

So Nexus builds the list from the machine it is running on: every binary in System32
and Program Files whose Authenticode signature is **valid and chains to a root
Windows already trusts**. That is smaller (a couple of MB), tailored to the machine's
actual patch level, free of licensing questions, and costs nothing to distribute.

That one rule — valid signature only — is what makes it safe on a machine that is
already compromised. Unsigned and badly-signed files are never recorded, and an
attacker who could satisfy that check could already sign code Windows accepts, at
which point the baseline is not the weak link. The generated file records its own
provenance and date, because a list that silently exonerates thousands of files
should say where it came from.

For known-bad, abuse.ch's MalwareBazaar publishes a full SHA-256 export under CC0,
with no API key. It is not bundled; drop it in as `assets/known-bad.txt`.

## Assets

Optional, and living in `assets/` beside the executable — deliberately not in a
user-writable directory, so a non-admin cannot swap the detection data:

| File | Effect if missing |
|---|---|
| `known-good.txt` | Curated known-good list. The locally built baseline covers this |
| `known-bad.txt` | Hash reputation cannot identify known malware |
| `patterns.txt` | Byte-pattern signatures are inert |

The locally built baseline lives in `%APPDATA%\Nexus\security\known-good-local.txt`,
not in `assets/`, because it is produced at runtime and the install directory is not
writable for a normal user.

Format for the hash lists: one lowercase hex SHA-256 per line; `#` comments and
`hash,name` exports are tolerated.

Format for `patterns.txt`: `name | weight | hex:4D5A9000 or text:literal | description`.
Literal patterns are capped at `Strong` — a byte sequence appears in benign files
too, and this engine has no rule language to express the context that would justify
certainty.

## What is not built

- **YARA** — implemented and working, but not bundled. Two files have to be added
  (below), because the DLL is ~21 MB and rule sets carry licences that would
  constrain how Nexus itself may be redistributed.
- **ML classifier** — deliberately dropped, not deferred. The tempting route is
  training on EMBER, and it is a trap: its 2,381-dimensional feature extractor would
  have to be reimplemented exactly, and any mismatch between training and inference
  silently destroys accuracy without erroring — a confident model that is quietly
  wrong, which is the worst failure shape available. The defensible route (training
  on the features `PeImage` already extracts) is real work for modest gain, since the
  fusion engine caps any single source at 60 points and PE heuristics already cover
  the same structural ground. A permanent "unavailable" stub would have
  misrepresented a scope decision as an unfinished feature.
- **Online reputation lookup** — an interface with no implementation wired in.
  Sending a hash of every file on the machine to a third party is a disclosure the
  user did not ask for; if this is ever added it stays opt-in and one file at a
  time.

An unavailable engine is excluded from the engines-consulted count, so its absence
makes files read "unknown" rather than falsely "clean".

## Honest limitations

- **Behaviour monitoring polls.** WMI delivers process-creation events on a
  one-second window, so a process that starts and exits inside that window is
  missed entirely.
- **Everything is after the fact.** By the time an event arrives, the process is
  already running. This is a reporting pipeline. It could not block an execution
  if it wanted to, and it does not claim it can.
- **Large files are skipped.** Over 512 MB, no hash; over 128 MB, no static
  analysis. A scanner that can be made to allocate gigabytes by pointing it at a
  big file is a denial of service against the machine it protects.
- **Detection strength depends entirely on the assets supplied.** With no hash
  lists and no patterns, Sentinel is a structural analyser and a behaviour monitor,
  not a signature scanner.
