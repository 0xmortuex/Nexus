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
| `MachineLearning` | PE-feature classifier (not shipped — see Assets) |
| `Behavior` | Process launches: ancestry, command lines, masquerading |
| `Persistence` | Run keys, tasks, services, IFEO, WMI, Winlogon, AppInit |

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

## Assets

These are optional and live in `assets/` beside the executable, deliberately not
in a user-writable directory:

| File | Effect if missing |
|---|---|
| `known-good.txt` | Hash reputation cannot exonerate by hash |
| `known-bad.txt` | Hash reputation cannot identify known malware |
| `patterns.txt` | Byte-pattern signatures are inert |
| `pe-classifier.onnx` | Not wired up in this build |

Format for the hash lists: one lowercase hex SHA-256 per line; `#` comments and
`hash,name` exports are tolerated.

Format for `patterns.txt`: `name | weight | hex:4D5A9000 or text:literal | description`.
Literal patterns are capped at `Strong` — a byte sequence appears in benign files
too, and this engine has no rule language to express the context that would justify
certainty.

## What is not built

- **YARA** — reports itself unavailable. Needs a native library shipped and a rule
  set chosen; rule sets carry licences, which is a decision rather than a default.
- **ML classifier** — reports itself unavailable. Shipping a classifier that has
  not been evaluated against a real false-positive budget would produce
  confident-sounding noise, which is the exact failure this design avoids.
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
