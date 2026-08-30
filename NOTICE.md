# Third-party components

Nexus itself is MIT (see [LICENSE](LICENSE)). No third-party binary is vendored into
this repository. One package is restored from NuGet at build time and is listed first;
everything after it is optional, downloaded by you, and listed so the licence position
is clear before you add it.

## Build dependencies

### SharpCompress — MIT

<https://github.com/adamhathcock/sharpcompress>

Reads 7z, RAR, tar, gzip, bzip2 and xz archives inside `Nexus.Scanner`. Malware moved
into these formats precisely because scanners that only understood ZIP reported
"unknown" and got out of the way.

It is a managed, dependency-free implementation, which is why it was chosen over
shelling out to 7-Zip: a scanner that spawns an external unpacker on an
attacker-controlled file has handed the attacker a process. It runs only in the
scanner worker, never in the elevated host — a parser bug in it costs a crashed
helper process rather than the machine.

MIT, the same licence as Nexus, so it adds no obligation beyond attribution.

## Optional native components

### YARA-X — BSD-3-Clause

<https://github.com/VirusTotal/yara-x>

The rule-matching engine, used by `Nexus.Scanner` when `yara_x_capi.dll` is present
beside the executable. Not bundled: the DLL is around 21 MB, roughly a third of the
size of Nexus itself, and it is VirusTotal's build rather than ours. Committing a
third-party binary into a security tool's repository makes it something reviewers
have to trust without being able to review it.

Nexus binds the C API directly rather than through a community wrapper package. In a
tool like this the supply chain is part of the threat model, and each wrapper is one
more party whose build you trust inside the process that parses hostile files.

BSD-3-Clause is compatible with MIT. If you redistribute a build with the DLL
included, ship YARA-X's licence text alongside it.

## Optional data

### YARA rule sets — various

Only `assets/yara/nexus-selftest.yar` ships with Nexus, and it is our own work under
the project licence. Anything else you add carries its own terms:

| Source | Licence | Notes |
|---|---|---|
| [ReversingLabs](https://github.com/reversinglabs/reversinglabs-yara-rules) | MIT | Safest fit for an MIT project |
| [Florian Roth, signature-base](https://github.com/Neo23x0/signature-base) | Detection Rule License 1.1 | Written for sharing detection rules; commercial use with attribution |
| [Elastic protections-artifacts](https://github.com/elastic/protections-artifacts) | Elastic License 2.0 | Fine for a distributed desktop app; restricts offering it as a managed service |
| [YARA-Rules/rules](https://github.com/Yara-Rules/rules) | mostly GPL-2.0 | Bundling these would constrain how you redistribute Nexus |

Because Sentinel reports rather than blocks, it can afford broader and noisier rule
sets than an enforcing product could: a false positive costs a line in a report, not
a deleted file.

### Malware hash lists — CC0

[abuse.ch MalwareBazaar](https://bazaar.abuse.ch/) publishes SHA-256 exports under
CC0, with no account required. Nexus can import one from the Security tab, or from a
file you download yourself. Nothing is bundled and no list is fetched unless you ask
for it.

### Known-good hashes — generated locally

Built from your own machine's validly-signed binaries. It never leaves the machine
and there is nothing to license.

## Deliberately not used

**ClamAV's signature database** is GPL. Using it would constrain how Nexus is
redistributed, which is why the byte-pattern engine uses its own format instead.

**VirusTotal's public API** is free for non-commercial use only, and per-file lookups
would mean sending hashes of your files to a third party. Sentinel's reputation is
local by design; the online-lookup interface exists but has no implementation wired
in.
