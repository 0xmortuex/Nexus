/*
    Nexus Sentinel — YARA self-test rules.

    These exist to prove the YARA pipeline is actually working, not to detect
    anything real. If a scan of a file containing the EICAR string does not report
    "yara-Nexus_SelfTest_Eicar", then the native library loaded but the rules are not
    reaching the scanner, and any other rule set you add is equally inert.

    Written for Nexus and covered by the project's MIT licence, so there is nothing
    to attribute. Third-party rule sets go alongside this file and carry their own
    licences — see docs/sentinel.md.
*/

rule Nexus_SelfTest_Eicar
{
    meta:
        author      = "Nexus"
        description = "The EICAR test marker. Harmless by design; this is what it is for."

    strings:
        // Split so this rule file does not itself contain the full EICAR string and
        // get quarantined by whatever antivirus is watching the source tree.
        $marker = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"

    condition:
        $marker
}

/*
    There was a second rule here that matched any PE file, to demonstrate that
    structural conditions work. It was removed, and the reason is worth recording.

    Every YARA hit is weighted Moderate, which is 20 points against a 15-point alert
    threshold. A rule matching every executable therefore raised a finding on every
    executable. Signed binaries survived on their exonerating signature, so it looked
    fine in testing — but any unsigned program would have been reported as "worth a
    look" purely because Nexus shipped a rule that matches everything.

    A detection engine whose own bundled rules generate false positives is worse than
    one with no rules at all. The EICAR rule above is enough to prove the pipeline
    works end to end: library loaded, rules compiled, scan ran, callback fired,
    identifier returned.
*/
