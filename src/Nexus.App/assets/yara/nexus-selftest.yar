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

rule Nexus_SelfTest_PeStructure
{
    meta:
        author      = "Nexus"
        description = "Proves structural conditions work, which is the whole point of YARA over literal byte patterns."

    condition:
        // A DOS header followed by a PE signature at the offset the stub points to.
        // A literal-pattern engine cannot express this; that is the capability gap
        // YARA fills.
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550
}
