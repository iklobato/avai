rule eicar_test_file
{
    meta:
        description = "EICAR anti-malware test file (a benign test artifact, not real malware)"
        reference = "https://www.eicar.org/download-anti-malware-testfile/"
        author = "avai (bundled baseline rule)"
    strings:
        // Literal backslash in the EICAR string is escaped as \\ for YARA.
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}
