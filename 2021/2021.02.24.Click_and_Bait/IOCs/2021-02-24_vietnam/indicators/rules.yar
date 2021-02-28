rule apt32_macos_dropper {
    meta:
        author = "Amnesty Tech"

    strings:
        $s1 = "setStartup" ascii
        $s2 = "getSizeDataLoader" ascii
        $s3 = "GET_LAUNCHNAME" ascii
        $s4 = "GET_PROCESSNAME" ascii
        $s5 = "getProcessnameRoot" ascii
        $s6 = "getProcessnameUser" ascii
        $s7 = "getProcessPathRoot" ascii
        $s8 = "getLabelnameRoot" ascii
        $s9 = "getLabelnameUser" ascii
        $s10 = "stringFromHex" ascii
        $s11 = "_b64_decode_ex" ascii

    condition:
        (uint16(0) == 0xfacf or uint16(0) == 0xface) and 9 of them
}

rule apt32_macos_backdoor_2018_encryption_key {
    strings:
        $key = { 63 49 2f 6e 22 00 10 fe 33 4f 2f c5 05 b2 11 03 ba 5b dd 02 }
        $ccc = "CCCrypt" ascii
    condition:
        (uint16(0) == 0xfacf or uint16(0) == 0xface) and all of them
}

rule apt32_macos_backdoor_2019_encryption_key {
    meta:
        report = "https://www.welivesecurity.com/2019/04/09/oceanlotus-macos-malware-update/"
    strings:
        $key1 = { 9D 72 74 AD 7B CE F0 DE D2 9B DB B4 28 C2 51 DF 8B 35 0B 92 }
        $key2 = {2c e4 25 29 5e 2a 20 40 9c a5 13 1e 61 1e 51 6f 2c b7 a7 7f }
        $key3 = { 8b b2 c4 67 56 5c 63 42 8e f0 cf c5 f4 8d 87 ae 58 0c 5b a4 }
        $ccc = "CCCrypt" ascii
    condition:
        (uint16(0) == 0xfacf or uint16(0) == 0xface) and $ccc and any of ($key*)
}

rule apt32_macos_backdoor_2018 {
    meta:
        author = "Amnesty Tech"

    strings:
        $s1 = "respondDownloadThreadP" ascii
        $s2 = "checkProcessExist" ascii
        $s3 = "setFristRandom" ascii
        $s4 = "getInstalledTime" ascii
        $s5 = "getSerialNumber" ascii
        $s6 = "appendPathComponent" ascii
        $s7 = "initFirstRandom" ascii
        $s8 = "CFURLToString" ascii
        $s9 = "GET_DOMAIN_CLIENT_INFO" ascii
        $s10 = "getFirstRandom_Header" ascii
        $s11 = "respondLoadLunaThread" ascii

    condition:
        (uint16(0) == 0xfacf or uint16(0) == 0xface) and 9 of them

}
