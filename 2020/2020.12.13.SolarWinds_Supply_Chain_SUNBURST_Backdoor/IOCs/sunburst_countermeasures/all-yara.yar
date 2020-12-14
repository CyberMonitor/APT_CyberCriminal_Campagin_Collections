// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/sunburst_countermeasures/blob/main/LICENSE.txt
import "pe"

rule APT_Backdoor_SUNBURST_1
{
    meta:
        author = "FireEye"
        description = "This rule is looking for portions of the SUNBURST backdoor that are vital to how it functions. The first signature fnv_xor matches a magic byte xor that the sample performs on process, service, and driver names/paths. SUNBURST is a backdoor that has the ability to spawn and kill processes, write and delete files, set and create registry keys, gather system information, and disable a set of forensic analysis tools and services."
    strings:
        $cmd_regex_encoded = "U4qpjjbQtUzUTdONrTY2q42pVapRgooABYxQuIZmtUoA" wide
        $cmd_regex_plain = { 5C 7B 5B 30 2D 39 61 2D 66 2D 5D 7B 33 36 7D 5C 7D 22 7C 22 5B 30 2D 39 61 2D 66 5D 7B 33 32 7D 22 7C 22 5B 30 2D 39 61 2D 66 5D 7B 31 36 7D }
        $fake_orion_event_encoded = "U3ItS80rCaksSFWyUvIvyszPU9IBAA==" wide
        $fake_orion_event_plain = { 22 45 76 65 6E 74 54 79 70 65 22 3A 22 4F 72 69 6F 6E 22 2C }
        $fake_orion_eventmanager_encoded = "U3ItS80r8UvMTVWyUgKzfRPzEtNTi5R0AA==" wide
        $fake_orion_eventmanager_plain = { 22 45 76 65 6E 74 4E 61 6D 65 22 3A 22 45 76 65 6E 74 4D 61 6E 61 67 65 72 22 2C }
        $fake_orion_message_encoded = "U/JNLS5OTE9VslKqNqhVAgA=" wide
        $fake_orion_message_plain = { 22 4D 65 73 73 61 67 65 22 3A 22 7B 30 7D 22 }
        $fnv_xor = { 67 19 D8 A7 3B 90 AC 5B }
    condition:
        $fnv_xor and ($cmd_regex_encoded or $cmd_regex_plain) or ( ($fake_orion_event_encoded or $fake_orion_event_plain) and ($fake_orion_eventmanager_encoded or $fake_orion_eventmanager_plain) and ($fake_orion_message_encoded and $fake_orion_message_plain) )
}
rule APT_Backdoor_SUNBURST_2
{
    meta:
        author = "FireEye"
        description = "The SUNBURST backdoor uses a domain generation algorithm (DGA) as part of C2 communications. This rule is looking for each branch of the code that checks for which HTTP method is being used. This is in one large conjunction, and all branches are then tied together via disjunction. The grouping is intentionally designed so that if any part of the DGA is re-used in another sample, this signature should match that re-used portion. SUNBURST is a backdoor that has the ability to spawn and kill processes, write and delete files, set and create registry keys, gather system information, and disable a set of forensic analysis tools and services."
    strings:
        $a = "0y3Kzy8BAA==" wide
        $aa = "S8vPKynWL89PS9OvNqjVrTYEYqNa3fLUpDSgTLVxrR5IzggA" wide
        $ab = "S8vPKynWL89PS9OvNqjVrTYEYqPaauNaPZCYEQA=" wide
        $ac = "C88sSs1JLS4GAA==" wide
        $ad = "C/UEAA==" wide
        $ae = "C89MSU8tKQYA" wide
        $af = "8wvwBQA=" wide
        $ag = "cyzIz8nJBwA=" wide
        $ah = "c87JL03xzc/LLMkvysxLBwA=" wide
        $ai = "88tPSS0GAA==" wide
        $aj = "C8vPKc1NLQYA" wide
        $ak = "88wrSS1KS0xOLQYA" wide
        $al = "c87PLcjPS80rKQYA" wide
        $am = "Ky7PLNAvLUjRBwA=" wide
        $an = "06vIzQEA" wide
        $b = "0y3NyyxLLSpOzIlPTgQA" wide
        $c = "001OBAA=" wide
        $d = "0y0oysxNLKqMT04EAA==" wide
        $e = "0y3JzE0tLknMLQAA" wide
        $f = "003PyU9KzAEA" wide
        $h = "0y1OTS4tSk1OBAA=" wide
        $i = "K8jO1E8uytGvNqitNqytNqrVA/IA" wide
        $j = "c8rPSQEA" wide
        $k = "c8rPSfEsSczJTAYA" wide
        $l = "c60oKUp0ys9JAQA=" wide
        $m = "c60oKUp0ys9J8SxJzMlMBgA=" wide
        $n = "8yxJzMlMBgA=" wide
        $o = "88lMzygBAA==" wide
        $p = "88lMzyjxLEnMyUwGAA==" wide
        $q = "C0pNL81JLAIA" wide
        $r = "C07NzXTKz0kBAA==" wide
        $s = "C07NzXTKz0nxLEnMyUwGAA==" wide
        $t = "yy9IzStOzCsGAA==" wide
        $u = "y8svyQcA" wide
        $v = "SytKTU3LzysBAA==" wide
        $w = "C84vLUpOdc5PSQ0oygcA" wide
        $x = "C84vLUpODU4tykwLKMoHAA==" wide
        $y = "C84vLUpO9UjMC07MKwYA" wide
        $z = "C84vLUpO9UjMC04tykwDAA==" wide
    condition:
        ($a and $b and $c and $d and $e and $f and $h and $i) or ($j and $k and $l and $m and $n and $o and $p and $q and $r and $s and ($aa or $ab)) or ($t and $u and $v and $w and $x and $y and $z and ($aa or $ab)) or ($ac and $ad and $ae and $af and $ag and $ah and ($am or $an)) or ($ai and $aj and $ak and $al and ($am or $an))
}
rule APT_Webshell_SUPERNOVA_1
{
    meta:
        author = "FireEye"
        description = "SUPERNOVA is a .NET web shell backdoor masquerading as a legitimate SolarWinds web service handler. SUPERNOVA inspects and responds to HTTP requests with the appropriate HTTP query strings, Cookies, and/or HTML form values (e.g. named codes, class, method, and args). This rule is looking for specific strings and attributes related to SUPERNOVA."
    strings:
        $compile1 = "CompileAssemblyFromSource"
        $compile2 = "CreateCompiler"
        $context = "ProcessRequest"
        $httpmodule = "IHttpHandler" ascii
        $string1 = "clazz"
        $string2 = "//NetPerfMon//images//NoLogo.gif" wide
        $string3 = "SolarWinds" ascii nocase wide
    condition:
        uint16(0) == 0x5a4d and uint32(uint32(0x3C)) == 0x00004550 and filesize < 10KB and pe.imports("mscoree.dll","_CorDllMain") and $httpmodule and $context and all of ($compile*) and all of ($string*)
}
rule APT_Webshell_SUPERNOVA_2
{
    meta:
        author = "FireEye"
        description = "This rule is looking for specific strings related to SUPERNOVA. SUPERNOVA is a .NET web shell backdoor masquerading as a legitimate SolarWinds web service handler. SUPERNOVA inspects and responds to HTTP requests with the appropriate HTTP query strings, Cookies, and/or HTML form values (e.g. named codes, class, method, and args)."
    strings:
        $dynamic = "DynamicRun"
        $solar = "Solarwinds" nocase
        $string1 = "codes"
        $string2 = "clazz"
        $string3 = "method"
        $string4 = "args"
    condition:
        uint16(0) == 0x5a4d and uint32(uint32(0x3C)) == 0x00004550 and filesize < 10KB and 3 of ($string*) and $dynamic and $solar
}
rule APT_HackTool_PS1_COSMICGALE_1
{
    meta:
        author = "FireEye"
        description = "This rule detects various unique strings related to COSMICGALE. COSMICGALE is a credential theft and reconnaissance PowerShell script that collects credentials using the publicly available Get-PassHashes routine. COSMICGALE clears log files, writes acquired data to a hard coded path, and encrypts the file with a password."
    strings:
        $sr1 = /\[byte\[\]\]@\([\x09\x20]{0,32}0xaa[\x09\x20]{0,32},[\x09\x20]{0,32}0xd3[\x09\x20]{0,32},[\x09\x20]{0,32}0xb4[\x09\x20]{0,32},[\x09\x20]{0,32}0x35[\x09\x20]{0,32},/ ascii nocase wide
        $sr2 = /\[bitconverter\]::toint32\(\$\w{1,64}\[0x0c..0x0f\][\x09\x20]{0,32},[\x09\x20]{0,32}0\)[\x09\x20]{0,32}\+[\x09\x20]{0,32}0xcc\x3b/ ascii nocase wide
        $sr3 = /\[byte\[\]\]\(\$\w{1,64}\.padright\(\d{1,2}\)\.substring\([\x09\x20]{0,32}0[\x09\x20]{0,32},[\x09\x20]{0,32}\d{1,2}\)\.tochararray\(\)\)/ ascii nocase wide
        $ss1 = "[text.encoding]::ascii.getbytes(\"ntpassword\x600\");" ascii nocase wide
        $ss2 = "system\\currentcontrolset\\control\\lsa\\$_" ascii nocase wide
        $ss3 = "[security.cryptography.md5]::create()" ascii nocase wide
        $ss4 = "[system.security.principal.windowsidentity]::getcurrent().name" ascii nocase wide
        $ss5 = "out-file" ascii nocase wide
        $ss6 = "convertto-securestring" ascii nocase wide
    condition:
        all of them
}
rule APT_Dropper_Raw64_TEARDROP_1
{
    meta:
        author = "FireEye"
        description = "This rule looks for portions of the TEARDROP backdoor that are vital to how it functions. TEARDROP is a memory only dropper that can read files and registry keys, XOR decode an embedded payload, and load the payload into memory. TEARDROP persists as a Windows service and has been observed dropping Cobalt Strike BEACON into memory."
    strings:
        $sb1 = { C7 44 24 ?? 80 00 00 00 [0-64] BA 00 00 00 80 [0-32] 48 8D 0D [4-32] FF 15 [4] 48 83 F8 FF [2-64] 41 B8 40 00 00 00 [0-64] FF 15 [4-5] 85 C0 7? ?? 80 3D [4] FF }
        $sb2 = { 80 3D [4] D8 [2-32] 41 B8 04 00 00 00 [0-32] C7 44 24 ?? 4A 46 49 46 [0-32] E8 [4-5] 85 C0 [2-32] C6 05 [4] 6A C6 05 [4] 70 C6 05 [4] 65 C6 05 [4] 67 }
        $sb3 = { BA [4] 48 89 ?? E8 [4] 41 B8 [4] 48 89 ?? 48 89 ?? E8 [4] 85 C0 7? [1-32] 8B 44 24 ?? 48 8B ?? 24 [1-16] 48 01 C8 [0-32] FF D0 }
    condition:
        all of them
}
rule APT_Dropper_Win64_TEARDROP_1
{
    meta:
        author = "FireEye"
        description = "This rule is intended match specific sequences of opcode found within TEARDROP, including those that decode the embedded payload. TEARDROP is a memory only dropper that can read files and registry keys, XOR decode an embedded payload, and load the payload into memory. TEARDROP persists as a Windows service and has been observed dropping Cobalt Strike BEACON into memory."
    strings:
        $loc_4218FE24A5 = { 48 89 C8 45 0F B6 4C 0A 30 }
        $loc_4218FE36CA = { 48 C1 E0 04 83 C3 01 48 01 E8 8B 48 28 8B 50 30 44 8B 40 2C 48 01 F1 4C 01 FA }
        $loc_4218FE2747 = { C6 05 ?? ?? ?? ?? 6A C6 05 ?? ?? ?? ?? 70 C6 05 ?? ?? ?? ?? 65 C6 05 ?? ?? ?? ?? 67 }
        $loc_5551D725A0 = { 48 89 C8 45 0F B6 4C 0A 30 48 89 CE 44 89 CF 48 F7 E3 48 C1 EA 05 48 8D 04 92 48 8D 04 42 48 C1 E0 04 48 29 C6 }
        $loc_5551D726F6 = { 53 4F 46 54 57 41 52 45 ?? ?? ?? ?? 66 74 5C 43 ?? ?? ?? ?? 00 }
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}