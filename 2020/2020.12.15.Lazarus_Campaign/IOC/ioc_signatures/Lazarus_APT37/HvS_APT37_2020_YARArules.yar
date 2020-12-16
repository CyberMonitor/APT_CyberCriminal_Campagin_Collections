import "pe"
rule HvS_APT37_smb_scanner {
   meta:
      description = "Unknown smb login scanner used by APT37"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Marc Stroebel"
      date = "2020-12-15"
      reference1 = "https://www.hvs-consulting.de/media/downloads/ThreatReport-Lazarus.pdf"
      reference2 = "https://www.hybrid-analysis.com/sample/d16163526242508d6961f061aaffe3ae5321bd64d8ceb6b2788f1570757595fc?environmentId=2"
   strings:
      $s1 = "Scan.exe StartIP EndIP ThreadCount logfilePath [Username Password Deep]" fullword ascii
      $s2 = "%s - %s:(Username - %s / Password - %s" fullword ascii
      $s3 = "Load mpr.dll Error " fullword ascii
      $s4 = "Load Netapi32.dll Error " fullword ascii
      $s5 = "%s U/P not Correct! - %d" fullword ascii
      $s6 = "GetNetWorkInfo Version 1.0" fullword wide
      $s7 = "Hello World!" fullword wide
      $s8 = "%s Error: %ld" fullword ascii
      $s9 = "%s U/P Correct!" fullword ascii
      $s10 = "%s --------" fullword ascii
      $s11 = "%s%-30s%I64d" fullword ascii
      $s12 = "%s%-30s(DIR)" fullword ascii
      $s13 = "%04d-%02d-%02d %02d:%02d" fullword ascii
      $s14 = "Share:              Local Path:                   Uses:   Descriptor:" fullword ascii
      $s15 = "Share:              Type:                   Remark:" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and (10 of them)
}

rule HvS_APT37_cred_tool {
   meta:
      description = "Unknown cred tool used by APT37"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Markus Poelloth"
      date = "2020-12-15"
      reference = "https://www.hvs-consulting.de/media/downloads/ThreatReport-Lazarus.pdf"
   strings:
      $s1 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii
      $s2 = "Domain Login" fullword ascii
      $s3 = "IEShims_GetOriginatingThreadContext" fullword ascii
      $s4 = " Type Descriptor'" fullword ascii
      $s5 = "User: %s" fullword ascii
      $s6 = "Pass: %s" fullword ascii
      $s7 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s8 = "E@c:\\u" fullword ascii
   condition:
      filesize < 500KB and 7 of them
}

rule HvS_APT37_RAT_loader {
   meta:
      description = "BLINDINGCAN RAT loader named iconcash.db used by APT37"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Marc Stroebel"
      date = "2020-12-15"
      hash = "b70e66d387e42f5f04b69b9eb15306036702ab8a50b16f5403289b5388292db9"
      reference1 = "https://www.hvs-consulting.de/media/downloads/ThreatReport-Lazarus.pdf"
      reference2 = "https://us-cert.cisa.gov/ncas/analysis-reports/ar20-232a"
   condition:
      (pe.version_info["OriginalFilename"] contains "MFC_DLL.dll") and
      (pe.exports("SMain") and pe.exports("SMainW") )
}


rule HvS_APT37_webshell_img_thumbs_asp {
   meta:
      description = "Webshell named img.asp, thumbs.asp or thumb.asp used by APT37"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Moritz Oettle"
      date = "2020-12-15"
      reference = "https://www.hvs-consulting.de/media/downloads/ThreatReport-Lazarus.pdf"
      hash = "94d2448d3794ae3f29678a7337473d259b5cfd1c7f703fe53ee6c84dd10a48ef"
   strings:
      $s1 = "strMsg = \"E : F\"" fullword ascii
      $s2 = "strMsg = \"S : \" & Len(fileData)" fullword ascii
      $s3 = "Left(workDir, InStrRev(workDir, \"/\")) & \"video\""

      $a1 = "Server.CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
      $a2 = "Dim tmpPath, workDir" fullword ascii
      $a3 = "Dim objFSO, objTextStream" fullword ascii
      $a4 = "workDir = Request.ServerVariables(\"URL\")" fullword ascii
      $a5 = "InStrRev(workDir, \"/\")" ascii

      $g1 = "WriteFile = 0" fullword ascii
      $g2 = "fileData = Request.Form(\"fp\")" fullword ascii
      $g3 = "fileName = Request.Form(\"fr\")" fullword ascii
      $g4 = "Err.Clear()" fullword ascii
      $g5 = "Option Explicit" fullword ascii
   condition:
      filesize < 2KB and (( 1 of ($s*) ) or (3 of ($a*)) or (5 of ($g*)))
}

rule HvS_APT37_webshell_template_query_asp {
   meta:
      description = "Webshell named template-query.aspimg.asp used by APT37"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Moritz Oettle"
      date = "2020-12-15"
      reference = "https://www.hvs-consulting.de/media/downloads/ThreatReport-Lazarus.pdf"
      hash = "961a66d01c86fa5982e0538215b17fb9fae2991331dfea812b8c031e2ceb0d90"
   strings:
      $g1 = "server.scripttimeout=600" fullword ascii
      $g2 = "response.buffer=true" fullword ascii
      $g3 = "response.expires=-1" fullword ascii
      $g4 = "session.timeout=600" fullword ascii

      $a1 = "redhat hacker" ascii
      $a2 = "want_pre.asp" ascii
      $a3 = "vgo=\"admin\"" ascii
      $a4 = "ywc=false" ascii

      $s1 = "public  br,ygv,gbc,ydo,yka,wzd,sod,vmd" fullword ascii
   condition:
      filesize > 70KB and filesize < 200KB and (( 1 of ($s*) ) or (2 of ($a*)) or (3 of ($g*)))
}

rule HvS_APT37_mimikatz_loader_DF012 {
   meta:
      description = "Loader for encrypted Mimikatz variant used by APT37"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Marc Stroebel"
      date = "2020-12-15"
      reference = "https://www.hvs-consulting.de/media/downloads/ThreatReport-Lazarus.pdf"
      hash = "42e4a9aeff3744bbbc0e82fd5b93eb9b078460d8f40e0b61b27b699882f521be"
   strings:
      $s1 = ".?AVCEncryption@@" fullword ascii
      $s2 = "afrfa"
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and 
      (pe.imphash() == "fa0b87c7e07d21001355caf7b5027219") and (all of them)
}

rule HvS_APT37_webshell_controllers_asp {
   meta:
      description = "Webshell named controllers.asp or inc-basket-offer.asp used by APT37"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Moritz Oettle"
      date = "2020-12-15"
      reference = "https://www.hvs-consulting.de/media/downloads/ThreatReport-Lazarus.pdf"
      hash = "829462fc6d84aae04a962dfc919d0a392265fbf255eab399980d2b021e385517"
   strings:
      $s0 = "<%@Language=VBScript.Encode" ascii
// Case permutations of the word SeRvEr encoded with the Microsoft Script Encoder followed by “.scriptrimeOut”
      $x1 = { 64 7F 44 2D 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x2 = { 64 7F 49 2D 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x3 = { 64 7F 49 2D 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x4 = { 64 7F 49 23 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x5 = { 64 7F 49 23 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x6 = { 64 7F 49 23 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x7 = { 64 7F 49 23 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x8 = { 64 41 44 2D 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x9 = { 64 41 44 2D 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x10 = { 64 41 44 2D 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x11 = { 64 41 44 2D 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x12 = { 64 7F 44 2D 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x13 = { 64 41 44 23 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x14 = { 64 41 44 23 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x15 = { 64 41 44 23 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x16 = { 64 41 44 23 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x17 = { 64 41 49 2D 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x18 = { 64 41 49 2D 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x19 = { 64 41 49 2D 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x20 = { 64 41 49 2D 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x21 = { 64 41 49 23 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x22 = { 64 41 49 23 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x23 = { 64 7F 44 2D 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x24 = { 64 41 49 23 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x25 = { 64 41 49 23 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x26 = { 6A 7F 44 2D 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x27 = { 6A 7F 44 2D 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x28 = { 6A 7F 44 2D 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x29 = { 6A 7F 44 2D 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x30 = { 6A 7F 44 23 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x31 = { 6A 7F 44 23 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x32 = { 6A 7F 44 23 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x33 = { 6A 7F 44 23 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x34 = { 64 7F 44 2D 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x35 = { 6A 7F 49 2D 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x36 = { 6A 7F 49 2D 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x37 = { 6A 7F 49 2D 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x38 = { 6A 7F 49 2D 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x39 = { 6A 7F 49 23 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x40 = { 6A 7F 49 23 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x41 = { 6A 7F 49 23 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x42 = { 6A 7F 49 23 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x43 = { 6A 41 44 2D 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x44 = { 6A 41 44 2D 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x45 = { 64 7F 44 23 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x46 = { 6A 41 44 2D 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x47 = { 6A 41 44 2D 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x48 = { 6A 41 44 23 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x49 = { 6A 41 44 23 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x50 = { 6A 41 44 23 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x51 = { 6A 41 44 23 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x52 = { 6A 41 49 2D 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x53 = { 6A 41 49 2D 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x54 = { 6A 41 49 2D 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x55 = { 6A 41 49 2D 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x56 = { 64 7F 44 23 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x57 = { 6A 41 49 23 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x58 = { 6A 41 49 23 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x59 = { 6A 41 49 23 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x60 = { 6A 41 49 23 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x61 = { 64 7F 44 23 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x62 = { 64 7F 44 23 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x63 = { 64 7F 49 2D 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x64 = { 64 7F 49 2D 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
   condition:
      filesize > 50KB and filesize < 200KB and ( $s0 and 1 of ($x*) )
}