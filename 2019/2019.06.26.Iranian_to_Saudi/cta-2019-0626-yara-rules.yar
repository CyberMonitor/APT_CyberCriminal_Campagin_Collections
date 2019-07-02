import "pe"

rule YARA_MAL_SpyNetRAT_1 {
   meta:
      description = "SpyNet RAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "314544478a1404891bed63b443b50544490a1bf85bcf8ff4aa2306434ad0aa62"
    strings:
      $x1 = "linkinfo.dll" fullword wide
      $x2 = "devrtl.dll" fullword wide
      $x3 = "srvcli.dll" fullword wide
      $x4 = "dfscli.dll" fullword wide
      $x5 = "browcli.dll" fullword wide
      $x6 = "Cannot create folder %sHChecksum error in the encrypted file %s. Corrupt file or wrong password." fullword wide
      $s7 = "atl.dll" fullword wide
      $s8 = "iphlpapi.DLL" fullword wide
      $s9 = "Unknown encryption method in %s$The specified password is incorrect." fullword wide
      $s10 = "UXTheme.dll" fullword wide
      $s11 = "WINNSI.DLL" fullword wide
      $s12 = "oleaccrc.dll" fullword wide
      $s13 = "dnsapi.DLL" fullword wide
      $s14 = "SSPICLI.DLL" fullword wide
      $s15 = "f819b84b=\"Foram encontrados erros ao executar a opera" fullword ascii
      $s16 = "Extracting files to %s folder$Extracting files to temporary folder" fullword wide
      $s17 = "&Enter password for the encrypted file:" fullword wide
      $s18 = "Security warningKPlease remove %s from folder %s. It is unsecure to run %s until it is done." fullword wide
      $s19 = "; version dynamically, depending on presence of \"Setup\" command. Note that" fullword ascii
      $s20 = "<!--The ID below indicates application support for Windows 10 -->" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 12000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule YARA_MAL_SpyNetRAT_2 {
   meta:
      description = "SpyNet RAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "405fcf7081546edbef69dbf11219611e754e144878b232e8794fc987b16db8c9"
    strings:
      $s1 = "'PASSWORDL" fullword ascii
      $s2 = ".dll.C" fullword ascii
      $s3 = "AppDataMo&2W" fullword ascii
      $s4 = "\\Mozilla " fullword ascii
      $s5 = "|x''''tplh''''d`\\X''''TPLH''''D@<8''''40,(''''$ " fullword ascii
      $s6 = "X'IELOGIO" fullword ascii
      $s7 = "\\open\\comm5" fullword ascii
      $s8 = "* .ss1" fullword ascii
      $s9 = "utostar" fullword ascii
      $s10 = "alKeySlot/" fullword ascii
      $s11 = "kstqrgdvef`abc\\]_" fullword ascii
      $s12 = "Network\\Connec!\\pbdg" fullword ascii
      $s13 = "[Ox_X_BLOCKMOUSE" fullword ascii
      $s14 = "teToolh,p.Snapshot7H~" fullword ascii
      $s15 = "olFmDir\"uHD*" fullword ascii
      $s16 = "g4\"ListFir" fullword ascii
      $s17 = "TWARE\\pplorr" fullword ascii
      $s18 = "ortions C" fullword ascii
      $s19 = "bieD$-G(h" fullword ascii
      $s20 = "$_Mefault" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "cba5bd52b3e624400ffe41eb22644b79" and ( 8 of them )
      ) or ( all of them )
}

rule YARA_MAL_SpyNetRAT_3 {
   meta:
      description = "SpyNet RAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "f22b7e63ae73d09f26829a9b958eceb7ac7a8bfb7a439e58573597fe4bf0dda7"
    strings:
      $s1 = "UnitInjectProcess" fullword ascii
      $s2 = "[Execute]" fullword wide
      $s3 = "%NOINJECT%" fullword wide
      $s4 = "UnitInjectServer" fullword ascii
      $s5 = "%DEFAULTBROWSER%" fullword wide
      $s6 = "[Numpad -]" fullword wide
      $s7 = "OThreadUnit" fullword ascii
      $s8 = "UnitConfigs" fullword ascii
      $s9 = "TThreadh" fullword ascii
      $s10 = " restart" fullword wide
      $s11 = "[Previous Track]" fullword wide
      $s12 = "UnitInstallServer" fullword ascii
      $s13 = "[Play / Pause]" fullword wide
      $s14 = "[Scrol Lock]" fullword wide
      $s15 = "[Backspace]" fullword wide
      $s16 = "[Arrow Down]" fullword wide
      $s17 = "[Page Up]" fullword wide
      $s18 = "[Numpad *]" fullword wide
      $s19 = "[Page Down]" fullword wide
      $s20 = "[Right Alt]" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule YARA_MAL_SpyNetRAT_4 {
   meta:
      description = "SpyNet RAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "d6efc78e72e62764b570ede6590851a8c5b0653f64305cdda30fdeccd8b91713"
   strings:
      $s1 = "mozcrt19.dll" fullword ascii
      $s2 = "Microsoft\\Network\\Connections\\pbk\\rasphone.pbk" fullword ascii
      $s3 = "\\signons3.txt" fullword ascii
      $s4 = "\\signons2.txt" fullword ascii
      $s5 = "\\signons1.txt" fullword ascii
      $s6 = "\\signons.txt" fullword ascii
      $s7 = "IEpasswords" fullword ascii
      $s8 = "UnitPasswords" fullword ascii
      $s9 = "\\Mozilla\\Firefox\\" fullword ascii
      $s10 = "L$_RasDefaultCredentials#0" fullword ascii
      $s11 = "\\Mozilla Firefox\\" fullword ascii
      $s12 = "Software\\Microsoft\\Internet Explorer\\IntelliForms\\Storage2" fullword ascii
      $s13 = "profiles.ini" fullword ascii
      $s14 = "uRASReader" fullword ascii
      $s15 = "SOFTWARE\\Vitalwerks\\DUC" fullword ascii
      $s16 = "uIE7_decodeU" fullword ascii
      $s17 = "Pstoreclib" fullword ascii
      $s18 = "gUnitServerUtils" fullword ascii
      $s19 = "WindowsLive:name=*" fullword ascii
      $s20 = "SPSTORECLib_TLB" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule YARA_MAL_SpyNetRAT_5 {
   meta:
      description = "SpyNet RAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "bd762cf10cdfaa84a837d3cd315d2e458f58fbdaec0e15efbbf51ed463ba4f47"
    strings:
      $s1 = "7_FIREFOX'IELOGIN" fullword ascii
      $s2 = "?.dll.C" fullword ascii
      $s3 = "/'PASSWORDL" fullword ascii
      $s4 = "* .ssf" fullword ascii
      $s5 = "AppDataWS" fullword ascii
      $s6 = "ortions Copyright (c) 19" fullword ascii
      $s7 = "wptukstqrgdv" fullword ascii
      $s8 = "Network\\Connec!" fullword ascii
      $s9 = "\\opZ\\comm" fullword ascii
      $s10 = "3 Avenger by NhT^j@" fullword ascii
      $s11 = "oolh,p.Snapshot7H4" fullword ascii
      $s12 = "Mozilln" fullword ascii
      $s13 = "OFTWARE\\pplo" fullword ascii
      $s14 = "'Active S" fullword ascii
      $s15 = "ms\\SHag!/t`:/" fullword ascii
      $s16 = "Ox_X_BLOCKMOUSE" fullword ascii
      $s17 = "}\\PolDie." fullword ascii
      $s18 = "SPSTORECL_TL^" fullword ascii
      $s19 = "eySlot/\"h" fullword ascii
      $s20 = "\"ListFir" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 800KB and pe.imphash() == "cba5bd52b3e624400ffe41eb22644b79" and ( 8 of them )
      ) or ( all of them )
}

rule YARA_MAL_SpyNetRAT_6 {
   meta:
      description = "SpyNet RAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "d6efc78e72e62764b570ede6590851a8c5b0653f64305cdda30fdeccd8b91713"
      strings:
      $s1 = "IELOGIN.abc" fullword ascii
      $s2 = "\\Internet Explorer\\iexplore.exe" fullword ascii
      $s3 = "0UnitInjectLibrary" fullword ascii
      $s4 = "UnitInjectLibrary" fullword ascii
      $s5 = "xxxyyyzzz.dat" fullword ascii
      $s6 = "Portions Copyright (c) 1999,2003 Avenger by NhT" fullword ascii
      $s7 = "(unnamed password)" fullword ascii
      $s8 = "_x_X_PASSWORDLIST_X_x_" fullword ascii
      $s9 = "IEPASS.abc" fullword ascii
      $s10 = "RAS Passwords |" fullword ascii
      $s11 = "TLoader" fullword ascii
      $s12 = "\\\\.\\SyserDbgMsg" fullword ascii
      $s13 = "\\\\.\\SyserBoot" fullword ascii
      $s14 = "IEAUTO.abc" fullword ascii
      $s15 = "FIREFOX.abc" fullword ascii
      $s16 = "IEWEB.abc" fullword ascii
      $s17 = "XX--XX--XX.txt" fullword ascii
      $s18 = "\\\\.\\Syser" fullword ascii
      $s19 = "RUnitVariaveis" fullword ascii
      $s20 = "UnitComandos" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule YARA_MAL_PlasmaRAT {
   meta:
      description = "SpyNet RAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "a0e4f9649a63e8a2ced3351d74d53ed48a0b64b4c9d72e6a13166beb9fb62b9f"
    strings:
      $x1 = "C:\\Users\\Gaming\\Desktop\\Plasma RAT development\\Plasma RAT 1.6.1\\StubAdmin.bin.pdb" fullword ascii
      $x2 = "System.Collections.Generic.IEnumerable<JLibrary.PortableExecutable.IMAGE_IMPORT_DESCRIPTOR>.GetEnumerator" fullword ascii
      $x3 = "System.Collections.Generic.IEnumerable<JLibrary.PortableExecutable.IMAGE_SECTION_HEADER>.GetEnumerator" fullword ascii
      $x4 = "System.Collections.Generic.IEnumerator<JLibrary.PortableExecutable.IMAGE_SECTION_HEADER>.Current" fullword ascii
      $x5 = "System.Collections.Generic.IEnumerator<JLibrary.PortableExecutable.IMAGE_SECTION_HEADER>.get_Current" fullword ascii
      $x6 = "System.Collections.Generic.IEnumerator<JLibrary.PortableExecutable.IMAGE_IMPORT_DESCRIPTOR>.get_Current" fullword ascii
      $x7 = "C:\\windows\\system32\\drivers\\etc\\hosts" fullword wide
      $x8 = "System.Collections.Generic.IEnumerator<JLibrary.PortableExecutable.IMAGE_IMPORT_DESCRIPTOR>.Current" fullword ascii
      $x9 = "Image contains a CLR runtime header. Currently only native binaries are supported; no .NET dependent libraries." fullword wide
      $x10 = "software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\" fullword wide
      $x11 = "software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options" fullword wide
      $x12 = "Target process has no targetable threads to hijack." fullword wide
      $s13 = "Shell Command Executed." fullword wide
      $s14 = "MpCmdRun.exe" fullword wide
      $s15 = "avgidsagent.exe" fullword wide
      $s16 = "spybotsd.exe" fullword wide
      $s17 = "bdagent.exe" fullword wide
      $s18 = "lSystem.Resources.ResourceReader, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii
      $s19 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\" fullword wide
      $s20 = "StubAdmin.bin.exe" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 500KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule YARA_MAL_QuasarRAT_1 {
   meta:
      description = "QuasarRAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "01b3ca7ab9ef87ca591775a43f95bc9319e3f622d916e0d6bf1c057a3d66ff37"
    strings:
      $x1 = "System.Collections.Generic.IEnumerable<xClient.Core.MouseKeyHook.KeyPressEventArgsExt>.GetEnumerator" fullword ascii
      $x2 = "System.Collections.Generic.IEnumerator<xClient.Core.MouseKeyHook.KeyPressEventArgsExt>.get_Current" fullword ascii
      $s3 = "<meta http-equiv='Content-Type' content='text/html; charset=utf-8' />Log created on " fullword wide
      $s4 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A" fullword wide
      $s5 = "Opera Software\\Opera Stable\\Login Data" fullword wide
      $s6 = "get_encryptedPassword" fullword ascii
      $s7 = "System.Collections.Generic.IEnumerator<xClient.Core.MouseKeyHook.KeyPressEventArgsExt>.Current" fullword ascii
      $s8 = "Client.exe" fullword wide
      $s9 = "Domain: {1}{0}Cookie Name: {2}{0}Value: {3}{0}Path: {4}{0}Expired: {5}{0}HttpOnly: {6}{0}Secure: {7}" fullword wide
      $s10 = "\\mozglue.dll" fullword wide
      $s11 = "\\msvcr120.dll" fullword wide
      $s12 = "\\msvcp120.dll" fullword wide
      $s13 = "\\msvcr100.dll" fullword wide
      $s14 = "\\msvcp100.dll" fullword wide
      $s15 = "get_Processname" fullword ascii
      $s16 = "Yandex\\YandexBrowser\\User Data\\Default\\Login Data" fullword wide
      $s17 = "Execution failed: {0}" fullword wide
      $s18 = "Execution failed!" fullword wide
      $s19 = "Passwords" fullword ascii
      $s20 = "Google\\Chrome\\User Data\\Default\\Login Data" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule YARA_MAL_QuasarRAT_2 {
   meta:
      description = "QuasarRAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "01b3ca7ab9ef87ca591775a43f95bc9319e3f622d916e0d6bf1c057a3d66ff37"
     strings:
      $s1 = "GetKeyloggerLogsResponse" fullword ascii
      $s2 = "GetKeyloggerLogs" fullword ascii
      $s3 = "DoDownloadAndExecute" fullword ascii
      $s4 = "Client.exe" fullword ascii
      $s5 = "GetProcessesResponse" fullword ascii
      $s6 = "DoUploadAndExecute" fullword ascii
      $s7 = "DoShellExecuteResponse" fullword ascii
      $s8 = "DoShellExecute" fullword ascii
      $s9 = "GetPasswordsResponse" fullword ascii
      $s10 = "GetPasswords" fullword ascii
      $s11 = "xClient.Core.Compression" fullword ascii
      $s12 = "DoProcessKill" fullword ascii
      $s13 = "DoProcessStart" fullword ascii
      $s14 = "xClient.Core.ReverseProxy.Packets" fullword ascii
      $s15 = "GetSystemInfoResponse" fullword ascii
      $s16 = "xClient.Core.MouseKeyHook" fullword ascii
      $s17 = "SetUserStatus" fullword ascii
      $s18 = "xClient.Core.NetSerializer.TypeSerializers" fullword ascii
      $s19 = "DoDownloadFileResponse" fullword ascii
      $s20 = "xClient.Core.Packets.ServerPackets" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule YARA_MAL_QuasarRAT_3 {
   meta:
      description = "QuasarRAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "01b3ca7ab9ef87ca591775a43f95bc9319e3f622d916e0d6bf1c057a3d66ff37"
    strings:
      $s1 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934" ascii
      $s2 = "GetDeleteRegistryKeyResponse" fullword ascii
      $s3 = "GetCreateRegistryKeyResponse" fullword ascii
      $s4 = "GetRenameRegistryKeyResponse" fullword ascii
      $s5 = "GetConnectionsResponse" fullword ascii
      $s6 = "GetRegistryKeysResponse" fullword ascii
      $s7 = "GetChangeRegistryValueResponse" fullword ascii
      $s8 = "GetRenameRegistryValueResponse" fullword ascii
      $s9 = "GetDeleteRegistryValueResponse" fullword ascii
      $s10 = "GetCreateRegistryValueResponse" fullword ascii
      $s11 = "<asmv3:application  xmlns:asmv3=\"urn:schemas-microsoft-com:asm.v3\" >" fullword ascii
      $s12 = "DoAskElevate" fullword ascii
      $s13 = "xClient.Core.Registry" fullword ascii
      $s14 = "DoCreateRegistryKey" fullword ascii
      $s15 = "DoCloseConnection" fullword ascii
      $s16 = "DoLoadRegistryKey" fullword ascii
      $s17 = "DoRenameRegistryKey" fullword ascii
      $s18 = "DoDeleteRegistryKey" fullword ascii
      $s19 = "AForge.Video.DirectShow" fullword ascii
      $s20 = "GetWebcamResponse" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule YARA_MAL_888RAT_1 {
   meta:
      description = "888RAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "81896145ad5bffd891dd47f3a53e530d4aa33e8317143422bd723bd7c1b306f7"
      strings:
      $x1 = "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" language=\"*\" processorArchitec" ascii
      $s2 = "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" language=\"*\" processorArchitec" ascii
      $s3 = "re=\"*\" publicKeyToken=\"6595b64144ccf1df\"></assemblyIdentity>" fullword ascii
      $s4 = "CDEFGH" fullword ascii
      $s5 = "Pkernel32" fullword ascii
      $s6 = "23$--%\"!' " fullword ascii
      $s7 = "AutoIt v3 Script: 3, 3, 8, 1" fullword wide
      $s8 = "T-HSvhk -" fullword ascii
      $s9 = "-  -a8] " fullword ascii
      $s10 = "logb'yn" fullword ascii
      $s11 = "yp0.CYY&v" fullword ascii
      $s12 = "ComplPe " fullword ascii
      $s13 = "&TUVWXYZ[\\]^_`abcdefghijklmnop" fullword ascii
      $s14 = "AIHRUN" fullword ascii
      $s15 = "@DLld<" fullword ascii
      $s16 = "bjectInform1Wf6La" fullword ascii
      $s17 = ")CSQu#gA8, " fullword ascii
      $s18 = "orExitPr\"ess" fullword ascii
      $s19 = "- 9} 7}" fullword ascii
      $s20 = "(>fmKIX~H(R" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "890e522b31701e079a367b89393329e6" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule YARA_MAL_ImminentMonitorRAT_1 {
   meta:
      description = "ImminentMonitor RAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "f369007b85607114b8206a986f751d0dee301a398f857c43d23fb5f80643b304"
    strings:
      $s1 = "ExecutePacket" fullword ascii
      $s2 = "dlExecute" fullword ascii
      $s3 = "get_SupportsCommandConnect" fullword ascii
      $s4 = "get_SupportsCommandAssociate" fullword ascii
      $s5 = "set_SupportsCommandConnect" fullword ascii
      $s6 = "set_SupportsCommandAssociate" fullword ascii
      $s7 = "KeyLoggerPacket" fullword ascii
      $s8 = "get_SupportsCommandBind" fullword ascii
      $s9 = "set_SupportsCommandBind" fullword ascii
      $s10 = "ResumeProcess" fullword ascii
      $s11 = "get_INetHost" fullword ascii
      $s12 = "get_SupportsIPv6Addresses" fullword ascii
      $s13 = "Userprofile" fullword ascii
      $s14 = "CommandPromptPacket" fullword ascii
      $s15 = "ChangeEncryptionKey" fullword ascii
      $s16 = "PasswordRecoveryPacket" fullword ascii
      $s17 = "get_LabelUser" fullword ascii
      $s18 = "get_ProxyClient" fullword ascii
      $s19 = "CommandPrompt" fullword ascii
      $s20 = "CommandSocket" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule YARA_MAL_ImminentMonitorRAT_2 {
   meta:
      description = "ImminentMonitor RAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "45b6e6623e109d21698bc3b13e5151b351fc6bdad7bf9c3881928e5904c5dac9"
     strings:
      $x1 = "BTRESULTDownload File|Mass Download : File Downloaded , Executing new one in temp dir...|" fullword wide
      $x2 = "C:\\Windows\\Microsoft.NET\\Framework\\v2.0.50727\\vbc.exe" fullword wide
      $s3 = "/C ping 1.1.1.1 -n 1 -w 100 > Nul & Del \"" fullword wide
      $s4 = "/C ping 1.1.1.1 -n 1 -w 1000 > Nul & Del \"" fullword wide
      $s5 = "Attempting to kill process" fullword wide
      $s6 = "IPHLPAPI.dll" fullword ascii
      $s7 = "ssutil3.dll" fullword wide
      $s8 = "plds4.dll" fullword wide
      $s9 = "\\Google\\Chrome\\User Data\\Default\\Login Data" fullword wide
      $s10 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.69 Safari/537.36" fullword wide
      $s11 = "winmgmts:{impersonationLevel=impersonate}!\\\\.\\root\\SecurityCenter2" fullword wide
      $s12 = "winmgmts:{impersonationLevel=impersonate}!\\\\.\\root\\SecurityCenter" fullword wide
      $s13 = "File downloaded & executed" fullword wide
      $s14 = "\"encryptedPassword\":\".*\"," fullword wide
      $s15 = "Failed to process." fullword wide
      $s16 = "http://www.iptrackeronline.com/" fullword wide
      $s17 = "client.log" fullword wide
      $s18 = "\\BitTorrent\\bittorrent.exe" fullword wide
      $s19 = "\\BitTorrent\\BitTorrent.exe" fullword wide
      $s20 = "\\uTorrent\\uTorrent.exe" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule YARA_MAL_OrcusRAT_1 {
   meta:
      description = "OrcusRAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "2d55a430dbd708eb0bae6d8bbd1ca8a207ad349b4552f7543a9f99a16d51b0a3"
      strings:
      $x1 = "Orcus.Commands.Passwords.Applications.JDownloader" fullword ascii
      $x2 = "System.Collections.Generic.IEnumerable<Orcus.Shared.Commands.Password.RecoveredPassword>.GetEnumerator" fullword ascii
      $x3 = "System.Collections.Generic.IEnumerator<Orcus.Shared.Commands.Password.RecoveredPassword>.Current" fullword ascii
      $x4 = "System.Collections.Generic.IEnumerator<Orcus.Shared.Commands.Password.RecoveredPassword>.get_Current" fullword ascii
      $x5 = "System.Collections.Generic.IEnumerable<Orcus.Commands.DeviceManager.HardwareHelper.TemporaryDeviceInfo>.GetEnumerator" fullword ascii
      $x6 = "System.Collections.Generic.IEnumerator<Orcus.Commands.DeviceManager.HardwareHelper.TemporaryDeviceInfo>.get_Current" fullword ascii
      $x7 = "System.Collections.Generic.IEnumerator<Orcus.Commands.DeviceManager.HardwareHelper.TemporaryDeviceInfo>.Current" fullword ascii
      $x8 = "Orcus.Shared.Commands.LiveKeylogger" fullword ascii
      $x9 = "Orcus.Shared.Commands.Keylogger" fullword ascii
      $x10 = "Orcus.Shared.Commands.DropAndExecute" fullword ascii
      $x11 = "System.Collections.Generic.IEnumerable<Orcus.Shared.Commands.UninstallPrograms.UninstallableProgram>.GetEnumerator" fullword ascii
      $x12 = "System.Collections.Generic.IEnumerator<Orcus.Shared.Commands.UninstallPrograms.UninstallableProgram>.get_Current" fullword ascii
      $x13 = "Orcus.Commands.DropAndExecute" fullword ascii
      $x14 = "Orcus.Shared.DynamicCommands.ExecutionEvents" fullword ascii
      $x15 = "ExecuteProcessCommand" fullword ascii
      $x16 = "Orcus.StaticCommandManagement.ExecutionEvents" fullword ascii
      $x17 = "Orcus.Commands.Passwords.Applications.Mozilla.Cryptography" fullword ascii
      $x18 = "System.Collections.Generic.IEnumerable<Orcus.Shared.Commands.WindowManager.WindowInformation>.GetEnumerator" fullword ascii
      $x19 = "System.Collections.Generic.IEnumerable<Orcus.Shared.Commands.AudioVolumeControl.AudioDevice>.GetEnumerator" fullword ascii
      $x20 = "System.Collections.Generic.IEnumerator<Orcus.Shared.Commands.UninstallPrograms.UninstallableProgram>.Current" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) )
      ) or ( all of them )
}

rule YARA_MAL_NanocoreRAT_1 {
   meta:
      description = "NanocoreRAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "05dffb58102f57c2e71ac42310af8d855957b81940dab2fc6b55319421ea5428"
    strings:
      $x1 = "N8yE2kimq3O6RJNZ37W1uN3DkVSmnBEA0IUC8zngwD/8l3nyj5tr2vyXefKPm2va/Jd58o+ba9pvE9AB6pZlSfzwtI8tzOYcbLuo4+nUZPGv9wxqvZYVNaQ/f8ArfQkg" ascii
      $x2 = "hSystem.Drawing.Bitmap, System.Drawing, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" fullword ascii
      $x3 = "C:\\Users\\ALAE\\Desktop\\Application\\Application\\obj\\x86\\Release\\Realtek-RTL8188CE.pdb" fullword ascii
      $x4 = "C:\\Users\\ALAE\\Desktop\\Server\\obj\\Debug\\Server.pdb" fullword ascii
      $s5 = "System.Windows.Forms.ImageListStreamer, System.Windows.Forms, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089P" ascii
      $s6 = "System.Windows.Forms.ImageListStreamer, System.Windows.Forms, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089P" ascii
      $s7 = "Server.exe" fullword wide
      $s8 = "http://pastebin.com/raw/jXgspE63" fullword ascii
      $s9 = "Realtek-RTL8188CJ.exe" fullword wide
      $s10 = "Realtek-RTL8188CE.exe" fullword wide
      $s11 = "antilogger" fullword wide
      $s12 = "4/FXruDtCyJwRLh4znEXEcMutZiCdiGWlbGM1k/iU8cZ19+z4PMftGIRXoj/MjLnyVpvwpZQ/mRDHNf7YWfAqeoQq6GgX0eap/YLIs7S9ubbaenKpeV/ueYmvyygd3qV" ascii
      $s13 = "KeyEncrypt" fullword wide
      $s14 = "jjRDFvwbEFzUGet0cynDwIFtxOAvVdKNgEirNAX638UW456igU0SM0zLJ4hMDHKGV4g5A7uEWr8u5uBbIN5sYFJL+yBP6jM/8QWFlzkqJvvYTDlf0gwVpRbjnqKBTRIz" ascii
      $s15 = "get_ForwardToolStripButton" fullword ascii
      $s16 = "get_ContentsToolStripMenuItem" fullword ascii
      $s17 = "Process Hacker" fullword wide
      $s18 = "$Processus h" fullword ascii
      $s19 = "Processus h" fullword wide
      $s20 = "lKmapgPu6O1yQJhnA3o84yDCm5v4WDeuoJISOAPiZV3rE4D9uPkPgl9WKrHyfIchWbTePAQZ6L+GGtfoKrEW1XnTdaZqPrn45NTyr3gNxKbm7tymyipiPEf+dGf4IDEo" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule YARA_MAL_NanocoreRAT_2 {
   meta:
      description = "NanocoreRAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "d1c1582e30b5d3ca1db4c337bfe5af6022a92b05ca0d9d1c102f2113223dd10e"
     strings:
      $s1 = "Microsoft.VSDesigner.DataSource.Design.TableAdapterManagerDesigner, Microsoft.VSDesigner, Version=10.0.0.0, Culture=neutral, Pub" ascii
      $s2 = "Microsoft.VSDesigner.DataSource.Design.TableAdapterDesigner, Microsoft.VSDesigner, Version=10.0.0.0, Culture=neutral, PublicKeyT" ascii
      $s3 = "Persist Security Info=False;Initial Catalog=jiaowu;Data Source=localhost;Integrated Security=SSPI;" fullword wide
      $s4 = "Microsoft.VSDesigner.DataSource.Design.TableAdapterDesigner, Microsoft.VSDesigner, Version=10.0.0.0, Culture=neutral, PublicKeyT" ascii
      $s5 = "jiaowupaike.exe" fullword wide
      $s6 = "http://tempuri.org/jiaowuDataSet.xsd" fullword wide
      $s7 = "form_login_KeyDown" fullword ascii
      $s8 = "form_login_FormClosed" fullword ascii
      $s9 = "Microsoft.VSDesigner.DataSource.Design.TableAdapterManagerDesigner, Microsoft.VSDesigner, Version=10.0.0.0, Culture=neutral, Pub" ascii
      $s10 = "select EID,Lname,Tname,CID from EduTask,Lesson,Room,Teacher where EduTask.LID=Lesson.LID " fullword wide
      $s11 = "select * from Users" fullword wide
      $s12 = "form_login_FormClosing" fullword ascii
      $s13 = "insert into Users(UID,pword,permission)values('" fullword wide
      $s14 = "EduTask.LID=Lesson.LID and EduTask.TID=Teacher.TID" fullword wide
      $s15 = "tmr_login_Tick" fullword ascii
      $s16 = "btn_login_Click" fullword ascii
      $s17 = "select Tname from Teacher,Institute where Teacher.IID=Institute.IID and Iname='" fullword wide
      $s18 = "form_login_Load" fullword ascii
      $s19 = "get_jiaowuConnectionString" fullword ascii
      $s20 = "update Users set pword='" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule YARA_MAL_NanocoreRAT_3 {
   meta:
      description = "NanocoreRAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "bd5fd2237ceaab10595a2e4b2976fe4199884aaa7c04a38323ce6d5006a9bb35"
    strings:
      $x1 = "Execute not supported: %s1Operation not allowed on a unidirectional dataset" fullword wide
      $x2 = "Field '%s' has no dataset\"Circular datalinks are not allowed/Lookup information for field '%s' is incomplete" fullword wide
      $s3 = "Remote Login/Top Legend Position must be between 0 and 100 %" fullword wide
      $s4 = "Unable to Find Procedure %sDLL/Shared Library Name not Set.Driver/Connection Registry File '%s' not found(dbExpress Error: Unkn" wide
      $s5 = "TSQLConnectionLoginEvent" fullword ascii
      $s6 = "SQL Server Error: %s&Driver (%s) not found in Cfg file (%s)" fullword wide
      $s7 = "OLE control activation failed*Could not obtain OLE control window handle" fullword wide
      $s8 = "dbxconnections.ini" fullword ascii
      $s9 = "+[0x0002]: Insufficient Memory for Operation" fullword wide
      $s10 = "dbxdrivers.ini" fullword ascii
      $s11 = "TPasswordDialog,UH" fullword ascii
      $s12 = "ElevationT" fullword ascii
      $s13 = " Invalid operation on TOleGraphic" fullword wide
      $s14 = "TCommonDialog\\" fullword ascii
      $s15 = "GetDriverFunc" fullword ascii
      $s16 = ": :$:(:,:0:4:8:<:@:D:H:L:P:T:X:\\:j:r:z:" fullword ascii
      $s17 = ": :$:(:,:0:4:8:<:@:D:H:L:P:T:X:\\:g:s:z:" fullword ascii
      $s18 = ": :$:4:<:@:D:H:L:P:T:X:\\:`:d:h:l:p:t:x:|:" fullword ascii
      $s19 = "dirtyread" fullword ascii
      $s20 = ":,:8:<:L:T:X:\\:`:d:h:l:p:t:x:|:" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and pe.imphash() == "7d4a1d899ac11a094c088d43aa2e9a5b" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule YARA_MAL_NanocoreRAT_4 {
   meta:
      description = "NanocoreRAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "0ffea07b7a5500475562195fb2a2b492989ef5678d56afe30e79b65dd08273dd"
              hash10 = "0aa076882f28dfc64aee18f86a725a05da3db74f5784ec6e7536588241fe5345"
      hash11 = "35aa0532e6b8e3516af75763cb4af335a3760288744b3055a0932c3cbe8bca16"
      hash12 = "ed3b542d8fdbfcac0db17417e5ded3fa6eaca3cf6cbbf677a3bf73d77da0e8f7"
      hash13 = "57f98a5ac9ebd816818ec347fefabb3761d274c9ae43306aa54c2e431b96b5e9"
      hash14 = "e53af8f12a6c79af55d320dd19a72485afecaea0bfc427a82613b12f6c6ae1b5"
      hash15 = "344ed043bc3bac73dc104d536183212b803d2738841f6e132454ebc5d770c2ff"
      hash16 = "d54cf8b747705acae1678e8a273c30a0dee7d1729a1fea231b0b8d833570929f"
      hash17 = "193dd7235fd8ed7adad4549c8b36f13f37d46685ef4dcc3bbead395894076f5a"
      hash18 = "5cb4e82a05433249d33b3d663f07f9b5e1defba4fb0c4235a421df80b29b3842"
      hash19 = "7793fd680f180c22cb904fa020d36cb46bf774b3372a3963da045034fc6c64d2"
                     strings:
      $s1 = "#=qiY1B9yU2oVkPHxhn$y67SFTP8x1Jb0botGqdUGkdpQg=" fullword ascii
      $s2 = "#=qPNzwB3EyeKwH$TwKjEdAjAC6A3IlGhANCdkUFCgvEiw=" fullword ascii
      $s3 = "#=q85afbI_HcqBFOZnC0iAqsNghLb3LsuyjFtpLEYYoPX8=" fullword ascii
      $s4 = "#=qh9KSqT0kHBFSDanZ7gXkKb1vdDfzZS3JIRcUnMfcljE=" fullword ascii
      $s5 = "#=qTfMnD_jfiITiB95ES2nWdLlDTdGOSDVgXEnjKNGkWcM=" fullword ascii
      $s6 = "#=q6Aboe3ONIkez7GgqcdWPi0_vrT_i53_89HUeagGM6MThXvFkvl8hpSeHO1UJawKN" fullword ascii
      $s7 = "#=qxJg7RxTW1v5mnt12xXeJiYJv_bcctbtL2BCD5MjDi45Hlz6t8vwDNTv1Rv7tgIct" fullword ascii
      $s8 = "#=qjcSlrUNMLgvZWN$58FXdrl22$0OjCpoqksNsslRtIFE=" fullword ascii
      $s9 = "#=qfLFZgbR_r0GETPSprP6O9w==" fullword ascii
      $s10 = "#=q6pErmyx6x4$YkotXXEXGCt_ysi5JdNm1fpNgnUvZ9LE6EtA8E0TapqXrPnqyBO1x" fullword ascii
      $s11 = "#=q9c$dxNln4J1nxxC7UNVnfSKvSgKS421$zTS6z9ahlusddEno_MZclU7Qbfc$Fyw5" fullword ascii
      $s12 = "#=qwVGSEK8LoRuNWEOYfq8$hq39mmxHzM3pIeoRef7XNt8=" fullword ascii
      $s13 = "#=quXVzKqGldmgtXgVm61aLog==" fullword ascii
      $s14 = "#=qmvGJ0E7$XHigSQAtHtZ6z$on2iAwFLBiFtrUR$DFhQPAtVI2LIgzNztIgPvlO9K$" fullword ascii
      $s15 = "#=qr9m9EjuYAP$2E3p2xadfFhcTH6toAhrm0dlfOTldiWRsdXd8UmnkRkYrV_8$1gaA" fullword ascii
      $s16 = "#=q6wR5WMLGkL9afTpqmWsw9g==" fullword ascii
      $s17 = "#=qVCHxDTr$$bwFMb6i9vBKRZciaa69edA3gsLNOty0RAzCorWRBUh2v0PgySYBEvZ0" fullword ascii
      $s18 = "#=qul8YRvQj1pWpo4_UxgOSzOBvtncEE$VPCzTeLK_rIz4EnXxineVkwF$lTxruKPxr" fullword ascii
      $s19 = "#=qgbI51haY38WJ4NumXDqnLC_uKv$aRHAyD63c9HgGYzlsFjikAASqT8RCSswEMouz" fullword ascii
      $s20 = "#=qrPQtMswclvOlK1AxL1S4K8M$owLGUpQfjJA8CWW$fj1az7m8LFibY8IeMxHKi4wi" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and ( 8 of them )
      ) or ( all of them )
}

rule YARA_MAL_NanocoreRAT_5 {
   meta:
      description = "NanocoreRAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "008561a800aa66833a6473a9bf742596e6a95d0b905906607362bbe26c1b7cab"
    strings:
      $s1 = "$Operation not allowed on sorted list$%s not in a class registration group" fullword wide
      $s2 = "(Failed to write ImageList data to stream$Error creating window device context" fullword wide
      $s3 = "Metafile is not valid!Cannot change the size of an icon Invalid operation on TOleGraphic" fullword wide
      $s4 = "PasswordCharX" fullword ascii
      $s5 = " Clipboard does not support Icons/Menu '%s' is already being used by another formDocked control must have a name%Error removing" wide
      $s6 = "9':+:0:@:P:X:\\:`:d:h:l:p:t:x:|:" fullword ascii
      $s7 = "CLOSEDFOLDER" fullword wide
      $s8 = "3 373;3?3]3e3~3" fullword ascii
      $s9 = "4'4-424D4{4" fullword ascii
      $s10 = "<7<?<\\<d<" fullword ascii
      $s11 = "EVariantInvalidArgError<" fullword ascii
      $s12 = ":&:.:6:>:F:" fullword ascii
      $s13 = "TPictureAdapter\\}G" fullword ascii
      $s14 = "3 3$3(3,3034383<3@3D3H3L3P3T3X3f3n3J4N4R4V4Z4^4b4f4j4n4r4v4z4~4" fullword ascii
      $s15 = "OnDockDrop8" fullword ascii
      $s16 = "AutoHotkeysx" fullword ascii
      $s17 = "HelpKeyword|" fullword ascii
      $s18 = "ComCtrlsDLF" fullword ascii
      $s19 = "ftReadOnly" fullword ascii
      $s20 = "TConversion|DF" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "0de11abe7f918ebcb69488cf91e27864" and ( 8 of them )
      ) or ( all of them )
}

rule YARA_MAL_NanocoreRAT_6 {
   meta:
      description = "NanocoreRAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "4a6cd5aef436121e851b39e70afa3ada4b340e609c92a2252296f6cc74fa4df5"
    strings:
      $x1 = "linkinfo.dll" fullword wide
      $x2 = "devrtl.dll" fullword wide
      $x3 = "dfscli.dll" fullword wide
      $x4 = "srvcli.dll" fullword wide
      $x5 = "browcli.dll" fullword wide
      $s6 = "atl.dll" fullword wide
      $s7 = "D:\\Projects\\WinRAR\\sfx\\build\\sfxrar32\\Release\\sfxrar.pdb" fullword ascii
      $s8 = "iphlpapi.DLL" fullword wide
      $s9 = "UXTheme.dll" fullword wide
      $s10 = "WINNSI.DLL" fullword wide
      $s11 = "oleaccrc.dll" fullword wide
      $s12 = "dnsapi.DLL" fullword wide
      $s13 = "SSPICLI.DLL" fullword wide
      $s14 = "sfxrar.exe" fullword ascii
      $s15 = "<!--The ID below indicates application support for Windows 10 -->" fullword ascii
      $s16 = "<pi-ms-win-core-processthreads-l1-1-2" fullword wide
      $s17 = "Please remove %s from %s folder. It is unsecure to run %s until it is done." fullword wide
      $s18 = "<pi-ms-win-core-localization-obsolete-l1-2-0" fullword wide
      $s19 = "xlistpos" fullword ascii
      $s20 = "sfxstime" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule YARA_MAL_NanocoreRAT_7 {
   meta:
      description = "NanocoreRAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "bd5fd2237ceaab10595a2e4b2976fe4199884aaa7c04a38323ce6d5006a9bb35"
     strings:
      $s1 = "[0x000A]: Result set at EOF+dbExpress Error [0x000B]: Parameter Not Set\"[0x000C] Invalid Username/Password" fullword wide
      $s2 = "[0x0015]: Connection failed&[0x0016]: Driver initialization failed#[0x0017]: Optimistic Locking failed" fullword wide
      $s3 = "[0x0004]: Invalid Handle![0x0005]: Operation Not Supported" fullword wide
      $s4 = "%s,Custom variant type (%s%.4x) is out of range" fullword wide
      $s5 = "TLOGINDIALOG" fullword wide
      $s6 = "?Access violation at address %p in module '%s'. %s of address %p" fullword wide
      $s7 = "Database Login" fullword ascii
      $s8 = "[0x0006]: Invalid Time\"[0x0007]: Invalid Data Translation'[0x0008]: Parameter/Column out of Range" fullword wide
      $s9 = "TLoginDialog" fullword ascii
      $s10 = "LoginPrompt" fullword ascii
      $s11 = "LoginParams" fullword ascii
      $s12 = "TPASSWORDDIALOG" fullword wide
      $s13 = "OnLogin" fullword ascii
      $s14 = "/Custom variant type (%s%.4x) already used by %s*Custom variant type (%s%.4x) is not usable2Too many custom variant types have b" wide
      $s15 = "TPasswordDialog" fullword ascii
      $s16 = "Invalid FieldKind Field '%s' is of an unknown type" fullword wide
      $s17 = "Invalid format type for BCD$Could not parse SQL TimeStamp string" fullword wide
      $s18 = "3333s33" fullword ascii
      $s19 = "33333s3" fullword ascii
      $s20 = "TFieldGetTextEvent" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule YARA_MAL_NanocoreRAT_8 {
   meta:
      description = "NanocoreRAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "88a76e9ec13fc46bf63e5bb2bc72f2dcd28125ca3c77a18091da681b92713277"
    strings:
      $x1 = "Ghttp://www.smartassembly.com/webservices/UploadReportLogin/GetServerURL" fullword ascii
      $x2 = "Namespace;http://www.smartassembly.com/webservices/UploadReportLogin/L" fullword ascii
      $s3 = "@http://www.smartassembly.com/webservices/Reporting/UploadReport2" fullword ascii
      $s4 = "npptools.dll" fullword ascii
      $s5 = "DHCPCSVC.dll" fullword ascii
      $s6 = "Namespace3http://www.smartassembly.com/webservices/Reporting/E" fullword ascii
      $s7 = "UploadReportLoginService" fullword ascii
      $s8 = "LoginServiceSoapT" fullword ascii
      $s9 = "qUse ShowContinueCheckbox instead, as this is now also false when the builder has chosen not to show the checkbox." fullword ascii
      $s10 = "processAttributes" fullword ascii
      $s11 = "UploadReport2" fullword ascii
      $s12 = "reportExceptionEventArgs" fullword ascii
      $s13 = "GetServerURL" fullword ascii
      $s14 = "ciacia.Resources.resources" fullword ascii
      $s15 = "\"Powered by SmartAssembly 6.9.0.114" fullword ascii
      $s16 = "AppNameMinusVersion" fullword ascii
      $s17 = "ReportingServiceSoapT" fullword ascii
      $s18 = "ReportingService" fullword ascii
      $s19 = "lpThreadParameter" fullword ascii
      $s20 = "SendingReportFeedback" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule YARA_MAL_NanocoreRAT_9 {
   meta:
      description = "NanocoreRAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "0ffea07b7a5500475562195fb2a2b492989ef5678d56afe30e79b65dd08273dd"
              hash10 = "0aa076882f28dfc64aee18f86a725a05da3db74f5784ec6e7536588241fe5345"
      hash11 = "35aa0532e6b8e3516af75763cb4af335a3760288744b3055a0932c3cbe8bca16"
      hash12 = "ed3b542d8fdbfcac0db17417e5ded3fa6eaca3cf6cbbf677a3bf73d77da0e8f7"
      hash13 = "20ed8f0edcc3ae2cd73e800ad2d4a571b73d575de7938540d9cac191e385a1a5"
      hash14 = "57f98a5ac9ebd816818ec347fefabb3761d274c9ae43306aa54c2e431b96b5e9"
      hash15 = "e53af8f12a6c79af55d320dd19a72485afecaea0bfc427a82613b12f6c6ae1b5"
      hash16 = "344ed043bc3bac73dc104d536183212b803d2738841f6e132454ebc5d770c2ff"
      hash17 = "d54cf8b747705acae1678e8a273c30a0dee7d1729a1fea231b0b8d833570929f"
      hash18 = "193dd7235fd8ed7adad4549c8b36f13f37d46685ef4dcc3bbead395894076f5a"
      hash19 = "de10f54ddc11ddd33a9373e66b5cd8f7119f99b1cb778241a90917b85300a5e6"
                       strings:
      $s1 = "IClientLoggingHost" fullword ascii
      $s2 = "NanoCore.ClientPluginHost" fullword ascii
      $s3 = "ClientLoaderForm" fullword ascii
      $s4 = "PluginCommand" fullword ascii
      $s5 = "GetBlockHash" fullword ascii
      $s6 = "FileCommand" fullword ascii
      $s7 = "IClientNetworkHost" fullword ascii
      $s8 = "LogClientMessage" fullword ascii
      $s9 = "PipeCreated" fullword ascii
      $s10 = "LogClientException" fullword ascii
      $s11 = "IClientReadOnlyNameObjectCollection" fullword ascii
      $s12 = "PipeExists" fullword ascii
      $s13 = "IClientAppHost" fullword ascii
      $s14 = "IClientDataHost" fullword ascii
      $s15 = "HostDetails" fullword ascii
      $s16 = "AddHostEntry" fullword ascii
      $s17 = "IClientUIHost" fullword ascii
      $s18 = "ClientInvokeDelegate" fullword ascii
      $s19 = "NanoCore.ClientPlugin" fullword ascii
      $s20 = "ReadBlockData" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and ( 8 of them )
      ) or ( all of them )
}

rule YARA_MAL_NanocoreRAT_10 {
   meta:
      description = "NanocoreRAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "20ed8f0edcc3ae2cd73e800ad2d4a571b73d575de7938540d9cac191e385a1a5"
    strings:
      $s1 = "ClientLoaderForm_FormClosing" fullword ascii
      $s2 = "clientLoaderForm_1" fullword ascii
      $s3 = "commandType_0" fullword ascii
      $s4 = "ipaddress_1" fullword ascii
      $s5 = "ipaddress_0" fullword ascii
      $s6 = "iclientNetwork_0" fullword ascii
      $s7 = "resolveEventArgs_0" fullword ascii
      $s8 = "GDelegate0" fullword ascii
      $s9 = "GDelegate1" fullword ascii
      $s10 = "GDelegate2" fullword ascii
      $s11 = "GDelegate3" fullword ascii
      $s12 = "GDelegate4" fullword ascii
      $s13 = "GDelegate5" fullword ascii
      $s14 = "GDelegate6" fullword ascii
      $s15 = "GDelegate7" fullword ascii
      $s16 = "GDelegate8" fullword ascii
      $s17 = "GDelegate9" fullword ascii
      $s18 = "gdelegate5_1" fullword ascii
      $s19 = "gdelegate1_1" fullword ascii
      $s20 = "gdelegate7_1" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule YARA_MAL_NanocoreRAT_11 {
   meta:
      description = "NanocoreRAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "0143b485ab72131f9ff9fa2e691c8a854cd883dd2cbcdf5be669c11e48739f74"
    strings:
      $s1 = "get_FolderBrowserDialog1" fullword ascii
      $s2 = "get_OpenFileDialog1" fullword ascii
      $s3 = "get_FileSystemWatcher1" fullword ascii
      $s4 = "set_FolderBrowserDialog1" fullword ascii
      $s5 = "FolderBrowserDialog1" fullword ascii
      $s6 = "get_NumericUpDown1" fullword ascii
      $s7 = "get_DataGridView1" fullword ascii
      $s8 = "set_OpenFileDialog1" fullword ascii
      $s9 = "_OpenFileDialog1" fullword ascii
      $s10 = "_FolderBrowserDialog1" fullword ascii
      $s11 = "OpenFileDialog1" fullword wide
      $s12 = "get_PictureBox1" fullword ascii
      $s13 = "Doeecmu Stuuaiu Pheuthomp Seompoigh Daouueeoi Ceiieao" fullword wide
      $s14 = "FileSystemWatcher1" fullword ascii
      $s15 = "5Doeecmu Stuuaiu Pheuthomp Seompoigh Daouueeoi Ceiieao" fullword ascii
      $s16 = " 2018 Deioiuuo Corporation" fullword wide
      $s17 = "set_FileSystemWatcher1" fullword ascii
      $s18 = "2018 Deioiuuo Corporation" fullword ascii
      $s19 = "_FileSystemWatcher1" fullword ascii
      $s20 = "Deioiuuo Corporation" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule YARA_MAL_RemcosRAT_1 {
   meta:
      description = "RemcosRAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "d8250867325f5c1204dbd46e67115273c68fa51209f4a66b1bed8ee9f350d5b5"
    strings:
      $x1 = "Error setting %s.Count8Listbox (%s) style must be virtual in order to set Count\"Unable to find a Table Of Contents" fullword wide
      $s2 = "MaxPointsPerPage must be >= 0+3D effect percent must be between %d and %d+Circular Series dependences are not allowed" fullword wide
      $s3 = "First Legend Value must be > 0.Legend Color Width must be between 0 and 100 %%No ParentChart to validate DataSource" fullword wide
      $s4 = "Directory not empty1The string %s does not translate into a valid IP." fullword wide
      $s5 = "Elevation<" fullword ascii
      $s6 = "+Cannot focus a disabled or invisible window!Control '%s' has no parent window" fullword wide
      $s7 = "Invalid network mask.#Invalid value length: Should be 32." fullword wide
      $s8 = "!'%s' is not a valid integer valueInvalid argument to date encode" fullword wide
      $s9 = "OnGetNextAxisLabel" fullword ascii
      $s10 = "Winsock stack/Top Legend Position must be between 0 and 100 %" fullword wide
      $s11 = "TAverageTeeFunction" fullword ascii
      $s12 = "TSeriesOnGetMarkText" fullword ascii
      $s13 = "TOnGetLegendText" fullword ascii
      $s14 = "TAxisOnGetNextLabel" fullword ascii
      $s15 = "TOnGetLegendRect" fullword ascii
      $s16 = "OnGetMarkTextSVW" fullword ascii
      $s17 = ":<:H:L:X:\\:d:h:l:p:t:x:|:" fullword ascii
      $s18 = "OnGetLegendRect" fullword ascii
      $s19 = "EIdConnClosedGracefullyU" fullword ascii
      $s20 = "Logarithmic<" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule YARA_MAL_RemcosRAT_2 {
   meta:
      description = "RemcosRAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "ecb931c41f1c39bcd8b53255720d53cea4e70715528f751520337fe483fcffdb"
     strings:
      $x1 = "Cannot create folder %sDCRC failed in the encrypted file %s. Corrupt file or wrong password." fullword wide
      $s2 = "=Total path and file name length must not exceed %d characters#Unsupported encryption method in %s" fullword wide
      $s3 = "Wrong password for %s5Write error in the file %s. Probably the disk is full" fullword wide
      $s4 = "Unexpected end of archiveThe file \"%s\" header is corrupt%The archive comment header is corrupt" fullword wide
      $s5 = "Extracting files to %s folder$Extracting files to temporary folder" fullword wide
      $s6 = "&Enter password for the encrypted file:" fullword wide
      $s7 = "ErroraErrors encountered while performing the operation" fullword wide
      $s8 = "Please download a fresh copy and retry the installation" fullword wide
      $s9 = "The required volume is absent2The archive is either in unknown format or damaged" fullword wide
      $s10 = "Please close all applications, reboot Windows and restart this installation\\Some installation files are corrupt." fullword wide
      $s11 = "folder is not accessiblelSome files could not be created." fullword wide
      $s12 = "CryptUnprotectMemory failed" fullword ascii
      $s13 = "Packed data CRC failed in %s" fullword wide
      $s14 = "File close error" fullword wide
      $s15 = "CRC failed in %s" fullword wide
      $s16 = "Look at the information window for more details" fullword wide
      $s17 = "Skipping %s" fullword wide
      $s18 = "WinRAR self-extracting archive" fullword wide
      $s19 = "IyO.CNc" fullword ascii
      $s20 = "Select destination folder" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "3c98c11017e670673be70ad841ea9c37" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule YARA_MAL_njRAT_1 {
   meta:
      description = "njRAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "07d9fa99acaafb08d76b1a87aa991e82cbff8dd30b167a145341300227344155"
    strings:
      $s1 = "get_Button6" fullword ascii
      $s2 = "get_Button7" fullword ascii
      $s3 = "get_Button4" fullword ascii
      $s4 = "get_Button5" fullword ascii
      $s5 = "get_Button8" fullword ascii
      $s6 = "get_Button9" fullword ascii
      $s7 = "get_Button34" fullword ascii
      $s8 = "get_Button35" fullword ascii
      $s9 = "get_Button32" fullword ascii
      $s10 = "get_Button33" fullword ascii
      $s11 = "get_Button30" fullword ascii
      $s12 = "get_Button31" fullword ascii
      $s13 = "get_Button54" fullword ascii
      $s14 = "get_Button55" fullword ascii
      $s15 = "get_Button56" fullword ascii
      $s16 = "get_Button50" fullword ascii
      $s17 = "get_Button51" fullword ascii
      $s18 = "get_Button52" fullword ascii
      $s19 = "get_Button53" fullword ascii
      $s20 = "get_Button21" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 700KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule YARA_MAL_NetWireRAT_1 {
   meta:
      description = "NetWireRAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "4784ac80808fbe144e6f63c8a0a2bad58710a0d01f4b6361b9cc2105046cc75f"
    strings:
      $s1 = "User-Agent: Mozilla/4.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko" fullword ascii
      $s2 = "ping 192.0.2.2 -n 1 -w %d >nul 2>&1" fullword ascii
      $s3 = "[Log Started] - [%.2d/%.2d/%d %.2d:%.2d:%.2d]" fullword ascii
      $s4 = "http://www.yandex.com" fullword wide
      $s5 = "start /b \"\" cmd /c del \"%%~f0\"&exit /b" fullword ascii
      $s6 = "Software\\Microsoft\\Office\\16.0\\Outlook\\Profiles\\Outlook\\9375CFF0413111d3B88A00104B2A6676" fullword ascii
      $s7 = "Software\\Microsoft\\Office\\15.0\\Outlook\\Profiles\\Outlook\\9375CFF0413111d3B88A00104B2A6676" fullword ascii
      $s8 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook\\9375CFF0413111d3B88A00104B2A667" ascii
      $s9 = "{GET %s HTTP/1.1" fullword ascii
      $s10 = "[%s] - [%.2d/%.2d/%d %.2d:%.2d:%.2d]" fullword ascii
      $s11 = "_BqwHaF8TkKDMfOzQASx4VuXdZibUIeylJWhj0m5o2ErLt6vGRN9sY1n3Ppc7g-C%.4d-%.2d-%.2d %.2d:%.2d:%.2d" fullword ascii
      $s12 = "Cs43l63g4R3YW0d3i4V0C0ZiWCSd03iG3G3y.Sii" fullword ascii
      $s13 = "%s\\%s.bat" fullword ascii
      $s14 = "DEL /s \"%s\" >nul 2>&1" fullword ascii
      $s15 = "Cs43l63g4R3YW0d3iWYCi4kC54WR3iG3h3y.Sii" fullword ascii
      $s16 = "Cs43l63g4R3YW0d3ICRSid3iG3G3y.Sii" fullword ascii
      $s17 = "Cs43l63g4R3Y053dR240WRldR53iG3G3y.Sii" fullword ascii
      $s18 = "Cs43l63g4R3YW0d305i6QssW053iG3G3y.Sii" fullword ascii
      $s19 = "Cs43l63g4R3YW0d34R5d0iWYwdS3iG3G3y.Sii" fullword ascii
      $s20 = "Cs43l63g4R3YW0d3ldlW0Z3iG3G3y.Sii" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and pe.imphash() == "8e97a1515090baa46f52cf0ff6a6d12f" and ( 8 of them )
      ) or ( all of them )
}

rule YARA_MAL_DarkCometRAT_1 {
   meta:
      description = "DarkComet RAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "4ac59bdb50d2a48f58741b3108eed936edeba6667f24d2de0021054f07aff4c5"
    strings:
      $x1 = "YMBO9HCTidCJXSjVEsDcK8+38xddAL2EGrcS2oM73/nX/rRGWFzRKrXWLzWWULPx8x/mhKzJoyYz77Hp+M/r6X47PpWsq0upK9+pBmZDybB8eodtPQSHgwxmzzzegmDZ" ascii
      $x2 = "meTwIFTvPAFg+mN8VXcMTyUBYnmcfg/Bou+jThcrno2JatDD/FXkAfUNt/Coh9kgpoePffjjsuyoZv+lzQjZF9/xFZnMJqeMuZmt4+rgDVS1olQQqfaqcQCsQp6MSwFh" ascii
      $x3 = "pZBP32lM/swQxmqqB/Alry+oaBP/7qmF93SQowDl5uKpiczavtnN6VO4qdi73GqjE9PwronaVe0mejPlmBg0UN5AE/byCJ/u+NyoFZSurn6OvmmK0sup6zPd3EHYu5M0" ascii
      $x4 = "N+EUZG4MPv2wInL+At4iQp57JO3kgWozFRMglmhyBsSlf4mdHdTDdco00zsBfNxMNQhTTFLEfdd0T/0wZhDpvOqStQoRgJVG5XstIt2YC4xtCVou0krk6597RBT30Xie" ascii
      $x5 = "5x2+lXeGZocbvAl5rXWlSZUOeACZt/vxt/lydkGgUHDgziIVCvyqlKXe3JTjEXJHI4GC5X+GL+E/bhSV/boLggx+Tv7AKEC9nwGLVRSg028hP3EwFNWthhWhGRemlqSp" ascii
      $s6 = "aa6yD++yUIKZ63XZxV+jouWqVtSsks3xeaTQojmXy2egiwhGf3EqhqLZypQy3jDCDscagyyQQOV9tuSeUlodZGk+kAayXBAy9f1vC2uvNvlFMLXn8ZaApxHts/U/EAfU" ascii
      $s7 = "RpwcPG2bCWHiTvKtpKRb2Yyj6IiqGJbM5HpIAtKtStCtEw8DRIzp6HdSCSBcInTa825xt5qceyb/9osYTlmjMZAs+rKp6ZWwxtvFj8W+F3baF9aCmtqBABq/f8zlVtYZ" ascii
      $s8 = "Decompression error*Error on call Winsock2 library function %s&Error on loading Winsock2 library (%s)" fullword wide
      $s9 = "+OJYMMLcPcKlLszFia9w4/myfDzubGBVrC+RWsPYXSkw912++yVRvHFy3a/fm7YwoKeXLpfPZO0oHpf4FAsqwm1v8tCs8+7K8S9tTzJJQDllnr4r1CznrDQVBLEzFEj0" ascii
      $s10 = "TSERVICE1" fullword wide
      $s11 = "TSERVICE2" fullword wide
      $s12 = "X8ObD1kR6bOMAjrzGpku3C0O2BfhVIWU4RuN7feOtYA+dYwGuLmLFdY7sLldDLzOg0GHhnuc3HuwCdAsBjrcOFTPVtXmAxNdZ8KKR9YLmMmrkYmkLuFldey+up8M2x0x" ascii
      $s13 = "EBg+b7zrijrzCQVRn50K9UqsAJ4osYiUzqTmb0azeTdCORcLvJdPCNGMV4EXs4PRkfs0etFZ6U3iYjiXj7COmFz6uSmb2ZblKHkqhoPscG0QX0ilspy+SLyH0WzbXN2/" ascii
      $s14 = "Z3ElXIXI+CuBB0vk9GwmIFZq3ZixNr3e2y9iBMoQD4PbVzGX1453g/loi21XqzGnLqesXazXcXH8i4CPO4HFUKSdlXjxjXuj0p7TDLliVN1WO+luL20W16//EY9G7G7V" ascii
      $s15 = "DrurOYkSqXpVsFei98CPnmmaRC+FMRvq8u+0FzIVP9Zv3bb5j4kvMHGO9KidhRq3p3+1sgCf9OKS5lTeCIylp2+gEtjdkVZZfkN//uKIjiin9I5N6/Or7EvzfKDHB+xe" ascii
      $s16 = "CjWkFdbDEtGQGwh9IJSnDJ89dp+siksrOkRDCnIfw1ZeedeyX39VNYSpyrucTmGST7mFYdgBxGtj//qvh7d7UHMi8yURE+Sz1divGk6YcU//RkfmpIZmAXsMvWeC0Tm3" ascii
      $s17 = "Dm/z/b/xLs3b2xfn3TewSDt+2e0xlkHoT2UWCjoFINvF5LCIBLeyEV8KEmXsoDzsBMKVddUTH5ii/QOzZyWoFX8a6Fllr6lT5fbTFqJ/+FXFOr8Tjqv4fzGMN/OlxMe+" ascii
      $s18 = "h/TIhTaxCeV/zzS4erPG/ljsJ/i4sqpRf0DrAsp/u/ln8uO6AXI3vDSgVEPoML3NA9DdfxumTmo55NOezwHX8Ao7" fullword ascii
      $s19 = "sVytfsr7Uuh30ZCZpPUmOuVkj4szm9pf/bc+GeToPKiZ2ljZis6wLmwtSvN5PWQPE1lvUF/7FrkdvWA+WY1lUhB3wTayFDaVkYz9tm7rvCjLzFAlPnm3A00B2e0ysnAI" ascii
      $s20 = "TbXHKDfDY6Qe+7vJKpW/OGdJQr0WDy0UeFPLAb0C5kzNxouaGfctV8wSC5VVT2sWN2A3LJuYqkKSFgVvEHSCLRFU" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule YARA_MAL_DarkCometRAT_2 {
   meta:
      description = "DarkComet RAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "007f746ac6cddb3856ddafbf4a29ab72b166498e5aa20245a66f72907a099413"
              hash10 = "11dda7b3ffb57f3484b1a0995bd01a5664fadcad597ce09e7be94254f4688b55"
      hash11 = "9cff51511203704c84f19f0a75ced13f931c55e63f3e60a1e22115dcb31c0d3d"
      hash12 = "0af9b967683c3e19661951bed41c8ad3eac0607147b71b0c745443206c57a2d1"
   strings:
      $x1 = "BTRESULTDownload File|Mass Download : File Downloaded , Executing new one in temp dir...|" fullword ascii
      $x2 = "BTRESULTUpdate from URL|Update : File Downloaded , Executing new one in temp dir...|" fullword ascii
      $s3 = "ping 127.0.0.1 -n 4 > NUL && \"" fullword ascii
      $s4 = "UnActiveOfflineKeylogger" fullword ascii
      $s5 = "Command successfully executed!|" fullword ascii
      $s6 = "TDownloaderThreadU" fullword ascii
      $s7 = "ActiveOfflineKeylogger" fullword ascii
      $s8 = "ActiveOnlineKeylogger" fullword ascii
      $s9 = ")UntDownloaderThread" fullword ascii
      $s10 = "OpenProcessToken error" fullword ascii
      $s11 = "UPLOADEXEC" fullword ascii
      $s12 = "BTMemoryLoadLibary: Get DLLEntyPoint failed" fullword ascii
      $s13 = "I wasn't able to open the hosts file, maybe because UAC is enabled in remote computer!" fullword ascii
      $s14 = "\\Internet Explorer\\iexplore.exe" fullword ascii
      $s15 = ") successfully dump in " fullword ascii
      $s16 = "DCOM not installed\"Unable to find a Table of Contents" fullword wide
      $s17 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\FontSubstitutes" fullword ascii
      $s18 = "!'%s' is not a valid integer value('%s' is not a valid floating point value!'%s' is not a valid date and time" fullword wide
      $s19 = "BTMemoryGetProcAddress: DLL doesn't export anything" fullword ascii
      $s20 = "BTMemoryLoadLibary: dll dos header is not valid" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule YARA_MAL_DarkCometRAT_3 {
   meta:
      description = "DarkComet RAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "c3178c99fb9c317dcf79a0ed46150a8c560835b78caee3c0fc6d69b4b64f77f8"
    strings:
      $x1 = "linkinfo.dll" fullword wide
      $x2 = "devrtl.dll" fullword wide
      $x3 = "dfscli.dll" fullword wide
      $x4 = "srvcli.dll" fullword wide
      $x5 = "browcli.dll" fullword wide
      $s6 = "atl.dll" fullword wide
      $s7 = "D:\\Projects\\WinRAR\\sfx\\build\\sfxrar32\\Release\\sfxrar.pdb" fullword ascii
      $s8 = "iphlpapi.DLL" fullword wide
      $s9 = "SSPICLI.DLL" fullword wide
      $s10 = "UXTheme.dll" fullword wide
      $s11 = "WINNSI.DLL" fullword wide
      $s12 = "oleaccrc.dll" fullword wide
      $s13 = "dnsapi.DLL" fullword wide
      $s14 = "sfxrar.exe" fullword ascii
      $s15 = "<!--The ID below indicates application support for Windows 10 -->" fullword ascii
      $s16 = "<pi-ms-win-core-processthreads-l1-1-2" fullword wide
      $s17 = "Please remove %s from %s folder. It is unsecure to run %s until it is done." fullword wide
      $s18 = ": :$:(:,:0:4:<:D:H:L:T:X:\\:`:d:h:l:p:t:|:" fullword ascii
      $s19 = "@Maximum allowed array size (%u) is exceeded" fullword wide
      $s20 = "<pi-ms-win-core-localization-obsolete-l1-2-0" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and pe.imphash() == "027ea80e8125c6dda271246922d4c3b0" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule YARA_MAL_DarkCometRAT_4 {
   meta:
      description = "DarkComet RAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "8ee213972c08ba75956dc2e1ae6c84ec996394dac031c8307478e557f4a11b95"
       strings:
      $s1 = "s{kernel32.dll" fullword ascii
      $s2 = "tPHotLigh" fullword ascii
      $s3 = "|''''xtpl''''hd`\\''''XTPL''''HD@<''''840,''''($ " fullword ascii
      $s4 = "cmd.expfH&" fullword ascii
      $s5 = "DarkO\\_2" fullword ascii
      $s6 = "WERRORM" fullword ascii
      $s7 = "d oAny2EO+- G" fullword ascii
      $s8 = "H_#SUPPORT_(_.SC3*" fullword ascii
      $s9 = "GetLo<\"" fullword ascii
      $s10 = "SpYW:TxS" fullword ascii
      $s11 = "T<-/HTTP://" fullword ascii
      $s12 = "@User/Ijhto" fullword ascii
      $s13 = "hxtheme" fullword ascii
      $s14 = "o#KCMDDC51#-" fullword ascii
      $s15 = "ETMONITORS" fullword ascii
      $s16 = "9,04dddd8<@DddddHLPTddddX\\`dq5" fullword ascii
      $s17 = "TThreadW" fullword ascii
      $s18 = "KeywnLF" fullword ascii
      $s19 = "itHashAr" fullword ascii
      $s20 = "TURKISHH" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "a38ad86d74cafc45094a5085e33419e4" and ( 8 of them )
      ) or ( all of them )
}

rule YARA_MAL_DarkCometRAT_5 {
   meta:
      description = "DarkComet RAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "e0ec6da41c9b30d053c00eaf9d1bf6ff2e85b387acdf1b776cf4a3de2abbde88"
              hash10 = "0af9b967683c3e19661951bed41c8ad3eac0607147b71b0c745443206c57a2d1"
   strings:
      $s1 = ":!:%:):-:1:5:9:=:A:E:I:\\:`:d:h:l:p:t:x:|:" fullword ascii
      $s2 = ":4:<:@:D:H:L:P:T:X:\\:`:d:" fullword ascii
      $s3 = ":(:H:P:T:X:\\:`:d:h:l:p:t:x:" fullword ascii
      $s4 = ": :4:@:T:\\:`:d:h:l:p:t:x:|:" fullword ascii
      $s5 = "5!575?5C5\\5" fullword ascii
      $s6 = "=#=5=D=\\=" fullword ascii
      $s7 = "5$6@6E6_6" fullword ascii
      $s8 = "?0?8?<?@?D?H?L?P?T?X?\\?`?d?h?l?p?t?x?|?" fullword ascii
      $s9 = "1'1+1/13171;1?1C1G1K1O1S1W1[1_1c1g1k1o1s1w1{1" fullword ascii
      $s10 = "4 4$444<4@4D4H4L4P4T4X4\\4`4d4h4l4p4t4x4|4" fullword ascii
      $s11 = "4 4$4(4,4044484<4@4D4H4L4P4T4X4\\4`4d4h4<6" fullword ascii
      $s12 = "9o:}:+</<3<7<;<?<C<G<K<O<S<W<[<_<c<g<k<o<s<w<{<" fullword ascii
      $s13 = ">0>8><>@>D>H>L>P>T>X>\\>`>d>h>l>p>t>x>|>" fullword ascii
      $s14 = "3*3.32363:3>3B3F3J3N3R3V3Z3^3b3f3j3n3r3v3z3~3" fullword ascii
      $s15 = "6(6064686<6@6D6H6L6P6T6X6\\6`6p6" fullword ascii
      $s16 = "040<0@0D0H0L0P0T0X0\\0`0d0h0l0p0t0x0|0" fullword ascii
      $s17 = "40484<4@4D4H4L4P4T4X4\\4`4d4h4t4" fullword ascii
      $s18 = "1 10181<1@1D1H1L1P1T1X1\\1`1d1h1l1p1|1" fullword ascii
      $s19 = "1\"1&1*1.12161:1>1B1F1J1N1R1V1Z1^1v1" fullword ascii
      $s20 = "3 3(3,3034383<3@3D3H3L3P3T3X3\\3`3d3t3" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "e5b4359a3773764a372173074ae9b6bd" and ( 8 of them )
      ) or ( all of them )
}

rule YARA_MAL_DarkCometRAT_6 {
   meta:
      description = "DarkComet RAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "007f746ac6cddb3856ddafbf4a29ab72b166498e5aa20245a66f72907a099413"
   strings:
      $s1 = "ERangeError " fullword ascii
      $s2 = "AutoHotkeysd-C" fullword ascii
      $s3 = "OnKeyDownL" fullword ascii
      $s4 = "TGlassFrameT" fullword ascii
      $s5 = "EWriteError|qA" fullword ascii
      $s6 = "OnDockDrop4" fullword ascii
      $s7 = "TGlassFramet" fullword ascii
      $s8 = "EFOpenErrortpA" fullword ascii
      $s9 = "HelpKeyword nA" fullword ascii
      $s10 = "EInOutError`" fullword ascii
      $s11 = "TInterfacedPersistent\\vA" fullword ascii
      $s12 = "TContainedAction4" fullword ascii
      $s13 = "EThreadD" fullword ascii
      $s14 = "TThreadX" fullword ascii
      $s15 = "TGraphicsObjectL-B" fullword ascii
      $s16 = "TGraphicsObject$-B" fullword ascii
      $s17 = "TCustomIpClientl" fullword ascii
      $s18 = "OnMouseActivatel" fullword ascii
      $s19 = "TSizeConstraints<" fullword ascii
      $s20 = "TOleServer4" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule YARA_MAL_RevengeRAT_1 {
   meta:
      description = "RevengeRAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "1546bde74af33fcdfe9674a1854a6da0217845bebf7153353ad6f1845041b815"
   strings:
      $x1 = "DVyxEvrx7St77JQX1wkH7MyIQj2iX4+c6Uvr2t4C4jRe6w9MQBLJo1mM3Xthr4FttvM+x/MFW9arZI7Dl9hKwLbzPsfzBVvWq2SOw5fYSsCkO943iaDoDpF4HA4NzrIO" ascii
      $s2 = "JCKvBvRIBxMNcpXYeSKGLlMCHLNDYsiEtzyzJcAOSyigjPoN.exe" fullword ascii
      $s3 = "8C5vvs/q5+dwSmXZnUUHRc6Uu20Hs0V8gIjUO1LlU+4L3u3FRdXlRWGFhwK7c6RKRBlGlKx4RfTPSeBu/geK11GqBAKLVs254TnE25XZ0kxONDmSxIsPYuhuQVMZVOe1" ascii
      $s4 = "T7HEFI/77FR5Vlufc6jv9CgLBf0dcmAcJdUMPDxPSfK1brEXHyv45m9+yYfhVIu/sKdKgSYiJMMVHfgXk6SbtL7Yavr9PQ6hUNHHk/3jVi8L7T8k0WysqETudt685Wxn" ascii
      $s5 = "iBMGrSw1+p3oXCtncP1JwdUifIWuEv+BPxVyBe7x/7WsCrRLZy1A+lF+A6wExtWYqevYmBINCKBGJRQpFULERtCoc9iTtJoFbb1SE2RvoO6xOEqkolOGFOgjnp/Q7dec" ascii
      $s6 = "tvM+x/MFW9arZI7Dl9hKwLbzPsfzBVvWq2SOw5fYSsC28z7H8wVb1qtkjsOX2ErAtvM+x/MFW9arZI7Dl9hKwHVevdAX9+XVIcLdsuU9ijQ= " fullword ascii
      $s7 = "Copyright 2006-2010 Adobe Systems Incorporated and its licensors. All rights reserved." fullword wide
      $s8 = "HLogh4DiknjVlgwgW8/0QE4kBT9GMb7iCsb7ag5hLkpVPhqGzYqBzcc//MjD7iHbR/656et+NkAKpcdnESfrMC6XRpWYbFm+GlB7yHBUIAq8n+MQq89YKUsMUEJv4zI3" ascii
      $s9 = "NKmBfBckbwzs2pHSdBOUsEO8DH6Joaf4lQbnkiIBmWOX1w3r+iZUM7RpR//reQ04P1Kkzyo0PKF45Yr/aKZrywrlYWpfDtUQ81rljhagTDmSPYR69ppRRIntq3MFNBmo" ascii
      $s10 = "pGkWUkk037mA2A2TnmjPYOhF4gGdLoGoFQWpKWuS1oPTVZgD2phoTRgK4TJI5MYI6klHA+g++tawucZDMkk//SjYqgPaom20Nqz46JzNvXYLBZQFqRE0Dmtu62FLOWQy" ascii
      $s11 = "vvGsfuugNALgZTJWyknlIkhAfM873//HqAKq2n9JU4NNNP+ZE8BQcuDhSGHxdV5O2spYEiT151Jgc8sxuxmbxlbjHtHedQc+ilJhy2f+HxSuYmwTdqGRowZ4KsKQ1yVu" ascii
      $s12 = "RHvagUYTY61NIJaZxyKm1jeR8lK1NweOV2i55KSDDhDPdTtrZXlaMkplkGeyEQ/3/xihAKlfPNZuHIiCgWtdTsTeXh8mvlo3IJQLMzmA8FRpt3uH4Gc0pFqAuULqbdiI" ascii
      $s13 = "Ex689KrF72f7B24yZHh7xa3rXZ4Pz/W7cfJ1rgmBC8F2VU24oVvas2MFUwdeyxQD04osSY/D/N7YMVMc0JDO4t8kHrJy1JS5NIpJaH7gsq5pMRIBw7sdLlPaYg0Fs24y" ascii
      $s14 = "dxxpu56heAdwPOs19ndMOCTK7BajngOoKo0QwwS1gQ9GH7FD7ET/s+TollJ4t+56f1EtVy30N1Q0qzVGk26YcKwTj05JYr2P/67UK63Gl1kXloQUbw58647B/opO2I7n" ascii
      $s15 = "T6ae69MSFY+r6F0l9XAuCbfI30cWftPdKh46i2SYu1Bqwy2xkNrDgyUne4l2hunZZ/VvXqTh9xGIUpz8eNJgYc9LF3zC0ePae+wYOpk2dhF8ifNjxMMsLADjcD2pzVq8" ascii
      $s16 = "4EnoVS22q6VMY/oX4p9ORgLg6y4XbhmoR4JHQOvcsjVnVeYAOm1WQ27eL6/OjqFmDW0RkfBtaB4cWKYSvfm7bcJDWR+XFdkDTWKZRzeeye7RSJBpYz8J/J3z39YLrmXJ" ascii
      $s17 = "kcpPizYdyXgqLaNL3TN1MoY0KxVN1jsBKiMqKE4KZHuGW/d2CjMa0ylYlxxBooyZMyBRJM8qAYSPYmF5eyTue9tHF/j0/8qcdHsQEb5U/cmmIODOntf5+0UTXdKjCwik" ascii
      $s18 = "eDwMqZjgvfu4RYaAnsOq+8V/8Eet1vZaHYsLTLG3X/qXXPK1CquyGDOVZ0UKJIloGzWzTu+Tj8CJT9sKqAJ1NK5Hcu5PRWF0MaLlr0HcvesPrOt+HW8A/cDph9qF4woj" ascii
      $s19 = "lrO3VBIU6Vyecsqa47aU7+GTHA8NXKSpYhYFsj7aQHSBGrITRKAmyxTPLpcWDq3FI+mAEmZQBzA6koZLFz1QsdOVJSu6P3zum34WxaX+IEXE1bCisBybTfDPyxAQ1h5b" ascii
      $s20 = "8trrfC6O7YilhaYzFK3VxxieoSI13PBlS7qgEtYjC/NsUJ0z2UQ0zG6pL3YQwgs6Dd5CjroXotHxvsCsXqgEPUAsprWG4T1xtVJZZ4JYxZNfUjtJJEsFFNa18jXmN3iI" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 12000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule YARA_MAL_RevengeRAT_2 {
   meta:
      description = "RevengeRAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "d29a1d60620e954b971953e92291b1bdf22b6c3759bb7c3058a9cc2602244e06"
    strings:
      $s1 = "OnBm0Ill0I/QjFkqNVzQim3igLAjcyY80IlATk1AZ1puKNCMTUAkSOKAnnd2fnIyLi1PIHPQgyZQWGBbJGVFPTvQgk/igJhP0InigKDigJkrfTA0KOKCrDI4" fullword ascii
      $s2 = "dDlLWFNYRGtIVEN3QTNrcUZiSm9kajRNM3picXkwOFVMYmh0NWNiNzJpNUY4MWc0Nk0wNDlVaUg5THhSS1RmUjlaNTlidm1tNFNLWm1MMDczVEJsMUhmUjgxSmgxS05J" ascii
      $s3 = "NdMJHVmxNThQQBlKhUmRvNNxEI.exe" fullword ascii
      $s4 = "RzBmdWduYzZlMUdMYTJPakl3RUJFVTZsOVNTMDNuQzAxaGFlUjFOeG1kU2pvOW8wZQ==" fullword ascii
      $s5 = "{6477c6ba-5699-4de8-9651-dc4b36135413}, PublicKeyToken=3e56350693f7355e" fullword wide
      $s6 = "cGphVDM1M3hxN081UDdENFNnbjJBVUN0NVFsSDdYSHJoejNhN2ZEYkZUMlNqb3dZcVYzSTE2MDVEOFQyUWowYXE2NlZVOG00YUZKNzljNnp0R2hwOGs4NjFVNDE5OEY1" ascii
      $s7 = "cjdvTkUydXVsYUI0WExSczk3WkR2bnVFWHU2eDRydmtlUTZtTWVpNTBHVkZ6OW43ZjRrUXhmS214MzBTQ1k1NjcyaUw1NFVBbFI0S0dKSTlYazJHM2NSakZoRjIyQ1FM" ascii
      $s8 = "cjdvTkUydXVsYUI0WExSczk3WkR2bnVFWHU2eDRydmtlUTZtTWVpNTBHVkZ6OW43ZjRrUXhmS214MzBTQ1k1NjcyaUw1NFVBbFI0S0dKSTlYazJHM2NSakZoRjIyQ1FM" ascii
      $s9 = "Sic3LH52Z08mTnh5UA==hQGBXL18yNkfQgjU+NWkqbCFENztZZjs3NWdFQ9GSZT030IN+fuKAmDRN0Ik1aklrTT87MWlReOKAmtCLcU95bERA0IrQidCC4oCgSTo=" fullword ascii
      $s10 = "igqxZa2U7WGtjQH7igJo6eUfQgnQlSuKAptCKVm/igJk9XuKAoQ==@6L+q6L+q5bC6dHHYrtC2WOOCs9iobm3mr5TQldmH6L+qVlTigIzYpti52LFLedio" fullword ascii
      $s11 = "XXzigKBrcm1HeGE6N1lEPuKAnuKAoFlTVkJK4oChcjpiLHpp4oCmOyFvfm3QgzdYNHNUcjdpWWkyayc2ajFBYEtnaClrKGbigKBx4oCgRjhabWpPbE5F" fullword ascii
      $s12 = "OGpRSEIzOUw5ejU3MmxBRkU=" fullword ascii
      $s13 = "QXB5Znk3a0o3YlluNEVnR2tzMw==" fullword ascii
      $s14 = "Z3VoeXRyZWR1eXQ=" fullword ascii
      $s15 = "UmFkaW9CdXR0b24x" fullword ascii
      $s16 = "RW50cnlQb2ludA==" fullword ascii
      $s17 = "KVvQjCQ1bCXigJhU0IkxN1FgfzzQj155Y3Yzezlx0InigLk7WEI9MmZ+OCPQiyDigJhB0Ip8QdGTS2lXaCtZMmN00IxH4oCwcg==" fullword ascii
      $s18 = "amh5dGRmanl0ZmQ=" fullword ascii
      $s19 = "Q2hlY2tlZExpc3RCb3gy" fullword ascii
      $s20 = "bWlreWpudGZ5dGY=" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 13000KB and ( 8 of them )
      ) or ( all of them )
}

rule YARA_MAL_RevengeRAT_3 {
   meta:
      description = "RevengeRAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "d3adeed1bb2bcb3c07253edae8a6d888e44f7b138a0264033fd50132bef077a3"
       strings:
      $x1 = "YSystem.Int16, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii
      $s2 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=2.0.0.0, Culture=neutral, Publickeytoken=b77a5c561934" ascii
      $s3 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=2.0.0.0, Culture=neutral, Publickeytoken=b77a5c561934" ascii
      $s4 = "System.Drawing.IconLib.ColorProcessing" fullword ascii
      $s5 = "<PrivateImplementationDetails>{6607AD2E-349D-4E63-8F04-BA5EF349E020}" fullword ascii
      $s6 = "System.Drawing.IconLib.Exceptions" fullword ascii
      $s7 = "System.Drawing.IconLib.EncodingFormats" fullword ascii
      $s8 = "GetLastErrorResult" fullword ascii
      $s9 = "System.Drawing.IconLib" fullword ascii
      $s10 = "DONT_RESOLVE_DLL_REFERENCES" fullword ascii
      $s11 = "get_BestFitIconIndex" fullword ascii
      $s12 = "get_GroupIconDir" fullword ascii
      $s13 = "get_IconNamesList" fullword ascii
      $s14 = "get_IconImageFormat" fullword ascii
      $s15 = "get_ColorsInPalette" fullword ascii
      $s16 = "get_GroupIconDirEntries" fullword ascii
      $s17 = "get_IsIntResource" fullword ascii
      $s18 = "get_IconDirEntries" fullword ascii
      $s19 = "get_ResourceRawData" fullword ascii
      $s20 = "Microsoft.API" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 7000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule YARA_MAL_RevengeRAT_4 {
   meta:
      description = "RevengeRAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "a94851be16d0a9ffe3ae423c73be760916d09e29e364e8c8b047542a9bd8f1ff"
    strings:
      $x1 = "c:\\Users\\piko\\Documents\\Visual Studio 2013\\Projects\\snvc\\snvc\\obj\\Debug\\snvc.pdb" fullword ascii
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
      $s5 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
      $s6 = "snvc.exe" fullword wide
      $s7 = "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
      $s8 = "AAAAAAAAAAAAAAAAAAFAAAAAA" ascii
      $s9 = "AACBAAAAAAAAAAAAAAAAAAABAACBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
      $s10 = "AAABAAAAAAAA" ascii
      $s11 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
      $s12 = "9AAAAAAAAAAA" ascii
      $s13 = "EAAAAACAAAAAAAAA" ascii
      $s14 = "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABE" ascii
      $s15 = "BAAABAAAAAAAAEAAAEAAAAAABAAAAAAAAAAAAAAA" ascii
      $s16 = "AAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABA" ascii
      $s17 = "CAAAAAAAAAEc" ascii
      $s18 = "snvc.Properties.Resources.resources" fullword ascii
      $s19 = "xHyFgUAEKclIxHyJgUAEKclIxHyNgUAEKclIxHyRgUAEKclIxHyVgUAEKclIxHyZgUAEKclIxHydAUAIKclIxHyhgWAIKclIxHylgUAEKclIxHypgUAEKclIyHGAoGZ8" ascii
      $s20 = "HackerTechnology" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule YARA_MAL_RevengeRAT_5 {
   meta:
      description = "RevengeRAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "ae2f709881615b4912938a33c3ee6072d63d9a10b2a9c0fccaa40c375386dca9"
    strings:
      $s1 = "<script language='javascript'>alert( \"This assembly is protected by an unregistered version of .NET Reactor!\" );</script>" fullword wide
      $s2 = " gY GgpW gY HQpZ gY I pZ gY JQpd gY Jwpd gY Kgpg gY * pg gY Ngpf  Y OQpf  Y Pwpd gY QQpd hY Qwpf BY Rwpf BY Swpk hY " fullword wide
      $s3 = "DQL+BiU   ZzOg  Cn*7   KEw4RDhENF40I   BJRYWjC*   GiFCg8   KKCc   pvPQ  Cg GFHKn QBwFo0I   BFBQUFygP   KJn*u   KChENbz4   oY/gE" fullword wide
      $s4 = "* DgIv KEC*QCh js oQJH KECSwCh gE Kw    Y  Q G    Bw Y x4DO *+ 2oDdQN5 54DqQOz 7sDxgP" fullword wide
      $s5 = "   EKB0   oCewo   QCew4   SaKB0   p+Ew  BCgd   K ige   GKB0   p+Ew  BCgd   K ih*   Kb00   ooIw  Bigd   Kfh*   QoHQ  CnK" fullword wide
      $s6 = "gBh G0 ZQ  B04 LwBB  C g0g SwBF Fk XwB* E8 QwBB Ew XwBN EE QwBI Ek " fullword wide
      $s7 = "This assembly is protected by an unregistered version of Eziriz's \".NET Reactor\"!" fullword wide
      $s8 = " G8 ZgB0 Hc YQBy GU X    1w   Nf   3S BL EU WQBf E* ...QBS FI RQBO FQ XwB... F* RQBS Fw UwBP EY ... BX EE UgBF Fw   dH F  " fullword wide
      $s9 = "GF0ZUluZG...4U2...0Q29tcGxle B*YXRlU2...0Q29tcGxle BUY3BDbGllbnQ c2...0X1JlY2...pdm...UaW1lb3...0 HNldF9" fullword wide
      $s10 = "   EoiUaBheaoiUbfh*   SiJRwWKCQ   qiKCU   ooEg  Bg oFg  Ct4    rSQ CHY0Z   BJRZy+Q  cKIlF34" fullword wide
      $s11 = "W92ZU5leHQ SURpc3Bvc2FibGU RGlzcG9zZQBJSWY Z2...0X0NhcGFjaXR5 E...uY29kaW5n GdldF9EZWZhdWx0 EdldEJ5dG...z EdldFN0cmluZwB" fullword wide
      $s12 = "gBF Fw S BB FI R BX EE UgBF Fw R BF F* QwBS Ek U BU Ek " fullword wide
      $s13 = " gBwKB0   qiFBQUFygP   KJgIRFH0N   E hEUfQ4   QXDN06+P//KBU   o cp8C H oIg  CigX   K  IWfQ0   QCFn0O   EKBY   re   RFBfWExQRFBE" fullword wide
      $s14 = "WFpbgBFeG...jdXRl ElOUwBQaW4 ZGF0YQBi ElO...gBO EJ5dG...z F* " fullword wide
      $s15 = "wBS Fw *   J1  cgBv G* ZQBz H* bwBy E4 YQBt GU UwB0 HI aQBu Gc     BG6mXs6fjUiONsEij" fullword wide
      $s16 = "2JqZWN0 FRhcmdldE1ldGhvZ BCZWdpbkludm9rZQBEZWxlZ2F0ZUNhbGxiYWNr ERlbG...nYXRlQXN5bmN" fullword wide
      $s17 = "* I Fg    Y  BE KHE   oDb2U   oocg  Cgor  Yq   " fullword wide
      $s18 = "ZW5k...GltZW91d BzZXRfU2...uZEJ1ZmZlclNpemU c2...0X1JlY2...pdm...CdWZmZXJ" fullword wide
      $s19 = "eXN0ZW0uQ29sbG...jdGlvbn*uR2...uZXJpYwB*aXN0YDE ...3JpdGU ...G9BcnJheQBBZGQ U3RyZWFt FN5c3RlbS5J" fullword wide
      $s20 = "gBU FI QQB* F  UgBP E* RQB" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule YARA_MAL_RevengeRAT_6 {
   meta:
      description = "RevengeRAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "48800d18970a9c3c8174973e76bb9a73194a37a597b9a783fbca2f0e4544636a"
    strings:
      $s1 = "FZYWhhhhhhh,&&#\")TZY\\hhhhh-**((>9E[ZYXhhhh//.@VJJRS[ZYhhh2113dC:7Af`[Z]hh455+L<::7Jc[Z]hh;60" fullword ascii
      $s2 = "wyyyyyyyyyyy" fullword ascii
      $s3 = "wyyyyyyvvyyyx" fullword ascii
      $s4 = "yyyyvvvt" fullword ascii
      $s5 = "(2>@@@@@@@;;;0,+&&&&" fullword ascii
      $s6 = "uuuuuuvvvvvuu" fullword ascii
      $s7 = "uuuuuuuussusss" fullword ascii
      $s8 = "vvvvvvvvvvvu" fullword ascii
      $s9 = "gdfjjeeffffb" fullword ascii
      $s10 = "jhhhiihhh" fullword ascii
      $s11 = "uuuuuuuuuuuuuw" fullword ascii
      $s12 = "rkkkkkkkf" fullword ascii
      $s13 = "\"!)?BEDD@@@@;;;;44444.--***$$$$" fullword ascii
      $s14 = "ollllmml" fullword ascii
      $s15 = "{yyyyyyyyyyl" fullword ascii
      $s16 = "rmmlmmmd" fullword ascii
      $s17 = "yyyyvt" fullword ascii
      $s18 = "kkkkiiki" fullword ascii
      $s19 = "yyyyyyyyy{w'" fullword ascii
      $s20 = "UKLLNROOKG" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule YARA_MAL_RevengeRAT_7 {
   meta:
      description = "RevengeRAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "5286e448a50dae86c4784d51f3c66d05c4428c710485196fe1a1b036fdbbb417"
    strings:
      $s1 = "Xmm3Pv7AsBuAHCCqL8.CJQA2nZZqw89Kg0Dgr/oYPh3gGKF9yrPsHfjj/s18kFK5FbQXF37NjaD`1[[System.Object, mscorlib, Version=2.0.0.0, Culture" ascii
      $s2 = "Xmm3Pv7AsBuAHCCqL8.CJQA2nZZqw89Kg0Dgr/oYPh3gGKF9yrPsHfjj/s18kFK5FbQXF37NjaD`1[[System.Object, mscorlib, Version=2.0.0.0, Culture" ascii
      $s3 = "GJCwAb0BX" fullword ascii
      $s4 = "<PrivateImplementationDetails>{63781324-1F51-45F4-BBDF-C22480FD8498}" fullword ascii
      $s5 = "<Module>{502C6BF1-2D34-4305-9862-A25B540F2D67}" fullword ascii
      $s6 = "IXA86T9OmSHW3QRGIC.O3o5hkk6bDeTbImfOi" fullword wide
      $s7 = "oYPh3gGKF9yrPsHfjj" fullword ascii
      $s8 = "V1ruLPErdDBNaIB1kn" fullword ascii
      $s9 = "BkDkfLR1C3NxrE7MAM" fullword ascii
      $s10 = "jRqwa8JDb6esrc1K8X" fullword ascii
      $s11 = "p7B2MhlLB1cg00SUX9" fullword ascii
      $s12 = "aSdGh4aZTtvl8s85xc" fullword ascii
      $s13 = "ATUgRaukiswCZYFhII" fullword ascii
      $s14 = "S8ZgBTOvY145mtNqSk" fullword ascii
      $s15 = "Ke5ffhoM5qqUC23sTd" fullword ascii
      $s16 = "jZlhT7Q4htDPeVAmls" fullword ascii
      $s17 = "Sh7qZWFgjPVAkXm6sT" fullword ascii
      $s18 = "SRJ2E5RJScMfwmKmRU" fullword ascii
      $s19 = "Iq2u7kAutcJyZkke8c" fullword ascii
      $s20 = "SIhrr1Yul5rmAcuXPP" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule YARA_MAL_RevengeRAT_8 {
   meta:
      description = "RevengeRAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "7b4cabeff83e4f7bf8832793fc4796830758f34ef33bd3035147a30231e5d376"
      strings:
      $s1 = "<!-- A list of all Windows versions that this application is designed to work with. Windows will automatically select the " fullword ascii
      $s2 = "Wincat.exe" fullword wide
      $s3 = "most compatible environment.-->" fullword ascii
      $s4 = "Wincat.pdb" fullword ascii
      $s5 = "ComboBox4" fullword ascii
      $s6 = "$$method0x6000279-2" fullword ascii
      $s7 = "MaskedTextBox9" fullword ascii
      $s8 = "MaskedTextBox8" fullword ascii
      $s9 = "MaskedTextBox3" fullword ascii
      $s10 = "MaskedTextBox2" fullword ascii
      $s11 = "MaskedTextBox5" fullword ascii
      $s12 = "MaskedTextBox4" fullword ascii
      $s13 = "MaskedTextBox7" fullword ascii
      $s14 = "MaskedTextBox6" fullword ascii
      $s15 = "RichTextBox2" fullword ascii
      $s16 = "CheckBox6" fullword ascii
      $s17 = "CheckBox7" fullword ascii
      $s18 = "PictureBox4" fullword ascii
      $s19 = "PictureBox5" fullword ascii
      $s20 = "PictureBox6" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 700KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule YARA_MAL_XtremeRAT_1 {
   meta:
      description = "XtremeRAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "cd05cc16c77dae01b350bb7d780f1ba467a5b4e32d6dcbeb573105a9dbd567f8"
     strings:
      $s1 = "UnitInjectProcess" fullword ascii
      $s2 = "[Execute]" fullword wide
      $s3 = "%NOINJECT%" fullword wide
      $s4 = "XtremeKeylogger" fullword wide
      $s5 = "UnitInjectServer" fullword ascii
      $s6 = "XTREMEBINDER" fullword wide
      $s7 = "BINDER" fullword wide
      $s8 = "SOFTWARE\\XtremeRAT" fullword wide
      $s9 = "frgjbfdkbnfsdjbvofsjfrfre" fullword wide
      $s10 = "jiejwogfdjieovevodnvfnievn" fullword wide
      $s11 = "%DEFAULTBROWSER%" fullword wide
      $s12 = "jytjyegrsfvfbgfsdf" fullword wide
      $s13 = "trhgtehgfsgrfgtrwegtre" fullword wide
      $s14 = "hgtrfsgfrsgfgregtregtr" fullword wide
      $s15 = "[Numpad -]" fullword wide
      $s16 = "YUnitBinder" fullword ascii
      $s17 = "UnitConfigs" fullword ascii
      $s18 = "KeyDelBackspace" fullword wide
      $s19 = "ENDSERVERBUFFER" fullword wide
      $s20 = " restart" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule YARA_MAL_XtremeRAT_2 {
   meta:
      description = "XtremeRAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "cd05cc16c77dae01b350bb7d780f1ba467a5b4e32d6dcbeb573105a9dbd567f8"
     strings:
      $s1 = "UnitInjectProcess" fullword ascii
      $s2 = "[Execute]" fullword wide
      $s3 = "%NOINJECT%" fullword wide
      $s4 = "XtremeKeylogger" fullword wide
      $s5 = "UnitInjectServer" fullword ascii
      $s6 = "XTREMEBINDER" fullword wide
      $s7 = "BINDER" fullword wide
      $s8 = "SOFTWARE\\XtremeRAT" fullword wide
      $s9 = "frgjbfdkbnfsdjbvofsjfrfre" fullword wide
      $s10 = "jiejwogfdjieovevodnvfnievn" fullword wide
      $s11 = "%DEFAULTBROWSER%" fullword wide
      $s12 = "jytjyegrsfvfbgfsdf" fullword wide
      $s13 = "trhgtehgfsgrfgtrwegtre" fullword wide
      $s14 = "hgtrfsgfrsgfgregtregtr" fullword wide
      $s15 = "[Numpad -]" fullword wide
      $s16 = "YUnitBinder" fullword ascii
      $s17 = "UnitConfigs" fullword ascii
      $s18 = "KeyDelBackspace" fullword wide
      $s19 = "ENDSERVERBUFFER" fullword wide
      $s20 = " restart" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule YARA_MAL_XtremeRAT_3 {
   meta:
      description = "XtremeRAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "cd05cc16c77dae01b350bb7d780f1ba467a5b4e32d6dcbeb573105a9dbd567f8"
    strings:
      $s1 = "icon=shell32.dll,4" fullword wide
      $s2 = "<meta http-equiv=\"Content-Type\" content=\"text/html;charset=UTF-8\">" fullword wide
      $s3 = "shell\\Open\\command=" fullword wide
      $s4 = "TServerKeylogger" fullword ascii
      $s5 = "ServerKeyloggerU" fullword ascii
      $s6 = "RECYCLER\\S-1-5-21-1482476501-3352491937-682996330-1013\\" fullword wide
      $s7 = ";open=RECYCLER\\S-1-5-21-1482476501-3352491937-682996330-1013\\" fullword wide
      $s8 = "shellexecute=" fullword wide
      $s9 = "<title>Xtreme RAT</title>" fullword wide
      $s10 = "shell\\Open=Open" fullword wide
      $s11 = "shell\\Open\\Default=1" fullword wide
      $s12 = "qualquercoisarsrsr" fullword wide
      $s13 = "TGetPlugin" fullword ascii
      $s14 = "TUnitInfectUSB" fullword ascii
      $s15 = "gsegtsrgrefsfsfsgrsgrt" fullword wide
      $s16 = "<FONT COLOR=\"red\">[Clipboard End]</font>" fullword wide
      $s17 = "STARTSERVERBUFFER" fullword wide
      $s18 = "action=Open folder to view files" fullword wide
      $s19 = "%SERVER%" fullword ascii
      $s20 = "OThreadUnit" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and pe.imphash() == "54d337e45f6015e5ce82372bfb9e9750" and ( 8 of them )
      ) or ( all of them )
}

rule YARA_MAL_XtremeRAT_4 {
   meta:
      description = "XtremeRAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "cd05cc16c77dae01b350bb7d780f1ba467a5b4e32d6dcbeb573105a9dbd567f8"
     strings:
      $s1 = "UnitInjectProcess" fullword ascii
      $s2 = "[Execute]" fullword wide
      $s3 = "%NOINJECT%" fullword wide
      $s4 = "XtremeKeylogger" fullword wide
      $s5 = "UnitInjectServer" fullword ascii
      $s6 = "XTREMEBINDER" fullword wide
      $s7 = "BINDER" fullword wide
      $s8 = "SOFTWARE\\XtremeRAT" fullword wide
      $s9 = "frgjbfdkbnfsdjbvofsjfrfre" fullword wide
      $s10 = "jiejwogfdjieovevodnvfnievn" fullword wide
      $s11 = "%DEFAULTBROWSER%" fullword wide
      $s12 = "jytjyegrsfvfbgfsdf" fullword wide
      $s13 = "trhgtehgfsgrfgtrwegtre" fullword wide
      $s14 = "hgtrfsgfrsgfgregtregtr" fullword wide
      $s15 = "[Numpad -]" fullword wide
      $s16 = "YUnitBinder" fullword ascii
      $s17 = "UnitConfigs" fullword ascii
      $s18 = "KeyDelBackspace" fullword wide
      $s19 = "ENDSERVERBUFFER" fullword wide
      $s20 = " restart" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule YARA_MAL_XtremeRAT_5 {
   meta:
      description = "XtremeRAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "a24e7fd588fb041813ad1c7b5af2cbe930ccb020ab114b0e53796fbcd2d48852"
    strings:
      $s1 = "WindowsApplication1n.exe" fullword ascii
      $s2 = "m_MyWebServicesObjectProvider" fullword ascii
      $s3 = "m_ComputerObjectProvider" fullword ascii
      $s4 = "ThreadSafeObjectProvider`1" fullword ascii
      $s5 = "m_UserObjectProvider" fullword ascii
      $s6 = "m_ThreadStaticValue" fullword ascii
      $s7 = "MyWebServices" fullword ascii
      $s8 = "WindowsApplication1n.Resources.resources" fullword ascii
      $s9 = "WindowsApplication1n.Form1.resources" fullword ascii
      $s10 = "m_MyFormsObjectProvider" fullword ascii
      $s11 = "m_AppObjectProvider" fullword ascii
      $s12 = "m_FormBeingCreated" fullword ascii
      $s13 = "AutoSaveSettings" fullword ascii
      $s14 = "WindowsApplication1n.Resources" fullword wide
      $s15 = "addedHandlerLockObject" fullword ascii
      $s16 = "inScopeNs" fullword ascii
      $s17 = "yAtroyDro" fullword ascii
      $s18 = "Term\\aHG" fullword ascii
      $s19 = "eekcv3b=L" fullword ascii
      $s20 = "Form1_Load" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and ( 8 of them )
      ) or ( all of them )
}

rule YARA_MAL_XtremeRAT_6 {
   meta:
      description = "XtremeRAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "cd05cc16c77dae01b350bb7d780f1ba467a5b4e32d6dcbeb573105a9dbd567f8"
    strings:
      $s1 = "icon=shell32.dll,4" fullword wide
      $s2 = "<meta http-equiv=\"Content-Type\" content=\"text/html;charset=UTF-8\">" fullword wide
      $s3 = "shell\\Open\\command=" fullword wide
      $s4 = "TServerKeylogger" fullword ascii
      $s5 = "ServerKeyloggerU" fullword ascii
      $s6 = "RECYCLER\\S-1-5-21-1482476501-3352491937-682996330-1013\\" fullword wide
      $s7 = ";open=RECYCLER\\S-1-5-21-1482476501-3352491937-682996330-1013\\" fullword wide
      $s8 = "shellexecute=" fullword wide
      $s9 = "<title>Xtreme RAT</title>" fullword wide
      $s10 = "shell\\Open=Open" fullword wide
      $s11 = "shell\\Open\\Default=1" fullword wide
      $s12 = "qualquercoisarsrsr" fullword wide
      $s13 = "TGetPlugin" fullword ascii
      $s14 = "TUnitInfectUSB" fullword ascii
      $s15 = "gsegtsrgrefsfsfsgrsgrt" fullword wide
      $s16 = "<FONT COLOR=\"red\">[Clipboard End]</font>" fullword wide
      $s17 = "STARTSERVERBUFFER" fullword wide
      $s18 = "action=Open folder to view files" fullword wide
      $s19 = "%SERVER%" fullword ascii
      $s20 = "OThreadUnit" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and pe.imphash() == "54d337e45f6015e5ce82372bfb9e9750" and ( 8 of them )
      ) or ( all of them )
}

rule YARA_MAL_ASyncRAT {
   meta:
      description = "ASyncRAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "b4fba2298f53e45e0062b8d7fd0767f7cab05da4c8c3cef8b2a60e0b81456d51"
   strings:
      $s1 = "AsyncRAT-Client.exe" fullword wide
      $s2 = "system.exe" fullword wide
      $s3 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii
      $s4 = "AES_Encryptor" fullword ascii
      $s5 = "/C choice /C Y /N /D Y /T 1 & Del " fullword wide
      $s6 = "AES_Decryptor" fullword ascii
      $s7 = "My.Computer" fullword ascii
      $s8 = "MyTemplate" fullword ascii
      $s09 = "AsyncRAT-Client" fullword ascii
      $s10 = "m_MyWebServicesObjectProvider" fullword ascii
      $s11 = "m_ComputerObjectProvider" fullword ascii
      $s12 = "AsyncRAT v1.9" fullword wide
      $s13 = "ThreadSafeObjectProvider`1" fullword ascii
      $s14 = "PacketHeader" fullword ascii
      $s15 = "m_UserObjectProvider" fullword ascii
      $s16 = "m_ThreadStaticValue" fullword ascii
      $s17 = "AsyncRAT" fullword ascii
      $s18 = "RemoteDesktopOpen" fullword ascii
      $s19 = "RemoteDesktopSend" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 60KB and
      9 of them
}

rule YARA_MAL_StoneDrill {
   meta:
      description = "StoneDrill variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "a217eb149b65552e3127c65c306aa521dca54959ceee89e85dd2e6e38c0d8f8b"
   strings:
      $x1 = "6QBM7io+rMH93E+XIqiM1k+Wm4usaH4345lJ4bg/sZzm41sQ5ydxbQcyXW21H2FzYGbQU+94bXXqyuGA3arhhfrkgdt1veYv8/m+l9u1MUC39Ud0KhQ2x764FQRO/oBr" wide
      $s2 = "FQMT4JLomOypw6DSq9yp7IIpWyJSJmMNbtyl1aHkiumb4pLmo82u3KXVoeSK6Zvikuajza7cpdWh5Irpm2ISZiM/PZXeriZaZ+PZn6MKLuwn7CIy1iHgHPwk53PTXNE1" wide
      $s3 = "lSystem.Resources.ResourceReader, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii
      $s4 = "wmi service.exe" fullword wide
      $s5 = "\\Google\\Google_update.exe" fullword wide
      $s6 = "Unable to save report to file - {0}" fullword wide
      $s7 = "\\Google_update.exe" fullword wide
      $s8 = "{0} has encountered a problem - {1}." fullword wide
      $s9 = "CryptoObfuscatorHelper.MyExceptionReporting.ExceptionReportingConsentForm.resources" fullword ascii
      $s10 = "Is64BitProcess" fullword wide
      $s11 = "get_TargetSite" fullword wide
      $s12 = "http://localhost:3030/Service.asmx" fullword wide
      $s13 = "wireshark" fullword wide
      $s14 = "runpppee.oei" fullword wide
      $s15 = "get_c1f8c4ff1f81c7ce990929abc8acba3e0" fullword ascii
      $s16 = "get_c370155bebcff11b28f0f0b911b4a8dad" fullword ascii
      $s17 = "{0} Automatic Error Reporting" fullword wide
      $s18 = "Exception Report (*.exr)|*.exr" fullword wide
      $s19 = "Send Error Report" fullword wide
      $s20 = "Exception reporting service URL not specified." fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and 4 of them
}

rule YARA_MAL_AdwindRAT_1 {
   meta:
      description = "AdwindRAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "3a05f3506ee8eb1ee0ac0e3062b5943240c4e9dd0efaeab2368d194dee0dbf82"
   strings:
      $s1 = "ibun/FakemaRonixav.classPK" fullword ascii
      $s2 = "ibun/FakemaRonixav.classUP" fullword ascii
      $s3 = "guha/JarepEgagizar" fullword ascii
      $s4 = "guha/ZoqeNubihiyap" fullword ascii
      $s5 = "guha/ZoqeNubihiyapPK" fullword ascii
      $s6 = "guha/JarepEgagizarPK" fullword ascii
      $s7 = "ugzJ$CoJ\"S" fullword ascii
      $s8 = "J -P&Z" fullword ascii
      $s9 = "$ /QcK" fullword ascii
      $s10 = "=intHBt#}v" fullword ascii
      $s11 = "gQfafV\"P" fullword ascii
      $s12 = "wFepik3" fullword ascii
      $s13 = "guha/AguwujuPK" fullword ascii
      $s14 = "guha/OvanojaPK" fullword ascii
      $s15 = "guha/Orocuje" fullword ascii
      $s16 = "}_mbTA+0>" fullword ascii
      $s17 = "guha/Uciwujo" fullword ascii
      $s18 = "^JwzkJC_Ob" fullword ascii
      $s19 = "&pQYrV^W~:" fullword ascii
      $s20 = "5mVFQenNH" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      8 of them
}

rule YARA_MAL_AdwindRAT_2 {
   meta:
      description = "AdwindRAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "e9cb6906a9ffbe6b0f16e708ba726d34e91229e75019cd22051ab0fd0ac9fd67"
   strings:
      $s1 = "eririwunoqe/gezadeyaqa/VaqeTuzaregApipEdazol.class" fullword ascii
      $s2 = "eririwunoqe/gezadeyaqa/VaqeTuzaregApipEdazol.classPK" fullword ascii
      $s3 = "eririwunoqe/gezadeyaqa/ZuzoperAwawAviqewawos.classm" fullword ascii
      $s4 = "eririwunoqe/gezadeyaqa/ZuzoperAwawAviqewawos.classPK" fullword ascii
      $s5 = "eririwunoqe/gezadeyaqa/VifaqufezeJapiCeqagoq" fullword ascii
      $s6 = "eririwunoqe/gezadeyaqa/WuwaYuzerEkagicEgasog" fullword ascii
      $s7 = "eririwunoqe/gezadeyaqa/VifaqufezeJapiCeqagoqPK" fullword ascii
      $s8 = "eririwunoqe/gezadeyaqa/WuwaYuzerEkagicEgasogPK" fullword ascii
      $s9 = "eririwunoqe/gezadeyaqa/AbijEcenOqalePK" fullword ascii
      $s10 = "eririwunoqe/gezadeyaqa/EwevawinuqelaPK" fullword ascii
      $s11 = "eririwunoqe/gezadeyaqa/AcomefAnuqalo.class}RkO" fullword ascii
      $s12 = "eririwunoqe/gezadeyaqa/Ewevawinuqela" fullword ascii
      $s13 = "eririwunoqe/gezadeyaqa/AbijEcenOqale" fullword ascii
      $s14 = "eririwunoqe/gezadeyaqa/AcomefAnuqalo.classPK" fullword ascii
      $s15 = "k%jj:\"" fullword ascii
      $s16 = "VrUN2RNr" fullword ascii
      $s17 = "nq -V;4\"w)" fullword ascii
      $s18 = "eririwunoqe/gezadeyaqa/ZoxeQobageBarikEkarox.class" fullword ascii
      $s19 = "eririwunoqe/gezadeyaqa/KedehIyavApanIyenavoj.class" fullword ascii
      $s20 = "eririwunoqe/gezadeyaqa/PocoNoyaGefahIdeqajon.class" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      8 of them
}

rule YARA_MAL_AdwindRAT_3 {
   meta:
      description = "AdwindRAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "aed6abdcdf7873e7adb4434cc7831dde05cdf827ac25913907955e4b3e7ad469"
   strings:
      $s1 = "mega.downloadPK" fullword ascii
      $s2 = "mega.download" fullword ascii
      $s3 = "operational/Jrat.classPK" fullword ascii
      $s4 = "operational/JRat.classPK" fullword ascii
      $s5 = "operational/Jrat.class" fullword ascii
      $s6 = "operational/JRat.class" fullword ascii
      $s7 = "drop.box" fullword ascii
      $s8 = "drop.boxPK" fullword ascii
      $s9 = "operational/iiiiiiiiii.class" fullword ascii
      $s10 = "sky.drivePK" fullword ascii
      $s11 = "operational/iiiiiiiiii.classPK" fullword ascii
      $s12 = "w/manintheskymanintheskymanintheskymanintheskymanintheskymanintheskymmanintheskymanintheskymanintheskymanintheskyanintheskyy.cla" ascii
      $s13 = "w/manintheskymanintheskymanintheskymanintheskymanintheskymanintheskymmanintheskymanintheskymanintheskymanintheskyanintheskys.cla" ascii
      $s14 = "w/manintheskymanintheskymanintheskymanintheskymanintheskymanintheskymmanintheskymanintheskymanintheskymanintheskyanintheskyi.cla" ascii
      $s15 = "w/manintheskymanintheskymanintheskymanintheskymanintheskymanintheskymmanintheskymanintheskymanintheskymanintheskyanintheskyv.cla" ascii
      $s16 = "w/manintheskymanintheskymanintheskymanintheskymanintheskymanintheskymmanintheskymanintheskymanintheskymanintheskyanintheskyn.cla" ascii
      $s17 = "w/manintheskymanintheskymanintheskymanintheskymanintheskymanintheskymmanintheskymanintheskymanintheskymanintheskyanintheskyq.cla" ascii
      $s18 = "w/manintheskymanintheskymanintheskymanintheskymanintheskymanintheskymmanintheskymanintheskymanintheskymanintheskyanintheskyt.cla" ascii
      $s19 = "w/manintheskymanintheskymanintheskymanintheskymanintheskymanintheskymmanintheskymanintheskymanintheskymanintheskyanintheskyg.cla" ascii
      $s20 = "w/manintheskymanintheskymanintheskymanintheskymanintheskymanintheskymmanintheskymanintheskymanintheskymanintheskyanintheskyb.cla" ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 1000KB and
      8 of them
}

rule YARA_MAL_qRAT_1 {
   meta:
      description = "qRAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "3234e479b4a078580e8d47f8596b1ef508481fc86cf62a17692ac211fc51b427"
   strings:
      $s1 = "com/kryptol/kynurin/TchiUnheadPK" fullword ascii
      $s2 = "com/kryptol/kynurin/SyceeHostPK" fullword ascii
      $s3 = "com/kryptol/kynurin/TchiUnhead" fullword ascii
      $s4 = "com/kryptol/kynurin/HeldGetaPK" fullword ascii
      $s5 = "com/kryptol/kynurin/HeldGeta" fullword ascii
      $s6 = "com/kryptol/kynurin/SyceeHost" fullword ascii
      $s7 = "com/kryptol/bottonhook/Docimology.classPK" fullword ascii
      $s8 = "com/kryptol/bottonhook/Docimology.class" fullword ascii
      $s9 = "com/conuzee/toolmark/MaiusMagaPK" fullword ascii
      $s10 = "com/kryptol/bottonhook/RefuseDisaPK" fullword ascii
      $s11 = "com/kryptol/Nutshells.classPK" fullword ascii
      $s12 = "com/kryptol/kynurin/WhodUndeckPK" fullword ascii
      $s13 = "com/kryptol/bottonhook/BaktunSpinesPK" fullword ascii
      $s14 = "com/kryptol/bottonhook/BaktunSpines" fullword ascii
      $s15 = "com/conuzee/buckle/SmilerWrapupPK" fullword ascii
      $s16 = "com/kryptol/bottonhook/RefuseDisa" fullword ascii
      $s17 = "com/kryptol/bottonhook/ShnookJivingPK" fullword ascii
      $s18 = "com/kryptol/bottonhook/GreesUpbuoy" fullword ascii
      $s19 = "com/kryptol/kynurin/CondBabulsPK" fullword ascii
      $s20 = "com/conuzee/buckle/MerilAnseisPK" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      8 of them
}

rule YARA_MAL_qRAT_2 {
   meta:
      description = "qRAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "d51ecc4e22fcba24ff6a6fe144a2a1849bd66e3efbf041e4ef919caf081f5a5b"
   strings:
      $s1 = "com/quadrisect/ozonizes/SolnRune" fullword ascii
      $s2 = "com/quadrisect/ozonizes/SolnRunePK" fullword ascii
      $s3 = "com/concurbit/carlylian/HeadleAccoilPK" fullword ascii
      $s4 = "com/concurbit/carlylian/HeadleAccoil" fullword ascii
      $s5 = "com/quadrisect/spinally/WeanlyWistPK" fullword ascii
      $s6 = "com/concurbit/absconders/PiggRetPK" fullword ascii
      $s7 = "com/lavation/inflicted/PplSalsaPK" fullword ascii
      $s8 = "com/lavation/inflicted/FavelaNacryPK" fullword ascii
      $s9 = "com/quadrisect/ozonizes/SundraJesusPK" fullword ascii
      $s10 = "com/lavation/unleakable/GooFilazek" fullword ascii
      $s11 = "com/quadrisect/ozonizes/ChawedAquoPK" fullword ascii
      $s12 = "com/lavation/tolutation/GwenHoppet" fullword ascii
      $s13 = "com/concurbit/absconders/PiggRet" fullword ascii
      $s14 = "com/concurbit/absconders/BtuSteedPK" fullword ascii
      $s15 = "com/quadrisect/spinally/PilausBow" fullword ascii
      $s16 = "com/lavation/tolutation/MxdTachi" fullword ascii
      $s17 = "com/concurbit/absconders/LetoTressyPK" fullword ascii
      $s18 = "com/lavation/inflicted/SputeFeil" fullword ascii
      $s19 = "com/quadrisect/spinally/AwaSorbus" fullword ascii
      $s20 = "com/lavation/tolutation/TawnleOvis" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      8 of them
}

rule YARA_MAL_qRAT_3 {
   meta:
      description = "qRAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "dc3b3704007f752e7bdb540ddec22a44842ff7f9244285ec179b08494b8b8228"
   strings:
      $s1 = "com/leaned/unround/YgapoStonerPK" fullword ascii
      $s2 = "com/inadhesion/obduracies/KevilDeddPK" fullword ascii
      $s3 = "com/effeminate/synovias/EyedFrugPK" fullword ascii
      $s4 = "com/inadhesion/obduracies/KevilDedd" fullword ascii
      $s5 = "com/effeminate/synovias/EyedFrug" fullword ascii
      $s6 = "com/leaned/unround/YgapoStoner" fullword ascii
      $s7 = "com/inadhesion/obduracies/Tempestical.class}" fullword ascii
      $s8 = "com/inadhesion/obduracies/Tempestical.classPK" fullword ascii
      $s9 = "com/effeminate/Temporizers.classPK" fullword ascii
      $s10 = "com/effeminate/synovias/MuniteMuck" fullword ascii
      $s11 = "com/effeminate/synovias/GoyimDyed" fullword ascii
      $s12 = "com/effeminate/synovias/JebelRenovePK" fullword ascii
      $s13 = "com/leaned/cocoas/CoitusJabblePK" fullword ascii
      $s14 = "com/effeminate/rouens/BarsNugaePK" fullword ascii
      $s15 = "com/inadhesion/jovite/PneumaCruraPK" fullword ascii
      $s16 = "com/effeminate/rouens/SoordLuian{&;" fullword ascii
      $s17 = "com/effeminate/rouens/BrukeEmbarkPK" fullword ascii
      $s18 = "com/effeminate/synovias/SeedRebear" fullword ascii
      $s19 = "com/effeminate/synovias/MuniteMuckPK" fullword ascii
      $s20 = "com/effeminate/synovias/PeaApiinPK" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      8 of them
}

rule YARA_MAL_qRAT_4 {
   meta:
      description = "qRAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "0b51af2dce7c8b395221414c3c9c0beda97ca888fcb9c554b18bb4e04e6c2f62"
   strings:
      $s1 = "com/thrushy/sithence/SkeyMeetPK" fullword ascii
      $s2 = "com/thrushy/sithence/SkeyMeet" fullword ascii
      $s3 = "com/thrushy/quintal/WhelkWinderPK" fullword ascii
      $s4 = "com/cephen/choleras/MallusSalmin" fullword ascii
      $s5 = "com/cephen/choleras/AgenesMyxoma" fullword ascii
      $s6 = "com/cephen/choleras/MimicsGauntPK" fullword ascii
      $s7 = "com/cephen/choleras/PedaMoniedPK" fullword ascii
      $s8 = "com/thrushy/sithence/AtesKieranPK" fullword ascii
      $s9 = "com/thrushy/sithence/MadafuSokPK" fullword ascii
      $s10 = "com/thrushy/quintal/AscrySemsenPK" fullword ascii
      $s11 = "com/thrushy/sithence/MobRugousPK" fullword ascii
      $s12 = "com/cephen/choleras/BaboenProsalPK" fullword ascii
      $s13 = "com/thrushy/quintal/TwibilBabuPK" fullword ascii
      $s14 = "com/thrushy/sithence/JacentHayPK" fullword ascii
      $s15 = "com/thrushy/sithence/SattvaDuxPK" fullword ascii
      $s16 = "com/cephen/choleras/DingeeBythPK" fullword ascii
      $s17 = "com/cephen/choleras/MallusSalminPK" fullword ascii
      $s18 = "com/cephen/choleras/LacsIsoporPK" fullword ascii
      $s19 = "com/thrushy/quintal/DadoFuggedPK" fullword ascii
      $s20 = "com/cephen/choleras/SeizorShtgPK" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      8 of them
}

rule YARA_MAL_BitterRAT {
   meta:
      description = "BitterRAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "a241cfcd60942ea401d53d6e02ec3dfb5f92e8f4fda0aef032bee7bb5a344c35"
   strings:
      $s1 = "winsvc.exe" fullword wide
      $s2 = "<assemblyIdentity type=\"win32\" name=\"Microsoft.VC90.CRT\" version=\"9.0.21022.8\" processorArchitecture=\"x86\" publicKeyToke" ascii
      $s3 = "DINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGX" fullword ascii
      $s4 = "Windows Service Logs" fullword wide
      $s5 = "4, 1, 0, 0" fullword wide
      $s6 = "Microsoft Copyright (C) 2007" fullword wide
      $s7 = "3, Version 1.0" fullword wide
      $s8 = "EEEEEEEEEFFB" ascii
      $s9 = "EEEEEEEEEEFC" ascii
      $s10 = "EEEEEEEEEEFD" ascii
      $s11 = "EFEEEEEEEEEB" ascii
      $s12 = "1MDRU?PC:+GAPMQMDR:5GLBMUQ" fullword ascii
      $s13 = "DINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPAD" ascii
      $s14 = "UALAFMQR" fullword ascii
      $s15 = ",2:!SPPCLRTCPQGML" fullword ascii
      $s16 = "Copyright (C) 2018" fullword wide
      $s17 = "\"1fc8b3b9a1e18e3b\"></assemblyIdentity>" fullword ascii
      $s18 = "winsvc" fullword wide
      $s19 = ".PMBSAR,?KC" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      ( pe.imphash() == "bd150558e1c4c42b635d4a15b8209380" or 8 of them )
}

rule YARA_MAL_SandroRAT {
   meta:
      description = "SandroRAT variant used by suspected APT33 threat actor"
      tlp = "white"
      author = "Insikt Group, Recorded Future"
      ref = "Recorded Future blog: APT33 Doubling-Down on Commodity RATs"
      date = "2019-06-16"
      hash1 = "410b5f374059cc21b2c738a71957c97e4183d92580d1d48df887deece6d2f663"
    strings:
      $s1 = "res/layout/videoview.xml" fullword ascii
      $s2 = "res/layout/activity_main.xml" fullword ascii
      $s3 = "net.droidjack.server" fullword wide
      $s4 = "resources.arscPK" fullword ascii
      $s5 = "videoview" fullword ascii
      $s6 = "AndroidManifest.xmlPK" fullword ascii
      $s7 = "resources.arsc" fullword ascii
      $s8 = "res/layout/videoview.xmlm" fullword ascii
      $s9 = "res/layout/activity_main.xmlm" fullword ascii
      $s10 = "res/layout/activity_main.xmlPK" fullword ascii
      $s11 = "res/layout/videoview.xmlPK" fullword ascii
      $s12 = "META-INF/CERT.SF" fullword ascii
      $s13 = "META-INF/CERT.RSAPK" fullword ascii
      $s14 = "META-INF/CERT.SFPK" fullword ascii
      $s15 = "META-INF/CERT.RSA3hbqa" fullword ascii
      $s16 = "res/layout/cameraview.xml" fullword ascii
      $s17 = "cameraview" fullword ascii
      $s18 = "6FMHJ\"?'" fullword ascii
      $s19 = "blankImage" fullword ascii
      $s20 = "ic_launcher" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and filesize < 800KB and ( 8 of them )
      ) or ( all of them )
}
