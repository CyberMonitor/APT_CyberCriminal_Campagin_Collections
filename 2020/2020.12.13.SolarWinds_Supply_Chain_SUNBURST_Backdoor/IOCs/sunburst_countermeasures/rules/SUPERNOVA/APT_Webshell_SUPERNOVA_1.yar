// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/sunburst_countermeasures/blob/main/LICENSE.txt
import "pe"

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