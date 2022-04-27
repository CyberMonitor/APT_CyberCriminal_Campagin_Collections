rule macro_GandCrab_Ursnif_dropper_2019_Q1 : TAU Trojan Ecrime Ransomware
{
	meta:
		author = "Carbon Black TAU" //jmyers
		date = "2019-Jan-14"
		description = "Designed to catch PowerShell encoded command in Word Shape box as alternative text"
		link = ""
		rule_version = 1
		yara_version = "3.7.0"
		Confidence = "Prod"
		Priority = "Medium"
		TLP = "White"
		exemplar_hashes = "0a3f915dd071e862046949885043b3ba61100b946cbc0d84ef7c44d77a50f080,cc5a14ff026ee593d7d25f213715b73833e6b9cf71091317121a009d5ad7fc36"
	strings:
		$s1 = "powershell.exe -NoP -Exec Bypass -EC " wide
	condition:
		all of them and 
		uint16(0) == 0xCFD0
}

rule GandCrab_Ursnif_PowerShell_cradle_2019_Q1 : TAU TROJAN Ecrime Ransomware
{
		meta:
		author = "Carbon Black TAU" //jmyers
		date = "2019-Jan-14"
		description = "Designed to catch PowerShell cradle from campaign"
		link = ""
		rule_version = 1
		yara_version = "3.7.0"
		Confidence = "Prod"
		Priority = "Medium"
		TLP = "White"
		exemplar_hashes = "3b59549507e0e3cfb4a363a306bf6eb4d26995066df643e1fc8e4e11eaffa7f9,debe4cb5645f10e6b6383838c25f26781a61acb536d2246cdf8dc33bbc1a2414"
	strings:
		$s1 = "If($ENV:PROCESSOR_ARCHITECTURE -contains 'AMD64')"
		$s2 = "$Env:WINDIR\\SysWOW64\\WindowsPowerShell"
		$s3 = "new-object net.webclient"
		$s4 = "downloadstring"
		$s5 = "Invoke"
		$s6 = "Sleep"
	condition:
		4 of ($s*) and 
		filesize < 2KB
}
