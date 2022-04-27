rule apt_RU_Delphocy_Maldocs {
  meta:
    desc = "Delphocy dropper docs"
    author = "JAG-S @ SentinelLabs"
    version = "1.0"
    TLP = "White"
    last_modified = "04.09.2021"
    hash1 = "3b548a851fb889d3cc84243eb8ce9cbf8a857c7d725a24408934c0d8342d5811"
    hash2 = "c213b60a63da80f960e7a7344f478eb1b72cee89fd0145361a088478c51b2c0e"
    hash3 = "d9e7325f266eda94bfa8b8938de7b7957734041a055b49b94af0627bd119c51c"
    hash4 = "1e8261104cbe4e09c19af7910f83e9545fd435483f24f60ec70c3186b98603cc"

  strings:
    $required1 = "_VBA_PROJECT" ascii wide
    $required2 = "Normal.dotm" ascii wide
    $required3 = "bin.base64" ascii wide
    $required4 = "ADODB.Stream$" ascii wide
    $author1 = "Dinara Tanmurzina" ascii wide
    $author2 = "Hewlett-Packard Company" ascii wide
    $specific = "Caption         =   \"\\wininition.exe\"" ascii wide
    $builder1 = "Begin {C62A69F0-16DC-11CE-9E98-00AA00574A4F} UserForm1" ascii wide
    $builder2 = "{02330CFE-305D-431C-93AC-29735EB37575}{33D6B9D9-9757-485A-89F4-4F27E5959B10}" ascii wide
    $builder3 = "VersionCompatible32=\"393222000\"" ascii wide
    $builder4 = "CMG=\"1517B95BC9F7CDF7CDF3D1F3D1\"" ascii wide
    $builder5 = "DPB=\"ADAF01C301461E461EB9E2471E616F01D06093C59A7C4D30F64A51BDEDDA98EC1590C9B191FF\"" ascii wide
    $builder6 = "GC=\"4547E96B19021A021A02\"" ascii wide

  condition:
    uint32(0) == 0xE011CFD0 and all of ($required*) and (all of ($author*) or $specific or 5 of ($builder*))
}