rule apt_RU_delphocy_encStrings {
  meta:
    desc = "Hex strings in Delphocy drops"
    author = "JAG-S @ SentinelLabs"
    version = "1.0"
    TLP = "White"
    last_modified = "04.09.2021"
    hash0 = "ee7cfc55a49b2e9825a393a94b0baad18ef5bfced67531382e572ef8a9ecda4b"
    hash1 = "07b2d21f4ef077ccf16935e44864b96fa039f2e88c73b518930b6048f6baad74"

  strings:
    $enc_keylogger2 = "5B4241434B53504143455D" ascii wide
    $enc_keylogger3 = "5B5441425D" ascii wide
    $enc_keylogger4 = "5B53484946545D" ascii wide
    $enc_keylogger5 = "5B434F4E54524F4C5D" ascii wide
    $enc_keylogger6 = "5B4553434150455D" ascii wide
    $enc_keylogger7 = "5B454E445D" ascii wide
    $enc_keylogger8 = "5B484F4D455D" ascii wide
    $enc_keylogger9 = "5B4C4546545D" ascii wide
    $enc_keylogger10 = "5B55505D" ascii wide
    $enc_keylogger11 = "5B52494748545D" ascii wide
    $enc_keylogger12 = "5B444F574E5D" ascii wide
    $enc_keylogger13 = "5B434150534C4F434B5D" ascii wide
    $cnc1 = "68747470733A2F2F7777772E786268702E636F6D2F646F6D696E61726772656174617369616E6F6479737365792F77702D636F6E74656E742F706C7567696E732F616B69736D65742F7374796C652E706870" ascii wide
    $cnc2 = "68747470733A2F2F7777772E63346373612E6F72672F696E636C756465732F736F75726365732F66656C696D732E706870" ascii wide

  condition:
    uint16(0) == 0x5a4d and (any of ($cnc*) or all of ($enc_keylogger*))
}