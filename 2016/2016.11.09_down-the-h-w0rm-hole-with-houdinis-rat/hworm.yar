rule win_vbs_rat_hworm

{

    strings:

        $sa1 = "CONFIG"

        $sa2 = "MYCODE"

        $sa3 = "SHELLOBJ.EXPANDENVIRONMENTSTRINGS"

        $sa4 = "BASE64TOHEX"

        $sa5 = "DCOM.VIRTUALALLOC"

        $sa6 = "LOADER_"

        $sa7 = "PE_PTR"

        $sa8 = "OBJWMISERVICE.EXECQUERY"

        $sa9 = "WSCRIPT.EXE" nocase

        $sa10 = "FUNCTION"

        $sa11 = "DIM"

        $sa12 = "END SUB"

        $sb1 = "HOST_FILE"

        $sb2 = "FILE_NAME"

        $sb3 = "INSTALL_DIR"

        $sb4 = "START_UP_REG"

        $sb5 = "START_UP_TASK"

        $sb6 = "START_UP_FOLDER"

        $sc1 = "DCOM_DATA"

        $sc2 = "LOADER_DATA"

        $sc3 = "FILE_DATA"

        $sc4 = "(1)"

        $sc5 = "(2)"

        $sc6 = "(3)"

        $sc7 = "FILE_SIZE"

    condition:

                (all of ($sa*)) and ( (all of ($sb*)) or (all of ($sc*)) )

}

rule win_exe_rat_hworm

{

    strings:

                $sa1 = "connection_host" wide ascii

                $sa2 = "connection_port" wide ascii

                $sa3 = "install_folder" wide ascii

                $sa4 = "install_name" wide ascii

                $sa5 = "nickname_id" wide ascii

                $sa6 = "password" wide ascii

                $sa7 = "injection" wide ascii

                $sa8 = "startup_registry" wide ascii

                $sa9 = "startup_folder" wide ascii

                $sa10 = "startup_task" wide ascii

                $sa11 = "process_name" wide ascii

                $sa12 = "fkeylogger_host" wide ascii

                $sa13 = "fkeylogger_port" wide ascii

                $sa14 = "keylogger_init" wide ascii

                $sa15 = "keylogger_offline" wide ascii

                $sa16 = "file_manager" wide ascii

                $sa17 = "usb" wide ascii

                $sa18 = "password" wide ascii

                $sa19 = "filemanager" wide ascii

                $sa20 = "keylogger" wide ascii

                $sa21 = "screenshot" wide ascii

                $sa22 = "show" nocase wide ascii

                $sa23 = "open" wide ascii

                $sa25 = "create" wide ascii

                $sa26 = "Self" wide ascii

                $sa27 = "createsuspended" wide ascii

    condition:

                (uint16(0) == 0x5A4D) and (all of them)

}
