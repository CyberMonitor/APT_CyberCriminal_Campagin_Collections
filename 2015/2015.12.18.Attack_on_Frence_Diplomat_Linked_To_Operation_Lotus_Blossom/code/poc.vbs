function runshell()
  On Error Resume Next
  set shell=createobject("Shell.Application")
  shell.ShellExecute "notepad.exe"
end function
