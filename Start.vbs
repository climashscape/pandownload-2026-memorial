Set WshShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
CurrentDir = fso.GetParentFolderName(WScript.ScriptFullName)

' Force change working directory
WshShell.CurrentDirectory = CurrentDir

' Kill existing processes first
WshShell.Run "taskkill /F /IM PanDownload.exe", 0, True
WshShell.Run "taskkill /F /IM python.exe", 0, True
WshShell.Run "taskkill /F /IM pythonw.exe", 0, True

' Run python with window HIDDEN (using window style 0)
' Note: We use python.exe (not pythonw) but tell WshShell to hide the window
PythonScriptPath = CurrentDir & "\pdproxy_bypass.py"
WshShell.Run "python """ & PythonScriptPath & """", 0, False

' Wait for proxy to initialize
WScript.Sleep 3000

' Start PanDownload
PanDownloadPath = CurrentDir & "\PanDownload\PanDownload.exe"
WshShell.Run """" & PanDownloadPath & """", 1, True

Set svc = GetObject("winmgmts:{impersonationLevel=impersonate}!\\.\root\cimv2")
For Each p In svc.ExecQuery("Select * from Win32_Process where Name='python.exe' or Name='pythonw.exe'")
  If InStr(1, p.CommandLine, PythonScriptPath, vbTextCompare) > 0 Or InStr(1, p.CommandLine, "pdproxy_bypass.py", vbTextCompare) > 0 Then
    p.Terminate()
  End If
Next

