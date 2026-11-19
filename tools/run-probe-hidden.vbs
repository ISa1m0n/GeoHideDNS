' run-probe-hidden.vbs - запускает geohide-probe.ps1 без окна консоли.
'
' Планировщик стартует wscript.exe, а это GUI-приложение: окно не создаётся.
' Раньше в действии задачи стоял powershell.exe с -WindowStyle Hidden, но этот
' ключ срабатывает уже после создания консоли, поэтому окно успевало мигнуть
' и снять с фокуса игру в полноэкранном режиме. Здесь окно скрыто с самого
' создания процесса (второй аргумент Run = 0), дочерние curl и git наследуют
' скрытую консоль и своих окон тоже не открывают.
Option Explicit
Dim fso, sh, tools, root, cmd
Set fso = CreateObject("Scripting.FileSystemObject")
Set sh = CreateObject("WScript.Shell")
tools = fso.GetParentFolderName(WScript.ScriptFullName)
root = fso.GetParentFolderName(tools)
sh.CurrentDirectory = root
cmd = "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File """ & tools & "\geohide-probe.ps1"""
sh.Run cmd, 0, True
