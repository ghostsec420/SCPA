# 02 - Process Manipulation

## 2.1 - List Processes

### 2.1.1 - Display Processes

`PS C:\> Get-Process`

`PS C:\> Get-Process -IncludeUserName`

## 2.2 - Terminate Processes

### 2.2.1 -Terminate Process

`PS C:\> Stop-Process notepad.exe`

## 2.3 - Fork Background Process

`PS C:\> Start-Process [-FilePath] <command> -NoNewWindow -ArgumentList ("arg_1","arg_2","arg_n") [-WorkingDirectory C:\path\to\directory]`