# Core Commands

## 01 - Help Menu

```
(Empire) > help

┌Help Options───┬──────────────────────────────────────────────────────────────────────────────────────────────────────────┬────────────────────────────────────┐
│ Name          │ Description                                                                                              │ Usage                              │
├───────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────────────────────────────┤
│ admin         │ View admin menu                                                                                          │ admin                              │
├───────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────────────────────────────┤
│ agents        │ View all agents.                                                                                         │ agents                             │
├───────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────────────────────────────┤
│ connect       │ Connect to empire instance                                                                               │ connect [--config | -c] <host>     │
│               │                                                                                                          │ [--port=<p>] [--socketport=<sp>]   │
│               │                                                                                                          │ [--username=<u>] [--password=<pw>] │
├───────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────────────────────────────┤
│ credentials   │ Add/display credentials to/from the database.                                                            │ credentials                        │
├───────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────────────────────────────┤
│ disconnect    │ Disconnect from an empire instance                                                                       │ disconnect                         │
├───────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────────────────────────────┤
│ help          │ Display the help menu for the                                                                            │ help                               │
│               │ current menu                                                                                             │                                    │
├───────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────────────────────────────┤
│ interact      │ Interact with active agents.                                                                             │ interact <agent_name>              │
├───────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────────────────────────────┤
│ listeners     │ View all listeners.                                                                                      │ listeners                          │
├───────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────────────────────────────┤
│ plugins       │ View active plugins menu.                                                                                │ plugins                            │
├───────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────────────────────────────┤
│ resource      │ Run the Empire commands in the specified resource file. Provide the -p flag for a file selection prompt. │ resource <file>                    │
├───────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────────────────────────────┤
│ sponsors      │ List of Empire sponsors.                                                                                 │ sponsors                           │
├───────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────────────────────────────┤
│ usecredential │ View and edit an credential.                                                                             │ usecredential <cred_id>            │
├───────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────────────────────────────┤
│ uselisteners  │ Use an Empire listener.                                                                                  │ uselisteners <listener_name>       │
├───────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────────────────────────────┤
│ usemodule     │ Use an Empire module.                                                                                    │ usemodule <module_name>            │
│───────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────────────────────────────┤
│ useplugin     │ Use an Empire plugin.                                                                                    │ useplugin <plugin_name>            │
├───────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────────────────────────────┤
│ usestager     │ Use an Empire stager.                                                                                    │ usestager <stager_name>            │
└───────────────┴──────────────────────────────────────────────────────────────────────────────────────────────────────────┴────────────────────────────────────┘
```

## 02 - Usage

### 2.1 - Admin

#### 2.1.1 - Help Menu

```
(Empire) > admin
(Empire: admin) > help

┌Help Options──────────────┬──────────────────────────────────────────────────────────────┬─────────────────────────────────────────┐
│ Name                     │ Description                                                  │ Usage                                   │
├──────────────────────────┼──────────────────────────────────────────────────────────────┼─────────────────────────────────────────┤
│ add_notes                │ Add user notes (use quotes)                                  │ add_notes <notes>                       │
├──────────────────────────┼──────────────────────────────────────────────────────────────┼─────────────────────────────────────────┤
│ clear_notes              │ Clear user notes                                             │ clear_notes                             │
├──────────────────────────┼──────────────────────────────────────────────────────────────┼─────────────────────────────────────────┤
│ create_user              │ Create user account for Empire                               │ create_user <username> <password>       │
├──────────────────────────┼──────────────────────────────────────────────────────────────┼─────────────────────────────────────────┤
│ delete_malleable_profile │ Delete malleable c2 profile from the database                │ delete_malleable_profile <profile_name> │
├──────────────────────────┼──────────────────────────────────────────────────────────────┼─────────────────────────────────────────┤
│ disable_user             │ Disable user account for Empire                              │ disable_user <user_id>                  │
├──────────────────────────┼──────────────────────────────────────────────────────────────┼─────────────────────────────────────────┤
│ download                 │ Download a file from the server to /empire/client/downloads  │ download <filename>                     │
├──────────────────────────┼──────────────────────────────────────────────────────────────┼─────────────────────────────────────────┤
│ enable_user              │ Enable user account for Empire                               │ enable_user <user_id>                   │
├──────────────────────────┼──────────────────────────────────────────────────────────────┼─────────────────────────────────────────┤
│ help                     │ Display the help menu for the current menu                   │ help                                    │
├──────────────────────────┼──────────────────────────────────────────────────────────────┼─────────────────────────────────────────┤
│ keyword_obfuscation      │ Add key words to to be obfuscated from commands. Empire will │ keyword_obfuscation <keyword>           │
│                          │ generate a random word if no replacement word is provided.   │ [replacement]                           │
├──────────────────────────┼──────────────────────────────────────────────────────────────┼─────────────────────────────────────────┤
│ load_malleable_profile   │ Load malleable c2 profile to the database                    │ load_malleable_profile                  │
│                          │                                                              │ <profile_directory> [profile_category]  │
├──────────────────────────┼──────────────────────────────────────────────────────────────┼─────────────────────────────────────────┤
│ malleable_profile        │ View malleable c2 profile                                    │ malleable_profile <profile_name>        │
├──────────────────────────┼──────────────────────────────────────────────────────────────┼─────────────────────────────────────────┤
│ notes                    │ Display your notes                                           │ notes                                   │
├──────────────────────────┼──────────────────────────────────────────────────────────────┼─────────────────────────────────────────┤
│ obfuscate                │ Turn on obfuscate all future powershell commands run on all  │ obfuscate <obfucate_bool>               │
│                          │ agents.                                                      │                                         │
├──────────────────────────┼──────────────────────────────────────────────────────────────┼─────────────────────────────────────────┤
│ obfuscate_command        │ Set obfuscation technique to run for all future powershell   │ obfuscate_command <obfucation_type>     │
│                          │ commands run on all agents.                                  │                                         │
├──────────────────────────┼──────────────────────────────────────────────────────────────┼─────────────────────────────────────────┤
│ preobfuscate             │ Preobfuscate modules on the server.                          │ preobfuscate <force_reobfuscation>      │
│                          │                                                              │ <obfuscation_command>                   │
├──────────────────────────┼──────────────────────────────────────────────────────────────┼─────────────────────────────────────────┤
│ report                   │ Produce report CSV and log files: sessions.csv,              │ report                                  │
│                          │ credentials.csv, master.log                                  │                                         │
├──────────────────────────┼──────────────────────────────────────────────────────────────┼─────────────────────────────────────────┤
│ upload                   │ Upload a file to the server from /empire/client/downloads.   │ upload <file_directory>                 │
│                          │ Use '-p' for a file selection dialog.                        │                                         │
├──────────────────────────┼──────────────────────────────────────────────────────────────┼─────────────────────────────────────────┤
│ user_list                │ Display all Empire user accounts                             │ user_list                               │
└──────────────────────────┴──────────────────────────────────────────────────────────────┴─────────────────────────────────────────┘

(Empire: admin) >
```

### 2.2 - Shell Handler

TODO: Finish the rest of shell handler section

#### 2.2.1 - HTTP

```
(Empire) > uselistener http

 Author       @harmj0y                                                              
 Description  Starts a http[s] listener (PowerShell or Python) that uses a GET/POST 
              approach.                                                             
 Name         HTTP[S]                                                               


┌Record Options────┬─────────────────────────────────────┬──────────┬─────────────────────────────────────┐
│ Name             │ Value                               │ Required │ Description                         │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ BindIP           │ 0.0.0.0                             │ True     │ The IP to bind to on the control    │
│                  │                                     │          │ server.                             │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ CertPath         │                                     │ False    │ Certificate path for https          │
│                  │                                     │          │ listeners.                          │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ Cookie           │ xhToxHyaIgSGxfmJ                    │ False    │ Custom Cookie Name                  │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ DefaultDelay     │ 5                                   │ True     │ Agent delay/reach back interval (in │
│                  │                                     │          │ seconds).                           │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ DefaultJitter    │ 0.0                                 │ True     │ Jitter in agent reachback interval  │
│                  │                                     │          │ (0.0-1.0).                          │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ DefaultLostLimit │ 60                                  │ True     │ Number of missed checkins before    │
│                  │                                     │          │ exiting                             │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ DefaultProfile   │ /admin/get.php,/news.php,/login/pro │ True     │ Default communication profile for   │
│                  │ cess.php|Mozilla/5.0 (Windows NT    │          │ the agent.                          │
│                  │ 6.1; WOW64; Trident/7.0; rv:11.0)   │          │                                     │
│                  │ like Gecko                          │          │                                     │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ Headers          │ Server:Microsoft-IIS/7.5            │ True     │ Headers for the control server.     │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ Host             │                                     │ True     │ Hostname/IP for staging.            │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ JA3_Evasion      │ False                               │ True     │ Randomly generate a JA3/S signature │
│                  │                                     │          │ using TLS ciphers.                  │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ KillDate         │                                     │ False    │ Date for the listener to exit       │
│                  │                                     │          │ (MM/dd/yyyy).                       │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ Launcher         │ powershell -noP -sta -w 1 -enc      │ True     │ Launcher string.                    │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ Name             │ http                                │ True     │ Name for the listener.              │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ Port             │                                     │ True     │ Port for the listener.              │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ Proxy            │ default                             │ False    │ Proxy to use for request (default,  │
│                  │                                     │          │ none, or other).                    │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ ProxyCreds       │ default                             │ False    │ Proxy credentials                   │
│                  │                                     │          │ ([domain\]username:password) to use │
│                  │                                     │          │ for request (default, none, or      │
│                  │                                     │          │ other).                             │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ SlackURL         │                                     │ False    │ Your Slack Incoming Webhook URL to  │
│                  │                                     │          │ communicate with your Slack         │
│                  │                                     │          │ instance.                           │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ StagerURI        │                                     │ False    │ URI for the stager. Must use        │
│                  │                                     │          │ /download/. Example:                │
│                  │                                     │          │ /download/stager.php                │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ StagingKey       │ e|E!-{[fIiJ6FAnw;:V7p>?)DS.HkN/&    │ True     │ Staging key for initial agent       │
│                  │                                     │          │ negotiation.                        │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ UserAgent        │ default                             │ False    │ User-agent string to use for the    │
│                  │                                     │          │ staging request (default, none, or  │
│                  │                                     │          │ other).                             │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ WorkingHours     │                                     │ False    │ Hours for the agent to operate      │
│                  │                                     │          │ (09:00-17:00).                      │
└──────────────────┴─────────────────────────────────────┴──────────┴─────────────────────────────────────┘

(Empire: uselistener/http) >
```

#### 2.2.2 - Dropbox

```
(Empire) > uselistener dbx

 Author       @harmj0y                   
 Description  Starts a Dropbox listener. 
 Name         Dropbox                    


┌Record Options────┬─────────────────────────────────────┬──────────┬─────────────────────────────────────┐
│ Name             │ Value                               │ Required │ Description                         │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ APIToken         │                                     │ True     │ Authorization token for Dropbox API │
│                  │                                     │          │ communication.                      │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ BaseFolder       │ /Empire/                            │ True     │ The base Dropbox folder to use for  │
│                  │                                     │          │ comms.                              │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ DefaultDelay     │ 60                                  │ True     │ Agent delay/reach back interval (in │
│                  │                                     │          │ seconds).                           │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ DefaultJitter    │ 0.0                                 │ True     │ Jitter in agent reachback interval  │
│                  │                                     │          │ (0.0-1.0).                          │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ DefaultLostLimit │ 10                                  │ True     │ Number of missed checkins before    │
│                  │                                     │          │ exiting                             │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ DefaultProfile   │ /admin/get.php,/news.php,/login/pro │ True     │ Default communication profile for   │
│                  │ cess.php|Mozilla/5.0 (Windows NT    │          │ the agent.                          │
│                  │ 6.1; WOW64; Trident/7.0; rv:11.0)   │          │                                     │
│                  │ like Gecko                          │          │                                     │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ KillDate         │                                     │ False    │ Date for the listener to exit       │
│                  │                                     │          │ (MM/dd/yyyy).                       │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ Launcher         │ powershell -noP -sta -w 1 -enc      │ True     │ Launcher string.                    │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ Name             │ dropbox                             │ True     │ Name for the listener.              │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ PollInterval     │ 5                                   │ True     │ Polling interval (in seconds) to    │
│                  │                                     │          │ communicate with the Dropbox        │
│                  │                                     │          │ Server.                             │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ ResultsFolder    │ /results/                           │ True     │ The nested Dropbox results folder.  │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ SlackURL         │                                     │ False    │ Your Slack Incoming Webhook URL to  │
│                  │                                     │          │ communicate with your Slack         │
│                  │                                     │          │ instance.                           │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ StagingFolder    │ /staging/                           │ True     │ The nested Dropbox staging folder.  │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ StagingKey       │ e|E!-{[fIiJ6FAnw;:V7p>?)DS.HkN/&    │ True     │ Staging key for initial agent       │
│                  │                                     │          │ negotiation.                        │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ TaskingsFolder   │ /taskings/                          │ True     │ The nested Dropbox taskings folder. │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ WorkingHours     │                                     │ False    │ Hours for the agent to operate      │
│                  │                                     │          │ (09:00-17:00).                      │
└──────────────────┴─────────────────────────────────────┴──────────┴─────────────────────────────────────┘

(Empire: uselistener/dbx) >
```

#### 2.2.3 - OneDrive

### 2.3 - Generate Payloads

#### 2.3.1 - Windows

##### 2.3.1.1 - Shellcode

* **UseStager**

```
(Empire) > usestager windows/shellcode

 Author       @xorrior
              @monogas
 Description  Generate a windows shellcode stager
 Name         windows/shellcode


┌Record Options────┬────────────────────┬──────────┬─────────────────────────────────────┐
│ Name             │ Value              │ Required │ Description                         │
├──────────────────┼────────────────────┼──────────┼─────────────────────────────────────┤
│ Architecture     │ both               │ True     │ Architecture of the .dll to         │
│                  │                    │          │ generate (x64 or x86).              │
├──────────────────┼────────────────────┼──────────┼─────────────────────────────────────┤
│ Bypasses         │ mattifestation etw │ False    │ Bypasses as a space separated list  │
│                  │                    │          │ to be prepended to the launcher     │
├──────────────────┼────────────────────┼──────────┼─────────────────────────────────────┤
│ DotNetVersion    │ net40              │ True     │ Language of the stager to           │
│                  │                    │          │ generate(powershell, csharp).       │
├──────────────────┼────────────────────┼──────────┼─────────────────────────────────────┤
│ Language         │ powershell         │ True     │ Language of the stager to generate. │
├──────────────────┼────────────────────┼──────────┼─────────────────────────────────────┤
│ Listener         │                    │ True     │ Listener to generate stager for.    │
├──────────────────┼────────────────────┼──────────┼─────────────────────────────────────┤
│ Obfuscate        │ False              │ False    │ Switch. Obfuscate the launcher      │
│                  │                    │          │ powershell code, uses the           │
│                  │                    │          │ ObfuscateCommand for obfuscation    │
│                  │                    │          │ types. For powershell only.         │
├──────────────────┼────────────────────┼──────────┼─────────────────────────────────────┤
│ ObfuscateCommand │ Token\All\1        │ False    │ The Invoke-Obfuscation command to   │
│                  │                    │          │ use. Only used if Obfuscate switch  │
│                  │                    │          │ is True. For powershell only.       │
├──────────────────┼────────────────────┼──────────┼─────────────────────────────────────┤
│ OutFile          │ launcher.bin       │ True     │ Filename that should be used for    │
│                  │                    │          │ the generated output.               │
├──────────────────┼────────────────────┼──────────┼─────────────────────────────────────┤
│ Proxy            │ default            │ False    │ Proxy to use for request (default,  │
│                  │                    │          │ none, or other).                    │
├──────────────────┼────────────────────┼──────────┼─────────────────────────────────────┤
│ ProxyCreds       │ default            │ False    │ Proxy credentials                   │
│                  │                    │          │ ([domain\]username:password) to use │
│                  │                    │          │ for request (default, none, or      │
│                  │                    │          │ other).                             │
├──────────────────┼────────────────────┼──────────┼─────────────────────────────────────┤
│ StagerRetries    │ 0                  │ False    │ Times for the stager to retry       │
│                  │                    │          │ connecting.                         │
├──────────────────┼────────────────────┼──────────┼─────────────────────────────────────┤
│ UserAgent        │ default            │ False    │ User-agent string to use for the    │
│                  │                    │          │ staging request (default, none, or  │
│                  │                    │          │ other).                             │
└──────────────────┴────────────────────┴──────────┴─────────────────────────────────────┘

(Empire: usestager/windows/shellcode) > set Listener http_80
[*] Set Listener to http_80
(Empire: usestager/windows/shellcode) > execute
[+] launcher.bin written to /var/lib/powershell-empire/empire/client/generated-stagers/launcher.bin
```

* **MSFVenom**

```
(Empire) > usestager windows/reverseshell

(Empire: usestager/windows/reverseshell) > set Listener http_80
[*] Set Listener to http_80
```

##### 2.3.1.2 - Batch

`(Empire) > usestager windows/launcher_bat`

##### 2.3.1.3 - HTA

`(Empire) > usestager windows/launcher_hta`

##### 2.3.1.4 - EXE

TODO: Fill this info

* **UseStager**

CSharp payload

* **MSFVenom**

##### 2.3.1.5 - LNK

TODO: Fill this info

`(Empire) > usestager windows/launcher_lnk`

##### 2.3.1.6 - VBS

TODO: Fill this info

`(Empire) > usestager windows/launcher_vbs`

##### 2.3.1.7 - SCT

TODO: Fill this info

`(Empire) > usestager windows/launcher_sct`

##### 2.3.1.8 - WMIC

TODO: Fill this info

`(Empire) > usestager windows/wmic`

##### 2.3.1.9 - DLL

TODO: Fill this info

`(Empire) > usestager windows/dll`

##### 2.3.1.10 - XML

TODO: Fill this info

`(Empire) > usestager windows/launcher_xml`

#### 2.3.2 - OSX

##### 2.3.2.1 - Shellcode

TODO: Fill this info

`(Empire) > usestager osx/shellcode`

#### 2.3.3 - Multi

##### 2.3.3.1 - Bash

TODO: Fill this info

`(Empire) > usestager multi/bash`

### 2.4 - Agents

#### 2.4.1 - Help Menu

```
(Empire) > agents

┌Agents─────┬──────────┬─────────────┬──────────┬─────────┬─────┬───────┬───────────┬──────────┐
│ ID │ Name │ Language │ Internal IP │ Username │ Process │ PID │ Delay │ Last Seen │ Listener │
└────┴──────┴──────────┴─────────────┴──────────┴─────────┴─────┴───────┴───────────┴──────────┘

(Empire: agents) > help

┌Help Options───────────────────────────────────────────────────────┬──────────────────────────────────────┐
│ Name   │ Description                                              │ Usage                                │
├────────┼──────────────────────────────────────────────────────────┼──────────────────────────────────────┤
│ clear  │ Clear tasks for selected listener                        │ clear <agent_name>                   │
├────────┼──────────────────────────────────────────────────────────┼──────────────────────────────────────┤
│ help   │ Display the help menu for the current menu               │ help                                 │
├────────┼──────────────────────────────────────────────────────────┼──────────────────────────────────────┤
│ kill   │ Kills and removes specified agent [agent_name, stale, or │ kill <agent_name>                    │
│        │ all].                                                    │                                      │
├────────┼──────────────────────────────────────────────────────────┼──────────────────────────────────────┤
│ list   │ Get running/available agents                             │ list                                 │
├────────┼──────────────────────────────────────────────────────────┼──────────────────────────────────────┤
│ rename │ Rename selected listener                                 │ rename <agent_name> <new_agent_name> │
└────────┴──────────────────────────────────────────────────────────┴──────────────────────────────────────┘
```

## 03 - Credentials Database

### 3.1 - Add Credentials Manually

#### 3.1.1 - Help Menu

```
(Empire) > usecredential add

┌Record Options────┬──────────┬───────────────────────────────┐
│ Name     │ Value │ Required │ Description                   │
├──────────┼───────┼──────────┼───────────────────────────────┤
│ credtype │       │ True     │ Must be one of "plaintext" or │
│          │       │          │ "hash"                        │
├──────────┼───────┼──────────┼───────────────────────────────┤
│ domain   │       │ True     │                               │
├──────────┼───────┼──────────┼───────────────────────────────┤
│ username │       │ True     │                               │
├──────────┼───────┼──────────┼───────────────────────────────┤
│ host     │       │ True     │                               │
├──────────┼───────┼──────────┼───────────────────────────────┤
│ password │       │ True     │                               │
├──────────┼───────┼──────────┼───────────────────────────────┤
│ sid      │       │ False    │                               │
├──────────┼───────┼──────────┼───────────────────────────────┤
│ os       │       │ False    │                               │
├──────────┼───────┼──────────┼───────────────────────────────┤
│ notes    │       │ False    │                               │
└──────────┴───────┴──────────┴───────────────────────────────┘
```

#### 3.1.2 - Usage

`(Empire: usecredential/add) > set credtype <plaintext | hash>`

`(Empire: usecredential/add) > set domain <domain_name>`

`(Empire: usecredential/add) > set username <username>`

`(Empire: usecredential/add) > set password <password>`

`(Empire: usecredential/add) > set host <target_IP>`

`(Empire: usecredential/add) > execute`

### 3.2 - Manage Credentials

#### 3.2.1 - Help Menu

```
(Empire: credentials) > help

┌Help Options─────────────────────────────────────────────────────────┬──────────────────┐
│ Name   │ Description                                                │ Usage            │
├────────┼────────────────────────────────────────────────────────────┼──────────────────┤
│ help   │ Display the help menu for the current menu                 │ help             │
├────────┼────────────────────────────────────────────────────────────┼──────────────────┤
│ list   │ Get running/available agents                               │ list             │
├────────┼────────────────────────────────────────────────────────────┼──────────────────┤
│ remove │ Removes specified credential ID. if 'all' is provided, all │ remove <cred_id> │
│        │ credentials will be removed.                               │                  │
└────────┴────────────────────────────────────────────────────────────┴──────────────────┘
```

#### 3.2.2 - Usage

* **List the credentials**

```
(Empire: usecredential/add) > list

┌Credentials─────┬────────┬───────────────┬──────────────┬───────────────┬─────┬────┬───────┐
│ ID │ CredType  │ Domain │ UserName      │ Host         │ Password/Hash │ SID │ OS │ Notes │
├────┼───────────┼────────┼───────────────┼──────────────┼───────────────┼─────┼────┼───────┤
│ 1  │ plaintext │ DEMO   │ Administrator │ 192.168.0.15 │ Password      │     │    │       │
└────┴───────────┴────────┴───────────────┴──────────────┴───────────────┴─────┴────┴───────┘
```

* **Remove credential**

```
(Empire: credentials) > remove 1
[*] Credential 1 removed.
```