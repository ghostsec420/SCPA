# Database Commands

## 01 - Help Menu

```
Database Backend Commands
=========================

    Command           Description
    -------           -----------
    analyze           Analyze database information about a specific address or address range
    db_connect        Connect to an existing data service
    db_disconnect     Disconnect from the current data service
    db_export         Export a file containing the contents of the database
    db_import         Import a scan result file (filetype will be auto-detected)
    db_nmap           Executes nmap and records the output automatically
    db_rebuild_cache  Rebuilds the database-stored module cache (deprecated)
    db_remove         Remove the saved data service entry
    db_save           Save the current data service connection as the default to reconnect on startup
    db_status         Show the current data service status
    hosts             List all hosts in the database
    klist             List Kerberos tickets in the database
    loot              List all loot in the database
    notes             List all notes in the database
    services          List all services in the database
    vulns             List all vulnerabilities in the database
    workspace         Switch between database workspaces
```

## 02 - Usage

### 2.1 - Workspace

#### 2.1.1 - Help Menu

`msf > workspace`

### 2.2 - Hosts

#### 2.2.1 - Help Menu

```
msf > hosts -h
Usage: hosts [ options ] [addr1 addr2 ...]


OPTIONS:

    -a, --add <host>                       Add the hosts instead of searching
    -c, --columns <columns>                Only show the given columns (see list below)
    -C, --columns-until-restart <columns>  Only show the given columns until the next restart (see list below)
    -d, --delete <hosts>                   Delete the hosts instead of searching
    -h, --help                             Show this help information
    -i, --info <info>                      Change the info of a host
    -m, --comment <comment>                Change the comment of a host
    -n, --name <name>                      Change the name of a host
    -O, --order <column id>                Order rows by specified column number
    -o, --output <filename>                Send output to a file in csv format
    -R, --rhosts                           Set RHOSTS from the results of the search
    -S, --search <filter>                  Search string to filter by
    -t, --tag                              Add or specify a tag to a range of hosts
    -u, --up                               Only show hosts which are up

Available columns: address, arch, comm, comments, created_at, cred_count, detected_arch, exploit_attempt_count, host_detail_count, info, mac, name, note_count, os_family, os_flavor, os_lang, os_name, os_sp, purpose, scope, service_count, state, updated_at, virtual_host, vuln_count, tags
```

#### 2.2.2 - Usage

```
msf > hosts

Hosts
=====

address    mac  name    os_name     os_flavor  os_sp  purpose  info  comments
-------    ---  ----    -------     ---------  -----  -------  ----  --------
10.0.2.15       DEFALT  Windows 10                    client

msf > hosts -c address,virtual_host,purpose,comm,state,scope,cred_count,exploit_attempt_count,host_detail_count,vuln_count,service_count --up -R
```

### 2.3 - Services

#### 2.3.1 - Help Menu

```
msf > services -h
Usage: services [-h] [-u] [-a] [-r <proto>] [-p <port1,port2>] [-s <name1,name2>] [-o <filename>] [addr1 addr2 ...]


OPTIONS:

    -a, --add                  Add the services instead of searching.
    -c, --column <col1,col2>   Only show the given columns.
    -d, --delete               Delete the services instead of searching.
    -h, --help                 Show this help information.
    -O, --order <column id>    Order rows by specified column number.
    -o, --output <filename>    Send output to a file in csv format.
    -p, --port <ports>         Search for a list of ports.
    -r, --protocol <protocol>  Protocol type of the service being added [tcp|udp].
    -R, --rhosts               Set RHOSTS from the results of the search.
    -s, --name <name>          Name of the service to add.
    -S, --search <filter>      Search string to filter by.
    -u, --up                   Only show services which are up.
    -U, --update               Update data for existing service.

Available columns: created_at, info, name, port, proto, state, updated_at
```

#### 2.3.2 - Usage

```
msf > services
Services
========

host       port  proto  name  state  info
----       ----  -----  ----  -----  ----
10.0.2.15  445   tcp    smb   open
```

### 2.4 - Loot

#### 2.4.1 - Help Menu

```
msf > loot -h
Usage: loot [options]
 Info: loot [-h] [addr1 addr2 ...] [-t <type1,type2>]
  Add: loot -f [fname] -i [info] -a [addr1 addr2 ...] -t [type]
  Del: loot -d [addr1 addr2 ...]


OPTIONS:

    -a, --add                 Add loot to the list of addresses, instead of listing.
    -d, --delete              Delete *all* loot matching host and type.
    -f, --file <filename>     File with contents of the loot to add.
    -h, --help                Show this help information.
    -i, --info <info>         Info of the loot to add.
    -S, --search <filter>     Search string to filter by.
    -t, --type <type1,type2>  Search for a list of types.
    -u, --update              Update loot. Not officially supported.
```

#### 2.4.2 - Usage

```
msf > loot

Loot
====

host       service  type            name               content     info            path
----       -------  ----            ----               -------     ----            ----
10.0.2.15           windows.hashes  DEFALT_hashes.txt  text/plain  Windows Hashes  /root/.msf4/loot/20220514174809_default_10.0.2.15_windows.hashes_764891.txt
```

### 2.5 - Credentials

#### 2.5.1 - Help Menu

```
Credentials Backend Commands
============================

    Command       Description
    -------       -----------
    creds         List all credentials in the database

msf > creds -h

With no sub-command, list credentials. If an address range is
given, show only credentials with logins on hosts within that
range.

Usage - Listing credentials:
  creds [filter options] [address range]

Usage - Adding credentials:
  creds add uses the following named parameters.
    user      :  Public, usually a username
    password  :  Private, private_type Password.
    ntlm      :  Private, private_type NTLM Hash.
    postgres  :  Private, private_type postgres MD5
    ssh-key   :  Private, private_type SSH key, must be a file path.
    hash      :  Private, private_type Nonreplayable hash
    jtr       :  Private, private_type John the Ripper hash type.
    realm     :  Realm, 
    realm-type:  Realm, realm_type (domain db2db sid pgdb rsync wildcard), defaults to domain.

Examples: Adding
   # Add a user, password and realm
   creds add user:admin password:notpassword realm:workgroup
   # Add a user and password
   creds add user:guest password:'guest password'
   # Add a password
   creds add password:'password without username'
   # Add a user with an NTLMHash
   creds add user:admin ntlm:E2FC15074BF7751DD408E6B105741864:A1074A69B1BDE45403AB680504BBDD1A
   # Add a NTLMHash
   creds add ntlm:E2FC15074BF7751DD408E6B105741864:A1074A69B1BDE45403AB680504BBDD1A
   # Add a Postgres MD5
   creds add user:postgres postgres:md5be86a79bf2043622d58d5453c47d4860
   # Add a user with an SSH key
   creds add user:sshadmin ssh-key:/path/to/id_rsa
   # Add a user and a NonReplayableHash
   creds add user:other hash:d19c32489b870735b5f587d76b934283 jtr:md5
   # Add a NonReplayableHash
   creds add hash:d19c32489b870735b5f587d76b934283

General options
  -h,--help             Show this help information
  -o <file>             Send output to a file in csv/jtr (john the ripper) format.
                        If file name ends in '.jtr', that format will be used.
                        If file name ends in '.hcat', the hashcat format will be used.
                        csv by default.
  -d,--delete           Delete one or more credentials

Filter options for listing
  -P,--password <text>  List passwords that match this text
  -p,--port <portspec>  List creds with logins on services matching this port spec
  -s <svc names>        List creds matching comma-separated service names
  -u,--user <text>      List users that match this text
  -t,--type <type>      List creds of the specified type: password, ntlm, hash or any valid JtR format
  -O,--origins <IP>     List creds that match these origins
  -r,--realm <realm>    List creds that match this realm
  -R,--rhosts           Set RHOSTS from the results of the search
  -v,--verbose          Don't truncate long password hashes

Examples, John the Ripper hash types:
  Operating Systems (starts with)
    Blowfish ($2a$)   : bf
    BSDi     (_)      : bsdi
    DES               : des,crypt
    MD5      ($1$)    : md5
    SHA256   ($5$)    : sha256,crypt
    SHA512   ($6$)    : sha512,crypt
  Databases
    MSSQL             : mssql
    MSSQL 2005        : mssql05
    MSSQL 2012/2014   : mssql12
    MySQL < 4.1       : mysql
    MySQL >= 4.1      : mysql-sha1
    Oracle            : des,oracle
    Oracle 11         : raw-sha1,oracle11
    Oracle 11 (H type): dynamic_1506
    Oracle 12c        : oracle12c
    Postgres          : postgres,raw-md5

Examples, listing:
  creds               # Default, returns all credentials
  creds 1.2.3.4/24    # Return credentials with logins in this range
  creds -O 1.2.3.4/24 # Return credentials with origins in this range
  creds -p 22-25,445  # nmap port specification
  creds -s ssh,smb    # All creds associated with a login on SSH or SMB services
  creds -t ntlm       # All NTLM creds

Example, deleting:
  # Delete all SMB credentials
  creds -d -s smb
```

#### 2.5.2 - Usage

```
msf > creds
Credentials
===========

host       origin     service        public              private                                                            realm  private_type  JtR Format
----       ------     -------        ------              -------                                                            -----  ------------  ----------
10.0.2.15  10.0.2.15  445/tcp (smb)  WDAGUtilityAccount  aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0         NTLM hash     nt,lm
10.0.2.15  10.0.2.15  445/tcp (smb)  WDAGUtilityAccount  aad3b435b51404eeaad3b435b51404ee:4cd2a45742e6693f6416abf9e2982956         NTLM hash     nt,lm
10.0.2.15  10.0.2.15  445/tcp (smb)  Winpwn10            aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0         NTLM hash     nt,lm
10.0.2.15  10.0.2.15  445/tcp (smb)  Winpwn10            aad3b435b51404eeaad3b435b51404ee:8034586795ebaf0427cc3417ebea341c         NTLM hash     nt,lm
10.0.2.15  10.0.2.15  445/tcp (smb)  Administrator       aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0         NTLM hash     nt,lm
10.0.2.15  10.0.2.15  445/tcp (smb)  DefaultAccount      aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0         NTLM hash     nt,lm
10.0.2.15  10.0.2.15  445/tcp (smb)  Guest               aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0         NTLM hash     nt,lm
10.0.2.15  10.0.2.15  445/tcp (smb)  administrator       aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0         NTLM hash     nt,lm
10.0.2.15  10.0.2.15  445/tcp (smb)  guest               aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0         NTLM hash     nt,lm
10.0.2.15  10.0.2.15  445/tcp (smb)  defaultaccount      aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0         NTLM hash     nt,lm
10.0.2.15  10.0.2.15  445/tcp (smb)  wdagutilityaccount  aad3b435b51404eeaad3b435b51404ee:4cd2a45742e6693f6416abf9e2982956         NTLM hash     nt,lm
10.0.2.15  10.0.2.15  445/tcp (smb)  winpwn10            aad3b435b51404eeaad3b435b51404ee:8034586795ebaf0427cc3417ebea341c         NTLM hash     nt,lm
```

## References

- [Metasploit for Pentester Database Workspace](https://www.hackingarticles.in/metasploit-for-pentester-database-workspace/)

- [Metasploit For Pentester Creds](https://www.hackingarticles.in/metasploit-for-pentester-creds/)