# VNC

## 01 - Manual

### 1.1 - Usage

`$ vncviewer -help`

`$ vncviewer <IP>[::<PORT>]`

## 02 - Nmap

`$ nmap -p 5900 -sV --script vnc-info <IP>`

`$ nmap -p 5900 --script vnc-title <IP>`

## 03 - Metasploit

### 3.1 - Null Authentication

```
msf > use auxiliary/scanner/vnc/vnc_none_auth

msf auxiliary(scanner/vnc/vnc_none_auth) > options

Module options (auxiliary/scanner/vnc/vnc_none_auth):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   RHOSTS                    yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT    5900             yes       The target port (TCP)
   THREADS  1                yes       The number of concurrent threads (max one per host)

msf auxiliary(scanner/vnc/vnc_none_auth) > set rhosts <IP>

msf auxiliary(scanner/vnc/vnc_none_auth) > set threats 2

msf auxiliary(scanner/vnc/vnc_none_auth) > run
```

### 3.2 - Default Passwords

```
msf > use auxiliary/scanner/vnc/vnc_login

msf auxiliary(scanner/vnc/vnc_login) > options

Module options (auxiliary/scanner/vnc/vnc_login):

   Name              Current Setting                                   Required  Description 
   ----              ---------------                                   --------  ----------- 
   BLANK_PASSWORDS   false                                             no        Try blank passwords for all users 
   BRUTEFORCE_SPEED  5                                                 yes       How fast to bruteforce, from 0 to 5 
   DB_ALL_CREDS      false                                             no        Try each user/password couple stored in the current database 
   DB_ALL_PASS       false                                             no        Add all passwords in the current database to the list 
   DB_ALL_USERS      false                                             no        Add all users in the current database to the list 
   DB_SKIP_EXISTING  none                                              no        Skip existing credentials stored in the current database (Accepted: none, user, user&realm) 
   PASSWORD                                                            no        The password to test 
   PASS_FILE         /opt/metasploit/data/wordlists/vnc_passwords.txt  no        File containing passwords, one per line 
   Proxies                                                             no        A proxy chain of format type:host:port[,type:host:port][...] 
   RHOSTS                                                              yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit 
   RPORT             5900                                              yes       The target port (TCP) 
   STOP_ON_SUCCESS   false                                             yes       Stop guessing when a credential works for a host 
   THREADS           1                                                 yes       The number of concurrent threads (max one per host) 
   USERNAME          <BLANK>                                           no        A specific username to authenticate as 
   USERPASS_FILE                                                       no        File containing users and passwords separated by space, one pair per line 
   USER_AS_PASS      false                                             no        Try the username as the password for all users 
   USER_FILE                                                           no        File containing usernames, one per line 
   VERBOSE           true                                              yes       Whether to print output for all attempts

msf auxiliary(scanner/vnc/vnc_login) > set rhosts <IP>

msf auxiliary(scanner/vnc/vnc_login) > set pass_file </path/to/wordlist.txt>

msf auxiliary(scanner/vnc/vnc_login) > run
```