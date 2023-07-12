# FTP

## 01 -  Manual

### 1.1 - Usage

#### 1.1.1 - Authenticate FTP server

- **Basic Commands**

List files and directories including hidden ones

`ftp> ls -a`

Set file transfers mode as binary

`ftp> binary`

Set file transfers mode as ascii

`ftp> ascii`

Disconnect FTP server

`ftp> <exit | quit | bye>`

- **Login using startttls**

Install a sophisticated cli based FTP client in Debian-based distros

`$ sudo apt install lftp`

Install a sophisticated cli based FTP client in Arch Linux-based distros

`$ sudo pacman -S lftp`

```
$ lftp
lftp :~> set ftp:ssl-force true
lftp :~> set ssl:verify-certificate no
lftp :~> connect <IP>
lftp <IP>:~> login
Usage: login <user|URL> [<pass>]
```

- **Web browser connection**

`ftp://<username>:<password>@<IP>`

### 1.2 - Banner Grab

`$ nc -nv <IP> 21`

`$ telnet -n <IP> 21`

Retrieve a certificate if any

`$ openssl s_client -connect <IP>:21 -starttls ftp`

### 1.3 - Anonymous Login

Pass these credentials username: `anonymous` and password: `anonymous`

`$ ftp <IP>`

## 02 -  Nmap

### Nmap NSE Enumeration

`$ nmap -p 21 -sV --script ftp-anon,ftp-syst <IP>`

## 03 -  Metasploit

### 3.1 - Banner Grab

```
msf > use auxiliary/scanner/ftp/ftp_version

msf auxiliary(scanner/ftp/ftp_version) > options

Module options (auxiliary/scanner/ftp/ftp_version):

   Name     Current Setting      Required  Description 
   ----     ---------------      --------  ----------- 
   FTPPASS  mozilla@example.com  no        The password for the specified username 
   FTPUSER  anonymous            no        The username to authenticate as 
   RHOSTS                        yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT    21                   yes       The target port (TCP) 
   THREADS  1                    yes       The number of concurrent threads (max one per host)

msf auxiliary(scanner/ftp/ftp_version) > set rhosts <IP>

msf auxiliary(scanner/ftp/ftp_version) > set threads 8

msf auxiliary(scanner/ftp/ftp_version) > run
```

### 3.2 - Anonymous Login

```
msf > use auxiliary/scanner/ftp/anonymous

msf auxiliary(scanner/ftp/anonymous) > options

Module options (auxiliary/scanner/ftp/anonymous):

   Name     Current Setting      Required  Description
   ----     ---------------      --------  -----------
   FTPPASS  mozilla@example.com  no        The password for the specified username
   FTPUSER  anonymous            no        The username to authenticate as
   RHOSTS                        yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT    21                   yes       The target port (TCP)
   THREADS  1                    yes       The number of concurrent threads (max one per host)

msf auxiliary(scanner/ftp/anonymous) > set rhosts <IP>

msf auxiliary(scanner/ftp/anonymous) > set threads 4

msf auxiliary(scanner/ftp/anonymous) > run -j
```

## References

- [Pentesting FTP](https://book.hacktricks.xyz/pentesting/pentesting-ftp)