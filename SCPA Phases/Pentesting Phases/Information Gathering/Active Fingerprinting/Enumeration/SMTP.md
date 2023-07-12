# SMTP

## 01 - Manual

### 1.1 - Banner Grab or Establish Connection

#### 1.1.1 - SMTP

`$ nc -nv <IP> 25`

#### 1.1.2 - SMTPS (Secure protocol that contains SSL/TLS)

- For port 465 without the `starttls` command

`$ openssl s_client -crlf -connect <smtp_mail_server>:465`

- For port 587

`$ openssl s_client -starttls smtp -crlf -connect <smtp_mail_server>:587`

### 1.2 - Search for MX servers of an organization you're targeting

`$ dig +short mx <target.com>`

### 1.3 - NTLM Auth - Information Disclosure

```
$ telnet <ip> 587
220 <IP> SMTP Server Banner
>> HELO
250 <IP> Hello [x.x.x.x]
>> AUTH NTLM 334
NTLM supported
>> TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA=
334 TlRMTVNTUAACAAAACgAKADgAAAAFgooCBqqVKFrKPCMAAAAAAAAAAEgASABCAAAABgOAJQAAAA9JAEkAUwAwADEAAgAKAEkASQBTADAAMQABAAoASQBJAFMAMAAxAAQACgBJAEkAUwAwADEAAwAKAEkASQBTADAAMQAHAAgAHwMI0VPy1QEAAAAA
```

### 1.4 -Username Bruteforce Enumeration

**Note:** Authenticating with SMTP protocols is not often required

#### 1.4.1 - RCPT TO

```
$ telnet <IP> 25
Trying <IP>...
Connected to <IP>.
Escape character is '^]'
220 myhost ESMTP Sendmail 8.9.3
HELO x
250 myhost Hello [<another_IP>], pleased to meet you
MAIL FROM:test@test.org
250 2.1.0 test@test.org... Sender ok
RCPT TO:test
550 5.1.1 test... User unknown
RCPT TO:admin
550 5.1.1 admin... User unknown
RCPT TO:ed
250 2.1.5 ed... Recipient ok
```

#### 1.4.2 - VRFY

```
$ telnet <IP> 25
Trying <IP>...
Connected to <IP>.
Escape character is '^]'
220 myhost ESMTP Sendmail 8.9.3
HELO
501 HELO requires domain address
HELO x
250 myhost Hello [<another_IP>], pleased to meet you
VRFY root
250 Super-User <root@myhost>
VRFY blah
550 blah... User unknown
```

#### 1.4.3 - EXPN

```
$ telnet <IP> 25
Trying <IP>...
Connected to <IP>.
Escape character is '^]'
220 myhost ESMTP Sendmail 8.9.3
HELO
501 HELO requires domain address
HELO x
EXPN test
550 5.1.1 test... User unknown
EXPN root
250 2.1.5 <ed.williams@myhost>
EXPN sshd
250 2.1.5 sshd privsep <sshd@mail2>
```

### 02 - SMTP-User-Enum

`$ smtp-user-enum -M <MODE> -u <USER> -t <IP>`

## 03 - Nmap

### 3.1 - Nmap NSE Enumeration

`$ nmap -p 25 -Pn --script smtp-commands,smtp-strangeport <IP>`

`$ nmap -p 25 -Pn --script smtp-enum-users <IP>`

`$ nmap -p 587 -Pn --script smtp-ntlm-info <IP>`

## 04 - Metasploit

### 4.1 - Banner Grab

```
msf > use auxiliary/scanner/smtp/smtp_version

msf auxiliary(scanner/smtp/smtp_version) > options

Module options (auxiliary/scanner/smtp/smtp_version):

   Name     Current Setting  Required  Description 
   ----     ---------------  --------  ----------- 
   RHOSTS                    yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT    25               yes       The target port (TCP) 
   THREADS  1                yes       The number of concurrent threads (max one per host) 

msf auxiliary(scanner/smtp/smtp_version) > set rhosts <IP>

msf auxiliary(scanner/smtp/smtp_version) > set threads 10

msf auxiliary(scanner/smtp/smtp_version) > run
```

- **For domain controller**

```
msf > use auxiliary/scanner/smtp/smtp_ntlm_domain

msf auxiliary(scanner/smtp/smtp_ntlm_domain) > options

Module options (auxiliary/scanner/smtp/smtp_ntlm_domain):

   Name         Current Setting  Required  Description
   ----         ---------------  --------  -----------
   EHLO_DOMAIN  localhost        yes       The domain to send with the EHLO command
   RHOSTS                        yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT        25               yes       The target port (TCP)
   THREADS      1                yes       The number of concurrent threads (max one per host)

msf auxiliary(scanner/smtp/smtp_ntlm_domain) > set rhosts <IP>

msf auxiliary(scanner/smtp/smtp_ntlm_domain) > run
```

### 4.2 - Checking for open SMTP relays that can be used to create a spoofed email when planning a spear phishing attempt

```
msf > use auxiliary/scanner/smtp/smtp_relay

msf auxiliary(scanner/smtp/smtp_relay) > options

Module options (auxiliary/scanner/smtp/smtp_relay):

   Name      Current Setting     Required  Description
   ----      ---------------     --------  -----------
   EXTENDED  false               yes       Do all the 16 extended checks
   MAILFROM  sender@example.com  yes       FROM address of the e-mail
   MAILTO    target@example.com  yes       TO address of the e-mail
   RHOSTS                        yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT     25                  yes       The target port (TCP)
   THREADS   1                   yes       The number of concurrent threads (max one per host)

msf auxiliary(scanner/smtp/smtp_relay) > set rhosts <IP>

msf auxiliary(scanner/smtp/smtp_relay) > set mailfrom <sender_email@target.com>

msf auxiliary(scanner/smtp/smtp_relay) > set mailto <victim@target.com>

msf auxiliary(scanner/smtp/smtp_relay) > set threads 2 <IP>

msf auxiliary(scanner/smtp/smtp_relay) > set extended <true | false>

msf auxiliary(scanner/smtp/smtp_relay) > exploit -j
```

### 4.3 - Username Bruteforce Enumeration

```
msf > use auxiliary/scanner/smtp/smtp_enum

msf auxiliary(scanner/smtp/smtp_enum) > options

Module options (auxiliary/scanner/smtp/smtp_enum):

   Name       Current Setting                                                Required  Description
   ----       ---------------                                                --------  -----------
   RHOSTS                                                                    yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT      25                                                             yes       The target port (TCP)
   THREADS    1                                                              yes       The number of concurrent threads (max one per host)
   UNIXONLY   true                                                           yes       Skip Microsoft bannered servers when testing unix users
   USER_FILE  /usr/share/metasploit-framework/data/wordlists/unix_users.txt  yes       The file that contains a list of probable users accounts.

msf auxiliary(scanner/smtp/smtp_enum) > set rhosts <IP>

msf auxiliary(scanner/smtp/smtp_enum) > set threads 256

msf auxiliary(scanner/smtp/smtp_enum) > run
```

## References

- [Pentesting SMTP](https://book.hacktricks.xyz/pentesting/pentesting-smtp)

- [SMTP Commands](https://book.hacktricks.xyz/pentesting/pentesting-smtp/smtp-commands)