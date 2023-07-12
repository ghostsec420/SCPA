# 02 - Banner Grab

### 2.1 - Manual

#### 2.1.1 - Ncat

`$ echo "EXIT" | ncat <IP> 80`

**`$`** `printf "GET / HTTP/1.0\r\n\r\n" | ncat <IP> 80`

`$ printf "HEAD / HTTP/1.0\r\n\r\n" | ncat <IP> 80`

`$ echo "" | ncat -v <IP> 80`

* If it has a secure certificate that you see a protocol of HTTPS with a letter (s) add a flag `--ssl`

`$ printf "GET / HTTP/1.0\r\n\r\n" | ncat <IP> 443 --ssl`

#### 2.1.2 - cURL

`$ curl -A <user_agent> -s -I <IP> | grep -e "Server: "`

#### 2.1.3 - Wget

`$ wget -U <user_agent> <IP> -q -S`

### 2.2 - Metasploit

```
msf > use auxiliary/scanner/http/http_version

msf auxiliary(scanner/http/http_version) > options

Module options (auxiliary/scanner/http/http_version):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                    yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT    80               yes       The target port (TCP)
   SSL      false            no        Negotiate SSL/TLS for outgoing connections
   THREADS  1                yes       The number of concurrent threads (max one per host)
   VHOST                     no        HTTP server virtual host


View the full module info with the info, or info -d command.

msf auxiliary(scanner/http/http_version) > set threads 8

msf auxiliary(scanner/http/http_version) > set rhosts <target_IP>

msf auxiliary(scanner/http/http_version) > run
```