# 03 - Robots

## 3.1 - Manual

### 3.1.1 - Web Browser

Open your web browser and Navigate to `http[s]://<IP>/robots.txt` by entering it on the URL depending on what website you're targeting

### 3.1.2 - cURL

`$ curl -A <user_agent> http[s]://<IP>/robots.txt`

## 3.2 - Nmap

`$ nmap -p 80,443 --script http-robots.txt <IP>`

## 3.3 - Metasploit

```
msf > use auxiliary/scanner/http/robots_txt

msf auxiliary(scanner/http/robots_txt) > options

Module options (auxiliary/scanner/http/robots_txt):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   PATH     /                yes       The test path to find robots.txt file
   Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                    yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT    80               yes       The target port (TCP)
   SSL      false            no        Negotiate SSL/TLS for outgoing connections
   THREADS  1                yes       The number of concurrent threads (max one per host)
   VHOST                     no        HTTP server virtual host


View the full module info with the info, or info -d command.

msf auxiliary(scanner/http/robots_txt) > set path <uri_path>

msf auxiliary(scanner/http/robots_txt) > set threads 8

msf auxiliary(scanner/http/robots_txt) > set rhosts <target_IP>

msf auxiliary(scanner/http/robots_txt) > set rport <target_port>

msf auxiliary(scanner/http/robots_txt) > run
```