# Metasploit

TODO: Help me organize these modules to specific categories

```
msf > use auxiliary/scanner/http/scraper

msf auxiliary(scanner/http/scraper) > options

Module options (auxiliary/scanner/http/scraper):

   Name     Current Setting      Required  Description
   ----     ---------------      --------  -----------
   PATH     /                    yes       The test path to the page to analize
   PATTERN  <title>(.*)</title>  yes       The regex to use (default regex is a sample to grab page title)
   Proxies                       no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                        yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT    80                   yes       The target port (TCP)
   SSL      false                no        Negotiate SSL/TLS for outgoing connections
   THREADS  1                    yes       The number of concurrent threads (max one per host)
   VHOST                         no        HTTP server virtual host


View the full module info with the info, or info -d command.

msf auxiliary(scanner/http/scraper) > set path <uri_path>

msf auxiliary(scanner/http/scraper) > set pattern <regex>

msf auxiliary(scanner/http/scraper) > set threads 2

msf auxiliary(scanner/http/scraper) > set rhosts <target_IP_1>,<target_IP_2>,<target_IP_n>

msf auxiliary(scanner/http/scraper) > set rport <PORT>

msf auxiliary(scanner/http/scraper) > run
```

`msf > use auxiliary/scanner/http/http_hsts`

`msf > use auxiliary/scanner/http/title`

`msf > use auxiliary/scanner/http/http_header`

`msf > use auxiliary/scanner/http/host_header_injection`

`msf > use auxiliary/scanner/http/lucky_punch`

`msf > use auxiliary/scanner/http/verb_auth_bypass`

`msf > use auxiliary/scanner/http/open_proxy`

`msf > use auxiliary/scanner/http/options`

`msf > use auxiliary/scanner/http/enum_wayback`

`msf > use auxiliary/scanner/http/backup_file`

Apache Tomcat

`msf > use auxiliary/scanner/http/tomcat_enum`

Office 365

`msf > use auxiliary/gather/office365userenum`

`msf > use auxiliary/scanner/http/docker_version`

`msf > use auxiliary/scanner/http/git_scanner`

`msf > use auxiliary/scanner/http/svn_scanner`