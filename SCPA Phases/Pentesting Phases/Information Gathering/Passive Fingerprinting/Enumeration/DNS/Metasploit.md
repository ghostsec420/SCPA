# Metasploit

## Subdomain Bruteforce and DNS Enumeration

```
msf > use auxiliary/gather/enum_dns

msf auxiliary(gather/enum_dns) > options

Module options (auxiliary/gather/enum_dns):

   Name         Current Setting                                              Required  Description
   ----         ---------------                                              --------  -----------
   DOMAIN                                                                    yes       The target domain
   ENUM_A       true                                                         yes       Enumerate DNS A record
   ENUM_AXFR    true                                                         yes       Initiate a zone transfer against each NS record
   ENUM_BRT     false                                                        yes       Brute force subdomains and hostnames via the supplied wordlist
   ENUM_CNAME   true                                                         yes       Enumerate DNS CNAME record
   ENUM_MX      true                                                         yes       Enumerate DNS MX record
   ENUM_NS      true                                                         yes       Enumerate DNS NS record
   ENUM_RVL     false                                                        yes       Reverse lookup a range of IP addresses
   ENUM_SOA     true                                                         yes       Enumerate DNS SOA record
   ENUM_SRV     true                                                         yes       Enumerate the most common SRV records
   ENUM_TLD     false                                                        yes       Perform a TLD expansion by replacing the TLD with the IANA TLD list
   ENUM_TXT     true                                                         yes       Enumerate DNS TXT record
   IPRANGE                                                                   no        The target address range or CIDR identifier
   NS                                                                        no        Specify the nameservers to use for queries, space separated
   Proxies                                                                   no        A proxy chain of format type:host:port[,type:host:port][...]
   RPORT        53                                                           yes       The target port (TCP)
   SEARCHLIST                                                                no        DNS domain search list, comma separated
   STOP_WLDCRD  false                                                        yes       Stops bruteforce enumeration if wildcard resolution is detected
   THREADS      1                                                            no        Threads for ENUM_BRT
   WORDLIST     /usr/share/metasploit-framework/data/wordlists/namelist.txt  no        Wordlist of subdomains

msf auxiliary(gather/enum_dns) > run threads=10 [ns=<nameserver_IP_1>,<nameserver_IP_2>,<nameserver_IP_n>] domain=<website.com>
```