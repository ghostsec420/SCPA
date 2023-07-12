# Metasploit

```
msf > use auxiliary/gather/searchengine_subdomains_collector

msf auxiliary(gather/searchengine_subdomains_collector) > options

Module options (auxiliary/gather/searchengine_subdomains_collector):

   Name        Current Setting  Required  Description
   ----        ---------------  --------  -----------
   ENUM_BING   true             yes       Enable Bing Search Subdomains
   ENUM_YAHOO  true             yes       Enable Yahoo Search Subdomains
   IP_SEARCH   true             no        Enable ip of subdomains to locate subdomains
   TARGET                       yes       The target to locate subdomains for, ex: rapid7.com, 8.8.8.8

msf auxiliary(gather/searchengine_subdomains_collector) > set target <website.com>

msf auxiliary(gather/searchengine_subdomains_collector) > set enum_bing <true | false>

msf auxiliary(gather/searchengine_subdomains_collector) > set enum_yahoo <true | false>

msf auxiliary(gather/searchengine_subdomains_collector) > set ip_search <true | false>

msf auxiliary(gather/searchengine_subdomains_collector) > run
```