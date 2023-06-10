# Metasploit

## Censys search auxiliary module

```
msf > use auxiliary/gather/censys_search

msf auxiliary(gather/censys_search) > options

Module options (auxiliary/gather/censys_search):

   Name               Current Setting  Required  Description
   ----               ---------------  --------  -----------
   CENSYS_DORK                         yes       The Censys Search Dork
   CENSYS_SEARCHTYPE  certificates     yes       The Censys Search Type (Accepted: certificates, ipv4, websites)
   CENSYS_SECRET                       yes       The Censys API SECRET
   CENSYS_UID                          yes       The Censys API UID

msf auxiliary(gather/censys_search) > set censys_dork <censys_dorks>

msf auxiliary(gather/censys_search) > set censys_searchtype <certificates | ipv4 | websites>

msf auxiliary(gather/censys_search) > set censys_secret <censys_secret_api_key>

msf auxiliary(gather/censys_search) > set censys_uid <censys_uid_api_key>

msf auxiliary(gather/censys_search) > run
```