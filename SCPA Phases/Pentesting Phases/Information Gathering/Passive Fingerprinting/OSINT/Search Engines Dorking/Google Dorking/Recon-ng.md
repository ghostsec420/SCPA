# Recon-ng

## Gathering other URLs

- **`google_site_web` recon-ng module**

```
[recon-ng][default] > marketplace install recon/domains-hosts/google_site_web

[recon-ng][default] > modules load recon/domains-hosts/google_site_web

[recon-ng][default][google_site_web] > options set SOURCE <domain.com>

[recon-ng][default][google_site_web] > back
```

## Discover sensitive information

- **`interesting_files` recon-ng module**

```
[recon-ng][default] > modules load discovery/info_disclosure/interesting_files

[recon-ng][default][interesting_files] > options list

  Name      Current Value                                           Required  Description
  --------  -------------                                           --------  -----------
  CSV_FILE  /home/user/.recon-ng/data/interesting_files_verify.csv  yes       custom filename map
  DOWNLOAD  True                                                    yes       download discovered files
  PORT      80                                                      yes       request port
  PROTOCOL  http                                                    yes       request protocol
  SOURCE    default                                                 yes       source of input (see 'info' for details)

[recon-ng][default][interesting_files] > options set SOURCE <domain.com>

[recon-ng][default][interesting_files] > run
```

## Google dorking with vulnerabilities

- **`ghdb` recon-ng module**

```
[recon-ng][default] > modules load recon/domains-vulnerabilities/ghdb

[recon-ng][default][ghdb] > options set DORKS <dork>

[recon-ng][default][ghdb] > options set GHDB_ADVISORIES_AND_VULNERABILITIES <True | False>

[recon-ng][default][ghdb] > options set GHDB_ERROR_MESSAGES <True | False>

[recon-ng][default][ghdb] > options set GHDB_FILES_CONTAINING_JUICY_INFO <True | False>

[recon-ng][default][ghdb] > options set GHDB_FILES_CONTAINING_PASSWORDS <True | False>

[recon-ng][default][ghdb] > options set GHDB_FILES_CONTAINING_USERNAMES <True | False>

[recon-ng][default][ghdb] > options set GHDB_FOOTHOLDS <True | False>

[recon-ng][default][ghdb] > options set GHDB_PAGES_CONTAINING_LOGIN_PORTALS <True | False>

[recon-ng][default][ghdb] > options set GHDB_SENSITIVE_DIRECTORIES <True | False>

[recon-ng][default][ghdb] > options set GHDB_SENSITIVE_ONLINE_SHOPPING_INFO <True | False>

[recon-ng][default][ghdb] > options set GHDB_VARIOUS_ONLINE_DEVICES <True | False>

[recon-ng][default][ghdb] > options set GHDB_VULNERABLE_FILES <True | False> 

[recon-ng][default][ghdb] > options set GHDB_VULNERABLE_SERVERS <True | False>

[recon-ng][default][ghdb] > options set GHDB_WEB_SERVER_DETECTION <True | False>

[recon-ng][default][ghdb] > options set SOURCE <domain.com>
```

## Resolve URLs with IPs

- **`resolve` recon-ng module**

```
[recon-ng][default] > marketplace install recon/hosts-hosts/resolve

[recon-ng][default] > modules load recon/hosts-hosts/resolve

[recon-ng][default][resolve] > run

[recon-ng][default][resolve] > back
```

## Reverse resolve netblocks

- **`reverse_resolve` recon-ng module**

```
[recon-ng][default] > modules load recon/netblocks-hosts/reverse_resolve

[recon-ng][default][reverse_resolve] > run
```