# 02 - SSL Server Test

## 2.1 - Recon-ng

- **`ssl_scan` recon-ng module**

```
[recon-ng][default] > marketplace install recon/ports-hosts/ssl_scan

[recon-ng][default] > modules load recon/ports-hosts/ssl_scan

[recon-ng][default][ssl_scan] > options set SOURCE <domain.com>:443

[recon-ng][default][ssl_scan] > options set SOURCE /path/to/urls.txt

[recon-ng][default][ssl_scan] > options set SOURCE query SELECT DISTINCT (host || ':' || '443') FROM hosts

[recon-ng][default][ssl_scan] > run

[recon-ng][default][ssl_scan] > back
```

- **`migrate_ports` recon-ng module**

```
[recon-ng][default] > marketplace install recon/ports-hosts/migrate_ports

[recon-ng][default] > modules load recon/ports-hosts/migrate_ports

[recon-ng][default][migrate_ports] > run

[recon-ng][default][migrate_ports] > back
```

## References

- [SSLTest](https://www.ssllabs.com/ssltest/)

- [SSLTools](https://ssltools.com/)