# PostgreSQL

## 01 - Manual

TODO: Fill this information by referring to the references down below

### 1.1 - Usage

#### 1.1.1 - Authenticate

- **Local**

`$ psql -U <username>`

`$ psql -U <username> -W`

- **Remote**

`$ psql -h <IP> -U <username> -W`

`$ psql postgresql://<username>:<password>@<IP>:<PORT>/<database_name>`

### 1.2 - PostgreSQL Version

### 1.3 - Operating System

### 1.4 - Database

#### 1.4.1 - Retrieve Databases

#### 1.4.2 - Retrieve Tables

#### 1.4.3 - Hashdump

`postgres=# SELECT username, passwd FROM pg_shadow;`

## 02 - Nmap

`$ nmap -p 5432 <IP>`

## 03 - Metasploit

### 3.1 - Banner Grab

```
msf > use auxiliary/scanner/postgres/postgres_version

msf auxiliary(scanner/postgres/postgres_version) > options

Module options (auxiliary/scanner/postgres/postgres_version):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   DATABASE  template1        yes       The database to authenticate against
   PASSWORD  postgres         no        The password for the specified username. Leave blank for a random password.
   RHOSTS                     yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT     5432             yes       The target port
   THREADS   1                yes       The number of concurrent threads (max one per host)
   USERNAME  postgres         yes       The username to authenticate as
   VERBOSE   false            no        Enable verbose output

msf auxiliary(scanner/postgres/postgres_version) > set database <database_name>

msf auxiliary(scanner/postgres/postgres_version) > run postgres://<username>:<password>@<IP> threads=8
```

### 3.2 - SQL Queries

#### 3.2.1 - Schema

```
msf > use auxiliary/scanner/postgres/postgres_schemadump

msf auxiliary(scanner/postgres/postgres_schemadump) > options

Module options (auxiliary/scanner/postgres/postgres_schemadump):

   Name               Current Setting      Required  Description
   ----               ---------------      --------  -----------
   DATABASE           postgres             yes       The database to authenticate against
   DISPLAY_RESULTS    true                 yes       Display the Results to the Screen
   IGNORED_DATABASES  template1,template0  yes       Comma separated list of databases to ignore during the schema dump
   PASSWORD           postgres             no        The password for the specified username. Leave blank for a random password.
   RHOSTS                                  yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT              5432                 yes       The target port
   THREADS            1                    yes       The number of concurrent threads (max one per host)
   USERNAME           postgres             yes       The username to authenticate as

msf auxiliary(scanner/postgres/postgres_schemadump) > set database <database>

msf auxiliary(scanner/postgres/postgres_schemadump) > set ignored_databases <database1>,<database2>,<etc>

msf auxiliary(scanner/postgres/postgres_schemadump) > run postgres://<username>:<password>@<IP> threads=8
```

#### 3.2.2 - Read File

```
msf > use auxiliary/admin/postgres/postgres_readfile

msf auxiliary(admin/postgres/postgres_readfile) > options

Module options (auxiliary/admin/postgres/postgres_readfile):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   DATABASE  template1        yes       The database to authenticate against
   PASSWORD  postgres         no        The password for the specified username. Leave blank for a random password.
   RFILE     /etc/passwd      yes       The remote file
   RHOSTS                     yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT     5432             yes       The target port
   USERNAME  postgres         yes       The username to authenticate as
   VERBOSE   false            no        Enable verbose output

msf auxiliary(admin/postgres/postgres_readfile) > set database <database>

msf auxiliary(admin/postgres/postgres_readfile) > set rfile </path/to/file>

msf auxiliary(admin/postgres/postgres_readfile) > run postgres://<username>:<password>@<IP> threads=8
```

#### 3.2.3 - Hashdump

```
msf > use auxiliary/scanner/postgres/postgres_hashdump

msf auxiliary(scanner/postgres/postgres_hashdump) > options

Module options (auxiliary/scanner/postgres/postgres_hashdump):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   DATABASE  postgres         yes       The database to authenticate against
   PASSWORD  postgres         no        The password for the specified username. Leave blank for a random password.
   RHOSTS                     yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT     5432             yes       The target port
   THREADS   1                yes       The number of concurrent threads (max one per host)
   USERNAME  postgres         yes       The username to authenticate as

msf auxiliary(scanner/postgres/postgres_hashdump) > set database <database>

msf auxiliary(scanner/postgres/postgres_hashdump) > run postgres://<username>:<password>@<IP> threads=8
```

## References

- [A Penetration Testers guide to PostgreSQL](https://medium.com/@cryptocracker99/a-penetration-testers-guide-to-postgresql-d78954921ee9)

- [Ultimate guide PostgreSQL Pentesting](https://medium.com/@lordhorcrux_/ultimate-guide-postgresql-pentesting-989055d5551e)

- [Pentration Testing on PostgreSQL 5432](https://www.hackingarticles.in/penetration-testing-on-postgresql-5432/)

- [Pentest Wiki Database Assessment PostgreSQL](https://github.com/nixawk/pentest-wiki/blob/master/2.Vulnerability-Assessment/Database-Assessment/postgresql/postgresql_hacking.md)

- [Metasploit Unleashed: Admin Postgre Auxiliary Module](https://www.offsec.com/metasploit-unleashed/admin-postgres-auxiliary-modules/)