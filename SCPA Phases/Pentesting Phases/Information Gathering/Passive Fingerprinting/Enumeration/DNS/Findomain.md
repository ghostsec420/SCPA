# Findomain

## Setup

### Install Rust compiler

`$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`

`$ wget -qO - https://sh.rustup.rs | sh`

`$ source "$HOME/.cargo/env"`

### Clone the repository

```
$ git clone https://github.com/findomain/findomain.git && \
cd findomain && rustup default stable && cargo b -r &&
sudo cp target/release/findomain /usr/bin/
```

## Help Menu

```
$ findomain -h
Findomain 9.0.0
Eduard Tolosa <edu4rdshl@protonmail.com>
The fastest and cross-platform subdomain enumerator, do not waste your time.

USAGE:
    findomain [FLAGS] [OPTIONS]

FLAGS:
    -x, --as-resolver            Use Findomain as resolver for a list of domains in a file.
        --mtimeout               Allow Findomain to insert data in the database when the webhook returns a timeout
                                 error.
        --enable-dot             Enable DNS over TLS for resolving subdomains IPs.
        --aempty                 Send alert to webhooks still when no new subdomains have been found.
        --external-subdomains    Get external subdomains with amass and subfinder.
    -h, --help                   Prints help information
        --http-status            Check the HTTP status of subdomains.
    -i, --ip                     Show/write the ip address of resolved subdomains.
        --ipv6-only              Perform a IPv6 lookup only.
    -m, --monitoring-flag        Activate Findomain monitoring mode.
    -n, --no-discover            Prevent findomain from searching subdomains itself. Useful when you are importing
                                 subdomains from other tools.
        --no-double-dns-check    Disable double DNS check. Currently the subdomains that report an IP address are
                                 checked again using a list of trustable resolvers to avoid false-positives. Only
                                 applies when using custom resolvers.
        --no-monitor             Disable monitoring mode while saving data to database.
        --no-resolve             Disable pre-screenshotting jobs (http check and ip discover) when used as resolver to
                                 take screenshots.
        --no-wildcards           Disable wilcard detection when resolving subdomains.
    -o, --output                 Write to an automatically generated output file. The name of the output file is
                                 generated using the format: target.txt. If you want a custom output file name, use the
                                 -u/--unique-output option.
        --pscan                  Enable port scanner.
        --query-database         Query the findomain database to search subdomains that have already been discovered.
        --query-jobname          Extract all the subdomains from the database where the job name is the specified using
                                 the jobname option.
    -q, --quiet                  Remove informative messages but show fatal errors or subdomains not found message.
        --randomize              Enable randomization when reading targets from files.
        --reset-database         Reset the database. It will delete all the data from the database.
    -r, --resolved               Show/write only resolved subdomains.
        --sandbox                Enable Chrome/Chromium sandbox. It is disabled by default because a big number of users
                                 run the tool using the root user by default. Make sure you are not running the program
                                 as root user before using this option.
        --stdin                  Read from stdin instead of files or aguments.
        --validate               Validate all the subdomains from the specified file.
    -V, --version                Prints version information
    -v, --verbose                Enable verbose mode (useful to debug problems).

OPTIONS:
    -c, --config <config-file>
            Use a configuration file. The default configuration file is findomain and the format can be toml, json,
            hjson, ini or yml.
        --resolvers <custom-resolvers>...
            Path to a file (or files) containing a list of DNS IP address. If no specified then Google, Cloudflare and
            Quad9 DNS servers are used.
        --exclude-sources <exclude-sources>...
            Exclude sources from searching subdomains in. [possible values: certspotter, crtsh, sublist3r, facebook,
            spyse, threatcrowd, virustotalapikey, anubis, urlscan, securitytrails, threatminer, archiveorg, c99,
            bufferover_free, bufferover_paid]
    -f, --file <files>...                                    Use a list of subdomains writen in a file as input.
        --http-retries <http-retries>
            Number of retries for the HTTP Status check of subdomains. Default 1.

        --http-timeout <http-timeout>
            Value in seconds for the HTTP Status check of subdomains. Default 5.

        --import-subdomains <import-subdomains>...
            Import subdomains from one or multiple files. Subdomains need to be one per line in the file to import.

        --iport <initial-port>                               Initial port to scan. Default 0.
    -j, --jobname <jobname>
            Use an database identifier for jobs. It is useful when you want to relate different targets into a same job
            name. To extract the data by job name identifier, use the query-jobname option.
        --lport <last-port>                                  Last port to scan. Default 1000.
        --lightweight-threads <lightweight-threads>
            Number of threads to use for lightweight tasks such as IP discovery and HTTP checks. Default is 50.

        --max-http-redirects <max-http-redirects>            Maximum number of HTTP redirects to follow. Default 0.
        --parallel-ip-ports-scan <parallel-ip-ports-scan>
            Number of IPs that will be port-scanned at the same time. Default is 10.

        --postgres-database <postgres-database>              Postgresql database.
        --postgres-host <postgres-host>                      Postgresql host.
        --postgres-password <postgres-password>              Postgresql password.
        --postgres-port <postgres-port>                      Postgresql port.
        --postgres-user <postgres-user>                      Postgresql username.
        --rate-limit <rate-limit>
            Set the rate limit in seconds for each target during enumeration.

        --resolver-timeout <resolver-timeout>                Timeout in seconds for the resolver. Default 1.
    -s, --screenshots <screenshots-path>
            Path to save the screenshots of the HTTP(S) website for subdomains with active ones.

        --screenshots-threads <screenshots-threads>
            Number of threads to use to use for taking screenshots. Default is 10.

        --exclude <string-exclude>...                        Exclude subdomains containing specifics strings.
        --filter <string-filter>...                          Filter subdomains containing specifics strings.
    -t, --target <target>                                    Target host.
        --tcp-connect-threads <tcp-connect-threads>
            Number of threads to use for TCP connections - It's the equivalent of Nmap's --min-rate. Default is 500.

        --tcp-connect-timeout <tcp-connect-timeout>
            Value in milliseconds to wait for the TCP connection (ip:port) in the ports scanning function. Default 2000.

        --threads <threads>
            Number of threads to use for lightweight tasks such as IP discovery and HTTP checks. Deprecated option, use
            --lighweight-threads instead. This would be removed in the future.
    -u, --unique-output <unique-output>
            Write all the results for a target or a list of targets to a specified filename.

        --ua <user-agents-file>                              Path to file containing user agents strings.
    -w, --wordlist <wordlists>
            Wordlist file to use in the bruteforce process. Using it option automatically enables bruteforce mode.
```

## Usage

TODO: Provide more usage coverage of findomain

`$ findomain -t <domain.com>`

`$ findomain -f domains.txt`

`$ findomain -f domains.txt -r -o output-resolved.txt`