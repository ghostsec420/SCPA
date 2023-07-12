# PostEnum

PostEnum will come in handy when targeting older and embedded systems. It's fully backward compatible for wider GNU+Linux distros including outdated systems.

- Perform all checks yet it's not recommended since it will be noisy

`$ ./postenum.sh -a`

- Searching through the filesystem for basic vulnerabilites, configuration files and database files

`$ ./postenum.sh -s`

- Shell escape, environment variables and development tools

`$ ./postenum.sh -l`

- Finding sensitive files like credentials and other interesting files

`$ ./postenum.sh -c`

- Enumerating network statistics

`$ ./postenum.sh -n`

- Find services and cron jobs

`$ ./postenum.sh -p`

- Enumerate the operating system about the kernel version, drivers and other security programs

`$ ./postenum.sh -o`

- Look for possible kernel exploits

`$ ./postenum.sh -x`

- Enumerating program's versions

`$ ./postenum.sh -v`

- Fstab credentials and database access

`$ ./postenum.sh -t`

## References

- [PosEenum](https://github.com/mostaphabahadou/postenum)