# LinPEAS

- Run the script to perform enumeration and save the results

`$ ./linpeas.sh | tee linux-enum.log`

- Perform all checks but it's noisy so be wise about your decision when it comes to OPSEC

`$ ./linpeas.sh -a | tee linux-enum.log`

- Do not display the banner (`-q`) and perform stealth mode enumeration (`-s`). I would go with this option since it is suitable when exploiting the common low hanging fruit vulnerabilities. It is highly recommended that it's OPSEC safe.

`$ ./linpeas.sh -qs | tee linux-enum.log`

- Execute the scripts from the following checks with comma separated list

`$ ./linpeas.sh -o UsrI,SysI,Devs,AvaSof,IntFiles`

## References

- [LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)