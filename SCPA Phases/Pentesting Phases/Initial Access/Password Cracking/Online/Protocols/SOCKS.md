# SOCKS

## 01 - Hydra

`$ hydra -l <username> -P <password_list> <IP> socks5`

## 02 - Nmap

`$ nmap -p 1080 -vvv -sCV --script socks-brute --script-args userdb=users.txt,passdb=passwords.txt,unpwndb.timelimit=30m <IP>`