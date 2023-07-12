# 05 - Detecting HTTP Methods

## 5.1 - Nmap

`$ nmap -p 80,443 -sV --script http-methods --script-args http-methods.test=all <IP>`