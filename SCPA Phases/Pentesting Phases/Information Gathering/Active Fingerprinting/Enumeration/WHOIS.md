# WHOIS

## 01 - Manual

`$ whois -h <IP> -p <PORT> "<website.com>"`

`$ echo "<website.com>" | nc -vn <IP> <PORT>`

## 02 - Nmap

`$ nmap -p 43 -sCV -Pn <IP>`