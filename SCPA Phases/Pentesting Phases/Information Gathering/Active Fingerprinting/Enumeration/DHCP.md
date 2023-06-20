# DHCP

## 01 - Nmap

`$ sudo nmap -sU -p 67 --script dhcp-discover <IP>`

- **These NSE scripts discovers the local network which is why an IP is not required as an input**

`$ sudo nmap --script broadcast-dhcp-discover`

`$ sudo nmap -6 --script broadcast-dhcp6-discover`