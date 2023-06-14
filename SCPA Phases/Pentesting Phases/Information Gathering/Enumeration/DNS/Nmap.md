# Nmap

## Usage

`$ sudo nmap -p 53 -sSU --script dns-nsid <domain.com>`

`$ nmap -n --script "(default and *dns*) or fcrdns or dns-srv-enum or dns-random-txid or dns-random-srcport" <IP>`