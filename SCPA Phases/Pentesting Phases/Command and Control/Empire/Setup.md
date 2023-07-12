# Setup

## 01 - Install

### 1.1 - Manual Installation

```
$ sudo git clone --recursive https://github.com/BC-SECURITY/Empire.git /opt/post-exploitation/Empire && \
cd /opt/post-exploitation/Empire && ./setup/checkout-latest-tag.sh && \
sudo ./setup/install.sh
```

## 02 - Troubleshoot

### 2.1 - Debian-based distros

`$ /opt/post-exploitation/Empire/setup/cert.sh`

### 2.2 - In Kali Linux

`$ /usr/share/powershell-empire/setup/cert.sh`