# Setup

## 01 - Dependencies

### Debian-based distros

`$ sudo apt install -y mingw-w64 nasm default-jdk default-jre`

### Arch-based distros

`$ sudo pacman -S mingw-w64-binutils mingw-w64-crt mingw-w64-gcc mingw-w64-headers mingw-w64-winpthreads nasm jdk-openjdk jre-openjdk`

## 02 - Launch teamserver and operator client

`$ sudo ./teamserver <IP> <password> /path/to/malleable_c2.profile`

`$ ./cobaltstrike.sh`