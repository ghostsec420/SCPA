# 02 - File and Directory Manipulation

## 2.1 - Touch

### 2.1.1 - Create an empty file

`$ touch file.txt`

## 2.2 -  File Attribution

`$ sudo chattr +i file.txt`

```
$ ls -lh file.txt
-rw-r--r-- 1 user user 22 Aug 13 18:11 file.txt
```

---

```
$ sudo rm file.txt
rm: cannot remove 'file.txt': Operation not permitted
```

---

```
$ lsattr file.txt
----i---------e------- file.txt
```