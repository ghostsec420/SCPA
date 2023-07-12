# 04 - Starts with/ends with, groups, and either/or

`^` - begins with a line

`$` - ends with a line

`(stand|sit)` - either/or using parentheses

`(spam){n}` - Repetition

- Match every string that starts with **"Password:"** **followed by any 10 characters excluding "0"**

`Password:[^0]{10}`

- Match **"username: "** **in the beginning of a line** (note the space!)

`^username:\s`

- Match every line that doesn't start with a digit

`^\D`

- Match this string at the end of a line: **EOF$**

`EOF\$$`

- Match all of the following sentences:

1. I use nano

2. I use vim

`I use (nano|vim)`

- Match all lines that start with $, followed by any single digit, followed by $, followed by one or more non-whitespace characters

`\$\d\$\S+`

- Match every possible IPv4 IP address

`(\d{1,3}\.){3}\d{1,3}`

- Match all of these emails while also adding the username and the domain name (not the TLD) in separate groups (use \w): `info@website.com`, `username@domain.com`, `example@email.com`

`(\w+)@(\w+)\.com`