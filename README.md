# SCPA

Sophisticated cyber penetration attacks is a series of advanced techniques, notes and guidance that will help you to prepare as a hacker on your journey.

## Information Gathering/External Reconnaissance and Vulnerability Assessment

Gathering Intel about the target's weaknesses and find an entrance to compromise the network with vulnerability assessment.

## Exploitation Delivery/Initial Foothold

Gaining enough reconnaissance about the target's network exploitation will be delivered as the final stage to infiltrate the network with vulnerability assessment and/or social engineering.

## Internal Reconnaissance and Enumeration

Same exact steps as Information Gathering phase but performing the network internally with privilege escalation.

CrackMapExec, Responder, Bettercap, Powersploit, Nishang, etc. That is related to phase 2, 3, 4 and 5. This 6th phase is part of the final stage of exploitation that the hacker will use any penetration tools that is needed to breach the security when it's necessary.

## Post Exploitation, Lateral Movement (Using C2 Frameworks) and Maintaining Access

After the 3rd phase has met any of the requirements in order to maintain access to re-establish the connection and keep penetrating the internal network with persistent access. In this phase the hacker must keep pivoting (island hopping) the target's network to gain more access after digging deeper either using a Command & Control (C2) post exploitation framework with socks proxy (proxychaining) or VPN tunnel (Layer-2 Network)

Command and Control (C2): Post exploitation toolkits like Metasploit Framework, Powershell Empire, Cobalt Strike, PupyRAT, and PoshC2.

## Monitoring and Data Exfiltration

Monitoring and Data Exfiltration: Performing activing sniffing and spoofing in the network using a technique such as, MITM (man-in-the-middle) to capture the unencrypted (clear plain text packets) network protocols such as, SMB, MSSQL, FTP, SMTP, Telnet, etc. Through active sniffing via ARP spoofing or passive sniffing in a compromised machine. Data Exfiltration is when the hacker harvests the data by looting the compromised machines in the network after successful penetration with full access.

## Miscellaneous

This is optional, however the hacker might find anything valuable whatever if it's related to the operation or not. This phase relates to gain profits of any kind or other sensitive data that is damaging to the organization.

## Reporting

After finishing by conducting a cyber offensive and the last step for every pentesting is about making reports based on their findings.
