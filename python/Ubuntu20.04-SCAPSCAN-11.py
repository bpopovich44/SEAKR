## Written by Bill Popovich - DevOps - Seakr
## NOTE: This script contains variable shell=True which is susceptible to shell injection.  Use with care
##

#!/usr/bin/env python3
import os # can delete
import socket
import sys
import getpass # password input
import re
import datetime
#Imports below in script
# -peramiko 
# -subprocess


hostname = socket.gethostname()
local_ip = socket.gethostbyname(hostname)

RED = '\033[1;31m' 
GREEN = '\033[1;32m' 
YELLOW = '\033[1;33m'
MAG = '\033[1;35m'
CYAN = '\033[1;36m'
ENDCLR = '\033[0;0m'

SSH_PORT=22

path = os.getcwd()
d = datetime.datetime.now().strftime("%Y-%m-%d_%H:%M:%S")
fname = "Ubuntu20.04_scap_"+str(d)+".txt"
FILE_NAME = os.path.join(path, fname)

def connect_passwd():
    # Create ssh connection using username and password
    ip = input("Enter a server to scan> ")
    username = input("Enter username> ")
    password = getpass.getpass("Enter password> ")

    try:
        ssh=paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip,SSH_PORT,username,password)
    except AuthenticationException as s:
        print("Authentication failed.  Please verify credentials: %s" % s)
        ssh.close()
    except SSHException as sshException:
        print("Unable to establish SSH connection: %s" % sshException)
        ssh.close()
    except socker.error as socketError:
        print("Socker error: %s" %socketError)
        ssh.close()

    return ssh

# Not configured/working
def connect_keys():
    # Create ssh connection with keys
    key = paramiko.RSAKey.from_private_key_file(keyfilename)

    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname=host, username=user, pkey=key)
    #badhostkey exception
    return 

def catagories_selected():
    counter = 1
    catagories = list(input("Which catagories do you want to scan for?  Select \'"+MAG+"CAT1"+ENDCLR+"\' \'"+MAG+"C"\
                            +"AT2"+ENDCLR+"\' \'"+MAG+"CAT3"+ENDCLR+"\' seperated by spaces > ").split())
    for x in range(len(catagories)):
        catagories[x] = catagories[x].lower()
     
    if len(catagories) != 0:
        for x in range(len(catagories)):
            try:
                while catagories[x] not in {'cat1', 'cat2', 'cat3'} and counter != 3:
                    print("invalid input.  Try again.")
                    catagories = list(input("Which catagories do you want to scan for?  Select \'"+MAG+"CAT1"+ENDCLR+"\' \'"+MAG+"C"\
                                            +"AT2"+ENDCLR+"\' \'"+MAG+"CAT3"+ENDCLR+"\' seperated by spaces > ").split())
                    for x in range(len(catagories)):
                        catagories[x] = catagories[x].lower()
                    if(counter == 3):
                        print("You had 3 attempts.  Ending stig scanner.")
                        quit()
                counter += 1    
            except IndexError:
                print("You did not enter a catagory.  Goodbye.")
                quit()
    else:
        print("You did not enter a catagory.  Goodbye.")
        quit()
    
    return catagories

def file_output():
    counter = 1
    output_type = input("Do you want to send output to a file? Enter \'"+MAG+"Yes"+ENDCLR+"\' or \'"+MAG+"No"+ENDCLR+"\' > ")
     
    if len(output_type) != 0:
        for x in range(len(output_type)):
            try:
                output_type = output_type.lower()
                while output_type not in {'yes', 'y', 'no', 'n'} and counter != 3:
                    print("invalid input.  Try again.")
                    output_type = input("Do you want to send output to a file? Enter "'"Yes"'" or "'"No"'" > ")
                    for x in range(len(output_type)):
                        output_type = output_type.lower()
                    if(counter == 3):
                        print("You had 3 attempts.  Ending stig scanner.")
                        quit()
                counter += 1    
            except IndexError:
                print("You did not enter Yes or No.  Goodbye.")
                quit()
    else:
        print("You did not enter Yes or No.  Goodbye.")
        quit()
    
    return output_type

def banner():
    print("##########################################################################")
    print("##                                                                      ##")
    print("##                                                                      ##")
    print("##                 "+GREEN+"Welcome to the Ubuntu 20.04 scap scanner             "+ENDCLR+"##")
    print("##                                                                      ##")
    print("##                                                                      ##")
    print("##########################################################################")
    print("")
    print("")
    return


# STIG VULN ID'S CATAGORY '1'           
# take a type of connection local-ssh                                                     
def CAT_1(conn, f):                                        
   
    ## send output to file
    if(f == "yes") or (f == "y"):
        print(YELLOW+"You can view your file with the following command > "+ENDCLR+"\"cat "+str(FILE_NAME)+"\"")
        sys.stdout= open(FILE_NAME, 'w')
        banner()
                                                       
    print(YELLOW+"\n\nPerforming Ubuntu 20.04 "'"cat 1"'" stig scan of server: \""+MAG+hostname+ENDCLR+YELLOW+"\" at"\
          +" IP: \""+MAG+local_ip+ENDCLR+YELLOW+"\""+ENDCLR)

    cat1_vuln_ids = [238201, 238204, 238206, 238215, 238218, 238219, 238326, 238327, 238363, 238379, 238380]
    
    # CALL CLASS VulnScanner AND REQUEST STIG RULES    
    # PASS DESIRED VULN ID ACCORDING TO 'STIG'         
    # INITIATE/PRIME THE CONSTRUCTOR ASSIGN TO OBJECT run_scan 
    for x in cat1_vuln_ids:                            
        run_scan = VulnScanner(x, conn)                 
        run_scan.stig_scan()# LAUNCH THE stig_scan() FUNCTION OF THE VulnScaner 'run_scan'
    if(f == "yes") or (f == "y"):
        sys.stdout.close()
    return                                             
                                                       
# STIG VULN ID'S CATATORY '2'           
# take a type of connection local-ssh                                                     
def CAT_2(conn, f):                                        
    ## send output to file
    if(f == "yes") or (f == "y"):
        print(YELLOW + "You can view your file with the following command > "+ENDCLR+"\"cat "+str(FILE_NAME)+"\"")
        sys.stdout= open(FILE_NAME, 'w')
        banner()
                                                       
    print(YELLOW+"\n\nPerforming Ubuntu 20.04 \'cat 1\' stig scan of server: \""+MAG+hostname+ENDCLR+YELLOW+"\" at"\
          +" IP: \""+MAG+local_ip+ENDCLR+YELLOW+"\""+ENDCLR)

    #NEED 238318
    #LIST 238305, 238307, 238308, 238331, 238336, 238362, 238363, 238234, 238235,238326, 238327
    cat2_vuln_ids = [238196, 238197, 238198, 238199, 238200, 238205, 238207, 238208, 238209, 238210, 238211, 238212, 238213, 238214, 238216, 238217,
                     238220, 238225, 238227, 238228, 238229, 238230, 238231, 238232, 238233, 238236, 238237, 238238, 238239, 238240, 238241, 238242,
                     238243, 238244, 238245, 238246, 238247, 238248, 238249, 238250, 238251, 238252, 238253, 238254, 238255, 238256, 238257, 238258,
                     238259, 238260, 238261, 238262, 238263, 238264, 238265, 238266, 238267, 238268, 238269, 238270, 238271, 238272, 238273, 238274,
                     238275, 238276, 238277, 238278, 238279, 238280, 238281, 238282, 238283, 238284, 238285, 238286, 238287, 238288, 238289, 238290,
                     238291, 238292, 238293, 238294, 238295, 238296, 238297, 238298, 238299, 238300, 238301, 238302, 238303, 238304, 238306, 238309,
                     238310, 238311, 238312, 238313, 238314, 238315, 238316, 238317, 238319, 238320, 238324, 238325, 238328, 238329, 238330, 238332,
                     238333, 238334, 238335, 238337, 238338, 238339, 238340, 238341, 238342, 238343, 238344, 238345, 238346, 238347, 238348, 238350,
                     238351, 238352, 238353, 238354, 238355, 238356, 238357, 238358, 238359, 238360, 238361, 238364, 238365, 238366, 238367, 238368,
                     238369, 238370, 238371, 238372, 238374, 238375, 238376, 238377, 238378]
    

    # CALL CLASS VulnScanner AND REQUEST STIG RULES
    # PASS DESIRED VULN ID ACCORDING TO 'STIG'
    # INIATITE/PRIME THE CONSTRUCTOR ASSIGN TO OBJECT run_scan 
    for x in cat2_vuln_ids:                            
        run_scan = VulnScanner(x, conn)                 
        run_scan.stig_scan()# LAUNCH THE stig_scan() FUNCTION OF THE VulnScaner 'run_scan'
    if(f == "yes") or (f == "y"):
        sys.stdout.close()
    return

def CAT_3(connect):
    print("cat3 no currently ready.")
    quit()

    return


class VulnScanner:

    # CONSTRUCTOR
    # iniates/primes the VulnScanner class
    # currently using STIG rules that have been built
    def __init__(self, v, c):
        self.vuln_id = v
        self.conn = c
        self.stig_rulebook = {

                238201 : {"cmd" : "sudo grep use_mappers /etc/pam_pkcs11/pam_pkcs11.conf",
                          "cmdl" : ['sudo', 'grep', 'use_mappers', '/etc/pam_pkcs11/pam_pkcs11.conf'],
                          "function" : self.stig_rule_238201,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must map the"\
                          + " authenticated identity to the user or group account for PKI-based authentication.\033[0;0m"},

                238204 : {"cmd" : "sudo grep -i password /boot/grub/grub.cfg",
                          "cmdl" : ['sudo', 'grep', '-i', 'password', '/boot/grub/grub.cfg'],
			  "function" : self.stig_rule_238204,
                          "rule" : "\033[1;36mRule Title: Ubuntu operating systems when booted must require"\
                          + " authentication upon booting into single-user and maintenance modes.\033[0;0m"},
                
                238206 : {"cmd" : "grep sudo /etc/group",
                          "cmdl" : ['grep', 'sudo', '/etc/group'],
			  "function" : self.stig_rule_238206,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must ensure only users"\
                          + " who need access to security functions are part of sudo group.\033[0;0m"},

                238215 : {"cmd" : "sudo dpkg -l | grep openssh",
                          "cmd1" : "sudo systemctl status sshd.service | egrep -i \"(active|loaded)\"",
                          "cmdl" : ['sudo', 'dpkg', '-l'],
                          "cmdl1" : ['grep', 'openssh'],
                          "cmdl2" : ['sudo', 'systemctl', 'status', 'sshd.service'],
                          "cmdl3" : ['grep', '-i', 'active'],
                          "cmdl4" : ['grep', '-i', 'loaded'],
                          #"cmdl3" : ['egrep', '-i', '{"(active|loaded)}"'],
                          "function" : self.stig_rule_238215,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must use SSH to protect"\
                          + " the confidentiality and integrity of transmitted information.\033[0;0m"},

                238218 : {"cmd" : "egrep '(Permit(.*?)(Passwords|Environment))' /etc/ssh/sshd_config",
                          "cmdl" : ['egrep', '''(Permit(.*?)(Passwords|Environment))''','/etc/ssh/sshd_config'],
			  "function" : self.stig_rule_238218,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must not allow unattended"\
                          + " or automatic login via SSH.\033[0;0m"},

                238219 : {"cmd" : "grep -i x11forwarding /etc/ssh/sshd_config | grep -v ^#",
                          "cmdl" : ['grep', '-i', 'x11forwarding', '/etc/ssh/sshd_config'],
                          "cmdl1" : ['grep', '-v', '^#'],
			  "function" : self.stig_rule_238219,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must be configured so that"\
                          + " remote X connections are disabled unless to fulfill documented and\nvalidated mission requirements.\033[0;0m"},

                238326 : {"cmd" : "dpkg -l | grep telnetd",
                          "cmdl" : ['dpkg', '-l'],
                          "cmdl1" : ['grep', 'telnetd'],
                          "function" : self.stig_rule_238326,
			  "rule" : "\033[1;36mRule Title: The Ubuntu operating system must not have the telnet package"\
                          + " installed.\033[0;0m"},

                238327 : {"cmd" : "dpkg -l | grep rsh-server",
                          "cmdl" : ['dpkg', '-l'],
                          "cmdl1" : ['grep', 'rsh-server'],
			  "function" : self.stig_rule_238327,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must not have the rsh-server package"\
                          + " installed.\033[0;0m"},

                238363 : {"cmd" : "grep -i 1 /proc/sys/crypto/fips_enabled",
                          "cmdl" : ['grep', '-i', '1', '/proc/sys/crypto/fips_enabled'],
			  "function" : self.stig_rule_238363,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must implement NIST FIPS-validated"\
                          + " cryptography to protect classified information and for the following:\nto provision digital signatures, to generate"\
                          + " cryptographic hashes, and to protect unclassified information requiring confidentiality and cryptographic\nprotection in"\
                          + " accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.\033[0;0m"},

                238379 : {"cmd" : "sudo grep logout /etc/dconf/db/local.d/00-disable-CAD",
                          "cmdl" : ['sudo', 'grep', 'logout', '/etc/dconf/db/local.d/00-disable-CAD'],
			  "function" : self.stig_rule_238379,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must disable the x86 Ctrl-Alt-Delete"\
                          + " key sequence if a graphical user interface is installed.\033[0;0m"},

                238380 : {"cmd" : "systemctl status ctrl-alt-del.target",
                          "cmdl" : ['systemctl', 'status', 'ctrl-alt-del.target'],
			  "function" : self.stig_rule_238380,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must disable the x86 Ctrl-Alt-Delete key"\
                          + " sequence.\033[0;0m"},

                238196 : {"cmd" : "cat /etc/passwd | cut -d: -f1",
                          "cmdlocal" : ['cat', '/etc/passwd', '|', 'cut -d:', '-f1'],
                          "function" : self.stig_rule_238196,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must provision temporary user accounts with an expiration"\
                          + " time of 72 hours or less.\033[0;0m"}, 
                
                238197 : {"cmd" : "grep ^banner-message-enable /etc/gdm3/greeter.dconf-defaults",
                          "cmd1" : "ls /usr/bin/*session",
                          "cmdlocal" : ['grep', '^banner-message-enable', '/etc/gdm3/greeter.dconf-defaults'],
                          "function" : self.stig_rule_238197,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must enable the graphical"\
                          + " user logon banner to display the ruletandard Mandatory DoD\n Notice and Consent Banner before granting"\
                          + " local access to the system via a graphical user logon.\033[0;0m"},

                238198 : {"cmd" : "grep ^banner-message-text /etc/gdm3/greeter.dconf-defaults",
                          "cmd1" : "ls /usr/bin/*session",
                          "cmdlocal" : ['grep', '^banner-message-text', '/etc/gdm3/greeter.dconf-defaults'],
                          "function" : self.stig_rule_238198,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must display the Standard"\
                          + " Mandatory DoD Notice and Consent Banner before granting local access\nto the system via a graphical user logon.\033[0;0m"},

                238199 : {"cmd" : "sudo gsettings get org.gnome.desktop.screensaver lock-enabled",
                          "cmdlocal" : ['sudo', 'gsettings', 'get', 'org.gnome.desktop.screensaver', 'lock-enabled'],
                          "function" : self.stig_rule_238199,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must retain a user's session lock"\
                          + " until that user reestablishes access using established\nidentification and authentication procedures.\033[0;0m"},

                238200 : {"cmd" : "dpkg -l | grep vlock",
                          "cmdlocal" : ['dpkg', '-l', '|', 'grep', 'vlock'],
                          "function" : self.stig_rule_238200,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must allow users to directly initiate a"\
                          + " session lock for all connection types.\033[0;0m"},

                238205 : {"cmd" : "awk -F \":\" \'list[]++{print , }\' /etc/passwd",
                          "cmdlocal" : ['awk', '-F', '\":\" \'list[]++{print , }\' /etc/passwd'],
                          "function" : self.stig_rule_238205,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must uniquely identify interactive users.\033[0;0m"},

                238207 : {"cmd" : "grep -E \"\\bTMOUT=[0-9]+\" /etc/bash.bashrc /etc/profile.d/*",
                          "cmdlocal" : [''],
                          "function" : self.stig_rule_238207,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must automatically terminate a user session after"\
                          + " inactivity timeouts have expired.\033[0;0m"},

                238208 : {"cmd" : "sudo egrep -i \'(nopasswd|!authenticate)\' /etc/sudoers /etc/sudoers.d/*",
                          "cmdlocal" : [''],
                          "function" : self.stig_rule_238208,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must require users to reauthenticate for privilege"\
                          + " escalation or when changing roles.\033[0;0m"},

                238209 : {"cmd" : "grep -i \"umask\" /etc/login.defs",
                          "cmdlocal" : [''],
                          "function" : self.stig_rule_238209,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system default filesystem permissions must be defined in"\
                          + " such a way that all authenticated users can\nread and modify only their own files.\033[0;0m"},

                238210 : {"cmd" : "dpkg -l | grep libpam-pkcs11",
                          "cmd1" : "grep ^PubkeyAuthentication /etc/ssh/sshd_config",
                          "cmdlocal" : ['dpkg', '-l', '|', 'grep', 'libpam-pkcs11'],
                          "cmdlocal1" : ['grep', '^PubkeyAuthentication', '/etc/ssh/sshd_config'],
                          "function" : self.stig_rule_238210,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must implement smart card logins for multifactor"\
                          + " authentication for local and network access\nto privileged and non-privileged accounts.\033[0;0m"},

                238211 : {"cmd" : "grep ^UsePAM /etc/ssh/sshd_config",
                          "cmdlocal" : ['grep', '^UsePAM', '/etc/ssh/sshd_config'],
                          "function" : self.stig_rule_238211,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must use strong authenticators in establishing"\
                          + " nonlocal maintenance and diagnostic sessions.\033[0;0m"},

                238212 : {"cmd" : "sudo grep -i clientalivecountmax /etc/ssh/sshd_config",
                          "cmdlocal" : ['sudo', 'grep', '-i', 'clientalivecountmax', '/etc/ssh/sshd_config'],
                          "function" : self.stig_rule_238212,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must immediately terminate all network connections"\
                          + " associated with SSH traffic after a period of inactivity.\033[0;0m"},

                238213 : {"cmd" : "sudo grep -i clientaliveinterval /etc/ssh/sshd_config",
                          "cmdlocal" : ['sudo', 'grep', '-i', 'clientaliveinterval', '/etc/ssh/sshd_config'],
                          "function" : self.stig_rule_238213,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must immediately terminate all network connections"\
                          + " associated with SSH traffic at the end of\nthe session or after 10 minutes of inactivity.\033[0;0m"},

                238214 : {"cmd" : "grep -i banner /etc/ssh/sshd_config",
                          "cmd1" : "cat /etc/issue.net",
                          "cmdlocal" : ['grep', '-i', 'banner /etc/ssh/sshd_config'],
                          "cmdlocal1" : ['cat', '/etc/issue.net'],
                          "function" : self.stig_rule_238214,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must display the Standard Mandatory DoD Notice and"\
                          + " Consent Banner before granting any local\nor remote connection to the system.\033[0;0m"},

                238216 : {"cmd" : "sudo grep -i macs /etc/ssh/sshd_config",
                          "cmdlocal" : ['sudo', 'grep', '-i', 'macs', '/etc/ssh/sshd_config'],
                          "function" : self.stig_rule_238216,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must configure the SSH daemon to use Message Authentication"\
                          + " Codes (MACs) employing FIPS 140-2 approved\ncryptographic hashes to prevent the unauthorized disclosure of information"\
                          + " and/or detect changes to information during transmission.\033[0;0m"},

                238217 : {"cmd" : "grep -E 'Ciphers' /etc/ssh/sshd_config",
                          #"cmdlocal" : ['grep', '-E', ''Ciphers'', '/etc/ssh/sshd_config'],
                          "function" : self.stig_rule_238217,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must configure the SSH daemon to use FIPS 140-2 approved"\
                          + " ciphers to prevent the unauthorized disclosure\nof information and/or detect changes to information during transmission.\033[0;0m"},

                238220 : {"cmd" : "sudo grep -i x11uselocalhost /etc/ssh/sshd_config",
                          "cmdlocal" : ['sudo', 'grep', '-i', 'x11uselocalhost', '/etc/ssh/sshd_config'],
                          "function" : self.stig_rule_238220,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system SSH daemon must prevent remote hosts from connecting to"\
                          + " the proxy display.\033[0;0m"},

                238225 : {"cmd" : "sudo grep -i ^minlen /etc/security/pwquality.conf",
                          "cmdlocal" : ['sudo', 'grep', '-i', '^minlen', '/etc/security/pwquality.conf'],
                          "function" : self.stig_rule_238225,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must enforce a minimum 15-character password length.\033[0;0m"},

                238227 : {"cmd" : "sudo grep dictcheck /etc/security/pwquality.conf",
                          "cmdlocal" : ['sudo', 'grep', 'dictcheck', '/etc/security/pwquality.conf'],
                          "function" : self.stig_rule_238227,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must prevent the use of dictionary words for passwords.\033[0;0m"},

                238228 : {"cmd" : "dpkg -l libpam-pwquality",
                          "cmd1" : "sudo grep -i enforcing /etc/security/pwquality.conf",
                          "cmd2" : "cat /etc/pam.d/common-password | grep requisite | grep pam_pwquality",
                          "cmdlocal" : ['dpkg', '-l', 'libpam-pwquality'],
                          "cmdlocal1" : ['sudo', 'grep', '-i', 'enforcing', '/etc/security/pwquality.conf'],
                          "cmdlocal2" : ['cat', '/etc/pam.d/common-password', '|', 'grep', 'requisite', '|', 'grep', 'pam_pwquality'],
                          "function" : self.stig_rule_238228,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must be configured so that when passwords are changed or"\
                          + " new passwords are established, pwquality must be used.\033[0;0m"},

                238229 : {"cmd" : "sudo grep use_pkcs11_module /etc/pam_pkcs11/pam_pkcs11.conf | awk '/pkcs11_module opensc {/,/}/' "\
                          + "/etc/pam_pkcs11/pam_pkcs11.conf | grep cert_policy | grep ca",
                          "cmdlocal" : [''],
                          "function" : self.stig_rule_238229,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system, for PKI-based authentication, must validate certificates"\
                          + " by constructing a certification path (which includes\nstatus information) to an accepted trust anchor.\033[0;0m"},

                238230 : {"cmd" : "dpkg -l | grep libpam-pkcs11",
                          "cmdlocal" : ['dpkg', '-l', '|', 'grep', 'libpam-pkcs11'],
                          "function" : self.stig_rule_238230,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must implement multifactor authentication for remote access"\
                          + " to privileged accounts in such a way that one of\nthe factors is provided by a device separate from the system gaining access.\033[0;0m"},

                238231 : {"cmd" : "dpkg -l | grep opensc-pkcs11",
                          "cmdlocal" : ['dpkg', '-l', '|', 'grep', 'opensc-pkcs11'],
                          "function" : self.stig_rule_238231,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must accept Personal Identity Verification (PIV) credentials.\033[0;0m"},

                238232 : {"cmd" : "sudo grep use_pkcs11_module /etc/pam_pkcs11/pam_pkcs11.conf | awk '/pkcs11_module opensc {/,/}/' "\
                          + "/etc/pam_pkcs11/pam_pkcs11.conf | grep cert_policy | grep ocsp_on",
                          "cmdlocal" : [''],
                          "function" : self.stig_rule_238232,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must electronically verify Personal Identity Verification (PIV)"\
                          + " credentials.\033[0;0m"},

                238233 : {"cmd" : "sudo grep cert_policy /etc/pam_pkcs11/pam_pkcs11.conf | grep -E -- 'crl_auto|crl_offline'",
                          "cmdlocal" : [''],
                          "function" : self.stig_rule_238233,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system for PKI-based authentication, must implement a local cache of"\
                          + " revocation data in case of the inability to access\nrevocation information via the network.\033[0;0m"},

		238234 : {"cmd" : "grep -i remember /etc/pam.d/common-password",
                          "cmdlocal" : ['grep', '-i', 'remember', '/etc/pam.d/common-password'],
                          "function" : self.stig_rule_238234,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must prohibit password reuse for a minimum of five "\
                                   + "generations.\033[0;0m"},

                238235 : {"cmd" : "sudo egrep 'silent|audit|deny|fail_interval| unlock_time' /etc/security/faillock.conf",
                          "cmdlocal" : [''],
                          "function" : self.stig_rule_238235,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must automatically lock an account until the locked account "\
                                   + "is released by an administrator when three\nunsuccessful logon attempts have been made.\033[0;0m"},
 
		238236 : {"cmd" : "cd /tmp; apt download aide-common",
                          "cmd1" : "dpkg-deb --fsys-tarfile /tmp/aide-common_*.deb | tar -xO ./usr/share/aide/config/cron.daily/aide | sha1sum",
                          "cmd2" : "sha1sum /etc/cron.{daily,monthly}/aide 2>/dev/null",
                          "cmdlocal" : ['cd', '/tmp;', 'apt', 'download aide-common'],
                          "cmdlocal1" : ['dpkg-deb', '--fsys-tarfile', '/tmp/aide-common_*.deb', '|', 'tar', '-xO', './usr/share/aide/config/cron.daily/aide', '|', 'sha1sum'],
                          "cmdlocal2" : ['sha1sum', '/etc/cron.{daily,monthly}/aide', '2>/dev/null'],
                          "function" : self.stig_rule_238236,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must be configured so that the script which runs each 30 days or"\
                          + " less to check file integrity is the default one.\033[0;0m"},

                238237 : {"cmd" : "grep pam_faildelay /etc/pam.d/common-auth",
                          "cmdlocal" : ['grep', 'pam_faildelay', '/etc/pam.d/common-auth'],
                          "function" : self.stig_rule_238237,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must enforce a delay of at least 4 seconds between logon prompts "\
			  + "following a failed logon attempt.\033[0;0m"},

                238238 : {"cmd" : "sudo auditctl -l | grep passwd",
                          "cmdlocal" : ['sudo', 'auditctl', '-l', '|', 'grep', 'passwd'],
                          "function" : self.stig_rule_238238,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for all account creations,"\
                          + " modifications, disabling, and termination events that\naffect /etc/passwd.\033[0;0m"},

                238239 : {"cmd" : "sudo auditctl -l | grep group",
                          "cmdlocal" : ['sudo', 'auditctl', '-l', '|', 'grep', 'group'],
                          "function" : self.stig_rule_238239,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for all account creations,"\
                          + " modifications, disabling, and termination events that\naffect /etc/group.\033[0;0m"},

                238240 : {"cmd" : "sudo auditctl -l | grep shadow",
                          "cmdlocal" : ['sudo', 'auditctl', '-l', '|', 'grep', 'shadow'],
                          "function" : self.stig_rule_238240,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for all account creations,"\
                          + " modifications, disabling, and termination events that\naffect /etc/shadow.\033[0;0m"},

                238241 : {"cmd" : "sudo auditctl -l | grep gshadow",
                          "cmdlocal" : ['sudo', 'auditctl', '-l', '|', 'grep', 'gshadow'],
                          "function" : self.stig_rule_238241,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for all account creations,"\
                          + " modifications, disabling, and ermination events\nthat affect /etc/gshadow.\033[0;0m"},

                238242 : {"cmd" : "sudo auditctl -l | grep opasswd",
                          "cmdlocal" : ['sudo', 'auditctl', '-l', '|', 'grep', 'opasswd'],
                          "function" : self.stig_rule_238242,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for all account creations,"\
                          + " modifications, disabling, and termination events\nthat affect /etc/opasswd\033[0;0m"},

                238243 : {"cmd" : "sudo grep \'^action_mail_acct = root\' /etc/audit/auditd.conf",
                          "cmdlocal" : ['sudo', 'grep', '\'^action_mail_acct = root\'', '/etc/audit/auditd.conf'],
                          "function" : self.stig_rule_238243,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must alert the ISSO and SA (at a minimum) in the event"\
                          + " of an audit processing failure.\033[0;0m"},

                238244 : {"cmd" : "sudo grep '^disk_full_action' /etc/audit/auditd.conf",
                          #"cmdlocal" : ['sudo', 'grep', ''^disk_full_action'', '/etc/audit/auditd.conf'],
                          "function" : self.stig_rule_238244,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must shut down by default upon audit failure"\
                          + "(unless availability is an overriding concern).\033[0;0m"},

                238245 : {"cmd" : "sudo grep -iw ^log_file /etc/audit/auditd.conf",
                          "cmd1" : "sudo ls /var/log/audit/",
                          "cmd2" : "sudo stat -c \"%n %a\" /var/log/audit/",
                          "cmdlocal" : ['sudo', 'grep', '-iw', 'log_file', '/etc/audit/auditd.conf'],
                          "cmdlocal1" : ['sudo', 'stat', '-c', '\"%n %a\"', '/var/log/audit/*'],
                          "function" : self.stig_rule_238245,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must be configured so that audit log files are not read"\
                          + " or write-accessible by unauthorized users\033[0;0m."},

                238246 : {"cmd" : "sudo grep -iw log_file /etc/audit/auditd.conf",
                          "cmd1" : "sudo ls /var/log/audit/",
                          "cmd2" : "sudo stat -c \"%n %U\" /var/log/audit/",
                          "cmdlocal" : ['sudo', 'grep', '-iw', 'log_file', '/etc/audit/auditd.conf'],
                          "cmdlocal1" : ['sudo', 'stat', '-c', '\"%n %U\"', '/var/log/audit/*'],
                          "function" : self.stig_rule_238246,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must permit only authorized groups ownership of the audit log files.\033[0;0m"},

                238247 : {"cmd" : "sudo grep -iw log_group /etc/audit/auditd.conf",
                          "cmd1" : "sudo ls /var/log/audit/",
                          "cmd2" : "sudo grep -iw log_file /etc/audit/auditd.conf",
                          "cmd3" : "sudo stat -c \"%n %G\" /var/log/audit/",
                          "cmdlocal" : ['sudo', 'grep', '-iw', 'log_group', '/etc/audit/auditd.conf'],
                          "cmdlocal1" : ['sudo', 'grep', '-iw', 'log_file', '/etc/audit/auditd.conf'],
                          "cmdlocal2" : ['sudo', 'stat', '-c', '\"%n %G\"', '/var/log/audit/*'],
                          "function" : self.stig_rule_238247,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must permit only authorized groups ownership of the audit log files.\033[0;0m"},

                238248 : {"cmd" : "sudo grep -iw ^log_file /etc/audit/auditd.conf",
                          "cmd1" : "sudo ls /var/log/audit/",
                          "cmd2" : "sudo stat -c \"%n %a\" /var/log/audit /var/log/audit/*",
                          "cmdlocal" : ['sudo', 'grep', '-iw', '^log_file /etc/audit/auditd.conf'],
                          "cmdlocal1" : ['sudo', 'stat', '-c', '\"%n %a\"', '/var/log/audit', '/var/log/audit/*'],
                          "function" : self.stig_rule_238248,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must be configured so that the audit log directory is"\
                          + " not write-accessible by unauthorized users.\033[0;0m"},

                238249 : {"cmd" : "sudo ls -al /etc/audit/ /etc/audit/rules.d/",
                          "cmdlocal" : ['sudo', 'ls', '-al', '/etc/audit/', '/etc/audit/rules.d/'],
                          "function" : self.stig_rule_238249,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must be configured so that audit configuration files are"\
                          + " not write-accessible by unauthorized users.\033[0;0m"},

                238250 : {"cmd" : "sudo ls /etc/audit/",
                          "cmd1" : "sudo ls /etc/audit/rules.d/",
                          "cmd2" : "sudo stat -c \"%n %U\" /etc/audit/",
                          "cmd3" : "sudo stat -c \"%n %U\" /etc/audit/rules.d/",
                          "cmdlocal" : ['sudo', 'ls', '-al', '/etc/audit/', '/etc/audit/rules.d/'],
                          "function" : self.stig_rule_238250,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must permit only authorized accounts to own the audit configuration"\
                          + " files.\033[0;0m"},

                238251 : {"cmd" : "sudo ls /etc/audit/",
                          "cmd1" : "sudo ls /etc/audit/rules.d/",
                          "cmd2" : "sudo stat -c \"%n %G\" /etc/audit/",
                          "cmd3" : "sudo stat -c \"%n %G\" /etc/audit/rules.d/",
                          "cmdlocal" : ['sudo', 'ls', '-al', '/etc/audit/', '/etc/audit/rules.d/'],
                          "function" : self.stig_rule_238251,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must permit only authorized groups to own the audit configuration"\
                          + " files.\033[0;0m"},
                
                238252 : {"cmd" : "sudo auditctl -l | grep \'/bin/su\'",
                          "cmdlocal" : [''],
                          "function" : self.stig_rule_238252,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the su"\
                          + " command.\033[0;0m"},
                
                238253 : {"cmd" : "sudo auditctl -l | grep '/usr/bin/chfn'",
                          "cmdlocal" : [''],
                          "function" : self.stig_rule_238253,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the"\
                          + " chfn command.\033[0;0m"},
                
                238254 : {"cmd" : "sudo auditctl -l | grep '/usr/bin/mount'",
                          "cmdlocal" : [''],
                          "function" : self.stig_rule_238254,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the"\
                          + " mount command.\033[0;0m"},
                
                238255 : {"cmd" : "sudo auditctl -l | grep '/usr/bin/umount'",
                          "cmdlocal" : [''],
                          "function" : self.stig_rule_238255,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the"\
                          + " umount command.\033[0;0m"},

                238256 : {"cmd" : "sudo auditctl -l | grep '/usr/bin/ssh-agent'",
                          "cmdlocal" : [''],
                          "function" : self.stig_rule_238256,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the"\
                          + " ssh-agent command.\033[0;0m"},
                
                238257 : {"cmd" : "sudo auditctl -l | grep ssh-keysign",
                          "cmdlocal" : ['sudo', 'auditctl', '-l', '|', 'grep', 'ssh-keysign'],
                          "function" : self.stig_rule_238257,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the"\
                          + "ssh-keysign command.\033[0;0m"},
                
                238258 : {"cmd" : "sudo auditctl -l | grep setxattr",
                          "cmdlocal" : ['sudo', 'auditctl', '-l', '|', 'grep', 'setxattr'],
                          "function" : self.stig_rule_238258,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for any use of the setxattr system call.\033[0;0m"},
                
                238259 : {"cmd" : "sudo auditctl -l | grep lsetxattr",
                          "cmdlocal" : ['sudo', 'auditctl', '-l', '|', 'grep', 'lsetxattr'],
                          "function" : self.stig_rule_238259,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for any use of the lsetxattr system call.\033[0;0m"},
                                           
                238260 : {"cmd" : "sudo auditctl -l | grep fsetxattr",
                          "cmdlocal" : ['sudo', 'auditctl', '-l', '|', 'grep', 'fsetxattr'],
                          "function" : self.stig_rule_238260,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for any use of the fsetxattr system call.\033[0;0m"},
                                           
                238261 : {"cmd" : "sudo auditctl -l | grep removexattr",
                          "cmdlocal" : ['sudo', 'auditctl', '-l', '|', 'grep', 'removexattr'],
                          "function" : self.stig_rule_238261,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for any use of the removexattr system call.\033[0;0m"},
                                           
                238262 : {"cmd" : "sudo auditctl -l | grep lremovexattr",
                          "cmdlocal" : ['sudo', 'auditctl', '-l', '|', 'grep', 'lremovexattr'],
                          "function" : self.stig_rule_238262,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for any use of the lremovexattr system call.\033[0;0m"},
                                            
                238263 : {"cmd" : "sudo auditctl -l | grep fremovexattr",
                          "cmdlocal" : ['sudo', 'auditctl', '-l', '|', 'grep', 'fremovexattr'],
                          "function" : self.stig_rule_238263,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for any use of the fremovexattr system call.\033[0;0m"},
                                            
                238264 : {"cmd" : "sudo auditctl -l | grep chown",
                          "cmdlocal" : ['sudo', 'auditctl', '-l', '|', 'grep', 'chown'],
                          "function" : self.stig_rule_238264,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the fchown"\
                          + " system call.\033[0;0m"},
                                            
                238265 : {"cmd" : "sudo auditctl -l | grep fchown",
                          "cmdlocal" : ['sudo', 'auditctl', '-l', '|', 'grep', 'fchown'],
                          "function" : self.stig_rule_238265,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the fchownat"\
                          + " system call.\033[0;0m"},
                                            
                238266 : {"cmd" : "sudo auditctl -l | grep fchownat",
                          "cmdlocal" : ['sudo', 'auditctl', '-l', '|', 'grep', 'fchownat'],
                          "function" : self.stig_rule_238266,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the lchown "\
                          + " system call.\033[0;0m"},
                                            
                238267 : {"cmd" : "sudo auditctl -l | grep lchown",
                          "cmdlocal" : ['sudo', 'auditctl', '-l', '|', 'grep', 'lchown'],
                          "function" : self.stig_rule_238267,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the chmod "\
                          + " system call.\033[0;0m"},
                                            
                238268 : {"cmd" : "sudo auditctl -l | grep chmod",    
                          "cmdlocal" : ['sudo', 'auditctl', '-l', '|', 'grep', 'chmod'],
                          "function" : self.stig_rule_238268,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the chmod "\
                          + " system call.\033[0;0m"},
                                            
                238269 : {"cmd" : "sudo auditctl -l | grep fchmod",
                          "cmdlocal" : ['sudo', 'auditctl', '-l', '|', 'grep', 'fchmod'],
                          "function" : self.stig_rule_238269,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the fchmod "\
                          + " system call.\033[0;0m"},
                
                238270 : {"cmd" : "sudo auditctl -l | grep fchmodat",
                          "cmdlocal" : ['sudo', 'auditctl', '-l', '|', 'grep', 'fchmodat'],
                          "function" : self.stig_rule_238270,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the fchmodat"\
                          + " system call.\033[0;0m"},
                                            
                238271 : {"cmd" : "sudo auditctl -l | grep open",
                          "cmdlocal" : ['sudo', 'auditctl', '-l', '|', 'grep', 'open'],
                          "function" : self.stig_rule_238271,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the open "\
                          + " system call.\033[0;0m"},
                                           
                238272 : {"cmd" : "sudo auditctl -l | grep truncate",
                          "cmdlocal" : ['sudo', 'auditctl', '-l', '|', 'grep', 'truncate'],
                          "function" : self.stig_rule_238272,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the truncate"\
                          + " system call.\033[0;0m"},
                                           
                238273 : {"cmd" : "sudo auditctl -l | grep ftruncate",
                          "cmdlocal" : ['sudo', 'auditctl', '-l', '|', 'grep', 'ftruncate'],
                          "function" : self.stig_rule_238273,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the ftruncate"\
                          + " system call.\033[0;0m"},
                                           
                238274 : {"cmd" : "sudo auditctl -l | grep creat",
                          "cmdlocal" : ['sudo', 'auditctl', '-l', '|', 'grep', 'creat'],
                          "function" : self.stig_rule_238274,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the creat"\
                          + " system call.\033[0;0m"},
                                            
                238275 : {"cmd" : "sudo auditctl -l | grep openat",
                          "cmdlocal" : ['sudo', 'auditctl', '-l', '|', 'grep', 'openat'],
                          "function" : self.stig_rule_238275,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the openat"\
                          + " system call.\033[0;0m"},
                                            
                238276 : {"cmd" : "sudo auditctl -l | grep open_by_handle_at",
                          "cmdlocal" : ['sudo', 'auditctl', '-l', '|', 'grep', 'open_by_handle_at'],
                          "function" : self.stig_rule_238276,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the "\
                          + "open_by_handle_at system call.\033[0;0m"},

                238277 : {"cmd" : "sudo auditctl -l | grep /usr/bin/sudo",
                          "cmdlocal" : ['sudo', 'auditctl', '-l', '|', 'grep', '/usr/bin/sudo'],
                          "function" : self.stig_rule_238277,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the "\
                          + " sudo command.\033[0;0m"},
                                            
                238278 : {"cmd" : "sudo auditctl -l | grep /usr/bin/sudoedit",
                          "cmdlocal" : ['sudo', 'auditctl', '-l', '|', 'grep', '/usr/bin/sudoedit'],
                          "function" : self.stig_rule_238278,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the"\
                          + " sudoedit command.\033[0;0m"},
                                            
                238279 : {"cmd" : "sudo auditctl -l | grep chsh",
                          "cmdlocal" : ['sudo', 'auditctl', '-l', '|', 'grep', 'chsh'],
                          "function" : self.stig_rule_238279,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the "\
                          + " chsh command.\033[0;0m"},
                                            
                238280 : {"cmd" : "sudo auditctl -l | grep newgrp",
                          "cmdlocal" : ['sudo', 'auditctl', '-l', '|', 'grep', 'newgrp'],
                          "function" : self.stig_rule_238280,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the "\
                          + " newgrp command.\033[0;0m"},
                                            
                238281 : {"cmd" : "sudo auditctl -l | grep chcon",
                          "cmdlocal" : ['sudo', 'auditctl', '-l', '|', 'grep', 'chcon'],
                          "function" : self.stig_rule_238281,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the "\
                          + " chcon command.\033[0;0m"},
                                            
                238282 : {"cmd" : "sudo auditctl -l | grep apparmor_parser",
                          "cmdlocal" : ['sudo', 'auditctl', '-l', '|', 'grep', 'apparmor_parser'],
                          "function" : self.stig_rule_238282,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the "\
                          + " apparmor_parser command.\033[0;0m"},
                                            
                238283 : {"cmd" : "sudo auditctl -l | grep setfacl",
                          "cmdlocal" : ['sudo', 'auditctl', '-l', '|', 'grep', 'setfacl'],
                          "function" : self.stig_rule_238283,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the setfacl "\
                          + " command.\033[0;0m"},
                                           
                238284 : {"cmd" : "sudo auditctl -l | grep chacl",
                          "cmdlocal" : ['sudo', 'auditctl', '-l', '|', 'grep', 'chacl'],
                          "function" : self.stig_rule_238284,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the chacl"\
                          + " command.\033[0;0m"},
                                           
                238285 : {"cmd" : "sudo auditctl -l | grep tallylog",
                          "cmdlocal" : ['sudo', 'auditctl', '-l', '|', 'grep', 'tallylog'],
                          "function" : self.stig_rule_238285,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for the use and modification of the tallylog"\
                          + " file.\033[0;0m"},
                
                238286 : {"cmd" : "sudo auditctl -l | grep faillog",
                          "cmdlocal" : ['sudo', 'auditctl', '-l', '|', 'grep', 'faillog'],
                          "function" : self.stig_rule_238286,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for the use and modification of faillog"\
                          + " file.\033[0;0m"},
                                            
                238287 : {"cmd" : "sudo auditctl -l | grep lastlog",
                          "cmdlocal" : ['sudo', 'auditctl', '-l', '|', 'grep', 'lastlog'],
                          "function" : self.stig_rule_238287,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for the use and modification of the lastlog"\
                          + " file.\033[0;0m"},
                                            
                238288 : {"cmd" : "sudo auditctl -l | grep -w passwd",
                          "cmdlocal" : ['sudo', 'auditctl', '-l', '|', 'grep', '-w', 'passwd'],
                          "function" : self.stig_rule_238288,
                          "rule" : "\033[1;36m Rule Title: The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the "\
                          + " passwd command.\033[0;0m"},
                                            
                238289 : {"cmd" : "sudo auditctl -l | grep -w unix_update",
                          "cmdlocal" : ['sudo', 'auditctl', '-l', '|', 'grep', '-w', 'unix_update'],
                          "function" : self.stig_rule_238289,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the"\
                          + " unix_update command.\033[0;0m"},
                                            
                238290 : {"cmd" : "sudo auditctl -l | grep -w gpasswd",
                          "cmdlocal" : ['sudo', 'auditctl', '-l', '|', 'grep', '-w', 'gpasswd'],
                          "function" : self.stig_rule_238290,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the gpasswd "\
                          + " command.\033[0;0m"},
                                            
                238291 : {"cmd" : "sudo auditctl -l | grep -w chage",
                          "cmdlocal" : ['sudo', 'auditctl', '-l', '|', 'grep', '-w', 'chage'],
                          "function" : self.stig_rule_238291,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the chage"\
                          + " command.\033[0;0m"},
                                            
                238292 : {"cmd" : "sudo auditctl -l | grep -w usermod",   
                          "cmdlocal" : ['sudo', 'auditctl', '-l', '|', 'grep', '-w', 'usermod'],
                          "function" : self.stig_rule_238292,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the usermod"\
                          + " command.\033[0;0m"},
                                            
                238293 : {"cmd" : "sudo auditctl -l | grep -w crontab",
                          "cmdlocal" : ['sudo', 'auditctl', '-l', '|', 'grep', '-w', 'crontab'],
                          "function" : self.stig_rule_238293,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the crontab "\
                          + " command.\033[0;0m"},
                                            
                238294 : {"cmd" : "sudo auditctl -l | grep -w pam_timestamp_check",
                          "cmdlocal" : ['sudo', 'auditctl', '-l', '|', 'grep', '-w', 'pam_timestamp_check'],
                          "function" : self.stig_rule_238294,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the"\
                          + "pam_timestamp_check command.\033[0;0m"},
                                            
                238295 : {"cmd" : "sudo auditctl -l | grep -w init_module",
                          "cmdlocal" : ['sudo', 'auditctl', '-l', '|', 'grep', '-w', 'init_module'],
                          "function" : self.stig_rule_238295,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the init_module "\
                          + " syscall.\033[0;0m"},
                                           
                238296 : {"cmd" : "sudo auditctl -l | grep -w finit_module",
                          "cmdlocal" : ['sudo', 'auditctl', '-l', '|', 'grep', '-w', 'finit_module'],
                          "function" : self.stig_rule_238296,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the finit_module"\
                          + " syscall.\033[0;0m"},
                                           
                238297 : {"cmd" : "sudo auditctl -l | grep -w delete_module",
                          "cmdlocal" : ['sudo', 'auditctl', '-l', '|', 'grep', '-w', 'delete_module'],
                          "function" : self.stig_rule_238297,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the delete_module"\
                          + " syscall.\033[0;0m"},

                238298 : {"cmd" : "dpkg -l | grep auditd",
                          "cmd1" : "systemctl is-enabled auditd.service",
                          "cmd2" : "systemctl is-active auditd.service",
                          "cmdlocal" : ['dpkg', '-l', '|', 'grep auditd'],
                          "cmdlocal1" : ['systemctl', 'is-enabled auditd.service'],
                          "function" : self.stig_rule_238298,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must produce audit records and reports containing information to establish when, " \
                          + "where, what type, the source,\nand the outcome for all DoD-defined auditable events and actions in near real time.\033[0;0m"},
                                            
                238299 : {"cmd" : "sudo grep \"^\s*linux\" /boot/grub/grub.cfg",
                          "cmdlocal" : [''],
                          "function" : self.stig_rule_238299,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must initiate session audits at system start-up.\033[0;0m"},
                
                238300 : {"cmd" : "sudo stat -c \"%n %a\" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/audispd",
                          "cmdlocal" : [''],
                          "function" : self.stig_rule_238300,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must configure audit tools with a mode of 0755 or less permissive.\033[0;0m"},
                                            
                238301 : {"cmd" : "sudo stat -c \"%n %U\" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/audispd",
                          "cmdlocal" : [''],
                          "function" : self.stig_rule_238301,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must configure audit tools to be owned by root.\033[0;0m"},
                                            
                238302 : {"cmd" : "sudo stat -c \"%n %G\" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/audispd",
                          "cmdlocal" : [''],
                          "function" : self.stig_rule_238302,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must configure the audit tools to be group-owned by root.\033[0;0m"},
                                            
                238303 : {"cmd" : "sudo egrep \'(\/sbin\/(audit|au))\' /etc/aide/aide.conf",
                          "cmdlocal" : [''],
                          "function" : self.stig_rule_238303,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must use cryptographic mechanisms to protect the integrity of audit tools.\033[0;0m"},
                                            
                238304 : {"cmd" : "sudo auditctl -l | grep execve",
                          "cmdlocal" : ['sudo', 'auditctl', '-l', '|', 'grep execve'],
                          "function" : self.stig_rule_238304,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must prevent all software from executing at higher privilege levels than users executing"\
                          + " the software and the\naudit system must be configured to audit the execution of privileged functions.\033[0;0m"},

		238305 : {"cmd" : "sudo grep ^log_file /etc/audit/auditd.conf",
			  "cmd1" : "sudo df –h /var/log/audit/",
			  "cmd2" : "sudo du –sh [audit_partition]",
                          "cmdlocal" : ['sudo', 'grep', '^log_file', '/etc/audit/auditd.conf'],
                          "cmdlocal1" : ['sudo', 'df', '–h', '/var/log/audit/'],
                          "cmdlocal2" : ['sudo', 'du', '–sh', '[audit_partition]'],
                          "function" : self.stig_rule_238305,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must allocate audit record storage capacity to store at least one "\
 			  + " weeks' worth of audit records, when audit records are not immediately sent to a central audit record storage facility.\033[0;0m"},

                238306 : {"cmd" : "sudo dpkg -s audispd-plugins",
			  "cmd1" : "sudo grep -i active /etc/audisp/plugins.d/au-remote.conf", 
			  "cmd2" : "sudo grep -i ^remote_server /etc/audisp/audisp-remote.conf",
                          "cmdlocal" : ['sudo', 'dpkg', '-s', 'audispd-plugins'],
                          "cmdlocal1" : ['sudo', 'grep', '-i', 'active', '/etc/audisp/plugins.d/au-remote.conf'],
                          "cmdlocal2" : ['sudo', 'grep', '-i', '^remote_server /etc/audisp/audisp-remote.conf'],
                          "function" : self.stig_rule_238306,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system audit event multiplexor must be configured to off-load audit logs "\
			  + "onto a different system or storage media\nfrom the system being audited.\033[0;0m"},
                
		238307 : {"cmd" : "sudo grep ^space_left_action /etc/audit/auditd.conf",
                          "function" : self.stig_rule_238307,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must immediately notify the SA and ISSO (at a minimum) when allocated "\
			  + "audit record storage volume reaches 75% of the repository maximum audit record storage capacity.\033[0;0m"},
   	
                238308 : {"cmd" : "timedatectl status | grep -i \"time zone\"",
                          "function" : self.stig_rule_238308,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must record time stamps for audit records that can be mapped to "\
			  + " Coordinated Universal Time (UTC) or Greenwich Mean Time (GMT).\033[0;0m"},

                238309 : {"cmd" : "sudo auditctl -l | grep sudo.log",
                          "function" : self.stig_rule_238309,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for privileged activities, nonlocal maintenance, diagnostic "\
                          + "sessions and other\nsystem-level access.\033[0;0m"},
                                     
                238310 : {"cmd" : "sudo auditctl -l | grep unlink",
                          "function" : self.stig_rule_238310,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for any successful/unsuccessful use of unlink system "\
                          + " call.\033[0;0m"},
                       
                238311 : {"cmd" : "sudo auditctl -l | grep unlinkat",
                          "function" : self.stig_rule_238311,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for any successful/unsuccessful use of unlinkat system "\
                          + " call.\033[0;0m"},
                                           
                238312 : {"cmd" : "sudo auditctl -l | grep rename",
                          "function" : self.stig_rule_238312,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for any successful/unsuccessful use of rename system "\
                          + " call.\033[0;0m"},
                                           
                238313 : {"cmd" : "sudo auditctl -l | grep renameat",
                          "function" : self.stig_rule_238313,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for any successful/unsuccessful use of renameat system "\
                          + " call.\033[0;0m"},
                                           
                238314 : {"cmd" : "sudo auditctl -l | grep init_module",
                          "function" : self.stig_rule_238314,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records when loading dynamic kernel modules.\033[0;0m"},
                                            
                238315 : {"cmd" : "sudo auditctl -l | grep "'"/var/log/wtmp"'" ",
                          "function" : self.stig_rule_238315,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for the /var/log/wtmp file.\033[0;0m"},
                                            
                238316 : {"cmd" : "sudo auditctl -l | grep "'"/var/run/wtmp"'" ",
                          "function" : self.stig_rule_238316,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for the /var/run/wtmp file.\033[0;0m"},
                                            
                238317 : {"cmd" : "sudo auditctl -l | grep "'"/var/log/btmp"'"",
                          "function" : self.stig_rule_238317,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records for the /var/log/btmp file.\033[0;0m"},
                                            
                238318 : {"cmd" : "sudo auditctl -l | grep '"'/sbin/modprobe'"'",
                          "function" : self.stig_rule_238318,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records when successful/unsuccessful attempts to use modprobe "\
                          + " command.\033[0;0m"},
                                            
                238319 : {"cmd" : "sudo auditctl -l | grep kmod",
                          "function" : self.stig_rule_238319,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records when successful/unsuccessful attempts to use the kmod"\
                          + " command.\033[0;0m"},
                                            
                238320 : {"cmd" : "sudo auditctl -l | grep fdisk",   
                          "function" : self.stig_rule_238320,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate audit records when successful/unsuccessful attempts to use the fdisk "\
                          + " command.\033[0;0m"},
                                            
                238324 : {"cmd" : "grep -E -r \'^(auth,authpriv\.\*|daemon\.\*)\' /etc/rsyslog.* ",
                          "function" : self.stig_rule_238324,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must monitor remote access methods.\033[0;0m"},

                238325 : {"cmd" : "cat /etc/login.defs | grep -i encrypt_method",
                          "function" : self.stig_rule_238325,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must encrypt all stored passwords with a FIPS 140-2 approved cryptographic hashing"\
                          + " algorithm.\033[0;0m"},

                238328 : {"cmd" : "sudo ufw show raw",
                          "function" : self.stig_rule_238328,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must be configured to prohibit or restrict the use of functions, ports, protocols, "\
                          + " and/or services, as\ndefined in the PPSM CAL and vulnerability assessments.\033[0;0m"},
                                           
                238329 : {"cmd" : "sudo passwd -S root",
                          "function" : self.stig_rule_238329,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must prevent direct login into the root account.\033[0;0m"},
                                           
                238330 : {"cmd" : "sudo grep INACTIVE /etc/default/useradd",
                          "function" : self.stig_rule_238330,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must disable account identifiers (individuals, groups, roles, and devices) after "\
                          + "35 days of inactivity.\033[0;0m"},
                
                238331 : {"cmd" : "sudo chage -l account_name | grep expires",
                          "function" : self.stig_rule_238331,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must automatically remove or disable emergency accounts after 72 hours.\033[0;0m"},
                
                238332 : {"cmd" : "sudo find / -type d -perm -002 ! -perm -1000",
                          "function" : self.stig_rule_238332,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must set a sticky bit on all public directories to prevent unauthorized and unintended "\
                          + "information transferred\nvia shared system resources.\033[0;0m"},
                                            
                238333 : {"cmd" : "sysctl net.ipv4.tcp_syncookies",
                          "cmd2" : "sudo grep -i net.ipv4.tcp_syncookies /etc/sysctl.conf /etc/sysctl.d/* | grep -v '#' ",
                          "function" : self.stig_rule_238333,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must be configured to use TCP syncookies.\033[0;0m"},
                                            
                238334 : {"cmd" : "systemctl is-active kdump.service",
                          "function" : self.stig_rule_238334,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must disable kernel core dumps so that it can fail to a secure state if "\
                          + " system initialization fails, shutdown\nfails or aborts fail.\033[0;0m"},
                                            
                238335 : {"cmd" : "sudo fdisk -l",
                          "function" : self.stig_rule_238335,
                          "rule" : "\033[1;36mRule Title: Ubuntu operating systems handling data requiring '"'data at rest'"' protections must employ cryptographic mechanisms "\
                          + " to prevent unauthorized\ndisclosure and modification of the information at rest.\033[0;0m"},

        	238336 : {"cmd" : "dpkg -l | grep mfetp ",
			  "cmd1" : "/opt/McAfee/ens/tp/init/mfetpd-control.sh status ",
                          "function" : self.stig_rule_238336,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must deploy Endpoint Security for Linux Threat Prevention (ENSLTP).\033[0;0m"},
                                            
                238337 : {"cmd" : "sudo find /var/log -perm /137 -type f -exec stat -c \"%n %a\" {} \;",
                          "function" : self.stig_rule_238337,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must generate error messages that provide information necessary for corrective actions "\
                          + "without revealing\ninformation that could be exploited by adversaries.\033[0;0m"},

                238338 : {"cmd" : "sudo stat -c \"%n %G\" /var/log",
                          "function" : self.stig_rule_238338,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must configure the /var/log directory to be group-owned by syslog.\033[0;0m"},
                                            
                238339 : {"cmd" : "sudo stat -c \"%n %U\" /var/log",
                          "function" : self.stig_rule_238339,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must configure the /var/log directory to be owned by root.\033[0;0m"},
                                            
                238340 : {"cmd" : "stat -c \"%n %a\" /var/log",
                          "function" : self.stig_rule_238340,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must configure the /var/log directory to have mode 0750 or less permissive.\033[0;0m"},
                                            
                238341 : {"cmd" : "sudo stat -c \"%n %G\" /var/log/syslog",
                          "function" : self.stig_rule_238341,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must configure the /var/log/syslog file to be group-owned by adm.\033[0;0m"},
                                            
                238342 : {"cmd" : "sudo stat -c \"%n %U\" /var/log/syslog",
                          "function" : self.stig_rule_238342,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must configure /var/log/syslog file to be owned by syslog.\033[0;0m"},
                                           
                238343 : {"cmd" : "sudo stat -c \"%n %a\" /var/log/syslog",
                          "function" : self.stig_rule_238343,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must configure /var/log/syslog file with mode 0640 or less permissive.\033[0;0m"},
                                           
                238344 : {"cmd" : "sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type d -exec stat -c \"%n %a\" \'{}\' \;",
                          "function" : self.stig_rule_238344,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must have directories that contain system commands set to a mode of 0755 or less"\
                          + " permissive.\033[0;0m"},
                                           
                238345 : {"cmd" : "sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type d -exec stat -c \"%n %U\" \'{}\' \;",   
                          "function" : self.stig_rule_238345,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must have directories that contain system commands owned by root.\033[0;0m"},
                                            
                238346 : {"cmd" : "sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type d -exec stat -c \"%n %G\" \'{}\' \;",
                          "function" : self.stig_rule_238346,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must have directories that contain system commands group-owned by root.\033[0;0m"},
                                            
                238347 : {"cmd" : "sudo find /lib /lib64 /usr/lib -perm /022 -type f -exec stat -c \"%n %a\" \'{}\' \;",
                          "function" : self.stig_rule_238347,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system library files must have mode 0755 or less permissive.\033[0;0m"},
                                            
                238348 : {"cmd" : "sudo find /lib /lib64 /usr/lib -perm /022 -type d -exec stat -c \"%n %a\" \'{}\' \;",
                          "function" : self.stig_rule_238348,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system library directories must have mode 0755 or less permissive.\033[0;0m"},
                                           
                238349 : {"cmd" : "sudo find /lib /usr/lib /lib64 ! -user root -type f -exec stat -c \"%n %U\" \'{}\' \;",
                          "function" : self.stig_rule_238349,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system library files must be owned by root.\033[0;0m"},
                                           
                238350 : {"cmd" : "sudo find /lib /usr/lib /lib64 ! -user root -type d -exec stat -c \"%n %U\" \'{}\' \;",
                          "function" : self.stig_rule_238350,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system library directories must be owned by root.\033[0;0m"},
                                           
                238351 : {"cmd" : "sudo find /lib /usr/lib /lib64 ! -group root -type f -exec stat -c \"%n %G\" \'{}\' \;",
                          "function" : self.stig_rule_238351,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system library files must be group-owned by root.\033[0;0m"},
                                            
                238352 : {"cmd" : "sudo find /lib /usr/lib /lib64 ! -group root -type d -exec stat -c \"%n %G\" \'{}\' \;",
                          "function" : self.stig_rule_238352,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system library directories must be group-owned by root.\033[0;0m"},
                                            
                238353 : {"cmd" : "dpkg -l | grep rsyslog    ",
                          "cmd2" : "systemctl is-enabled rsyslog ",
                          "cmd3" : "systemctl is-active rsyslog ",
                          "function" : self.stig_rule_238353,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must be configured to preserve log records from failure events.\033[0;0m"},
                                            
                238354 : {"cmd" : "dpkg -l | grep ufw",
                          "function" : self.stig_rule_238354,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must have an application firewall installed in order to control remote access "\
                          + " methods.\033[0;0m"},
                                            
                238355 : {"cmd" : "systemctl is-enabled ufw",
                          "cmd2" : "systemctl is-active ufw",
                          "function" : self.stig_rule_238355,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must enable and run the uncomplicated firewall(ufw).\033[0;0m"},
                                            
                238356 : {"cmd" : "sudo grep maxpoll /etc/chrony/chrony.conf",
                          "cmd2" : "grep -i server /etc/chrony/chrony.conf",
                          "function" : self.stig_rule_238356,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must, for networked systems, compare internal information system clocks" \
                          + " at least every 24 hours\nwith a server which is synchronized to one of the redundant United States Naval Observatory (USNO) time "\
                          + " servers, or a time server designated\nfor the appropriate DoD network (NIPRNet/SIPRNet), and/or the Global Positioning System"\
                          + " (GPS).\033[0;0m"},
 		
		238357 : {"cmd" : "sudo grep makestep /etc/chrony/chrony.conf ",
                          "function" : self.stig_rule_238357,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must synchronize internal information system clocks to the authoritative "\
			  + "time source when the time difference\nis greater than one second.\033[0;0m"},             

                238358 : {"cmd" : "grep SILENTREPORTS /etc/default/aide",
                          "function" : self.stig_rule_238358,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must notify designated personnel if baseline configurations are changed"\
                          + " in an unauthorized manner. The file\nintegrity tool must notify the System Administrator when changes to the baseline configuration"\
                          + " or anomalies in the oper\033[0;0m"},
                                            
                238359 : {"cmd" : "grep AllowUnauthenticated /etc/apt/apt.conf.d/*",
                          "function" : self.stig_rule_238359,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system's Advance Package Tool (APT) must be configured to prevent the installation "\
                          + "of patches, service packs, device\ndrivers, or Ubuntu operating system components without verification they have been digitally signed"\
                          + " using a certificate that is recognized and approved by the\norganization.\033[0;0m"},
                                            
                238360 : {"cmd" : "dpkg -l | grep apparmor",
                          "cmd1" : "systemctl is-active apparmor.service",
                          "cmd2" : "systemctl is-enabled apparmor.service",
                          "function" : self.stig_rule_238360,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must be configured to use AppArmor.\033[0;0m"},
                                            
                238361 : {"cmd" : "exits",
                          "function" : self.stig_rule_238361,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must allow the use of a temporary password for system logons with an "\
                          + "immediate change to a permanent password.\033[0;0m"},
                          
                238362 : {"cmd" : "sudo grep offline_credentials_expiration /etc/sssd/sssd.conf /etc/sssd/conf.d/*.conf ",
                          "function" : self.stig_rule_238362,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must be configured such that Pluggable Authentication "\
			  + " Module (PAM) prohibits the use of cached authentications after one day.\033[0;0m"},

                238364 : {"cmd" : "for f in $(ls /etc/ssl/certs); do openssl x509 -sha256 -in $f -noout -fingerprint | cut -d= -f2 | tr -d ':' | egrep -vw",
                          "function" : self.stig_rule_238364,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must only allow the use of DoD PKI-established certificate authorities"\
                          + " for verification of the establishment\nof protected sessions.\033[0;0m"},
                                           
                238365 : {"cmd" : "  sudo fdisk -l",
                          "cmd2" : "more /etc/crypttab",
                          "function" : self.stig_rule_238365,
                          "rule" : "\033[1;36mRule Title: Ubuntu operating system must implement cryptographic mechanisms to prevent unauthorized modification"\
                          + " of all information at rest.\033[0;0m"},
                       
                238366 : {"cmd" : "sudo fdisk -l",
                          "cmd2" : "more /etc/crypttab",
                          "function" : self.stig_rule_238366,
                          "rule" : "\033[1;36mRule Title: Ubuntu operating system must implement cryptographic mechanisms to prevent unauthorized disclosure of"\
                          + " all information at rest.\033[0;0m"},
                                            
                238367 : {"cmd" : "sudo ss -l46ut",
                          "cmd1" : "sudo ufw status ",
                          "function" : self.stig_rule_238367,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must configure the uncomplicated firewall to rate-limit impacted network "\
                          + "interfaces.\033[0;0m"},
                                            
                238368 : {"cmd" : "dmesg | grep -i '"'execute disable'"'",
                          "cmd2" : "grep flags /proc/cpuinfo | grep -w nx | sort -u ",
                          "function" : self.stig_rule_238368,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must implement non-executable data to protect its memory from unauthorized "\
                          + "code execution.\033[0;0m"},
                                            
                238369 : {"cmd" : "sudo sysctl kernel.randomize_va_space",
                          "cmd2" : "cat /proc/sys/kernel/randomize_va_space",
                          "cmd3" : "sudo egrep -R '"'^kernel.randomize_va_space=[^2]'"' /etc/sysctl.conf /etc/sysctl.d",
                          "function" : self.stig_rule_238369,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must implement address space layout randomization to protect its memory "\
                          + "from unauthorized code execution.\033[0;0m"},
                                            
                238370 : {"cmd" : "grep -i remove-unused /etc/apt/apt.conf.d/50unattended-upgrades",
                          "function" : self.stig_rule_238370,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must be configured so that Advance Package Tool (APT) removes all software "\
                          + "components after updated versions\nhave been installed.\033[0;0m"},
                                            
                238371 : {"cmd" : "sudo dpkg -l | grep aide",
                          "function" : self.stig_rule_238371,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must use a file integrity tool to verify correct operation of all security "\
                          + " functions.\033[0;0m"},
                                            
                238372 : {"cmd" : "sudo grep SILENTREPORTS /etc/default/aide",
                          "function" : self.stig_rule_238372,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must notify designated personnel if baseline configurations are changed "\
                          + "in an unauthorized manner.\nThe file integrity tool must notify the System Administrator when changes to the baseline configuration "\
                          + "or anomalies in the operation of\nany security functions are discovered.\033[0;0m"},
                                            
                238374 : {"cmd" : "sudo systemctl status ufw.service | grep -i \"active:\"",
                          "function" : self.stig_rule_238374,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must have an application firewall enabled.\033[0;0m"},        

                238375 : {"cmd" : "ls -L -d /sys/class/net/*/wireless | xargs dirname | xargs basename",
                          "function" : self.stig_rule_238375,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must disable all wireless network adapters.\033[0;0m"},
                                            
                238376 : {"cmd" : "sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type f -exec stat -c '"'%n %a'"' "'"{}"'" \;",
                          "function" : self.stig_rule_238376,
                          "rule" : "\033[1;36m Rule Title: The Ubuntu operating system must have system commands set to a mode of 0755 or less permissive.\033[0;0m"},
                                           
                238377 : {"cmd" : "sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type f -exec stat -c '"'%n %U'"' "'"{}"'" \;",
                          "function" : self.stig_rule_238377,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must have system commands owned by root.\033[0;0m"},
                
                238378 : {"cmd" : "sudo find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type f -exec stat -c '"'%n %G'"' "'"{}"'" \;",
                          "function" : self.stig_rule_238378,
                          "rule" : "\033[1;36mRule Title: The Ubuntu operating system must have system commands group-owned by root.\033[0;0m"},
                }

   
    # FUNCTION/METHOD of the 'VulnScanner' 
    def stig_scan(self):

        # Get rule title
        finding="Vul ID {} is \033[1;31m FINDING \033[0;0m\n".format(self.vuln_id)
        not_finding="Vul ID {} is \033[1;32m NOT FINDING \033[0;0m \n".format(self.vuln_id)

        if(self.conn == "local"):
            r = subprocess.run(self.stig_rulebook[self.vuln_id]["cmd"], capture_output=True, text=True, shell=True)
            ro = r.stdout
        else:
            # Use ssh protocol exec_command  and pass rules from dictionary taking vuln id and asking for "cmd" rule to test
            stdin, stdout, stderr=self.conn.exec_command(self.stig_rulebook[self.vuln_id]["cmd"])
            ro=''.join(stdout.readlines()) 

        # Verify if server passes this vuln id using rules
        # This result looks through stored rules below functions
        result = self.stig_rulebook[self.vuln_id]['function'](ro)
        rule_title=self.stig_rulebook[self.vuln_id]["rule"]

        # This output below prints results
        # prints rule and "finding" or "non finding" if the server violates the stig rules
        print(rule_title)
        if(result) == "finding":
            print(finding)
        elif(result) == "not_finding":
            print(not_finding)

    def stig_rule_238201(self, ro):
        if re.search("No such file or directory", ro):
            return "finding"
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("#use_mappers", ro):
            return "finding"
        if re.search("use_mappers" and "pwent", ro):
            return "not_finding"
        else:
            return "finding"

    def stig_rule_238204(self, ro):
        if re.search("password_pbkdf2", ro):
            return "not_finding"
        else:
            return "finding"

    def stig_rule_238206(self, ro):
        if(len(ro.strip())) == 0 or 1:
            return "not_finding"
        else:
            return "finding"

    def stig_rule_238215(self, ro):
        if(self.conn == "local"):
            r = subprocess.run(self.stig_rulebook[self.vuln_id]["cmd1"], capture_output=True, text=True, shell=True)
            ro1 = r.stdout
        else:
            stdin, stdout, stderr=self.conn.exec_command(self.stig_rulebook[self.vuln_id]["cmd1"])
            ro1=''.join(stdout.readlines()) 

        if re.search("openssh-client", ro):
            if re.search("openssh-server", ro):
                if re.search("openssh-sftp-server", ro):
                    if re.search("Loaded", ro1):
                            if re.search("Active", ro1):
                                return "not_finding"
                            else:
                                return "finding"
                    else:
                        return "finding"
                else:
                    return "finding"
            else:
                return "finding"
        else:
            return "finding"

    def stig_rule_238218(self, ro):
        if re.search("#PermitEmptyPasswords" or "#PermitUserEnvironment", ro):
            return "finding"
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("PermitEmptyPasswords no", ro):
            if re.search("PermitUserEnvironment no", ro):
                return "not_finding"
        else:
            return "finding"

    def stig_rule_238219(self, ro):
        if re.search("#X11Forwarding", ro):
            return "finding"
        if re.search("X11Forwarding yes", ro):
            return "finding"
        if re.search("X11Forwarding no", ro):
            return "not_finding"
        else:
            return "finding"

    def stig_rule_238326(self, ro):
        if(len(ro.strip())) == 0:
            return "not_finding"
        else:
            return "finding"

    def stig_rule_238327(self, ro):
        if(len(ro.strip())) == 0:
            return "not_finding"
        else:
            return "finding"

    def stig_rule_238363(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("1", ro):
            return "not_finding"
        else:
            return "finding"

    def stig_rule_238379(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("logout=''", ro):
            return "not_finding"
        else:
            return "finding"

    def stig_rule_238380(self, ro):
        if re.findall("inactive" and "dead", ro):
            return "not_finding"
        else:
            return "finding"

    ###############################
    ## BIGIN CAT2 RULEBOOK   
    ###############################
    def stig_rule_238196(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        print("\n\n\033[1;33mVuln_id 238196 Verify any temporary accounts expire within 72 hours of account creation"\
              + " expiration time of 72 hours\033[0;0m")
        user = ro.splitlines()
        if(self.conn == "local"):
            for name in user:
                print("Account: " +str(name))
                r = subprocess.run("sudo chage -l "+name+" | grep expires",capture_output=True,text=True,shell=True)
                ro1 = r.stdout
                print(ro1)
            return "finding"
        else:
            for name in user:
                print("Account: " + str(name))
                stdin, stdout, stderr=self.conn.exec_command("sudo chage -l "+name+" | grep expires")
                rout=''.join(stdout.readlines())
                print(rout)    
            return "finding"

    def stig_rule_238197(self, ro):
        if re.search("No such file or directory", ro) or len(ro.strip()) == 0:
            if(self.conn == "local"):
                r = subprocess.run(self.stig_rulebook[self.vuln_id]["cmd1"],capture_output=True,text=True,shell=True)
                ro1 = r.stdout
                if(len(ro1.strip())) == 0:
                    return "finding"
                if re.search("ibanner-message-enable=true", ro):
                    return "not_finding"
                if re.findall("#banner-message-enable",ro1) or re.findall("banner-message-enable=false",ro1):
                    return "finding"
                if re.search("/usr/bin/byobu-select-session",ro1) or re.search("/usr/bin/dbus-run-session",ro1):
                    return "not_finding"
                else:
                    return "finding"
            else:
                if re.search("ibanner-message-enable=true", ro):
                    return "not_finding"
                if re.findall("#banner-message-enable" or "banner-message-enable=false", ro):
                    return "finding"
                else:
                    return "finding"

    def stig_rule_238198(self, ro):
        if re.search("No such file or directory", ro) or len(ro.strip()) == 0:
            if(self.conn == "local"):
                r = subprocess.run(self.stig_rulebook[self.vuln_id]["cmd1"],capture_output=True,text=True,shell=True)
                ro1 = r.stdout
                if(len(ro1.strip())) == 0:
                    return "finding"
                if re.search("#banner", ro):
                    return "finding"
                if re.search("/usr/bin/byobu-select-session",ro1) or re.search("/usr/bin/dbus-run-session",ro1):
                    return "not_finding"
                else:
                    return "finding"
            else:
                stdin, stdout, stderr=self.conn.exec_command(self.stig_rulebook[self.vuln_id]["cmd1"])
                ro1=''.join(stdout.readlines())
                print("ro1 --> ",ro1)
                if re.search("/usr/bin/byobu-select-session",ro1) or re.search("/usr/bin/dbus-run-session",ro1):
                    return "not_finding"
            if re.search("banner-message-text=\"You are accessing a U.S. Government \(USG\) Information System \(IS\) that is provided for"\
                         + " USG-authorized use only.\s+By using this IS \(which includes any device attached to this IS\), you consent to the"\
                         + " following conditions:\s+-The USG routinely intercepts and monitors communications on this IS for purposes including,"\
                         + " but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct \(PM\),"\
                         + " law enforcement \(LE\), and counterintelligence \(CI\) investigations.\s+-At any time, the USG may inspect and seize data"\
                         + " stored on this IS.\s+-Communications using, or data stored on, this IS are not private, are subject to routine monitoring,"\
                         + " interception, and search, and may be disclosed or used for any USG-authorized purpose.\s+-This IS includes security measures"\
                         + " \(e.g., authentication and access controls\) to protect USG interests--not for your personal benefit or privacy.\s+-Notwithstanding"\
                         + " the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of"\
                         + " privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, "\
                         + " or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.", ro):
                return "not_finding"
            if re.search("#banner", ro):
                return "finding"
            else:
                return "finding"

    def stig_rule_238199(self, ro):
        if re.search("true", ro):
            return "not_finding"
        else:
            return "finding"

    def stig_rule_238200(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("vlock", ro):
            return "not_finding"
        else:
            return "finding"

    def stig_rule_238205(self, ro):
        if(len(ro.strip())) == 0:
            return "not_finding"
        else:
            return "finding"

    def stig_rule_238207(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.findall("#TMOUT=", ro):
            return "finding"
        if re.search("TMOUT=", ro):
            return "not_finding"
        else:
            return "finding"

    def stig_rule_238208(self, ro):
        #print("output is " + str(ro))
        if re.search("NOPASSWD" or "!authenticate", ro):
            return "finding"
        else:
            return "not_finding"

    def stig_rule_238209(self, ro):
        if re.search("#UMASK", ro):
            return "finding"
        if re.search("UMASK" and "077", ro):
            return "not_finding"
        else:
            return "finding"

    def stig_rule_238210(self, ro):
        if(self.conn == "local"):
            r = subprocess.run(self.stig_rulebook[self.vuln_id]["cmd1"], capture_output=True, text=True, shell=True)
            ro1 = r.stdout
        else:
            stdin, stdout, stderr=self.conn.exec_command(self.stig_rulebook[self.vuln_id]["cmd1"])
            ro1=''.join(stdout.readlines()) 

        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("libpam-pkcs11" and "smart cards", ro):
            if re.search("PubkeyAuthentication" and "yes", ro1):
                return "not_finding"
            else:
                return "finding"
        else:
            return "finding"
            
    def stig_rule_238211(self, ro):
        if re.search("UsePam" and "yes", ro):
            return "not_finding"
        else:
            return "finding"
    
    def stig_rule_238212(self, ro):
        if re.search("#ClientAliveCountMax", ro):
            return "finding"
        if re.search("ClientAlivecountMax" and "1", ro):
            return "not_finding"
        else:
            return "finding"

    def stig_rule_238213(self, ro):
        if re.search("#ClientAliveInterval", ro):
            return "finding"
        if re.search("ClientAliveInterval" and "600", ro):
            return "not_finding"
        else:
            return "finding"

    def stig_rule_238214(self, ro):
        print("\033[1;33m--Vuln_id 238214 needs to be manually configured-------\033[0;0m")
        print("\033[1;33mGet copy of Standard Mandatory DoD Notice and Consent Banner and verify.\033[0;0m")
        return "finding"
        
        """
        print("\033[1;32mNEED TO LOOK AT THIS ITEM IN MORE DETAIL\033[0;0m")
        if re.search("#Banner" or "none", ro):
            return "finding"
        if re.search("Banner" and "/etc/issue.net", ro):
            stdin, stdout, stderr=ssh.exec_command(self.stig_rulebook[self.vuln_id]["cmd1"])
            
            ro=''.join(stdout.readlines())
            print("response is " + str(ro))
            
            if re.findall("You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only."\
                         + "By using this IS (which includes any device attached to this IS), you consent to the following conditions:"\
                         + "-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited "\
                         + "to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement "\
                         + "(LE), and counterintelligence (CI) investigations."\
                         + "-At any time, the USG may inspect and seize data stored on this IS."\
                         + "-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception,"\
                         + "and search, and may be disclosed or used for any USG-authorized purpose."\
                         + "-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your"\
                         + " personal benefit or privacy."\
                         + "-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring "\
                         + "of the content of privileged communications, or work product, related to personal representation or services by attorneys, "\
                         + "psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential."\
                         + "  See User Agreement for details.", ro):
                return "not_finding"
            else:
                return "finding"
        """

    def stig_rule_238216(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("#MACs", ro):
            return "finding"
        if re.search("MACs hmac-sha2-512" and "hmac-sha2-256", ro):
            return "not_finding"
        else:
            return "finding"

    def stig_rule_238217(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("#Ciphers", ro):
            return "finding"
        if re.search("Ciphers" and "aes256-ctr" and "aes192-ctr" and "aes128-ctr", ro):
            return "not_finding"
        else:
            return "finding"

    def stig_rule_238220(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("#X11UseLocalhost", ro):
            return "finding"
        if re.search("X11useLocalhost" and "yes", ro):
            return "not_finding"
        else:
            return "finding"
    
    def stig_rule_238225(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("No such file or directory", ro):
            return "finding"
        if re.search("#minlen", ro):
            return "finding"
        if re.search("minlen" and "15", ro):
            return "not_finding"
        else:
            return "finding"
   

    def stig_rule_238227(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("No such file or directory", ro):
            return "finding"
        if re.search("#dictcheck", ro):
            return "finding"
        if re.search("dictcheck" and "1", ro):
            return "not_finding"
        else:
            return "finding"
    
    
    def stig_rule_238228(self, ro):
        if(self.conn == "local"):
            r = subprocess.run(self.stig_rulebook[self.vuln_id]["cmd1"], capture_output=True, text=True, shell=True)
            ro1 = r.stdout
            
            r1 = subprocess.run(self.stig_rulebook[self.vuln_id]["cmd2"], capture_output=True, text=True, shell=True)
            ro2 = r1.stdout
        else:
            stdin, stdout, stderr=self.conn.exec_command(self.stig_rulebook[self.vuln_id]["cmd1"])
            ro1=''.join(stdout.readlines()) 
            
            stdin, stdout, stderr=self.conn.exec_command(self.stig_rulebook[self.vuln_id]["cmd2"])
            ro2=''.join(stdout.readlines()) 

        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("ii",ro) and re.search("libpam-pwquality:amd64",ro) and re.search("PAM module", ro):
            if re.search("enforcing",ro1) and re.search("1",ro1):
                if(len(ro1.strip())) == 0:
                    return "finding"
                if re.search("#enforcing",ro1):
                    return "finding"
                if re.search("enforcing = 1",ro1):
                    if(len(ro2.strip())) == 0:
                        return "finding"
                    if re.search("#password",ro2):
                        return "finding"
                    if re.search("retry=3",ro2):
                        return "not_finding"
                    else:
                        return "finding"
            else:
                return "finding"
        else:
            return "finding"
    
    
    def stig_rule_238229(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("#cert_policy", ro):
                return "not_finding"
        if re.search("cert_policy", ro):
            if re.search("ca", ro):
                return "not_finding"
            else:
                return "finding"
        else:
            return "finding"
    
    
    def stig_rule_238230(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("libpam-pkcs11", ro):
                return "not_finding"
        else:
            return "finding"
    
    
    def stig_rule_238231(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("opensc-pkcs11", ro):
            return "not_finding"
        else:
            return "finding"
   

    def stig_rule_238232(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("#cert_policy", ro):
                return "not_finding"
        if re.search("cert_policy", ro):
            if re.search("ocsp_on", ro):
                return "not_finding"
            else:
                return "finding"
        else:
            return "finding"
   

    def stig_rule_238233(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("#cert_policy", ro):
                return "not_finding"
        if re.search("cert_policy", ro):
            if re.search("crl_auto", ro):
                return "not_finding"
            else:
                return "finding"
        else:
            return "finding"

    def stig_rule_238234(self, ro):
        # need to correct this to greated than 5
        print("output is " + str(ro))
        print("\033[1;33m--should i leave in use_authtok and try_first_pass------\033[0;0m\n")
        print("\033[1;33m----I DON'T SEE ANYMORE IN STIG----\033[0;0m\n")
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("#remember", ro):
            return "finding"
        if re.search("remember=5", ro):
            return "not_finding"
        else:
            return "finding"

    def stig_rule_238235(self, ro):
        #print("output is " + str(ro))
        print("\033[1;33m--I DON'T SEE ANYMORE IN STIG------\033[0;0m\n")
        
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("#audit", ro):
            return "finding"
        if re.search("audit", ro):
            return "not_finding"
        else:
            return "finding"
    
    def stig_rule_238236(self, ro):
        if(self.conn == "local"):
            r = subprocess.run(self.stig_rulebook[self.vuln_id]["cmd1"], capture_output=True, text=True, shell=True)
            ro1 = r.stdout
            
            r1 = subprocess.run(self.stig_rulebook[self.vuln_id]["cmd2"], capture_output=True, text=True, shell=True)
            ro2 = r.stdout
        else:
            stdin, stdout, stderr=self.conn.exec_command(self.stig_rulebook[self.vuln_id]["cmd1"])
            ro1=''.join(stdout.readlines())
            if(len(ro1.strip())) == 0:
                    return "finding"
            stdin, stdout, stderr=self.conn.exec_command(self.stig_rulebook[self.vuln_id]["cmd2"])
            ro2=''.join(stdout.readlines())
            if(len(ro2.strip())) == 0:
                    return "finding"

        num1 = ro1.split()[0]
        num2 = ro2.split()[0]

        if num1 == num2:
            return "not_finding"
        else:
            return "finding"

    def stig_rule_238237(self, ro):
        # change to 4000000 or greater
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("pam_faildelay", ro):
            if re.search("4000000", ro):
                return "not_finding"
            else:
                return "finding"
        else:
            return "finding"

    def stig_rule_238238(self, ro):
        if(len(ro.strip())) == 0:
            print("Check if autidctl is installed")
            return "finding"
        if re.search("-w /etc/passwd -p wa -k usergroup_modification", ro):
            return "not_finding"
        else:
            return "finding"
    
    def stig_rule_238239(self, ro):
        if(len(ro.strip())) == 0:
            print("Check if autidctl is installed")
            return "finding"
        if re.search("-w /etc/group -p wa -k usergroup_modification", ro):
            return "not_finding"
        else:
            return "finding"
    
    def stig_rule_238240(self, ro):
        if(len(ro.strip())) == 0:
            print("Check if autidctl is installed")
            return "finding"
        if re.search("-w /etc/shadow -p wa -k usergroup_modification", ro):
            return "not_finding"
        else:
            return "finding"
    
    def stig_rule_238241(self, ro):
        if(len(ro.strip())) == 0:
            print("Check if autidctl is installed")
            return "finding"
        if re.search("-w /etc/gshadow -p wa -k usergroup_modification", ro):
            return "not_finding"
        else:
            return "finding"
    
    def stig_rule_238242(self, ro):
        if(len(ro.strip())) == 0:
            print("Check if autidctl is installed")
            return "finding"
        if re.search("-w /etc/security/opasswd -p wa -k usergroup_modification", ro):
            return "not_finding"
        else:
            return "finding"
    
    def stig_rule_238243(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("action_mail_acct = root", ro):
            return "not_finding"
        else:
            return "finding"
    
    def stig_rule_238244(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("SYSLOG", ro):
            return "not_finding"
        if re.search("SINGLE", ro):
            return "not_finding"
        if re.search("HALT", ro):
            return "not_finding"
        else:
            return "finding"
    
    def stig_rule_238245(self, ro):
        # CAN MODIFY TO CHECK FOR STICKY BIT
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("log_file = /var/log/audit/audit.log", ro):
            
            if(self.conn == "local"):
                r = subprocess.run(self.stig_rulebook[self.vuln_id]["cmd1"], capture_output=True, text=True, shell=True)
                ro1 = r.stdout
                if(len(ro1.strip())) == 0:
                    return "finding"

                fname = ro1.split()
                for name in fname:

                    r1 = subprocess.run(self.stig_rulebook[self.vuln_id]["cmd2"]+name, capture_output=True, text=True, shell=True)
                    ro2 = r1.stdout
                    perm = re.findall(r"\b\d{3}\b", ro2)
                  
                    if ( int(perm[0]) > 600 ):
                        return "finding"
                return "not_finding"
            else:
                stdin, stdout, stderr=self.conn.exec_command(self.stig_rulebook[self.vuln_id]["cmd1"])
                ro1=''.join(stdout.readlines())
                if(len(ro1.strip())) == 0:
                        return "finding"

                fname = ro1.split()
                for name in fname:

                    stdin, stdout, stderr=self.conn.exec_command(self.stig_rulebook[self.vuln_id]["cmd2"]+name)
                    ro2=''.join(stdout.readlines())
                    perm = re.findall(r"\b\d{3}\b", ro2)
                
                    if (int(perm[0]) > 600 ):
                        return "finding"
                return "not_finding"
    
    def stig_rule_238246(self, ro):
        # CAN MODIFY TO CHECK FOR STICKY BIT
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("log_file = /var/log/audit/audit.log", ro):
            
            if(self.conn == "local"):
                r = subprocess.run(self.stig_rulebook[self.vuln_id]["cmd1"], capture_output=True, text=True, shell=True)
                ro1 = r.stdout
                if(len(ro1.strip())) == 0:
                    return "finding"

                fname = ro1.split()
                for name in fname:

                    r1 = subprocess.run(self.stig_rulebook[self.vuln_id]["cmd2"]+name, capture_output=True, text=True, shell=True)
                    ro2 = r1.stdout
                    own = ro2.split() 
                    owner = own[-1]
        
                    if(owner != "root"):
                        return "finding"
                    else:
                        return "not_finding"
            else:
                stdin, stdout, stderr=self.conn.exec_command(self.stig_rulebook[self.vuln_id]["cmd1"])
                ro1=''.join(stdout.readlines())
                if(len(ro1.strip())) == 0:
                        return "finding"

                fname = ro1.split()
                for name in fname:

                    stdin, stdout, stderr=self.conn.exec_command(self.stig_rulebook[self.vuln_id]["cmd2"]+name)
                    ro2=''.join(stdout.readlines())
                    own = ro2.split() 
                    owner = own[-1]
        
                    if(owner != "root"):
                        return "finding"
                    else:
                        return "not_finding"

    def stig_rule_238247(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("log_group = root", ro):
            if(self.conn == "local"):
                r = subprocess.run(self.stig_rulebook[self.vuln_id]["cmd2"], capture_output=True, text=True, shell=True)
                ro1 = r.stdout
                if(len(ro1.strip())) == 0:
                    return "finding"
            else:
                stdin, stdout, stderr=self.conn.exec_command(self.stig_rulebook[self.vuln_id]["cmd2"])
                ro1=''.join(stdout.readlines())
                if(len(ro1.strip())) == 0:
                        return "finding"

        if re.search("log_file = /var/log/audit/audit.log", ro1):
            if(self.conn == "local"):
                r = subprocess.run(self.stig_rulebook[self.vuln_id]["cmd1"], capture_output=True, text=True, shell=True)
                ro2 = r.stdout
                if(len(ro1.strip())) == 0:
                    return "finding"

                fname = ro2.split()
                for name in fname:

                    r1 = subprocess.run(self.stig_rulebook[self.vuln_id]["cmd3"]+name, capture_output=True, text=True, shell=True)
                    r2 = r1.stdout
                    own = r2.split() 
                    owner = own[-1]
        
                    if(owner != "root"):
                        return "finding"
                    else:
                        return "not_finding"
            else:
                stdin, stdout, stderr=self.conn.exec_command(self.stig_rulebook[self.vuln_id]["cmd1"])
                ro2=''.join(stdout.readlines())
                if(len(ro1.strip())) == 0:
                        return "finding"

                fname = ro2.split()
                for name in fname:

                    stdin, stdout, stderr=self.conn.exec_command(self.stig_rulebook[self.vuln_id]["cmd3"]+name)
                    r2=''.join(stdout.readlines())
                    own = ro2.split() 
                    owner = own[-1]
        
                    if(owner != "root"):
                        return "finding"
                    else:
                        return "not_finding"

    def stig_rule_238248(self, ro):
        # CAN MODIFY TO CHECK FOR STICKY BIT
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("log_file = /var/log/audit/audit.log", ro):
            
            if(self.conn == "local"):
                r = subprocess.run(self.stig_rulebook[self.vuln_id]["cmd1"], capture_output=True, text=True, shell=True)
                ro1 = r.stdout
                if(len(ro1.strip())) == 0:
                    return "finding"

                fname = ro1.split()
                for name in fname:

                    r1 = subprocess.run(self.stig_rulebook[self.vuln_id]["cmd2"]+name, capture_output=True, text=True, shell=True)
                    ro2 = r1.stdout
                    perm = re.findall(r"\b\d{3}\b", ro2)
                  
                    if ( int(perm[0]) > 750 ):
                        return "finding"
                return "not_finding"

            else:
                stdin, stdout, stderr=self.conn.exec_command(self.stig_rulebook[self.vuln_id]["cmd1"])
                ro1=''.join(stdout.readlines())
                if(len(ro1.strip())) == 0:
                        return "finding"

                fname = ro1.split()
                for name in fname:
                    stdin, stdout, stderr=self.conn.exec_command(self.stig_rulebook[self.vuln_id]["cmd2"]+name)
                    ro2=''.join(stdout.readlines())
                    perm = re.findall(r"\b\d{3}\b", ro2)
                
                    if ( int(perm[0]) > 750 ):
                        return "finding"
                return "not_finding"
        
    def stig_rule_238249(self, ro):
        # can modify to be if file have mode more permissive than 0640 is a finding
        if(len(ro.strip())) == 0:
            return "finding"
        
        fname = ro.split()
        for name in fname:
            if re.match(r'-', name):
                if(name != "-rw-r-----"):
                    print(name)
                    return "finding"
        return "not_finding"

    def stig_rule_238250(self, ro):
        if(self.conn == "local"):
            r = subprocess.run(self.stig_rulebook[self.vuln_id]["cmd"], capture_output=True, text=True, shell=True)
            ro2 = r.stdout
            if(len(ro2.strip())) == 0:
                return "finding"

            fname = ro2.split()
            for name in fname:

                r1 = subprocess.run(self.stig_rulebook[self.vuln_id]["cmd2"]+name, capture_output=True, text=True, shell=True)
                r2 = r1.stdout
                own = r2.split() 
                owner = own[-1]
    
                if(owner != "root"):
                    return "finding"

            r = subprocess.run(self.stig_rulebook[self.vuln_id]["cmd1"], capture_output=True, text=True, shell=True)
            ro2 = r.stdout
            if(len(ro2.strip())) == 0:
                return "finding"

            fname = ro2.split()
            for name in fname:

                r1 = subprocess.run(self.stig_rulebook[self.vuln_id]["cmd3"]+name, capture_output=True, text=True, shell=True)
                r2 = r1.stdout
                own = r2.split() 
                owner = own[-1]
    
                if(owner != "root"):
                    return "finding"
                else:
                    return "not_finding"
        else:
            stdin, stdout, stderr=self.conn.exec_command(self.stig_rulebook[self.vuln_id]["cmd"])
            rout=''.join(stdout.readlines())
            if(len(rout.strip())) == 0:
                return "finding"
            
            fname = rout.split()
            for name in fname:
                stdin, stdout, stderr=self.conn.exec_command(self.stig_rulebook[self.vuln_id]["cmd2"]+name)
                rout=''.join(stdout.readlines())
                own = rout.split() 
                owner = own[-1]
            
                if(owner != "root"):
                    return "finding"

            stdin, stdout, stderr=self.conn.exec_command(self.stig_rulebook[self.vuln_id]["cmd1"])
            rout=''.join(stdout.readlines())
            if(len(rout.strip())) == 0:
                return "finding"
            
            fname = rout.split()
            for name in fname:
                stdin, stdout, stderr=self.conn.exec_command(self.stig_rulebook[self.vuln_id]["cmd3"]+name)
                rout=''.join(stdout.readlines())
                own = rout.split() 
                owner = own[-1]
            
                if(owner != "root"):
                    return "finding"
                else:
                    return "not_finding"

    def stig_rule_238251(self, ro):
        if(self.conn == "local"):
            r = subprocess.run(self.stig_rulebook[self.vuln_id]["cmd"], capture_output=True, text=True, shell=True)
            ro2 = r.stdout
            if(len(ro2.strip())) == 0:
                return "finding"

            fname = ro2.split()
            for name in fname:
                r1 = subprocess.run(self.stig_rulebook[self.vuln_id]["cmd2"]+name, capture_output=True, text=True, shell=True)
                r2 = r1.stdout
                own = r2.split() 
                owner = own[-1]
    
                if(owner != "root"):
                    return "finding"

            r = subprocess.run(self.stig_rulebook[self.vuln_id]["cmd1"], capture_output=True, text=True, shell=True)
            ro2 = r.stdout
            if(len(ro2.strip())) == 0:
                return "finding"

            fname = ro2.split()
            for name in fname:
                r1 = subprocess.run(self.stig_rulebook[self.vuln_id]["cmd3"]+name, capture_output=True, text=True, shell=True)
                r2 = r1.stdout
                own = r2.split() 
                owner = own[-1]
    
                if(owner != "root"):
                    return "finding"
                else:
                    return "not_finding"
        else:
            stdin, stdout, stderr=self.conn.exec_command(self.stig_rulebook[self.vuln_id]["cmd"])
            rout=''.join(stdout.readlines())
            if(len(rout.strip())) == 0:
                return "finding"
            
            fname = rout.split()
            for name in fname:
                stdin, stdout, stderr=self.conn.exec_command(self.stig_rulebook[self.vuln_id]["cmd2"]+name)
                rout=''.join(stdout.readlines())
                own = rout.split() 
                owner = own[-1]
            
                if(owner != "root"):
                    return "finding"

            stdin, stdout, stderr=self.conn.exec_command(self.stig_rulebook[self.vuln_id]["cmd1"])
            rout=''.join(stdout.readlines())
            if(len(rout.strip())) == 0:
                return "finding"
            
            fname = rout.split()
            for name in fname:
                stdin, stdout, stderr=self.conn.exec_command(self.stig_rulebook[self.vuln_id]["cmd3"]+name)
                rout=''.join(stdout.readlines())
                own = rout.split() 
                owner = own[-1]
            
                if(owner != "root"):
                    return "finding"
                else:
                    return "not_finding"
  
    def stig_rule_238252(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("-a always,exit -S all -F path=/bin/su -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-priv_change", ro):
            return "not_finding"
        else:
            return "finding"

    def stig_rule_238253(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("-a always,exit -S all -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-chfn", ro):
            return "not_finding"
        else:
            return "finding"
    
    def stig_rule_238254(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("-a always,exit -S all -F path=/usr/bin/mount -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-mount", ro):
            return "not_finding"
        else:
            return "finding"
      
    def stig_rule_238255(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("-a always,exit -S all -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-umount", ro):
            return "not_finding"
        else:
            return "finding"
    
    def stig_rule_238256(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("-a always,exit -S all -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-ssh", ro):
            return "not_finding"
        else:
            return "finding"
       
    def stig_rule_238257(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("-a always,exit -S all -F path=/usr/lib/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-ssh", ro):
            return "not_finding"
        else:
            return "finding"
        
    def stig_rule_238258(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("-a always,exit -F arch=b32 -S setxattr -F auid>=1000 -F auid!=-1 -F key=perm_mod", ro):
            if re.search("-a always,exit -F arch=b32 -S setxattr -F auid=0 -F key=perm_mod", ro):
                if re.search("-a always,exit -F arch=b64 -S setxattr -F auid>=1000 -F auid!=-1 -F key=perm_mod", ro):
                    if re.search("-a always,exit -F arch=b64 -S setxattr -F auid=0 -F key=perm_mod", ro):
                        return "not_finding"
                    else:
                        return "finding"
                else:
                    return "finding"
            else:
                return "finding"
        else:
            return "finding"
    
    def stig_rule_238259(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("-a always,exit -F arch=b32 -S lsetxattr -F auid>=1000 -F auid!=-1 -F key=perm_mod", ro):
            if re.search("-a always,exit -F arch=b32 -S lsetxattr -F auid=0 -F key=perm_mod", ro):
                if re.search("-a always,exit -F arch=b64 -S lsetxattr -F auid>=1000 -F auid!=-1 -F key=perm_mod", ro):
                    if re.search("-a always,exit -F arch=b64 -S lsetxattr -F auid=0 -F key=perm_mod", ro):
                        return "not_finding"
                    else:
                        return "finding"
                else:
                    return "finding"
            else:
                return "finding"
        else:
            return "finding"
    
    def stig_rule_238260(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("-a always,exit -F arch=b32 -S fsetxattr -F auid>=1000 -F auid!=-1 -F key=perm_mod", ro):
            if re.search("-a always,exit -F arch=b32 -S fsetxattr -F auid=0 -F key=perm_mod", ro):
                if re.search("-a always,exit -F arch=b64 -S fsetxattr -F auid>=1000 -F auid!=-1 -F key=perm_mod", ro):
                    if re.search("-a always,exit -F arch=b64 -S fsetxattr -F auid=0 -F key=perm_mod", ro):
                        return "not_finding"
                    else:
                        return "finding"
                else:
                    return "finding"
            else:
                return "finding"
        else:
            return "finding"
       
    def stig_rule_238261(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("-a always,exit -F arch=b32 -S removexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod", ro):
            if re.search("-a always,exit -F arch=b32 -S removexattr -F auid=0 -F key=perm_mod", ro):
                if re.search("-a always,exit -F arch=b64 -S removexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod", ro):
                    if re.search("-a always,exit -F arch=b64 -S removexattr -F auid=0 -F key=perm_mod", ro):
                        return "not_finding"
                    else:
                        return "finding"
                else:
                    return "finding"
            else:
                return "finding"
        else:
            return "finding"
        
    def stig_rule_238262(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("-a always,exit -F arch=b64 -S lremovexattr -F auid=0 -F key=perm_mod", ro):
            if re.search("-a always,exit -F arch=b32 -S lremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod", ro):
                if re.search("-a always,exit -F arch=b32 -S lremovexattr -F auid=0 -F key=perm_mod", ro):
                    if re.search("-a always,exit -F arch=b64 -S lremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod", ro):
                        return "not_finding"
                    else:
                        return "finding"
                else:
                    return "finding"
            else:
                return "finding"
        else:
            return "finding"
        
    def stig_rule_238263(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("-a always,exit -F arch=b32 -S fremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod", ro):
            if re.search("-a always,exit -F arch=b32 -S fremovexattr -F auid=0 -F key=perm_mod", ro):
                if re.search("-a always,exit -F arch=b64 -S fremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod", ro):
                    if re.search("-a always,exit -F arch=b64 -S fremovexattr -F auid=0 -F key=perm_mod", ro):
                        return "not_finding"
                    else:
                        return "finding"
                else:
                    return "finding"
            else:
                return "finding"
        else:
            return "finding"
       
    def stig_rule_238264(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("-a always,exit -F arch=b32 -S chown -F auid>=1000 -F auid!=-1 -F key=perm_chng", ro):
            if re.search("-a always,exit -F arch=b64 -S chown -F auid>=1000 -F auid!=-1 -F key=perm_chng", ro):
                return "not_finding"
            else:
                return "finding"
        else:
            return "finding"
      
    def stig_rule_238265(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("-a always,exit -F arch=b32 -S fchown -F auid>=1000 -F auid!=-1 -F key=perm_chng", ro):
            if re.search("-a always,exit -F arch=b64 -S fchown -F auid>=1000 -F auid!=-1 -F key=perm_chng", ro):
                return "not_finding"
            else:
                return "finding"
        else:
            return "finding"
        
    def stig_rule_238266(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("-a always,exit -F arch=b32 -S fchownat -F auid>=1000 -F auid!=-1 -F key=perm_chng", ro):
            if re.search("-a always,exit -F arch=b64 -S fchownat -F auid>=1000 -F auid!=-1 -F key=perm_chng", ro):
                return "not_finding"
            else:
                return "finding"
        else:
            return "finding"
        
    def stig_rule_238267(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("-a always,exit -F arch=b32 -S lchown -F auid>=1000 -F auid!=-1 -F key=perm_chng", ro):
            if re.search("-a always,exit -F arch=b64 -S lchown -F auid>=1000 -F auid!=-1 -F key=perm_chng", ro):
            	return "not_finding"
            else:
                return "finding"
        else:
            return "finding"
        
    def stig_rule_238268(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("-a always,exit -F arch=b32 -S chmod -F auid>=1000 -F auid!=-1 -F key=perm_chng", ro):
            if re.search("-a always,exit -F arch=b64 -S chmod -F auid>=1000 -F auid!=-1 -F key=perm_chng", ro):
               return "not_finding"
            else:
                return "finding"
        else:
            return "finding"
    
    def stig_rule_238269(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("-a always,exit -F arch=b32 -S fchmod -F auid>=1000 -F auid!=-1 -F key=perm_chng", ro):
            if re.search("-a always,exit -F arch=b64 -S fchmod -F auid>=1000 -F auid!=-1 -F key=perm_chng", ro):
               return "not_finding"
            else:
                return "finding"
        else:
            return "finding"
       
    def stig_rule_238270(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("-a always,exit -F arch=b32 -S fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_chng", ro):
            if re.search("-a always,exit -F arch=b64 -S fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_chng", ro):
                if re.search("", ro):
            	    return "not_finding"
            else:
                return "finding"
        else:
            return "finding"
    
    def stig_rule_238271(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("-a always,exit -F arch=b32 -S open -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=perm_access", ro):
            if re.search("-a always,exit -F arch=b32 -S open -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=perm_access", ro):
                if re.search("-a always,exit -F arch=b64 -S open -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=perm_access", ro):
                    if re.search("-a always,exit -F arch=b64 -S open -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=perm_access", ro):
                        return "not_finding"
                    else:
                        return "finding"
                else:
                    return "finding"
            else:
                return "finding"
        else:
            return "finding"
    
    def stig_rule_238272(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("-a always,exit -F arch=b32 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=perm_access", ro):
            if re.search("-a always,exit -F arch=b32 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=perm_access", ro):
                if re.search("-a always,exit -F arch=b64 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=perm_access", ro):
                    if re.search("-a always,exit -F arch=b64 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=perm_access", ro):
                        return "not_finding"
                    else:
                        return "finding"
                else:
                    return "finding"
            else:
                return "finding"
        else:
            return "finding"
       
    def stig_rule_238273(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("-a always,exit -F arch=b32 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=perm_access", ro):
            if re.search("-a always,exit -F arch=b32 -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=perm_access", ro):
                if re.search("-a always,exit -F arch=b64 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=perm_access", ro):
                    if re.search("-a always,exit -F arch=b64 -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=perm_access", ro):
                        return "not_finding"
                    else:
                        return "finding"
                else:
                    return "finding"
            else:
                return "finding"
        else:
            return "finding"
    
    def stig_rule_238274(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("-a always,exit -F arch=b32 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=perm_access", ro):
            if re.search("-a always,exit -F arch=b32 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=perm_access", ro):
                if re.search("-a always,exit -F arch=b64 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=perm_access", ro):
                    if re.search("-a always,exit -F arch=b64 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=perm_access", ro):
                        return "not_finding"
                    else:
                        return "finding"
                else:
                    return "finding"
            else:
                return "finding"
        else:
            return "finding"
    
    def stig_rule_238275(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("-a always,exit -F arch=b32 -S openat -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=perm_access", ro):
            if re.search("-a always,exit -F arch=b32 -S openat -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=perm_access", ro):
                if re.search("-a always,exit -F arch=b64 -S openat -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=perm_access", ro):
                    if re.search("-a always,exit -F arch=b64 -S openat -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=perm_access", ro):
                        return "not_finding"
                    else:
                        return "finding"
                else:
                    return "finding"
            else:
                return "finding"
        else:
            return "finding"
    
    def stig_rule_238276(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("-a always,exit -F arch=b32 -S open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=perm_access", ro):
            if re.search("-a always,exit -F arch=b32 -S open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=perm_access", ro):
                if re.search("-a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=perm_access", ro):
                    if re.search("-a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=perm_access", ro):
                        return "not_finding"
                    else:
                        return "finding"
                else:
                    return "finding"
            else:
                return "finding"
        else:
            return "finding"
    
    def stig_rule_238277(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("-a always,exit -S all -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=-1 -F key=priv_cmd", ro):
            return "not_finding"
        else:
            return "finding"
    
    def stig_rule_238278(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("-a always,exit -S all -F path=/usr/bin/sudoedit -F perm=x -F auid>=1000 -F auid!=-1 -F key=priv_cmd", ro):
            return "not_finding"
        else:
            return "finding"
        
    def stig_rule_238279(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("-a always,exit -S all -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=-1 -F key=priv_cmd", ro):
            return "not_finding"
        else:
            return "finding"
        
    def stig_rule_238280(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("-a always,exit -S all -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=-1 -F key=priv_cmd", ro):
            return "not_finding"
        else:
            return "finding"
    
    def stig_rule_238281(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("-a always,exit -S all -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=-1 -F key=perm_chng", ro):
           return "not_finding"
        else:
            return "finding"
        
    def stig_rule_238282(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("-a always,exit -S all -F path=/sbin/apparmor_parser -F perm=x -F auid>=1000 -F auid!=-1 -F key=perm_chng", ro):
           return "not_finding"
        else:
            return "finding"
        
    def stig_rule_238283(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("-a always,exit -S all -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=-1 -F key=perm_chng", ro):
          return "not_finding"
        else:
            return "finding"
    
    def stig_rule_238284(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("", ro):
            if re.search("-a always,exit -S all -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=-1 -F key=perm_chng", ro):
               return "not_finding"
        else:
            return "finding"
    
    def stig_rule_238285(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("-w /var/log/tallylog -p wa -k logins", ro):
            return "not_finding"
        else:
            return "finding"
       
    def stig_rule_238286(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("-w /var/log/faillog -p wa -k logins", ro):
           return "not_finding"
        else:
            return "finding"
        
    def stig_rule_238287(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("-w /var/log/lastlog -p wa -k logins", ro):
           return "not_finding"
        else:
            return "finding"
       
    def stig_rule_238288(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("-a always,exit -S all -F path=/usr/bin/passwd -F perm=x -F auid>=500 -F auid!=-1 -F key=privileged-passwd", ro):
        	return "not_finding"
        else:
            return "finding"
    
    def stig_rule_238289(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("-a always,exit -S all -F path=/sbin/unix_update -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-unix-update", ro):
           return "not_finding"
        else:
            return "finding"
    
    def stig_rule_238290(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("-a always,exit -S all -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-gpasswd", ro):
            return "not_finding"
        else:
            return "finding"
    
    def stig_rule_238291(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("-a always,exit -S all -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-chage", ro):
            return "not_finding"
        else:
            return "finding"
    
    def stig_rule_238292(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("-a always,exit -S all -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-usermod", ro):
            return "not_finding"
        else:
            return "finding"
    
    def stig_rule_238293(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("-a always,exit -S all -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-crontab", ro):
           return "not_finding"
        else:
            return "finding"
    
    def stig_rule_238294(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("-a always,exit -S all -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-pam_timestamp_check", ro):
           return "not_finding"
        else:
            return "finding"
    
    def stig_rule_238295(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("-a always,exit -F arch=b32 -S init_module -F auid>=1000 -F auid!=-1 -F key=module_chng", ro):
            if re.search("-a always,exit -F arch=b64 -S init_module -F auid>=1000 -F auid!=-1 -F key=module_chng", ro):
               return "not_finding"
            else:
                return "finding"
        else:
            return "finding"
    
    def stig_rule_238296(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("-a always,exit -F arch=b32 -S finit_module -F auid>=1000 -F auid!=-1 -F key=module_chng", ro):
            if re.search("-a always,exit -F arch=b64 -S finit_module -F auid>=1000 -F auid!=-1 -F key=module_chng", ro):
            	return "not_finding"
            else:
                return "finding"
        else:
            return "finding"
    
    def stig_rule_238297(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("-a always,exit -F arch=b32 -S delete_module -F auid>=1000 -F auid!=-1 -F key=module_chng", ro):
            if re.search("-a always,exit -F arch=b64 -S delete_module -F auid>=1000 -F auid!=-1 -F key=module_chng", ro):
                return "not_finding"
            else:
                return "finding"
        else:
            return "finding"
    
    def stig_rule_238298(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("auditd", ro):
            if(self.conn == "local"):
                r = subprocess.run(self.stig_rulebook[self.vuln_id]["cmd1"], capture_output=True, text=True, shell=True)
                ro1 = r.stdout
                if(len(ro1.strip())) == 0:
                    return "finding"
                if re.search("enabled", ro1):
                    r = subprocess.run(self.stig_rulebook[self.vuln_id]["cmd2"], capture_output=True, text=True, shell=True)
                    ro1 = r.stdout
                    if(len(ro1.strip())) == 0:
                        return "finding"
                    if re.search("active",ro1):
                        return "not_finding"
                    else:
                        return "finding"
                else:
                    return "finding"
            else:
                stdin, stdout, stderr=self.conn.exec_command(self.stig_rulebook[self.vuln_id]["cmd1"])
                ro2=''.join(stdout.readlines())
                if(len(ro2.strip())) == 0:
                    return "finding"
                if re.search("enabled", ro2):
                    stdin, stdout, stderr=self.conn.exec_command(self.stig_rulebook[self.vuln_id]["cmd2"])
                    ro3=''.join(stdout.readlines())
                    if(len(ro3.strip())) == 0:
                        return "finding"
                    if re.search("active",ro3):
                        return "not_finding"
                    else:
                        return "finding"
                else:
                    return "finding"
        else:
            return "finding"
    
    def stig_rule_238299(self, ro):
        #should add to check all functions
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("audit=1", ro):
                return "not_finding"
        else:
            return "finding"
    
    def stig_rule_238300(self, ro):
        # Can modify to check for sticky bit
        # need to look into permissions more
        if(len(ro.strip())) == 0:
            return "finding"
        
        fname = ro.splitlines()
        for name in fname:
            perm = re.findall(r"\b\d{3}\b", name)
            if (int(perm[0]) > 755):
                return "finding"
        return "not_finding"

    def stig_rule_238301(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        own = ro.split()
        owner = own[-1]
        
        if(owner != "root"):
            return "finding"
        else:
            return "not_finding"

    def stig_rule_238302(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        own = ro.split()
        owner = own[-1]
        
        if(owner != "root"):
            return "finding"
        else:
            return "not_finding"
   
    def stig_rule_238303(self, ro):
        if re.search("/sbin/auditctl",ro) and re.search("p\+i\+n\+u\+g\+s\+b\+acl\+xattrs\+sha512", ro):
            if re.search("/sbin/auditd p\+i\+n\+u\+g\+s\+b\+acl\+xattrs\+sha512", ro):
                if re.search("/sbin/ausearch p\+i\+n\+u\+g\+s\+b\+acl\+xattrs\+sha512", ro):
                    if re.search("/sbin/aureport p\+i\+n\+u\+g\+s\+b\+acl\+xattrs\+sha512", ro):
                        if re.search("/sbin/autrace p\+i\+n\+u\+g\+s\+b\+acl\+xattrs\+sha512", ro):
                            if re.search("/sbin/audispd p\+i\+n\+u\+g\+s\+b\+acl\+xattrs\+sha512", ro):
                                if re.search("/sbin/augenrules p\+i\+n\+u\+g\+s\+b\+acl\+xattrs\+sha512", ro):
                                    return "not_finding"
                                else:
                                    print("a")
                                    return "finding"
                            else:
                                print("b")
                                return "finding"
                        else:
                            print("c")
                            return "finding"
                    else:
                        print("d")
                        return "finding"
                else:
                    print("e")
                    return "finding"
            else:
                print("f")
                return "finding"
        else:
            print("g")
            return "finding"
    
    def stig_rule_238304(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -F key=execpriv", ro):
            if re.search("-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -F key=execpriv", ro):
                if re.search("-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -F key=execpriv", ro):
                    if re.search("-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -F key=execpriv", ro):
                        return "not_finding"
                    else:
                        return "finding"
                else:
                    return "finding"
            else:
                return "finding"
        else:
            return "finding"
    
    def stig_rule_238305(self, ro):
        print("\033[1;33m--Perform manual test-------\033[0;0m")
        return "finding"
    
    def stig_rule_238306(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("Status", ro):
            if re.search("installed", ro):
                if(self.conn == "local"):
                    r = subprocess.run(self.stig_rulebook[self.vuln_id]["cmd1"], capture_output=True, text=True, shell=True)
                    ro1 = r.stdout
                    if(len(ro.strip())) == 0:
                        return "finding"
                    if re.search("#active", ro):
                        return "finding"
                    if re.search("active", ro):
                        if re.search("no", ro):
                            return "finding"
                        if re.search("yes", ro):
                            r = subprocess.run(self.stig_rulebook[self.vuln_id]["cmd2"], capture_output=True, text=True, shell=True)
                            ro1 = r.stdout
                            if(len(ro.strip())) == 0:
                                return "finding"
                            else:
                                return "not_finding"
                        else:
                            return "finding"
                    else:
                        return "finding"
                else:
                    stdin, stdout, stderr=self.conn.exec_command(self.stig_rulebook[self.vuln_id]["cmd1"])
                    ro=''.join(stdout.readlines())
                    if(len(ro.strip())) == 0:
                        return "finding"
                    if re.search("#active", ro):
                        return "finding"
                    if re.search("active", ro):
                        if re.search("no", ro):
                            return "finding"
                        if re.search("yes", ro):
                            stdin, stdout, stderr=self.conn.exec_command(self.stig_rulebook[self.vuln_id]["cmd2"])
                            ro=''.join(stdout.readlines())
                            if(len(ro.strip())) == 0:
                                return "finding"
                            else:
                                return "not_finding"
                        else:
                            return "finding"
                    else:
                        return "finding"
            else:
                return "finding"
        else:
            return "finding"
                
    def stig_rule_238307(self, ro):
        print("\033[1;33m--need to configure file-------\033[0;0m")
        return "finding"
    
    def stig_rule_238308(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        print("output " + str(ro))
        if re.search("Time zone", ro):
            print("1")
            if re.search("GMT" or "(UTC, +0000)", ro):
                print("2")
                return "not_finding"
            else:
                print("3")
                return "finding"
        else:
            print("4")
            return "finding"

    def stig_rule_238309(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("-w /var/log/sudo.log -p wa -k maintenance", ro):
            return "not_finding"
        else:
            return "finding"

    def stig_rule_238310(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("-a always,exit -F arch=b64 -S unlink -F auid>=1000 -F auid!=-1 -F key=delete", ro):
            if re.search("-a always,exit -F arch=b32 -S unlink -F auid>=1000 -F auid!=-1 -F key=delete", ro):
                return "not_finding"
            else:
                return "finding"
        else:
            return "finding"
    
    def stig_rule_238311(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("-a always,exit -F arch=b64 -S unlinkat -F auid>=1000 -F auid!=-1 -F key=delete", ro):
            if re.search("-a always,exit -F arch=b32 -S unlinkat -F auid>=1000 -F auid!=-1 -F key=delete", ro):
                return "not_finding"
            else:
                return "finding"
        else:
            return "finding"
    
    def stig_rule_238312(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("-a always,exit -F arch=b64 -S rename -F auid>=1000 -F auid!=-1 -F key=delete", ro):
            if re.search("-a always,exit -F arch=b32 -S rename -F auid>=1000 -F auid!=-1 -F key=delete", ro):
                return "not_finding"
            else:
                return "finding"
        else: 
           return "finding"
    
    def stig_rule_238313(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("-a always,exit -F arch=b64 -S renameat -F auid>=1000 -F auid!=-1 -F key=delete", ro):
            if re.search("-a always,exit -F arch=b32 -S renameat -F auid>=1000 -F auid!=-1 -F key=delete", ro):
                return "not_finding"
            else: 
                return "finding"
        else:
            return "finding"
    
    def stig_rule_238314(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("-a always,exit -F arch=b32 -S init_module -F key=modules",ro):
            if re.search("-a always,exit -F arch=b64 -S init_module -F key=modules",ro):
                return "not_finding"
            else:
                print("a")
                return "finding"
        else:
            print("b")
            return "finding"
    
    def stig_rule_238315(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("", ro):
            return "not_finding"
        else:
            return "finding"
    
    def stig_rule_238316(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("", ro):
            return "not_finding"
        else:
            return "finding"
       
    def stig_rule_238317(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("", ro):
            return "not_finding"
        else:
            return "finding"
       
    def stig_rule_238318(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("", ro):
            return "not_finding"
        else:
            return "finding"
    
    def stig_rule_238319(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("", ro):
            return "not_finding"
        else:
            return "finding"
    
    def stig_rule_238320(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("", ro):
            return "not_finding"
        else:
            return "finding"
    
    def stig_rule_238321(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("audit-offload", ro):
            return "not_finding"
        else:
            print("Create a script that offloads audit logs to external media and runs weekly.")
            return "finding"

    def stig_rule_238323(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("", ro):
            return "not_finding"
        else:
            return "finding"
    
    def stig_rule_238324(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("auth.#", ro):
            return "not_finding"
        if re.search("authpriv.*", ro):
            return "not_finding"
        if re.search("daemon.*", ro):
            return "not_working"
        else:
            return "finding"
    
    def stig_rule_238325(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("ENCRYPT_METHOD", ro):
            if re.search("SHA512", ro):
                return "not_finding"
            else:
                return "finding"
        else:
            return "finding"

    def stig_rule_238326(self, ro):
        if(len(ro.strip())) == 0:
            return "not_finding"
        else:
            return "finding"

    def stig_rule_238327(self, ro):
        if(len(ro.strip())) == 0:
            return "not_finding"
        else:
            return "finding"

    def stig_rule_238328(self, ro):
        print("\033[1;33m--Vuln_id 238328 needs to be manually configured-------\033[0;0m")
        print("\033[1;33mAsk the System Administrator for the site or program PPSM CLSA. "\
              + "Verify the services allowed by the firewall match the PPSM CLSA\033[0;0m")
        return "finding"
    
    def stig_rule_238329(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("root L", ro):
            return "not_finding"
        else:
            return "finding"

    def stig_rule_238330(self, ro):
        # Can modify to check between values
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("#", ro):
            return "finding"
        if re.search("INACTIVE=35", ro):
            return "not_finding"
        else:
            return "finding"
    
    def stig_rule_238331(self, ro):
        print("\033[1;33m--need to be manually configured-------\033[0;0m")
        return "finding"
    
    def stig_rule_238332(self, ro):
        if(len(ro.strip())) == 0:
            return "not_finding"
        else:
            return "finding"
    
    def stig_rule_238333(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("net.ipv4.tcp_syncookies = 1", ro):
            return "not_finding"
        else:
            return "finding"
    
    def stig_rule_238334(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("inactive", ro):
            return "not_finding"
        else:
            return "finding"
    
    def stig_rule_238335(self, ro):
        print("\033[1;33m--Vuln_id 238335 needs to be manually configured-------\033[0;0m")
        print("\033[1;33mVerify system partitions are encrypted.\033[0;0m")
        return "finding"

    def stig_rule_238336(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("mfetp", ro):
            return "not_finding"
        else:
            return "finding"

    def stig_rule_238337(self, ro):
        if(len(ro.strip())) == 0:
            return "not_finding"
        else:
            return "finding"
    
    def stig_rule_238338(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("/var/log syslog", ro):
            return "not_finding"
        else:
            return "finding"

    def stig_rule_238339(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("/var/log root", ro):
            return "not_finding"
        else:
            return "finding"
    
    def stig_rule_238340(self, ro):
        # modify to 750 or greater
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("/var/log 775", ro):
            return "not_finding"
        else:
            return "finding"

    def stig_rule_238341(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("/var/log/syslog adm", ro):
            return "not_finding"
        else:
            return "finding"
    
    def stig_rule_238342(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("/var/log/syslog syslog", ro):
            return "not_finding"
        else:
            return "finding"

    def stig_rule_238343(self, ro):
        # can modify to check if value of 640 or less permissive return is a finding
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("/var/log/syslog 640", ro):
            return "not_finding"
        else:
            return "finding"

    def stig_rule_238344(self, ro) :
        if(len(ro.strip())) == 0:
            return "not_finding"
        else:
            return "finding"

    def stig_rule_238345(self, ro):
        if(len(ro.strip())) == 0:
            return "not_finding"
        else:
            return "finding"
    
    def stig_rule_238346(self, ro):
        if(len(ro.strip())) == 0:
            return "not_finding"
        else:
            return "finding"
   
    def stig_rule_238347(self, ro):
        if(len(ro.strip())) == 0:
            return "not_finding"
        else:
            return "finding"
    
    def stig_rule_238348(self, ro):
        if(len(ro.strip())) == 0:
            return "not_finding"
        else:
            return "finding"
    
    def stig_rule_238349(self, ro):
        if(len(ro.strip())) == 0:
            return "not_finding"
        else:
            return "finding"
    
    def stig_rule_238350(self, ro):
        if(len(ro.strip())) == 0:
            return "not_finding"
        else:
            return "finding"

    def stig_rule_238351(self, ro):
        if(len(ro.strip())) == 0:
            return "not_finding"
        else:
            return "finding"

    def stig_rule_238352(self, ro):
        if(len(ro.strip())) == 0:
            return "not_finding"
        else:
            return "finding"
    
    def stig_rule_238353(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("rsyslog", ro):
            return "not_finding"
        else:
            return "finding"
    
    def stig_rule_238354(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("ufw", ro):
            return "not_finding"
        else:
            return "finding"
    
    def stig_rule_238355(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("enabled", ro):
            return "not_finding"
        else:
            return "finding"
    
    def stig_rule_238356(self, ro):
        print("\033[1;33m--Configure system clock manually--\033[0;0m")
        return "finding"

    def stig_rule_238357(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("makestep 1 -1", ro):
            return "not_finding"
        else:
            return "finding"
    
    def stig_rule_238358(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("#SILENTREPORTS", ro):
            return "finding"
        if re.search("SILENTREPORTS=yes", ro):
            return "finding"
        if re.search("SILENTREPORTS=no", ro):
            return "not_finding"
        if re.search("SILENTREPORTS=", ro):
            return "finding"
        else:
            return "finding"

    def stig_rule_238359(self, ro):
        if(len(ro.strip())) == 0:
            return "not_finding"
        else:
            return "finding"
    
    def stig_rule_238360(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("apparmor", ro):
            if(self.conn == "local"):
                r = subprocess.run(self.stig_rulebook[self.vuln_id]["cmd1"], capture_output=True, text=True, shell=True)
                ro1 = r.stdout
                if(len(ro.strip())) == 0:
                    return "finding"
                if re.search("active", ro1):
                    r = subprocess.run(self.stig_rulebook[self.vuln_id]["cmd2"], capture_output=True, text=True, shell=True)
                    ro2 = r.stdout
                    if(len(ro.strip())) == 0:
                        return "finding"
                    if re.search("enabled", ro2):
                        return "not_finding"
                    else:
                        return "finding"
                else:
                    return "finding"
            else:
                stdin, stdout, stderr=self.conn.exec_command(self.stig_rulebook[self.vuln_id]["cmd1"])
                ro=''.join(stdout.readlines())
                if(len(ro.strip())) == 0:
                    return "finding"
                if re.search("active", ro):
                    stdin, stdout, stderr=self.conn.exec_command(self.stig_rulebook[self.vuln_id]["cmd2"])
                    ro=''.join(stdout.readlines())
                    if(len(ro.strip())) == 0:
                        return "finding"
                    if re.search("enabled", ro):
                        return "not_finding"
                    else:
                        return "finding"
                else:
                    return "finding"
        else:
            return "finding"
    
    def stig_rule_238361(self, ro):
        print("\033[1;33mVuln_id 238361 -- Verify a policy exists that ensures when a user account is created, it is created using a method that "\
                + "forces\na user to change their password upon their next login. -----\033[0;0m")
        return "finding"
    
    def stig_rule_238362(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("offline_credentials_expiration = 1", ro):
            return "not_finding"
        else:
            return "finding"

    def stig_rule_238364(self, ro):
        print("\033[1;33m--Vuln_id 238365 needs to be manually configured-------\033[0;0m")
        print("\033[1;33mVerify certs.\033[0;0m")
        return "finding"

    def stig_rule_238365(self, ro):
        print("\033[1;33m--Vuln_id 238365 needs to be manually configured-------\033[0;0m")
        print("\033[1;33mVerify system partitions are encrypted.\033[0;0m")
        return "finding"
   
    def stig_rule_238366(self, ro):
        print("\033[1;33m--Vuln_id 238366 needs to be manually configured-------\033[0;0m")
        print("\033[1;33mVerify system partitions are encrypted.\033[0;0m")
        return "finding"
    
    def stig_rule_238367(self, ro):
        print("\033[1;33m--Vuln_id 238367 needs to be manually configured-------\033[0;0m")
        print("\033[1;33mVerify Application Firewall is configured.\033[0;0m")
        return "finding"

        """
        if(len(ro.strip())) == 0:
            return "finding"
        print("output is " + str(ro))
        stdin, stdout, stderr=ssh.exec_command(self.stig_rulebook[self.vuln_id]["cmd1"])
        rout=''.join(stdout.readlines())
        print("out " + str(ro))
        if re.search("inactive", rout):
            print("a")
            return "finding"
        """
    def stig_rule_238368(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("NX", ro):
            if re.search("(Execute Disable)", ro):
                if re.search("protection: active", ro):
                    return "not_finding"
                else:
                    return "finding"
            else:
                return "finding"
        else:
            return "finding"
    
    def stig_rule_238369(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("kernel.randomize_va_space = 2", ro):
            return "not_finding"
        else:
            return "finding"
    
    def stig_rule_238370(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("//Unattended-Upgrade", ro):
            return "finding"
        if re.search("Unattended-Upgrade::Remove-Unused-Kernel-Packages \"true\";", ro):
            if re.search("Unattended-Upgrade::Remove-Unused-Dependencies \"true\";", ro):
                return "not_finding"
            else:
                return "finding"
        else:
            return "finding"
    
    def stig_rule_238371(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("aide", ro):
            return "not_finding"
        else:
            return "finding"
        
    def stig_rule_238372(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("#SILENTREPORTS", ro):
            return "finding"
        if re.search("SILENTREPORTS=yes", ro):
            return "finding"
        if re.search("SILENTREPORTS=no", ro):
            return "not_finding"
        else:
            return "finding"
    
    def stig_rule_238374(self, ro):
        if(len(ro.strip())) == 0:
            return "finding"
        if re.search("inactive", ro):
            return "finding"
        if re.search("active", ro):
            return "not_finding"
        else:
            return "finding"

    def stig_rule_238375(self, ro): 
        if(len(ro.strip())) == 0:
            return "not_finding"
        else:
            print("\033[1;33m--Need to configure wireless interface accoriding to stig guidlines--\033[0;0m")
        return "finding"
    
    def stig_rule_238376(self, ro):
        if(len(ro.strip())) == 0:
            return "not_finding"
        else:
            return "finding"
    
    def stig_rule_238377(self, ro):
        if(len(ro.strip())) == 0:
            return "not_finding"
        else:
            return "finding"
    
    def stig_rule_238378(self, ro):
        print("\033[1;33m--Vuln_id 238378 needs to be manually configured-------\033[0;0m")
        print("\033[1;33mVerify group ownership.\033[0;0m")
        return "finding"
        return
                                                       
                                                       

if __name__ == '__main__':

    banner()
    counter = 1
    
    # Give user 3 tries and end program to not have a infinite loop
    print("Welcome to the Ubuntu 20.04 scap scanner.  How do you want to implement the scanner?")
    access = input("Use ssh protocol with either \'"+MAG+"password"+ENDCLR+"\' or \'"+MAG+"keys"+ENDCLR+"\', or locally"\
                    + " using \'"+MAG+"localhost"+ENDCLR+"\'?  Enter \""+RED+"quit"+ENDCLR+"\" to end scan> ")
    access = access.lower()
    while access != "quit":
        counter = 1
        while access not in {'password', 'keys', 'localhost'} and counter != 3:
            print("Invalid input.  Try again.")
            access = input("Use ssh protocol with either \'"+MAG+"password"+ENDCLR+"\' or \'"+MAG+"keys"+ENDCLR+"\', or locally"\
                           +" using \'"+MAG+"localhost"+ENDCLR+"\'?  Enter \""+RED+"quit"+ENDCLR+"\" to end scan> ")
            access = access.lower()
            if(counter == 3): 
                print("You had 3 attempts.  Ending stig scanner.")
                quit()
        if access == 'keys':
            print("You entered "'"keys"'".  Keys option currently not configured.  Ending stig scan.  Goodbye.")
            quit()
        elif access == 'password':
        
            #from paramiko import SSHClient, AutoAddPolicy, ssh_exception, client 
            import paramiko #ssh encryption

            catagories_chosen = catagories_selected()
            ssh = connect_passwd()
            location = file_output()       
            
            if "cat1" in catagories_chosen:
                CAT_1(ssh, location)
            if "cat2" in catagories_chosen:
                CAT_2(ssh, location)
            if "cat3" in catagories_chosen:
                CAT_3(ssh, location)

            ssh.close()
            quit()

        elif access == 'localhost':
            import subprocess # secure way to run command on local os
            
            catagories_chosen = catagories_selected()
            location = file_output()       
            
            if "cat1" in catagories_chosen:
                CAT_1("local", location)
            if "cat2" in catagories_chosen:
                CAT_2("local", location)
            if "cat3" in catagories_chosen:
                CAT_3("local", location)
            quit()
            
        counter += 1
    else:
        print("You entered "'"quit"'".  Ending stig scan.  Goodbye.")
        quit()
