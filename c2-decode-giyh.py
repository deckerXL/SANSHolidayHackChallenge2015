#!/usr/bin/python
# Exploit Title: c2-decode-giyh.py
# Date: 12/2015
# Exploit Author: @deckerXL
# Version: 1.1
# Description: Decode the DNS C2 channel being used by the "Gnone in your home" IoT

import os
import sys
import base64
import argparse
import datetime
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

state = 0
fname = ""
outfile = ""
dt = datetime.datetime.now()
dirnow = dt.strftime("%G_%m_%d-%H_%M_%S_%f")
extract_path = "extract_"+dirnow

rdatafile = extract_path+"/rawpayloaddata.txt"

def c2Parser ( commFlag, commStr ):
	global state
	global fname
	global outfile
	if ( commFlag in commStr ):
		subcomm = commStr.split(":")[1]
		#print "COMM STRING: [" + commStr + "]"
		if ( "START_STATE" in subcomm ):
			state = 1
			outfile = open(fname,'w+')
		elif ( "STOP_STATE" in subcomm ):
			state = 0
			print "Writing decoded data to file: [" + fname + "]"
			outfile.close()
		else:
			if ( state == 0 ):
				#print commFlag + " Request: [" + subcomm + "]"
				dtlocal = datetime.datetime.now()
				fname = extract_path+"/extract_"+str(dtlocal.microsecond)+"_"+subcomm.replace("/","_").replace(" ","")
			else:
				rawfiledata = comm.split(commFlag)[1]
				#print rawfiledata
				if (commFlag == "EXEC:"):
					rawfiledata = rawfiledata + "\n"
				outfile.write(rawfiledata)
	

parser = argparse.ArgumentParser(description='Parse the Gnome In Your Home C2 Channel')
parser.add_argument('-f', action="store", required=True, dest="pcapfile")

results = parser.parse_args()
file = results.pcapfile

if ( not os.path.isfile(file) ) :
	print "ERROR: PCAP File [" + file + "] does not exist!"
	sys.exit(1)

print "Using PCAP file: [" + file + "]\n"
p=rdpcap(file)

record_command = 0
record_file = 0

os.mkdir(extract_path)
rawdata = open(rdatafile,"w+")

print "Decoding C2 Channel in PCAP...\n"
for pkt in p:
	if pkt and pkt.haslayer('UDP') and pkt.haslayer('DNS') and pkt.haslayer('DNSRR'):
		#print pkt.payload.payload.payload.payload.payload[IP][UDP][DNS][DNSRR]
		rdata = pkt.payload.payload.payload.payload.payload[IP][UDP][DNS][DNSRR].rdata
		comm = base64.b64decode(rdata[1:]).rstrip('\n')   # [1:] = Stripping the leading extraneous character in rdata that corrupts the base64 decode

		rawdata.write("Raw Data:\t[" + rdata + "]\n")
		rawdata.write("Decoded Data:\t[" + comm + "]\n")

		if   ( "EXEC:" in comm ):
			c2Parser("EXEC:", comm)
		elif ( "FILE:" in comm ):
			c2Parser("FILE:", comm)
		else:
			pass		# Other c2 intruction types could be handled here

print "\nWriting RAW data to file: [" + rdatafile + "]"
rawdata.close()
sys.exit(0)
