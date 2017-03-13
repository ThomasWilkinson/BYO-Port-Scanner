#!/usr/bin/python

#Assignment 3 - Thomas Wilkinson - IT 567

from BaseHTTPServer import HTTPServer,BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn
import threading
import socket
import sys
import re
from os import curdir, sep, listdir
import os
import urllib
import threading
import subprocess
from netaddr import *
import pprint
import datetime

"""
Welcome to my Port scanner and route tracer!

This comment section is dedicated to show you what I attempted to do for each of the requirements for the assignment to give some direction as to my train of thought

Requirements
------------------
1 point = 1 percent. Standard IT567 Grading Scale (75 = A)

At a minimum your tool should (40 points):

	1. Allow command-line switches to specify a host and port. 
		- This is all handled through my web interface in the two forms for ports and hosts - DONE
	2. Present a simple response to the user.
		- It prints out what it finds in the browser window asynchronously with AJAX in two sections for port scans and traceroutes. As well as lets the user print results to a text file.

Additional points are provided depending on the comprehensiveness of the feature. For example:

	Allow more than one host to be scanned - 10 points maximum.
		Reading a text file of host IP's or reading a range from the command line - 5 points.
			Doing both +2 points
		- It does a list of various sorts. You enter in the hosts in the HTML form. It does not read from a text file.
		
		o Allowing different ways to specify hosts (subnet mask and range) - 5 points.
		- You can do hyphenated lists AND CIDR addressing AS WELL as a comma seperated list in the box in the form. Or both at the same time if you comma seperate them!
	
	Allow multiple ports to be specified - 10 points maximum.
	- You can definitely do mutliple ports. you can represent them by a comma seperated list or a hyphenated range. Or both at the same time if you comma seperate them!
	
	Use of more than one protocol (TCP or UDP is assumed within the base 40 points)
		o ICMP 5 points
		o TCP or UDP (to complement the one already provided) - 10 points
	- I only used TCP. I did not use UDP or ICMP
	
	Traceroute - Max 5 points
		- Supports the traceroute feature, you put in your lists of hosts, cidr, or range, and click the trace route button and it calculates the route and writes it to the page.
	
	User experience results - eg. An HTML or PDF report:
		- The results of the scan and traceroute are posted in the HTML page in the HTML language.
		- It can handle multiple users to avoid frustration (user experience haha)
		- It is loosely Lord of the Rings themed for Creativity.
		o Max 10 points
	
	GUI or Web management of tool
		- It's a web page that uses some bootstrap and some other cool features with CSS to render the text and results.
		o Max 10 points
	
	Other ideas or concepts not mentioned 
		- I used my network and os and cs classes knowledge and made this into a multi-threaded web server that handles 6 or so different URL requests and can be run from any computer on the same network.
		- I added a feature to write the results out to a text file.
		o Max 20 points

Basically I feel like other than allowing the user to upload a file of IP's and use ICMP and UDP, I have done everything else in these requirements. If you disagree I would love to learn from you how I could have done it better.

I would love to know how to do some of these things if I failed to meet the expectation for them.

"""

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""

#This is what handles all the webrequests to the computer running this code on port 9020
class RequestHandler(BaseHTTPRequestHandler):

	#This variable tracks the hosts from the form data
	hosts = []
	#This variable tracks the ports from the form data
	ports = []
	#This variable tracks the output data for the port scanner
	output = []
	#this variable is a variation of the output variable that gets written out to a text file
	fancy = []
	#This variable is the HTML output for the traceroute feature
	routes = []
	#This variable is like the hosts variable but to avoid conflict with trace routes and port scans happening on different threads this variable tracks those hosts for traceroute
	traceHosts= []
	#This variable is the formmatted txt version of the HTML page in the routes variable. This gets written to a text file.
	tracedRoutes = []

	#This function takes in a path and a substring and then grabs the various hosts from the query string.
	#These hosts can be CIDR addressed (192.168.207.2/24), comma seperated (192.168.207.122, 192.168.207.121), or even hyphenated (192.168.207.22-34).
	def getHosts(self, path, subs):
		#This line is important because the URLS that use the hosts are different lengths
		query_string = path[subs:]
		query = {k:v for k,v in [i.split("=") for i in query_string.split("&")]}
		#Pulls whats after the hosts= in the string
		hosts = urllib.unquote_plus(query["hosts"])

		#try splitting on the commas first
		self.hosts = hosts.split(', ')

		for host in self.hosts:
			#Check for CIDR addressing
			if re.match('.*\/.*', str(host)):
				#use IPNetwork module to generate list of IPs for a given CIDR
				network = IPNetwork(str(host))
				ipList = list(network)
				#be sure to take the 192.168.207.2/24 out of the list so it doesn't try that as a single IP and break
				self.hosts.remove(host)
				
				#add the list of IPs in the subnet to the list of hosts
				for ip in ipList:
					#I used the print statement below to test functionality
					#print str(ip) + "\n"
					self.hosts.append(str(ip))

			#now check for the hyphen instead, and use search because its a part of the string not the whole part.
			elif re.search('-', host):
				#print str(hosts) + "\n"
				#We must grab the two numbers, this is best accomplished by searching for the last '.' and the characters after it and then cutting the period off.
				rangeIPs = re.search("\.[0-9]+-[0-9]+", host)
				span = ""
				if rangeIPs:
					#cut off '.'
					span = rangeIPs.group(0)[1:]
					
					#split of the hyphen so we can get the two numbers
					splitnumbers = span.split('-')
					#print "Host: " + str(host)
					firstpart = re.search("[0-9]+\.[0-9]+\.[0-9]+\.", host)
					print "End numbers of Host: " + str(splitnumbers[0]) + " " + str(splitnumbers[1])
					for i in range (int(splitnumbers[0]), int(splitnumbers[1])+1):
						print "Compiled host: " + str(firstpart.group(0)) + str(i)
						self.hosts.append(str(firstpart.group(0) + str(i)))
					self.hosts.remove(host)
		#return self.hosts

	#This function traces the routes from your machine to the IP addresses given (which are pulled from the query string in the getHosts function)
	#Max of thirty hops. I used to have a wait time in my process for some reason... so it used to take close to 10 times longer, if not more...
	def doTrace(self):
		print "Welcome to the traceroute feature..."

		for host in self.hosts:
			#For every host in the list, show the time the trace was initiated and issue the subprocess to begin the traceroute
			print "Tracing to: " + str(host) + ": " +  str(datetime.datetime.now().strftime("%y-%m-%d-%H-%M"))
			traceroute = subprocess.Popen(["traceroute", str(host)],stdout=subprocess.PIPE, stderr=subprocess.STDOUT)  
			result = ""	
			route = ""
			format = ""
			#For every hop it took to get to the machine (obviously max of 30)
			for hop in iter(traceroute.stdout.readline, "\n"):
				if not hop:
					break
				print str(hop)
				#We must put together the formatted result for both the HTML page and our file we write out to.
				route += "<p>" + hop +"</p>"
				format += hop + "\n"
			result += "<h4>Traceroute:</h4>" + str(route)
			#print result
			formattedResult = "Traceroute for " + str(host) + "\n" + format
			self.tracedRoutes.append(formattedResult)
			self.routes.append(result)
		self.routes.append("<p>Trace complete</p>")	
	#This puts together the formatted output from a list just prior to writing it to a file.
	def generateReport(self, outputForm):
		results = ""
		for entry in outputForm:
			results += entry
		return results

	#This is the longest part of the program, it scans the ports in the query string for the ports hithertofor evaluated.
	def scanPorts(self):
		query_string = self.path[13:]
		#print query_string

		#attack the query string to get the hosts and the ports
		query = {k:v for k,v in [i.split("=") for i in query_string.split("&")]}
		#print query

		#the unquote plus is what inserts in the spaces and the "" and the ? marks back in.
		ports1 = urllib.unquote_plus(query["ports"])

		#print ports1
		#Try splitting on commas first
		self.ports = ports1.split(', ')

		#Testing query string results:
		#print "Ports are: " + str(self.ports)

		for port in self.ports:
			#print "Port: " + str(port)
			#Search for hyphen now
			if re.search("-", str(port)):
				#print "Found hyphen!" + "\n"
				twoNums = port.split('-')
				print "Range = " + str(twoNums)
				print twoNums[0] + " " + twoNums[1]
				for i in range (int(twoNums[0]), int(twoNums[1]) + 1):
					#print str(i) + "\n"
					#Append each port in the range into the list
					self.ports.append(str(i))
				#Remove entry with hyphen because hyphen is not a legit port number...
				self.ports.remove(port)
		#reset path		
		self.path = "/portScanner.html"

		try:
			i = 0
			for host in self.hosts:
				result = "<h3>Host: " + str(host) + ": " + str(datetime.datetime.now().strftime("%y-%m-%d-%H-%M")) + "</h3>"
				#section = "<p>Ports:</p><br>"
				self.output.append(result)
				self.fancy.append("\nHost: " + str(host) +"\n")
				#print "Host: " + host
				for port in self.ports:
					#print "Port: " + port
					print "Connecting to Host!\n"
					#Create socket to connect - this is a TCP connection
					sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
					print "Connected, testing port.\n"
					#See if you get a response from the port
					result = sock.connect_ex((host, int(port)))
					
					#If open
					if result == 0:
						print host + ": Port {}:     Open".format(port)
						portOutput = "<p>Port {}:     Open".format(port)+"</p>"
						self.fancy.append("Port: " + port + " open!\n")
						self.output.append(portOutput)
					#If closed
					else: 
						print host + ": Port {}:     Closed".format(port)
						portOutput = "<p>Port {}:     Closed".format(port)+"</p>"
						self.fancy.append("Port: " + port + " closed!\n")
						self.output.append(portOutput)
					sock.close()
				self.output.append("<p>Scan of " + str(host) + " complete</p>")	

		except socket.gaierror:
			print 'Hostname could not be resolved. Exiting'
			sys.exit()
		except socket.error:
			print "Couldn't connect to server"
			sys.exit()
		except SystemExit:
			sys.exit()
		except KeyboardInterrupt:
			print ".... oh... We get the message... you're done?"
			sys.exit()

	#This is the method that is called by default by the handler. It handles all URL requests and when the page loads a certain type of file.
	#If you add any URLs to this, make sure the code for the request goes in this method.
	def do_GET(self):
		#This line was useful, but because of all the ajax requests it became annoying in the terminal and clogged up my other print statements
		#print "Getting " + str(self.path)
		try:
			respond = False
			#To see if the client is asking for a port scan
			isValid = re.match("\/portScanner\?hosts=.*&ports=.*", str(self.path))

			#To see if the client is asking for a traceroute
			isTrace = re.match("\/traceroute\?hosts=.*&ports=.*", str(self.path))
			
			#We tracing the route?
			if isTrace:
				#to eliminate the url to get what's important for the functionality, the substring is taken to cut it 
				traceSubString = 12
				self.getHosts(self.path, traceSubString)
				self.doTrace()
				self.path = "/portScanner.html"

			isPorts = re.match("\/report", str(self.path))
			#We using ajax to see port scan results?
			if isPorts:
				results = self.generateReport(self.output)
				#whammy = [results, "port"]

				self.wfile.write(results)

			#We generating the tracerports?
			isTraceResults = re.match("\/trace", str(self.path))
			if isTraceResults:
				results = self.generateReport(self.routes)
				#whammy = [results, "trace"]

				self.wfile.write(results)
			"""
			This functionality was deprecated because I decided to time stamp everything for more effective logging.
			isClear = re.match("\/clear", str(self.path))
			#We clearing out of entries?
			if isClear:
				print self.path
				self.output = []
				self.fancy= []
				self.path = "/portScanner.html"
			"""

			isStore = re.match("\/write", str(self.path))
			#We writing to a file?
			if isStore:
				print self.path
				myFile = "./Port Scan.txt"
				target = open(myFile, 'w')
				for entry in self.fancy:
					target.write(entry)

				for entry in self.tracedRoutes:
					target.write(entry)
				target.close()
				self.path = "/portScanner.html"

			#print self.path
			if isValid:

				if self.path == "/":
					self.path = "/portScanner.html"
					print "Resetting path"
				else:
					#print "Hello there " + self.path
					portSub = 13
					self.getHosts(self.path, portSub)
					self.scanPorts()
			
			#print "The output: " + self.output
			if self.path == "/portScanner":
				self.path = "/portScanner.html"

			#Deal with the following file types. This is how I render the images and CSS content on the page.
			if self.path.endswith(".html"):
				mimetype ='text/html'
				respond = True
			elif self.path.endswith(".txt"):
				mimetype = "text/plain"
				respond = True
			elif self.path.endswith(".jpg"):
				mimetype = "image/jpeg"
				respond = True
			elif self.path.endswith(".gif"):
				mimetype = "image/gif"
				respond = True
			elif self.path.endswith(".css"):
				mimetype = "text/css"
				respond = True
			elif self.path.endswith(".ico"):
				mimetype = "image/x-icon"
				respond = True		

			#If it is something we are going to respond to and send content, then do this:
			if respond:
				myFile = open(curdir + sep + self.path)
				self.send_response(200)
				self.send_header('Content-type', mimetype)
				self.end_headers()
				self.wfile.write(myFile.read())
				myFile.close()

			return
		except IOError:
			self.send_error(404, 'File Not Found: %s' % self.path)

#This code is intended to pull the ip address of the computer so you as the user or the grader don't have to modify this code with your own IP
#This code for get_lan_ip and get_interface_ip were taken from http://stackoverflow.com/questions/11735821/python-get-localhost-ip
#It checks to see which interface is active on the computer and grabs the associated IP from it.
if os.name != "nt":
    import fcntl
    import struct

    def get_interface_ip(ifname):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s',
                                ifname[:15]))[20:24])

def get_lan_ip():
    ip = socket.gethostbyname(socket.gethostname())
    if ip.startswith("127.") and os.name != "nt":
        interfaces = [
            "eth0",
            "eth1",
            "eth2",
            "wlan0",
            "wlan1",
            "wifi0",
            "ath0",
            "ath1",
            "ppp0",
            ]
        for ifname in interfaces:
            try:
                ip = get_interface_ip(ifname)
                break
            except IOError:
                pass
    return ip


#This is where the program begins
try:
	print "Creating Server...\n"
	#Address for the server and it's port number
	serverAddress = (str(get_lan_ip()), 9020)
	
	#Create server and pass it my address and handlder class from above 
	#The HTTPServer class creates TCP connections and uses sockets. This combined with the ajax from my chat.html allows for threading
	myServer = ThreadedHTTPServer(serverAddress, RequestHandler)
	print "Server created and running...\n"
	
	#Serve stuff
	myServer.serve_forever()

except KeyboardInterrupt:
	print " .... oh... We get the message... you're done?"
	myServer.socket.close()
	myServer.shutdown()
	sys.exit()
except socket.gaierror:
	myServer.socket.close()
	myServer.shutdown()
	print 'Hostname could not be resolved. Exiting'
	sys.exit()
except SystemExit:
	print "Exitting..."
	myServer.socket.close()
	myServer.shutdown()
	sys.exit()
finally:
	print " Thank you"
	#sys.exit()