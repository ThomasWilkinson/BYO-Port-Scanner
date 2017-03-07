# BYO-Port-Scanner
Assignment 3 for IT 567

For IT 567 at Brigham Young University, we were tasked with creating and building our own Port Scanner.
Our score started at 0, and as we add features to it, those points increased based on the feature.

Mine functions as a multi-threaded python web server with a html front end that allows users to traceroutes, scan ports on multiple machines, and write their results to a file.

Here are the requirements for the program. My own comments on what I did follow each of the '-' as add-ons to the requirements. You can also find these requirements in the server.py code:

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

----------------------------------------------

Now, this program has the ability to pull your IP address so you don't need to edit the code with your own IP.

This program also supports multiple users and multiple ways to represents hosts and ports

It is run simply by running ./server.py from the command line and navigating to your IP in the browser on port 9020.

Let me know if you have any questions! 
