#! /usr/bin/python3

"""
IPsearchWithinACpolicy.py is a python script that makes use of the requests
module to search within an Access Control Policy for a specified IP.

To run the script use the following syntax:
./IPsearchWithinACpolicy.py <IP address of server> <IP address you are looking for>
python3 ./IPsearchWithinACpolicy.py <IP address of server> <IP address you are looking for>
"""

import requests
import ipaddress
import sys
import os

from requests.models import HTTPError


def sanitizeInput(inputs):
	""" if there is more than one command line argument, exit """
	if len(inputs) != 3:
		print(f"Usage: {inputs[0]}  <IP address of FMC management interface>\n ")
		sys.exit(1)

	""" now that there are only two command line arguments, make sure both are an IP & return """	
	try:
		fmcIP = ipaddress.ip_address(inputs[1])
		return fmcIP
	except ValueError:
	    print(f"address/netmask is invalid: {inputs[1]}\n")
	    sys.exit(1)
	except HTTPError:
		print(f"address has no exposed API: {inputs[1]}\n")
		sys.exit(1)
	except:
	    print(f"Usage: {inputs[0]}  <IP address of FTD management interface>\n")
	    sys.exit(1)



def FMCexists(fmcIP):
	""" make sure IP exists """
	IP = str(fmcIP)
	if (os.system(f"ping -c 1 -t 1 {IP}") != 0):
		print("Please enter a useable IP address.\n")
		sys.exit(1)

	""" getting valid versions using the built-in module exceptions to handle errors """
	r = requests.get('https://{}/api/versions'.format(str(IPaddr)), verify=False)

	try:
		r.raise_for_status()
	except:
		print(f"The IP address at {IPaddr} has no exposed API and has returned a {r.status_code} error.")
		exit(1)

	return r,IPaddr


if __name__ == "__main__":
	try:
		whichVersions, IP = FMCexists(sanitizeInput(sys.argv))
		
	except:
		exit(1)