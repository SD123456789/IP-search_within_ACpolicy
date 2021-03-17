#! /usr/bin/python3
"""
File: IPsearchWithinACpolicy.py 

Usage: is a python script that makes use of the requests
    module to search within an Access Control Policy for a specified IP.

    ./IPsearchWithinACpolicy.py <username> <password> <IP address of FMC> <IP address you are looking for>
    python3 ./IPsearchWithinACpolicy.py <username> <password> <IP address of FMC> <IP address you are looking for>

Inputs: 
    username,
    password,
    IP address of FMC,
    IP address you are looking for

Outputs:
    Name of the Access Control Policy that contains the IP address (if it exists)

Author: Sudhir H Desai <suddesai@cisco.com>


License: BSD 3-Clause License

Copyright (c) 2020, Cisco Systems, Inc. and/or its affiliates

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of the copyright holder nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

import argparse
import ipaddress
import json
import pprint
import re
from typing import ValuesView
import requests
import sys
import os
from collections import defaultdict
from requests.models import HTTPError
from requestToken import get_token


def FMCexists(fmcIP):

    # make sure IP exists
    if (os.system(f"ping -c 1 -t 1 {str(fmcIP)}") != 0):
        print("Please enter a useable IP address.\n")
        sys.exit(1)

    # lets disable the certificate warning first (this is NOT advised in prod)
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    # getting valid versions using the built-in module exceptions to handle errors
    try:
        r = requests.get('https://{}//api/fmc_platform/v1/info/serverversion'.format(str(fmcIP)), verify=False)

    except:
        print(f"The IP address at {fmcIP} has no exposed API and has returned a {r.status_code} error.")
        exit(1)

    return fmcIP


def getFunction(fmcIP, apiPath, authHeader):

    # now to try and GET our list of whatever
    try:
        r = requests.get(f"https://{fmcIP}/api/fmc_config/v1/domain/{authHeader['DOMAIN_UUID']}/{apiPath}", headers=authHeader, 
            verify=False) # always verify the SSL cert in prod!
    except requests.exceptions.HTTPError as errh:
        raise SystemExit(errh)
    except requests.exceptions.RequestException as err:
        raise SystemExit(err)


    # if it worked, we will have received a list of whatever so return it
    try:
        return r.json()
    except Exception as err:
        raise SystemExit(err)


if __name__ == "__main__":
    # first set up the command line arguments and parse them
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("username", type=str, help ="API username")
    parser.add_argument("password", type=str, help="password of API user")
    parser.add_argument("ip_of_fmc", type=str, help="IP of FMC")
    parser.add_argument("ip_to_search", type=str, help="IP that is being searched for")
    args = parser.parse_args()


    # set needed variables to generate a token
    user = args.username
    passwd = args.password
    fmcIP = args.ip_of_fmc
    queriedIP = args.ip_to_search

    # let's first make sure that the IP address we're looking for is legitimate
    try:
        queriedIP = ipaddress.ip_network(queriedIP)
    except:
        print(f"{queriedIP} does not represent a valid IPv4 or IPv6 address")
        sys.exit(1)


    # then make sure that the FMC IP is valid
    try:
        fmcIP = FMCexists(fmcIP)
    except Exception as err:
        raise SystemExit(err)

    
    # next get a valid token
    apiPath = "/api/fmc_platform/v1/auth/generatetoken"
    try:
        authHeader = get_token(fmcIP, apiPath, user, passwd)
    except Exception as err:
        raise SystemExit(err)

    """ GETTING NETWORK OBJECTS """
    # get all networkgroups from the FMC
    # set the path to the network groups and expand them for values
    apiPath = "object/networkgroups?expanded=true"
    try:
        networkObjectGroups = getFunction(fmcIP, apiPath, authHeader)
    except Exception as err:
        raise SystemExit(err)

    # next grab all network objects from the FMC
    # set the path to get network objects and expand them for values
    apiPath = "object/networks?expanded=true"
    try:
        networkObjects = getFunction(fmcIP, apiPath, authHeader)
    except Exception as err:
        raise SystemExit(err)

    # then pull all IP addresses from each network object and object group
    # saving them in a dict of the form object:[list, of, IPs]
    ipDict = defaultdict(list)
    for networkObjectGroup in networkObjectGroups['items']:
        if networkObjectGroup.get('literals') != None:
            if len(networkObjectGroup['literals']) > 1:
                for literal in networkObjectGroup['literals']:
                    ipDict[ipaddress.ip_network(literal['value'])].extend([networkObjectGroup['id'], networkObjectGroup['name']])
            else:
                ipDict[ipaddress.ip_network(networkObjectGroup['literals'][0]['value'])].extend([networkObjectGroup['id'], networkObjectGroup['name']])

    for networkObject in networkObjects['items']:
        ipDict[ipaddress.ip_network(networkObject['value'])].extend([networkObject['id'], networkObjectGroup['name']])


    """ GETTING HOSTS """
    # change the path 
    apiPath = "object/hosts?expanded=true"
    try:
        hostObjects = getFunction(fmcIP, apiPath, authHeader)
    except Exception as err:
        raise SystemExit(err)

    # add the hosts to the dictionary
    for hostObject in hostObjects['items']:
        ipDict[ipaddress.ip_network(hostObject['value'])].extend([hostObject['id'], hostObject['name']])

    """ GRABBING ACCESS CONTROL POLICIES and RULES """
    # change the path and download all AC policies
    apiPath = "policy/accesspolicies?expanded=false"
    try:
        acPolicies = getFunction(fmcIP, apiPath, authHeader)
    except Exception as err:
        raise SystemExit(err)

    # go into each AC policy and get an expanded view of each policy element
    # store in the "rules" key of each AC policy
    for acPolicy in acPolicies['items']:
        apiPath = f"policy/accesspolicies/{acPolicy['id']}/accessrules?expanded=true"
        try:
            acPolicy['rules'] = getFunction(fmcIP, apiPath, authHeader)
        except Exception as err:
            raise SystemExit(err)


    # create a dictionary to store any matching objects
    ipMatches = defaultdict(list)

    # next find the IP we are looking for from within that list 
    # of objects if it exists and store the object id for further processing
    for ip in ipDict:
        try:
            if queriedIP.subnet_of(ip) or (queriedIP == ip):
                ipMatches.update({ip:ipDict[ip]})
        except TypeError:
            pass

    # now doubly iterate through the access control policies and see if the
    # IP address we are searching for does exist within one of them, either 
    # as a raw IP or contained within an object
    policyMatches = []
    for acPolicy in acPolicies['items']:
        for acpKey, acpValue in acPolicy['rules'].items():
            if (acpKey == 'items'):
                for rule in acpValue:
                    if 'sourceNetworks' in rule:
                        if 'literals' in rule['sourceNetworks']:
                            for literal in rule['sourceNetworks']['literals']:
                                if queriedIP.subnet_of(ipaddress.ip_network(literal['value'])) or (queriedIP == ipaddress.ip_network(literal['value'])):
                                    tempStr = f"the IP we're looking for ({queriedIP}) is used in a source network in the ACPolicy named {acPolicy['name']} in rule #{rule['metadata']['ruleIndex']}:\n{rule}"
                                    if tempStr not in policyMatches:
                                        policyMatches.append(tempStr)
                        if 'objects' in rule['sourceNetworks']:
                            for ipKey, ipValue in ipMatches.items():
                                for object in rule['sourceNetworks']['objects']:
                                    if queriedIP.subnet_of(ipKey) or (queriedIP == ipKey):
                                        tempStr = f"the IP we're looking for ({queriedIP}) is used in a source object in the ACPolicy named {acPolicy['name']} in rule #{rule['metadata']['ruleIndex']}:\n{rule}"
                                        if tempStr not in policyMatches:
                                            policyMatches.append(tempStr)
                    if 'destinationNetworks' in rule:
                        if 'literals' in rule['destinationNetworks']:
                            for literal in rule['destinationNetworks']['literals']:
                                if queriedIP.subnet_of(ipaddress.ip_network(literal['value'])) or (queriedIP == ipaddress.ip_network(literal['value'])):
                                    tempStr = f"the IP we're looking for ({queriedIP}) is used in a destination network in the ACPolicy named {acPolicy['name']} in rule #{rule['metadata']['ruleIndex']}:\n{rule}"
                                    if tempStr not in policyMatches:
                                        policyMatches.append(tempStr)
                        if 'objects' in rule['destinationNetworks']:
                            for ipKey, ipValue in ipMatches.items():
                                for object in rule['destinationNetworks']['objects']:
                                    if queriedIP.subnet_of(ipKey) or (queriedIP == ipKey):
                                        tempStr = f"the IP we're looking for ({queriedIP}) is used in a destination object in the ACPolicy named {acPolicy['name']} in rule #{rule['metadata']['ruleIndex']}:\n{rule}"
                                        if tempStr not in policyMatches:
                                            policyMatches.append(tempStr)
    
    print(f"outputs for queried IP {queriedIP}:")
    for match in policyMatches:
        print(match)
    