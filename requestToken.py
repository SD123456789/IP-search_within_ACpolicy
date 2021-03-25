#!/usr/bin/python3
"""
File: requestToken.py
Inputs: none
Outputs: print both access token and refresh token to screen

To use this file as a standalone script the username, password, & FMC IP
will need to be populated in the __main__ section below.

Author: Sudhir H Desai <suddesai@cisco.com>


License: BSD 3-Clause License

Copyright (c) 2021, Cisco Systems, Inc. and/or its affiliates

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

# include the necessary modules
import argparse
import requests

"""
function: get_token(fmcIP, path, username, password)
use: generates a list of necessary headers to be included with all 
    subsequent requests

inputs: IP of FMC, path to API, API user, API password
returns: access token, refresh token, domain uuid
"""
def get_token(fmcIP, path, username, password):
    # lets disable the certificate warning first (this is NOT advised in prod)
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    # send request with a try/catch block to handle errors safely
    try:
        r = requests.post(f"https://{fmcIP}/{path}", auth=(f"{username}", 
            f"{password}"), verify=False) # always verify the SSL cert in prod!
    except requests.exceptions.HTTPError as errh:
        raise SystemExit(errh)
    except requests.exceptions.RequestException as err:
        raise SystemExit(err)
    
    if (r.status_code < 200) or (r.status_code > 299):
        print(f"There was an issue with the token request and an error {r.status_code} was returned.")
        exit(1)

    # return the request token by identifying which key:value pairs we need
    required_headers = ('X-auth-access-token', 'X-auth-refresh-token', 'DOMAIN_UUID')
    result = {key: r.headers.get(key) for key in required_headers}
    return result

"""
function: refresh_token(fmcIP, path, access token, refresh token)
use: updates the access and refresh tokens of the passed-in header bundle

inputs: IP of FMC, path to API, access token, refresh token
returns: none
"""
def refresh_token(fmcIP, path, header):
    # lets disable the certificate warning first (this is NOT advised in prod)
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    # send request with a try/catch block to handle errors safely
    try:
        r = requests.post(f"https://{fmcIP}/{path}", headers=header, 
            verify=False) # always verify the SSL cert in prod!
    except requests.exceptions.HTTPError as errh:
        raise SystemExit(errh)
    except requests.exceptions.RequestException as err:
        raise SystemExit(err)

     # update the request token
    header['X-auth-access-token'] = r.headers.get('X-auth-access-token')
    header['X-auth-refresh-token'] = r.headers.get('X-auth-refresh-token')

    # pass since not returning anything
    pass


# if used as a stand-alone script, run the following
if __name__ == "__main__":
    # first set up the command line arguments and parse them
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("username", type=str, help ="API username")
    parser.add_argument("password", type=str, help="password of API user")
    parser.add_argument("ip_address", type=str, help="IP of FMC")
    args = parser.parse_args()

    # set needed variables to generate a token
    u = args.username
    p = args.password
    ip = args.ip_address
    path = "/api/fmc_platform/v1/auth/generatetoken"

    # call the token generating function and populate our header
    header = get_token(ip, path, u, p)

    # print the access token, refresh token, and domain uuid to the cli
    print(f"The Access Token received is: {header.get('X-auth-access-token')}")
    print(f"The Refresh Token received is: {header.get('X-auth-refresh-token')}")
    print(f"The DOMAIN_UUID is: {header.get('DOMAIN_UUID')}")

    # set the needed variables to refresh a token - only the new path, really
    path = "/api/fmc_platform/v1/auth/refreshtoken"

    # call the token refreshing function
    refresh_token(ip, path, header)

    # print the new access token and refresh token to the cli
    print(f"The refreshed Access Token received is: {header.get('X-auth-access-token')}")
    print(f"The refreshed Refresh Token received is: {header.get('X-auth-refresh-token')}")
