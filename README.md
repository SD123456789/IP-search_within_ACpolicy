# API-versions-accepted

**apiGET.py** is a python3 script that makes use of the requests module to ask the target server what APIVersions it accepts.  
There is only one input (first command line argument) which is an IP address.  
The accepted API versions are the output.  
This script can be executed on any platform that has python3 installed and the requests plugin installed.
 

## Use Case Description

This script assists an API developer to determine which API versions are accepted with a specific Firepower Defense Manager console.  
It can be run from any platform that has python3 installed.


## Installation

After installing python3 and pip3 on your operating system of choice, please run the following command in the directory containing the requirements.txt file so that necessary dependencies can be installed:  
```shell
pip3 install -r requirements.txt
```


## Configuration

No configuration needed. This script is a simple GET request for the accepted API versions.


## Usage

To use the **apiGET.py** python script

```shell
API-versions-accepted % python3 ./apiGET.py               
Usage: apiGET.py  <IP address of FTD management interface>

API-versions-accepted % python3 ./apiGET.py 192.168.10.196
PING 192.168.10.196 (192.168.10.196): 56 data bytes
64 bytes from 192.168.10.196: icmp_seq=0 ttl=62 time=4.046 ms

--- 192.168.10.196 ping statistics ---
1 packets transmitted, 1 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 4.046/4.046/4.046/0.000 ms
/usr/local/lib/python3.8/site-packages/urllib3/connectionpool.py:981: InsecureRequestWarning: Unverified HTTPS request is being made to host '192.168.10.196'. Adding certificate verification is strongly advised. See: https://urllib3.readthedocs.io/en/latest/advanced-usage.html#ssl-warnings
  warnings.warn(


The Firepower Device Manager at 192.168.10.196 accepts the following API versions:
{
    "supportedVersions":["v5", "v6", "latest"]
}
```

## How to test the software

For testing, please review the "apiGETtest.py" script bundled in this repo.
You will need to edit the unittest script for valid and invalid IP addresses in your environment.

To run the testing script, enter the following at the command-line and press return:
```shell
API-versions-accepted % python3 ./apiGETtest.py
```


## Getting help

If you have questions, concerns, bug reports, etc., please contact me.


## Author(s)

This project was written and is maintained by the following individuals:  

* Sudhir H. Desai — suddesai@cisco.com
