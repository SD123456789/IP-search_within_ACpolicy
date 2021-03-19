# IPsearchWithinACpolicy

**IPsearchWithinACpolicy.py** 

Input(s): 
    username,
    password,
    IP address of FMC,
    IP address you are looking for

Output(s):
    Name of the Access Control Policy and the specific Access Control Policy Rule that contains the IP address (if it exists).

Author: Sudhir H Desai <suddesai@cisco.com>

 

## Use Case Description

This is a python script that makes use of the requests module to search within all Access Control Policies within a single Firepower Management Center for a specified IP. 
It will GET all network objects and object groups, all Access Control Policies (and associated rules), and then provide 

This script can be executed on any platform that has python3 installed and the dependencies from **requirements.txt** installed.


## Installation

After installing python3 and pip3 on your operating system of choice, please run the following command in the directory containing the requirements.txt file so that necessary dependencies can be installed:  
```shell
pip3 install -r requirements.txt
```


## Configuration

No configuration needed. This script is a simple GET request for the accepted API versions.


## Usage

To use the **IPsearchWithinACpolicy.py** python script

```shell
IP-search_within_ACpolicy % python3 ./IPsearchWithinACpolicy.py
usage: IPsearchWithinACpolicy.py [-h] username password ip_of_fmc ip_to_search
IPsearchWithinACpolicy.py: error: the following arguments are required: username, password, ip_of_fmc, ip_to_search


IP-search_within_ACpolicy % python3 IPsearchWithinACpolicy.py apiuser S0urc3f1r3\! testfmc 10.10.10.24   
PING testfmc (10.10.10.10): 56 data bytes
64 bytes from 10.10.10.10: icmp_seq=0 ttl=51 time=19.381 ms

--- nemesisfmc.cisco.com ping statistics ---
1 packets transmitted, 1 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 19.381/19.381/19.381/0.000 ms
---------------------\_* RESULTS *_/---------------------
the IP we are looking for (10.10.10.24/32) is used as a source object in the ACPolicy named test0 in rule #10, Person - Basic Purple Block
the IP we are looking for (10.10.10.24/32) is used as a destination object in the ACPolicy named test1 in rule #1, TestingFQDN
the IP we are looking for (10.10.10.24/32) is used as a source object in the ACPolicy named test1 in rule #11, Person - Basic Purple Block
the IP we are looking for (10.10.10.24/32) is used as a source network in the ACPolicy named test2 in rule #1, TestingIP
```

## How to test the software

For testing, please review the help text outputted by the script:
```shell
IP-search_within_ACpolicy % python3 ./IPsearchWithinACpolicy.py -h
usage: IPsearchWithinACpolicy.py [-h] [-e] username password ip_of_fmc ip_to_search

positional arguments:
  username        API username
  password        password of API user
  ip_of_fmc       IP of FMC
  ip_to_search    IP that is being searched for

optional arguments:
  -h, --help      show this help message and exit
  -e, --expanded  If this flag is used, output the entire rule instead of just the rule name.
  ```

You can use the [FMC sandbox](https://devnetsandbox.cisco.com/RM/Diagram/Index/1228cb22-b2ba-48d3-a70a-86a53f4eecc0?diagramType=Topology) or the Firepower Management Center [API Learning Labs](https://developer.cisco.com/learning/lab/firepower-restapi-101/step/1) if you need to access an FMC.


## Getting help

If you have questions, concerns, bug reports, etc., please contact me.


## Author(s)

This project was written and is maintained by the following individuals:  

* Sudhir H. Desai — suddesai@cisco.com
