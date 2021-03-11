#! /usr/bin/python3

""" importing modules """
import os # python module which handles system calls
import unittest # python module for unit testing
import ipaddress # setting up IP addresses more logically
import requests # to help us unittest our responses below


""" importing what we're testing """
import IPsearchWithinACpolicy # our actual script

""" A class is used to hold all test methods as we create them and fill out our main script """
class TestAPIMethods(unittest.TestCase):
	def setUp(self):
		"""
		setting up the test
		"""


	def test_too_many_CLI_params(self):
		"""
		test that we are cleanly implementing command-line sanitization
		correctly counting
		"""
		arguments = ["apiGET.py" "127.0.0.1", "HELLO_WORLD!", "oogieboogie"]
		with self.assertRaises(SystemExit) as e:
			ipaddress.ip_address(apiGET.sanitizeInput(arguments))
		self.assertEqual(e.exception.code, 1)


	def test_bad_CLI_input(self):
		"""
		test that we are cleanly implementing command-line sanitization
		eliminating bad input
		"""
		arguments = ["apiGET.py", "2540abc"]
		with self.assertRaises(SystemExit) as e:
			apiGET.sanitizeInput(arguments)
		self.assertEqual(e.exception.code, 1)
 

	def test_good_IPv4_CLI_input(self):
		"""
		test that we are cleanly implementing command-line sanitization
		good for IPv4
		"""
		arguments = ["apiGET.py", "127.0.0.1"]
		self.assertTrue(ipaddress.ip_address(apiGET.sanitizeInput(arguments)))


	def test_good_IPv6_CLI_input(self):
		"""
		test that we are cleanly implementing command-line sanitization
		good for IPv6
		"""
		arguments = ["apiGET.py", "::1"]
		self.assertTrue(ipaddress.ip_address(apiGET.sanitizeInput(arguments)))


	def test_default_api_call_to_bad_IP(self):
		"""
		test our API GET method which returns the supported API versions,
		in this case 'v5', 'v6', and 'latest'
		this test will fail because the IP address 192.168.45.45 does not exist
		"""
		with self.assertRaises(SystemExit) as e:
			apiGET.getVersions("192.168.45.45")
		self.assertEqual(e.exception.code, 1)


	def test_default_api_call_to_no_API(self):
		"""
		test our API GET method which returns the supported API versions,
		in this case 'v5', 'v6', and 'latest'
		this test will fail because the IP address does exist but does not have an exposed API
		"""
		with self.assertRaises(SystemExit) as e:
			apiGET.getVersions('192.168.10.254')
		self.assertEqual(e.exception.code, 1)


	def test_default_api_call(self):
		"""
		test our API GET method which returns the supported API versions,
		in this case 'v5', 'v6', and 'latest'
		this test will succeed because the IP address does exist and will respond
		"""
		getVersions = apiGET.getVersions('192.168.10.196')[0]
		self.assertEqual(getVersions.text, '{\n    "supportedVersions":["v5", "v6", "latest"]\n}\n')


if __name__ == '__main__':
	unittest.main()