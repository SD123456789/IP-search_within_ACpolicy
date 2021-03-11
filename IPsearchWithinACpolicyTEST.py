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


	


if __name__ == '__main__':
	unittest.main()