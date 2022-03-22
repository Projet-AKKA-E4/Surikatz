#!/usr/bin/env python3

from surikatz.error import APIError
from surikatz.error import ReadError 
from dotenv import load_dotenv
import os
import re
import requests
import whois
import socket
import subprocess
import untangle
import csv
from rich import print
from rich.console import Console
import shodan
from datetime import datetime

console = Console()

class ConfReader:

	def __init__(self):
		load_dotenv()

	def _getApiKey(self, api):
		try:
			key = os.getenv(api)
			if key=="":
				raise ReadError("Impossible to read API key value. Make sure you fill it in .env file")

		except:
			key = f"Error, no {api} API key fond in .env file"
		
		return key
		
	def getShodan(self):
		return self._getApiKey("SHODAN_API")

	def getRapid(self):
		return self._getApiKey("RAPID_API")

	def getWappalyzer(self):
		return self._getApiKey("WAPPALYZER_API")


class Checker:
    @staticmethod
    def checkIpAddress(Ip):
        regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
    	# pass the regular expression
    	# and the string in search() method
        if(re.search(regex, Ip)):
            return True
        else:
            return False
            
    @staticmethod        
    def checkDomain(domain):
        regex= "^(?!-)[A-Za-z0-9-]+([\\-\\.]{1}[a-z0-9]+)*\\.[A-Za-z]{2,6}$"
        #a = input("Enter a domain name:")
        if re.search(regex, domain):
            return True

        else:
            return False

    @staticmethod
    def checkIPPublic():
        ip = APIClient('https://api.ipify.org')
        ip = ip.request("/", params={"format": "json"})
        print(f'My public IP address is: {ip["ip"]}')

    @staticmethod
    def checkTime():
        now = datetime.now()
        datenow = now.strftime("%d/%m/%Y, %H:%M:%S")
        print(f'Date: {datenow}')
   
    @staticmethod
    def checkKali():
        f = open("/etc/os-release", "r")
        OS="ID=kali"
        for line in f:  
            if OS in line: 
                return 
            else:
                f.close()
                raise OSError("You don't have a kali Distibution")

class APIClient:

    def __init__(self, basic_url,key= None, proxies=None):
        self.base_url = basic_url
        self._session = requests.Session()
        if proxies:
            self._session.proxies.update(proxies)
            self._session.trust_env = False
        if key:
            self._session.headers.update(key)

    def resultUrl(self, result):
        """ A function that create a string that will return an URL link for accesssing any API
        
        Arguments:
            result  -- a dictionnary that will contain the parameters that we must add to the URL in order to access the ressources

        Returns:
            A string character that will represent an URL link for accesssing the ressources of an API
        """
        for i, key in enumerate(result.keys()):		
            if i ==0:
                res = f"?{key}={result[key]}"
            else:
                res += ","+f"{key}={result[key]}"
        return res 


    def request(self, target,params= None):
            """General-purpose function to create web requests to any API.

            Arguments:
                function  -- name of the function you want to execute
                target    -- The endpoint for accessing the ressources we aim for.
                params    -- dictionary of parameters for the function

            Returns
                A dictionary containing the function's results.

            """
            if params:
                target += self.resultUrl(params)

            # Send the request
            try:
                data = self._session.get(self.base_url + target)
            except Exception:
                raise APIError(f'Unable to connect to {self.base_url}')

            # Check that the API key wasn't rejected
            if data.status_code == 401:
                try:
                    # Return the actual error message if the API returned valid JSON
                    error = data.json()['error']
                except Exception as e:
                    raise APIError(error)
            elif data.status_code == 403:
                raise APIError('Access denied (403 Forbidden)')

            # Parse the text into JSON
            try:
                data = data.json()
            except ValueError:
                raise APIError('Unable to parse JSON response')

            # Raise an exception if an error occurred
            if type(data) == dict and 'error' in data:
                raise APIError(data['error'])

            # Return the data
            return data

