#!/usr/bin/env python3

from surikatz.error import APIError, ReadError
import importlib.resources
from dotenv import load_dotenv
import os
from pathlib import Path
import re
import requests
from rich.console import Console
from datetime import datetime

console = Console()


class ConfManager:
    def __init__(self):
        self.confExists()
        load_dotenv(Path.home() / ".config/surikatz/.env")

    def confExists(self):
        if not Path(Path.home() / ".config/surikatz/.env").exists():
            Path.mkdir(Path.home() / ".config/surikatz", parents=True, exist_ok=True)
            with importlib.resources.open_text(
                "surikatz.static", "template.env"
            ) as templatefile, Path(Path.home() / ".config/surikatz/.env") as envfile:
                envfile.write_text(templatefile.read())
            print(
                f"Configuration file generated at {Path.home() / '.config/surikatz/.env'}\n"
                "For some modules, API key is required. Make sure you fill the configuration file."
            )

    def _getApiKey(self, api):
        try:
            key = os.getenv(api)
            if key == "":
                raise ReadError(
                    "Impossible to read API key value. Make sure you fill it in .env file"
                )

        except:
            print(f"Error, no {api} API key fond in .env file")
            key = None

        return key

    def getShodan(self):
        return self._getApiKey("SHODAN_API")

    def getRapid(self):
        return self._getApiKey("RAPID_API")

    def getWappalyzer(self):
        return self._getApiKey("WAPPALYZER_API")


class Checker:
    """
        A class that is mainly used for checking and verification parts that will be useful for the smooth running of the operation.
    """
    @staticmethod
    def checkIpAddress(Ip: str) -> bool:
        """
        Function allowing to check if an Ip have a correct form

        Args:
            Ip: The IP address to check

        Returns:
            A boolean
        """
        regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
        # pass the regular expression
        # and the string in search() method
        if re.search(regex, Ip):
            return True
        else:
            return False

    @staticmethod
    def checkDomain(domain: str) -> bool:
        """
        Function allowing to check if a domain name have a correct form

        Args:
            domain: The domain name to check

        Returns:
            A boolean
        """
        regex = "^(?!-)[A-Za-z0-9-]+([\\-\\.]{1}[a-z0-9]+)*\\.[A-Za-z]{2,6}$"
        # a = input("Enter a domain name:")
        if re.search(regex, domain):
            return True

        else:
            return False

    @staticmethod
    def checkIPPublic():
        """
            A function that will check and return our public IP address through the Ipify's
        """
        ip = APIClient('https://api.ipify.org')
        ip = ip.request("/", params={"format": "json"})
        print(f'My public IP address is: {ip["ip"]}')

    @staticmethod
    def checkTime():
        """
            A function that will check and return the date and the time when we run our program
        """
        now = datetime.now()
        datenow = now.strftime("%d/%m/%Y, %H:%M:%S")
        print(f'Date: {datenow}')
   
    @staticmethod
    def checkKali():
        """
            A function that will check if the OS used is a Kali Linux distribution

            Returns:
                - Raise an exception if we do not have a Kali Linux Distribution
        """
        f = open("/etc/os-release", "r")
        OS="ID=kali"
        for line in f:  
            if OS in line: 
                return 
            else:
                f.close()
                raise OSError("You don't have a kali Distibution")


class APIClient:
    """
        A class that will be used for gathering information from any API.
    """
    def __init__(self, basic_url, key=None, proxies=None):
        self.base_url = basic_url
        self._session = requests.Session()
        if proxies:
            self._session.proxies.update(proxies)
            self._session.trust_env = False
        if key:
            self._session.headers.update(key)

    def makeUrlParams(self, params):
        """A function that create a string that will return an URL link for accesssing any API

        Arguments:
            result  -- a dictionnary that will contain the parameters that we must add to the URL in order to access the ressources

        Returns:
            A string character that will represent an URL link for accesssing the ressources of an API
        """
        for i, key in enumerate(params.keys()):
            if i == 0:
                urlParams = f"?{key}={params[key]}"
            else:
                urlParams += "&" + f"{key}={params[key]}"
        return urlParams

    def request(self, target, params=None):
        """General-purpose function to create web requests to any API.

        Arguments:
            function  -- name of the function you want to execute
            target    -- The endpoint for accessing the ressources we aim for.
            params    -- dictionary of parameters for the function

        Returns
            A dictionary containing the function's results.

        """
        if params:
            target += self.makeUrlParams(params)

        # Send the request
        try:
            data = self._session.get(self.base_url + target)
        except Exception:
            raise APIError(f"Unable to connect to {self.base_url}")

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
