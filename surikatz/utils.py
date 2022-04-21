#!/usr/bin/env python3

from surikatz.error import APIError, ReadError
from surikatz import SURIKATZ_PATH,SCAN_DATE
import importlib.resources
from dotenv import load_dotenv
import os
from pathlib import Path
import re
import requests
from urllib.parse import urlparse
from datetime import datetime
from rich import console, traceback

traceback.install(show_locals=True)
console = console.Console()


class ConfManager:
    """
    Class that has 3 main roles : 
        - check if a config already exists, otherwise it will generate it
        - check if the surikatz folder in /tmp exists, otherwise it will create it
        - read the config file, and complete it with the API keys
    """

    def __init__(self):
        """Init the Shodan object."""
        self.conf_exists()
        self.tmp_exists()
        load_dotenv(Path.home() / ".config/surikatz/.env")

    def tmp_exists(self):
        """Check if the surikatz folder in /tmp exists"""
        if not Path(SURIKATZ_PATH).exists():
            Path.mkdir(Path("/tmp/surikatz") / SCAN_DATE, parents=True, exist_ok=True)
        else :
            console.print(f"Your result temporary files are located in {Path('/tmp/surikatz') / SCAN_DATE}\n", style="bold red")

    def conf_exists(self):
        """Check if a config already exists"""
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
        else:
            console.print(f"Your .env file is located in {Path.home() / '.config/surikatz/.env'}\n", style="bold red",)

    def _get_api_key(self, api: str) -> str:
        """Read the config file and try to get API keys
        
        Args : 
            api: name of API key

        Returns: 
            key: API key if found
        """
        try:
            key = os.getenv(api)
            if key == "":
                return None
            return key

        except:
            print(f"Error, no {api} API key fond in .env file")
            return None

    def get_shodan_key(self) -> str:
        """Get Shodan API key

        Returns: 
            SHODAN_API: API key for Shodan
        """
        return self._get_api_key("SHODAN_API")

    def get_wappalyzer_key(self):
        """Get Wappalyser API key
        
        Returns: 
            WAPPALYSER_API: API key for Wappalyser
        """
        return self._get_api_key("WAPPALYZER_API")

    def get_wpscan_key(self):
        return self._get_api_key("WPSCAN_API")


class Checker:
    """
        A class that is mainly used for checking and verification parts that will be useful for the smooth running of the operation.
    """
    @staticmethod
    def check_ip_address(Ip: str) -> bool:
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
    def check_domain(domain: str) -> bool:
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
    def get_target(target: str) -> str:
        """Get target IP address or domain name
        
        Args: 
            target: IP address or domain name

        Returns: 
            domain: retrun domain name
        """

        if Checker.check_ip_address(urlparse(target).path):
            return urlparse(target).path
        
        if not urlparse(target).scheme:
            domain = urlparse(target).path
        else:
            domain = urlparse(target).netloc
        # à corriger car va dans path si pas de scheme
        if Checker.check_domain(domain):
            return domain
        else:
            return None

    @staticmethod
    def check_ip_public():
        """
            A function that will check and return our public IP address through the Ipify's
        """
        ip = APIClient('https://api.ipify.org')
        ip = ip.request("/", params={"format": "json"})
        console.print(f'My public IP address is: {ip["ip"]}', style="bold red",)

    @staticmethod
    def check_time():
        """
            A function that will check and return the date and the time when we run our program
        """
        now = datetime.now()
        datenow = now.strftime("%d/%m/%Y, %H:%M:%S")
        console.print(f'Date: {datenow}', style="bold red",)
   
    @staticmethod
    def check_kali():
        """
            A function that will check if the OS used is a Kali Linux distribution

            Returns:
                Raise an exception if we do not have a Kali Linux Distribution
        """
        f = open("/etc/os-release", "r")
        OS="ID=kali"
        for line in f:  
            if OS in line: 
                return 
            else:
                f.close()
                raise OSError("You don't have a kali Distibution")
    
    @staticmethod
    def service_exists(name :str, data :dict) -> bool:
        """Check if service is in data

        Args: 
            name: name of service (http, ssh, ...)
            data: data from the dictionary

        Returns: 
            boolean
        """

        if "nmap" in data:
            for service in data["nmap"]:
                if name in service["type"]:
                    return True
        
        elif "shodan" in data:
            for service in data["shodan"]["services"]:
                if name in service["type"]:
                    return True
        return False       


class APIClient:
    """
        A class that will be used for gathering information from any API.

        Args: 
            basic_url: URL on which we want to make an API request
            key: API key if needed
            proxies: proxies address
    """
    def __init__(self, basic_url, key=None, proxies=None):
        """Init the APIClient object."""
        self.base_url = basic_url
        self._session = requests.Session()
        if proxies:
            self._session.proxies.update(proxies)
            self._session.trust_env = False
        if key:
            self._session.headers.update(key)

    def make_url_params(self, params:dict) -> str:
        """A function that create a string that will return an URL link for accesssing any API

        Args:
            result: a dictionnary that will contain the parameters that we must add to the URL in order to access the ressources

        Returns:
            A string character that will represent an URL link for accesssing the ressources of an API
        """
        for i, key in enumerate(params.keys()):
            if i == 0:
                urlParams = f"?{key}={params[key]}"
            else:
                urlParams += "&" + f"{key}={params[key]}"
        return urlParams

    def request(self, target:str, params=None) -> dict:
        """General-purpose function to create web requests to any API.

        Args:
            target: The endpoint for accessing the ressources we aim for.
            params: dictionary of parameters for the function

        Returns
            A dictionary containing the function's results.

        """
        if params:
            target += self.make_url_params(params)

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
