"""
    Module for perform some kind of enumeration on an information system
"""
import subprocess
from surikatz.error import AppNotInstalled
import json
from rich import console, traceback

traceback.install(show_locals=True)
console = console.Console()


class DirSearch:
    """
    Class allowing the manipulation of DirBuster for Website enumeration and the parsing of its output

    Attributes:
        self: DirSearch object.
        ip: ip adress. For example : 10.10.0.1
    """
    def __init__(self, ip: str):
            """Init the DirSearch object with ip address."""
            self.ip = ip
            
    def get_data(self, path: str) -> list:
        """Returns data found by DirSearch

        Args:
            self: DirSearch object.

        Returns:
            A list of urls. For example :

            ['http://blabla.fr:80/admin',
            'http://blabla.fr:80/admin/passwd.txt',
            'http://blabla.fr:80/js/app.js',
            'http://blabla.fr:80/index.html']

        Raises:
            AppNotInstalled: Please install DirSearch on your device.
        """
        try:
            dirsearch = subprocess.run(
                ["dirsearch", "-u", self.ip, "--format", "json", "-o", path,"--skip-on-status", "401,402,403,404","-r","-t","60"],
                stderr=subprocess.STDOUT, stdout=subprocess.PIPE
            )  # Launch dirsearch from the user's computer
        except OSError:
            raise AppNotInstalled(
                "Please install Dirsearch on your device."
            )
        # try to open dirsearch output and parsed the data
        try:
            with open(path, "r") as json_file:
                dirsearch_data = json.load(json_file)
                parsed_data = list()
                # Get all the informations on the urls founded
                urls = list(dirsearch_data['results'][0].values())[0]
                # Get the fqdn -> example : http://blabla.fr:80/
                fqdn = list(dirsearch_data['results'][0].keys())[0]
                # Remove the last '/' of the fqdn in order to not get '//'
                # And append the result to parsed_data
                for url in urls:
                    parsed_data.append(fqdn.rstrip(fqdn[-1])+url['path'])
                return parsed_data
        except :
            return None


class Kerbrut:
    """
    Class allowing the manipulation of Kerbrut for Kerberos enumeration and the parsing of its output
    """


class SMBMap:
    """
    Class allowing the manipulation of SMBMap for SMB enumeration and the parsing of its output
    """


class LDAP:
    """
    Class allowing the enumeration of LDAP directory
    """
