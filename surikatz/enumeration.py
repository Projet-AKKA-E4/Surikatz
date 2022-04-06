"""
    Module for perform some kind of enumeration on an information system
"""
import subprocess
from surikatz.error import AppNotInstalled
import json

class DirSearch:
    """
    Class allowing the manipulation of DirBuster for Website enumeration and the parsing of its output
    """
    def __init__(self, domain):
            """Init the DirSearch object.

            Args:
                self: DirSearch object.
                domain: domain name. For example : blabla.fr
            """
            self.domain = domain
    def get_data(self):
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
            AppNotInstalled: Please install theHarvester on your device or use a Kali Linux.
        """
        try:
            dirsearch = subprocess.run(
                ["dirsearch", "-u", self.domain, "--format", "json", "-o", "/tmp/dirsearch.json","--skip-on-status", "401,402,403,404"],
                stdout=subprocess.PIPE,
            )  # Launch dirsearch from the user's computer
        except OSError:
            raise AppNotInstalled(
                "Please install theHarvester on your device or use a Kali Linux."
            )
        with open('/tmp/dirsearch.json') as jsonFile:
            dirsearchData = json.load(jsonFile)

            return dirsearchData


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
