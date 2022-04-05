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

            Retrieves rows pertaining to the given keys from the Table instance
            represented by table_handle.  String keys will be UTF-8 encoded.

            Args:
                self: DirSearch object.
                domain: domain name. For example : blabla.fr
            """
            self.domain = domain
    def get_data_dirsearch(self):
        # try:
        #     dirsearch = subprocess.run(
        #         ["dirsearch", "-u", self.domain, "--format", "json", "-o", "/tmp/dirsearch.json","--skip-on-status", "401,402,403,404"],
        #         stdout=subprocess.PIPE,

        #     )  # Launch dirsearch from the user's computer
        # except OSError:
        #     raise AppNotInstalled(
        #         "Please install theHarvester on your device or use a Kali Linux."
        #     )
        new_data= []
        with open('/tmp/dirsearch.json') as json_file:
            dirsearch_data = json.load(json_file)
            test_data = list(dirsearch_data['results'][0].values())[0]
            www = str(list(dirsearch_data['results'][0].keys())[0])
            for i,element in enumerate(test_data):
                new_data.append(www.rstrip(www[-1]) +element['path'])
            #     #new_data.append({"Module":element['path']})
            
            return new_data


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
