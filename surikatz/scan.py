"""
    Module for performing several scans
"""
#from surikatz import SURIKATZ_PATH
# from rich import print
# from rich.console import Console
import json

import subprocess

import nmap
from surikatz.error import AppNotInstalled
import subprocess

class Nmap:
    """
    Class allowing the manipulation of nmap and the parsing of its output
    """

    def __init__(self):
        self.scanner = nmap.PortScanner()
        self.scan_result = {}

    def start_nmap(self, target, args, timeout):
        self.scan_result = self.scanner.scan(hosts=target, arguments=args, timeout=timeout)        
        
class HTTrak:
    """
    Class allowing the manipulation of HTTrack and the parsing of its output
    """


class OpenVAS:
    """
    Class allowing the manipulation of OpenVAS and the parsing of its output
    """



class WpScan():
    def __init__(self, domain, key):
        self.domain = domain
        self.key = key
        self.wapplayzer_dict = wapplayzer_dict

    def wappalyzer_to_wpscan(self):
        #for plugin in wapplayzer_dict["plugins"] :
        pass


    def discret_wp_scan(self)->dict:
        """
        Allows to use wp_scan tool which returns the Wordpress website vulnerabilities
        """
        # scan = subprocess.run(
        #     ["wpscan", "--url", self.domain, "--api-token", self.key, "--detection-mode", "passive"], # Passive mode
        #     capture_output=True,
        # )

        p = Popen(["wpscan", "--url", self.domain, "--api-token", self.key, "--detection-mode", "passive", "--random-user-agent", "--output", SURIKATZ_PATH / "wpscan.json", "--format", "json"],
                  stdout = PIPE,
                  stderr = STDOUT,
                  shell = True)
        while True:
            line = p.stdout.readline()
            print(line)
            if not line: break





    def aggressive_wp_scan(self)->dict:
        subprocess.run(
            ["wpscan", "--url", self.domain, "--api-token", self.key, "--detection-mode", "aggressive", "--random-user-agent", "--output", "wpscan.json", "--format", "json"], # Passive mode
            capture_output=True,
        )

    def dict_concatenate(self,):
        with open('wpscan.json') as json_file:
            wpscan_data = json.load(json_file)





class Nikto:
    """
    Class allowing the manipulation of Nikto and the parsing of its output
    """
    def __init__(self, target: str, port: int) -> None:
        try:    
            self.nikto = subprocess.run(
                ["nikto","-output","/tmp/nikto.txt","-h",target,"-port",str(port)],
                stdout=subprocess.PIPE,
            )
        except OSError:
            raise AppNotInstalled("Please install nikto on your device or use a Kali Linux.")

class Wafwoof:
    """
    Class allowing the manipulation of WafW00f and the parsing of its output
    """
    def __init__(self, target) -> None:
        try:    
            self.wafwoof = subprocess.run(
                ["wafw00f","-a","-o","/tmp/wafwoof.json",target],
                stdout=subprocess.PIPE,
            )
        except OSError:
            raise AppNotInstalled("Please install wafw00f on your device or use a Kali Linux.")