"""
    Module for performing several scans
"""

import nmap
from rich import Console
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
    def __init__(self, target, path):
        try :
            subprocess.run(
                ["httrack",target,"-o", path],
                stdout=subprocess.PIPE
            )
            Console.print(f"HTTrack finished, saved to {path}")
        except OSError:
            raise AppNotInstalled(
                "Please install httrack on your device."
            )



class OpenVAS:
    """
    Class allowing the manipulation of OpenVAS and the parsing of its output
    """


class WPScan:
    """
    Class allowing the manipulation of WPScan and the parsing of its output
    """


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