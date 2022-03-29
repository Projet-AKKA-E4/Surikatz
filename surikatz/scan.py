"""
    Module for performing several scans
"""

import nmap
import asyncio


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


class WPScan:
    """
    Class allowing the manipulation of WPScan and the parsing of its output
    """


class Nikto:
    """
    Class allowing the manipulation of Nikto and the parsing of its output
    """
