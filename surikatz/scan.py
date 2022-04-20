"""
    Module for performing several scans
"""
from typing import Any

from surikatz import SURIKATZ_PATH
from surikatz.utils import APIClient
from rich import print
from rich.console import Console
import json
import subprocess
import nmap
from rich import Console
from surikatz.error import AppNotInstalled
import subprocess
from os.path import exists
import os
from rich import console, traceback

traceback.install(show_locals=True)
console = console.Console()

class Nmap:
    """
    Class allowing the manipulation of nmap and the parsing of its output
    """

    def __init__(self):
        self.scanner = nmap.PortScanner()
        self.scan_result = {}

    def start_nmap(self, target: str, args: str, timeout: int) -> None:
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


class WpScan():
    """
        Class allowing to get more information about Wordpress vulnerabilities

        Args:
            self: WpScan object.
            domain: A string representing the domain name to analyze. For example : blabla.fr
            key: A string representing the WpScan API Key available at https://wpscan.com/
            wapplayzer_dict: A python dict representing Wappalizer result

        Returns:
            A dict containing wpscan passive part and wpscan aggressive|discret part
    """

    def __init__(self, domain, key, wapplayzer_dict):
        """
        Init the WpScan object.
        """
        self.domain = "http://" + domain
        self.key = key
        self.wapplayzer_dict = wapplayzer_dict

    def passive_wp_scan(self) -> dict:
        """
        Passive WpScan analyze wich call WpScan API for every Wordpress plugins and themes contained in wappalyzer dict


        Returns:
            wappalyzer_vuln: a dict containing WpScan API call from wappalyzer containing plugins and theme
        """
        base = {"Authorization": "Token token=" + self.key}
        apiCall = APIClient("https://wpscan.com/api/v3/", base)
        wappalyzer_vuln = {}
        wappalyzer_vuln["plugins"] = []
        wappalyzer_vuln["themes"] = []
        if not len(self.wapplayzer_dict["wp-plugins"]) == 0:
            for plugin in self.wapplayzer_dict["wp-plugins"]:
                call = apiCall.request("plugins/" + plugin["slug"])
                if 'status' in call.keys() and call['status'] == 'rate limit hit':
                    console.print(
                        "You have reached your API limit call. You need to refund your wpscan api plan or change api key in .env config",
                        style="bold red")
                    break
                else:
                    wappalyzer_vuln["plugins"].append(call)

        if not len(self.wapplayzer_dict["wp-themes"]) == 0:
            for theme in self.wapplayzer_dict["wp-themes"]:
                call = apiCall.request("themes/" + theme["slug"])
                if 'status' in call.keys() and call['status'] == 'rate limit hit':
                    console.print(
                        "You have reached your API limit call. You need to refund your wpscan api plan or change api key in .env config",
                        style="bold red")
                    break
                else:
                    wappalyzer_vuln["themes"].append(call)
        return wappalyzer_vuln

    def discret_wp_scan(self):
        """
        Allows to use wp_scan tool which returns the Wordpress website vulnerabilities with discret arguments.
        Write the output (wpscan.json) and it's cleaned version (wpscan_clean.json) in a file at /tmp/surikatz/<date>
        """
        subprocess.run(
            ["wpscan", "--url", self.domain, "--api-token", self.key, "--detection-mode", "passive",
             "--random-user-agent", "--output", SURIKATZ_PATH / "wpscan.json", "--format", "json"],  # Passive mode
            capture_output=True,
        )
        with open(SURIKATZ_PATH / 'wpscan.json') as json_file:
            wpscan_data = json.load(json_file)
            if "scan_aborted" in wpscan_data:
                console.print(
                    "Failed to scan the host, maybe FQDN or IP adresse is not correct. Or you have reached your API limit call. You need to refund your wpscan api plan or change api key in .env config")
                return
            subprocess.run(["python3", "-m", "wpscan_out_parse", "--summary",
                            "/tmp/surikatz/test/wpscan.json"])  # Summary printed in command line
        with open(SURIKATZ_PATH / 'wpscan_clean.json', "w") as fp:
            subprocess.run(["python3", "-m", "wpscan_out_parse", SURIKATZ_PATH / "wpscan.json", "--format", "json"],
                           stdout=fp)

    def aggressive_wp_scan(self):
        """
        Allows to use wp_scan tool which returns the Wordpress website vulnerabilities with aggressive arguments.
        Write the output (wpscan.json) and it's cleaned version (wpscan_clean.json) in a file at /tmp/surikatz/<date>
        """
        subprocess.run(
            ["wpscan", "--url", self.domain, "--api-token", self.key, "--detection-mode", "aggressive",
             "--random-user-agent", "--output", SURIKATZ_PATH / "wpscan.json", "--format", "json"],  # Aggressive mode
            capture_output=True,
        )
        with open(SURIKATZ_PATH / 'wpscan.json') as json_file:
            wpscan_data = json.load(json_file)
            if "scan_aborted" in wpscan_data:
                console.print(
                    "Failed to scan the host, maybe FQDN or IP adresse is not correct. Or you have reached your API limit call. You need to refund your wpscan api plan or change api key in .env config")
                return
            # Summary printed in command line
            subprocess.run(["python3", "-m", "wpscan_out_parse", "--summary",
                            SURIKATZ_PATH / "wpscan.json"])

        with open(SURIKATZ_PATH / 'wpscan_clean.json', "w") as fp:
            subprocess.run(["python3", "-m", "wpscan_out_parse", SURIKATZ_PATH / "wpscan.json", "--format", "json"],
                           stdout=fp)

    def dict_concatenate(self) -> dict:
        """
            Function wich concatenate passive and aggressive/discret dict


            Returns:
                final_dict: Final dict containing all dict
        """
        if exists(SURIKATZ_PATH / "wpscan_clean.json") and os.stat("wpscan_clean.json").st_size == 0:
            with open(SURIKATZ_PATH / "wpscan_clean.json") as wp_json_file:
                try:
                    wp_data = json.loads(wp_json_file.read())
                except:
                    console.print("Cannot open wpscan_clean.json", style="bold red")
                    return
                final_dict = {
                    "wp_scan_passive_mode": self.passive_wp_scan(),
                    "wp_scan_discret_or_agressive_mode": wp_data
                }

        else:
            final_dict = self.passive_wp_scan()

        return final_dict


class Nikto:
    """
    Class allowing the manipulation of Nikto and the parsing of its output
    """
    def __init__(self, target: str) -> None:
        try:    
            self.nikto = subprocess.run(
                ["nikto","-output",f"/tmp/{target}_nikto.txt","-h",target],
                stdout=subprocess.PIPE,
            )
        except OSError:
            raise AppNotInstalled("Please install nikto on your device or use a Kali Linux.")

class Wafwoof:
    """
    Class allowing the manipulation of WafW00f and the parsing of its output
    """
    def __init__(self, target, path) -> None:
        try:    
            self.wafwoof = subprocess.run(
                ["wafw00f", "-a", "-o", path, target],
                stdout=subprocess.PIPE,
            )
        except OSError:
            raise AppNotInstalled("Please install wafw00f on your device or use a Kali Linux.")