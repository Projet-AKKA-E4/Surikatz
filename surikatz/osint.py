"""
    Module for using OSINT tools and databases to perform passives scans
"""
from surikatz.error import AppNotInstalled
from surikatz.utils import Checker, APIClient
import re
import whois
import socket
import subprocess
import untangle
import csv
from rich import print
from rich.console import Console
import shodan

console = Console()


class TheHarvester:
    """
    Class allowing the manipulation of The Harvester tool and the parsing of its output
    """

    def __init__(self, domain):
        self.domain = domain

    def _parse_xml(self):
        regex = "^(?!:\/\/)(?=.{1,255}$)((.{1,63}\.){1,127}(?![0-9]*$)[a-z0-9-]+\.?)$"
        harvester_obj = untangle.parse("output.xml")
        emails = set()
        fqdns = set()
        ips = set()
        if "email" in dir(harvester_obj.theHarvester):
            for email in harvester_obj.theHarvester.email:
                emails.add(email.cdata)

        if "host" in dir(harvester_obj.theHarvester):
            for host in harvester_obj.theHarvester.host:
                if host.cdata == "":
                    fqdns.add(host.hostname.cdata)
                    if not (re.search(regex, host.ip.cdata)):
                        tmp_ips = str(host.ip.cdata).split(",")
                        for ip in tmp_ips:
                            ips.add(ip.replace(" ", ""))

                else:
                    fqdns.add(host.cdata)
        return list(emails), list(ips), list(fqdns)

    def _print(self, emails, ips, fqdns):
        interresting = ["test", "admin", "vpn", "login"]
        console.print("emails:", emails)
        console.print("ips:", ips)

        console.print("FQDN:")
        count = 0
        for fqdn in fqdns:
            if fqdn.split(".")[0] in interresting:
                count += 1
                console.print(fqdn)

        if count == 0:
            for i in fqdns:
                if count == 5:
                    break
                count += 1

    def get_data(self):
        try:
            harvester = subprocess.run(
                ["theHarvester", "-d", self.domain, "-b", "all", "-f", "output"],
                stdout=subprocess.PIPE,
            )
        except OSError:
            raise AppNotInstalled("Please install theHarvester on your device or use a Kali Linux.")

        emails, ips, fqdns = self._parse_xml()

        emails, ips, fqdns = list(emails), list(ips), list(fqdns)

        self._print(emails, ips, fqdns)

        return {"emails": emails, "ips": ips, "fqdns": fqdns}


class IHaveBeenPawn:
    """
    Class allowing the manipulation of I Have Been Pawn API
    """


class Whois:
    """
    Class allowing the manipulation of Whois service provide by registars

    Methods
    -------
    whoIs(a)
        Return whois information from a
    """

    def whoIs(self, target):
        """
        Whois function get information about an Ip address or a domain name

        Parameters
        ----------
        a : str
            The IP address or the domain name
        """
        if Checker.checkIpAddress(target):  # For an ip Address
            # print("Valid Ip address: ", target)

            host = whois.whois(target)
            dict_ip = {
                "domain_name": host.domain_name,
                "ip_address": target,
                "status": host.status,
                "registrar": host.registrar,
                "emails": host.emails,
                "name_servers": host.name_servers,
            }
            print(dict_ip)

            num = 0
            for key, value in dict_ip.items():
                if value == None:
                    num += 1
                if num > 3:
                    console.print(
                        "Are you sure that you ip address is correct ?",
                        style="bold #FFA500",
                    )

            return dict_ip

        elif Checker.checkDomain(target):  # For Domain Name
            # print("Valid Domain Name: ",target)
            whoisData = whois.whois(target)

            try:
                host = socket.gethostbyname(target)
            except:
                host = None

            dict_domain = {
                "domain_name": target,
                "ip_address": host,
                "status": whoisData.status,
                "registrar": whoisData.registrar,
                "emails": whoisData.emails,
                "name_servers": whoisData.name_servers,
            }
            print(dict_domain)
            num = 0
            for key, value in dict_domain.items():
                if value == None:
                    num += 1
                if num > 3:
                    console.print(
                        "Are you sure that you ip address is correct ?",
                        style="bold #FFA500",
                    )
            return dict_domain
        else:
            console.print(
                "Please enter a valid IP address or domain name", style="bold red"
            )
            exit()


class ShodanUtils:
    """
    Class allowing the manipulation of Shodan API
    """

    _SHODAN_API_KEY = "yZ77YuFRvpdwn9ZCA3Uk8yJkmkyisi3k"

    def __init__(self, target: str, key):
        self.target = target
        self.internetdb = APIClient("https://internetdb.shodan.io/")
        self.shodan = shodan.Shodan(ShodanUtils._SHODAN_API_KEY)

    def _request_data(self) -> dict():
        return (self.internetdb.request(self.target), self.shodan.host(self.target))

    def _cpe_to_cpe23(self, cpes: dict) -> dict:
        return [cpe.replace("/", "2.3:") for cpe in cpes]

    def get_data(self) -> dict():
        """Collect and generate data from databases

        Return:
            A tuple containing two dictionnaries:
             - the first contain most revelant data
             - the second contain the complete data
        """
        intdb_data, shodan_data = self._request_data()

        for key in intdb_data.keys():
            if key not in shodan_data.keys():
                shodan_data[key] = intdb_data[key]
            if key == "ip":
                shodan_data["ip"] = shodan_data["ip_str"]
                del shodan_data["ip_str"]
            elif isinstance(intdb_data[key], list):
                shodan_data[key] += intdb_data[key]
                shodan_data[key] = list(set(shodan_data[key]))

        shodan_data["cpes"] = self._cpe_to_cpe23(shodan_data["cpes"])

        for service in shodan_data["data"]:
            if "cpe23" in service:
                shodan_data["cpes"] += service["cpe23"]

        for unless_data in [
            "city",
            "region_code",
            "latitude",
            "longitude",
            "isp",
            "asn",
            "area_code",
        ]:
            del shodan_data[unless_data]

        return shodan_data


class PawnDB:
    """
    Class allowing the manipulation of PawnDB database
    """


class OWASPfavicon:
    """
    Class allowing the identification of website information with favicon
    """


class Rapid7:
    """
    Class allowing the manipulation of Rapid7 API/database
    """


class SearchSploit:
    """
    Class allowing the manipulation of Searchsploit tool and Exploit-DB database and the parsing of its output
    """
