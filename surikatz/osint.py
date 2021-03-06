"""
    Module for using OSINT tools and databases to perform passives scans
"""
import surikatz.error
from surikatz.utils import Checker, APIClient
from urllib.parse import urlparse
import re
import whois
import socket
import subprocess
import untangle
import shodan
from rich import print, console, traceback
from surikatz import SURIKATZ_PATH

traceback.install(show_locals=True)
console = console.Console()


class TheHarvester:
    """
    Class allowing the manipulation of The Harvester tool and the parsing of its output

    Attributes:
        self: TheHarvester object.
        domain: domain name. For example : blabla.fr
    """

    def __init__(self, domain: str):
        """Init the theHarvester object with domain name."""
        self.domain = domain

    def _parse_xml(self) -> list:
        """Parse the xml file output of theHarvester.

        Args:
            self: TheHarvester object.

        Returns:
            Three sets of emails, ips and FQDNs. For
            example:

            {admissions@blabla.fr, admin@blabla.fr, jean.dupond@blabla.fr},
            {6.23.128.1, 6.23.128.2, 134.1.1.2, 134.1.1.6, 10.10.1.2, 128.2.2.1},
            {vpn.blabla.fr, test200.blabla.fr, www.blabla.fr}

        """
        # Regex matching IPv4 IP address
        regex = "^(?!:\/\/)(?=.{1,255}$)((.{1,63}\.){1,127}(?![0-9]*$)[a-z0-9-]+\.?)$"

        # create sets for the data
        emails = set()
        fqdns = set()
        ips = set()

        # parse the xml
        try:
            path = SURIKATZ_PATH / "theharvester.xml"
            harvester_obj = untangle.parse(str(path))
        except TypeError:
            console.print("The XML file is probably empty",style="bold red")
            console.print_exception()
            return emails,ips,fqdns


        # Check if there is emails in the parsed object
        if "email" in dir(harvester_obj.theHarvester):
            # Loop through the emails elements of the parsed objet and add them in the email set
            for email in harvester_obj.theHarvester.email:
                emails.add(email.cdata)

        # Check if there is hosts elements in the parsed object
        if "host" in dir(harvester_obj.theHarvester):
            # Loop through the hosts elements of the parsed objet and add them to the corresponding set (ips or fqdns)
            for host in harvester_obj.theHarvester.host:
                # If there is no cdata to the host element, it must have both fqdn and ip
                if host.cdata == "":
                    fqdns.add(host.hostname.cdata)
                    # Check if there is valid ip object
                    if not (re.search(regex, host.ip.cdata)):
                        # Split the ip string when there is multiple IP in one string
                        tmp_ips = str(host.ip.cdata).split(",")
                        for ip in tmp_ips:
                            ips.add(ip.replace(" ", ""))
                # If there is cdata, then it must have only an fqdn
                else:
                    fqdns.add(host.cdata)
        return emails, ips, fqdns

    def get_data(self) -> dict:
        """Returns data found by TheHarvester

        Args:
            self: TheHarvester object.

        Returns:
            A dict of list. For example :

            {"emails": [admissions@blabla.fr, admin@blabla.fr, jean.dupond@blabla.fr],
            "ips": [6.23.128.1, 6.23.128.2, 134.1.1.2, 134.1.1.6, 10.10.1.2, 128.2.2.1],
            "FQDN": [vpn.blabla.fr, test200.blabla.fr, www.blabla.fr]}

        Raises:
            AppNotInstalled: Please install theHarvester on your device or use a Kali Linux.
        """
        try:
            harvester = subprocess.run(
                ["theHarvester", "-d", self.domain, "-b", "all", "-f", f"{SURIKATZ_PATH}/theharvester"],
                stdout=subprocess.PIPE,
            )  # Launch theHarvester from the user's computer
        except OSError:
            raise surikatz.error.AppNotInstalled(
                "Please install theHarvester on your device or use a Kali Linux."
            )
        except TypeError:
            console.print_exception()
            return

        emails, ips, fqdns = self._parse_xml()

        dic = {"emails": list(emails), "ips": list(ips), "fqdns": list(fqdns)}
        
        if dic["emails"] == list():
            dic.pop("emails")
        if dic["ips"] == list():
            dic.pop("ips")
        if dic["fqdns"] == list():
            dic.pop("fqdns")
        
        return dic


class IHaveBeenPawn:
    """
    Class allowing the manipulation of I Have Been Pawn API
    """


class Whois:
    """
    Class allowing the manipulation of Whois service provide by registars
    """

    def whoIs(self, target: str) -> dict:
        """
        Whois function get information about an Ip address or a domain name

        Args:
            target: The IP address or the domain name

        Return:
            A dictionnary of Whois information
        """

        target = Checker.get_target(target)

        if Checker.check_ip_address(target):  # For an ip Address
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

            # Test if dict_ip have more than 3 None inside -> means that probably the address is not correct
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
        # For Domain Name
        elif Checker.check_domain(target):
            whois_data = whois.whois(target)

            try:
                host = socket.gethostbyname(target)
            except:
                host = None

            dict_domain = {
                "domain_name": target,
                "ip_address": host,
                "status": whois_data.status,
                "registrar": whois_data.registrar,
                "emails": whois_data.emails,
                "name_servers": whois_data.name_servers,
            }
        
            # Test if dict_domain have more than 3 None inside -> means that probably the domain name is not correct
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

    Attributes:
        self: Shodan object.
        key: API key for Shodan.
    """

    def __init__(self, key: str):
        """Init the Shodan object with API key."""
        self.internetdb = APIClient("https://internetdb.shodan.io/")
        self.shodan = shodan.Shodan(key)

    def _request_data(self, target: str) -> tuple:
        """
        Make requests to InternetDB and Shodan databases

        Args:
            target: Device's IP to target

        Returns:
            A tuple containing two dictionnaries:
             - the first contain InternetDB data
             - the second contain Shodan data
        """
        if not self.shodan.api_key:
            console.print("No Shodan key has been provided. Only InternetDB data will be used")
            try:
                rq = self.internetdb.request(target)
            except surikatz.error.APIError:
                print(rq["error"])
                rq = None
            finally:
                return (rq, None)

        try:
            intdb_rq = self.internetdb.request(target)
        except surikatz.error.APIError:
            intdb_rq = None
        
        try:
            shodan_rq = self.shodan.host(target)
        except shodan.APIError:
            shodan_rq = None
        
        return (intdb_rq, shodan_rq)

    def _cpe_to_cpe23(self, cpes: dict) -> dict:
        """
        Convert old CPEs to CPE 2.3 format

        Args:
            cpes: A dictionnary with outdated CPEs

        Returns:
            dict: A translated CPEs dictionnary
        """
        return [cpe.replace("/", "2.3:") for cpe in cpes]

    def get_data(self, target: str) -> dict:
        """
        Collect and generate data from databases

        Args:
            target: Device's IP to target

        Returns:
            A dictionnary with all revelant information
        """
        try :
            intdb_data, shodan_data = self._request_data(target)
        except TypeError:
            console.print(f"InternetDB does not have any information for {target}")
            return

        if not shodan_data:
            return intdb_data

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

        for useless_data in [
            "city",
            "region_code",
            "latitude",
            "longitude",
            "isp",
            "asn",
            "area_code",
            "country_code",
            
        ]:
            del shodan_data[useless_data]

        services = []
        for i,element in enumerate(shodan_data['data']):
            services.append({"type": element['_shodan']['module'], "fqdn": element['hostnames'], "port": element['port'], "product": element['product'] if 'product' in element else "Undefined", "version": element['version'] if 'version' in element else "Undefined"})
    
        shodan_data["services"] = services
        del shodan_data["data"]

        return shodan_data


class PwnDB:
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


class Wappalyser:
    """
    Class allowing the manipulation of Wappalyser and the parsing of its output

    Attributes:
        self: Wappalyser object
        key: API key for Wappalyser
    """

    def __init__(self, key: str):
        """Init the Wappalyser object with API key."""
        self.api = APIClient("https://api.wappalyzer.com/v2", key={"x-api-key": key})

    def lookup(self, target: str) -> dict:
        """
        Function for finding out the technology stack of any website, such as the CMS or ecommerce platform.

        Args:
            target: Device's FQDN to target

        Returns:
            data: Dict of technology stack of the target
        """
        try:
            secured_rq = self.api.request(
                "/lookup",
                params={"urls": f"https://{target}", "set": "all", "recursive": "false"},
            )[0]
            unsecured_rq = self.api.request(
                "/lookup",
                params={"urls": f"http://{target}", "set": "all", "recursive": "false"},
            )[0]
        except surikatz.error.APIError:
            return None

        if all("errors" in rq for rq in [secured_rq, unsecured_rq]):
            return None
        elif "errors" in secured_rq:
            rq = unsecured_rq
        else:
            rq = secured_rq
        data = {"url": rq["url"], "technologies": [], "wp-plugins": [], "wp-themes": []}
        for techno in rq["technologies"]:
            slugs = [categorie["slug"] for categorie in techno["categories"]]
            if any( slug in [
                    "cms",
                    "web-servers",
                    "programming-languages",
                    "security",
                ]
                for slug in slugs
            ):
                if "trafficRank" in techno: del techno["trafficRank"]
                if "confirmedAt" in techno: del techno["confirmedAt"]
                data["technologies"].append(techno)
            if any( slug in [
                    "wordpress-plugins",
                ]
                for slug in slugs
            ):
                if "trafficRank" in techno: del techno["trafficRank"]
                if "confirmedAt" in techno: del techno["confirmedAt"]
                data["wp-plugins"].append(techno)
            if any( slug in [
                    "wordpress-themes",
                ]
                for slug in slugs
            ):
                if "trafficRank" in techno: del techno["trafficRank"]
                if "confirmedAt" in techno: del techno["confirmedAt"]
                data["wp-themes"].append(techno)

        return data
