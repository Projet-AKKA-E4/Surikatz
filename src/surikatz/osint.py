"""
    Module for using OSINT tools and databases to perform passives scans
"""
from surikatz.error import APIError
import re
import requests
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

    def TheHarvester(self):
        harvester = subprocess.run(['theHarvester','-d',self.domain,'-b','all','-f','output'], stdout=subprocess.PIPE)
        harvester = harvester.stdout.decode('utf-8')

        harvester_obj = untangle.parse('output.xml')
        emails = set()
        hostnames = set()
        ips = set()
        regex = "^(?!:\/\/)(?=.{1,255}$)((.{1,63}\.){1,127}(?![0-9]*$)[a-z0-9-]+\.?)$"
        interresting = ["test","admin","vpn","login"]

        for email in harvester_obj.theHarvester.email:
            emails.add(email.cdata)

        for host in harvester_obj.theHarvester.host:
            if(host.cdata==""):
                hostnames.add(host.hostname.cdata)
                if(not(re.search(regex, host.ip.cdata))):
                    ips.add(host.ip.cdata)
                
            else:
                hostnames.add(host.cdata)

        print("emails: ", emails)
        print("ips: ", ips)

        count = 0
        for hostname in hostnames:
            if hostname.split('.')[0] in interresting:
                count += 1
                print(hostname)

        if count==0:
            for i in hostnames:
                if count == 5:
                    break
                count += 1

        maxlen = max(len(emails),len(ips),len(hostnames))
        emails = list(emails)
        hostnames = list(hostnames)
        ips = list(ips)

        with open('output.csv', 'w') as f:
            writer = csv.writer(f)
            for w in range(0,maxlen):
                if(w<len(emails)):
                    test_email = emails[w]
                else:
                    test_email = ""
                    
                if(w<len(ips)):
                    test_ip = ips[w]
                else:
                    test_ip = ""

                if(w<len(hostnames)):
                    test_hostname = hostnames[w]
                else:
                    test_hostname = ""
                
                
                writer.writerow([test_email, test_ip, test_hostname])

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
    def checkIpAddress(self,Ip):
        """
        Function allowing to check if an Ip have a correct form

        Parameter
        ----------
        Ip : str
            The IP address to check
        """
        regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
    # pass the regular expression
    # and the string in search() method
        if(re.search(regex, Ip)):
            return True
        else:
            return False


    def checkDomain(self,domain):
        """
        Function allowing to check if a domain name have a correct form

        Parameter
        ----------
        domain : str
            The domain name to check
        """
        regex= "^(?!-)[A-Za-z0-9-]+([\\-\\.]{1}[a-z0-9]+)*\\.[A-Za-z]{2,6}$"
        #a = input("Enter a domain name:")
        if re.search(regex, domain):
            return True

        else:
            return False

    def whoIs(self, target):
        """
        Whois function get information about an Ip address or a domain name

        Parameters
        ----------
        a : str
            The IP address or the domain name
        """
        if self.checkIpAddress(target):  # For an ip Address
            print("Valid Ip address: ", target)

            host = whois.whois(target)
            dict_ip = {
                "domain name" : host.domain_name,
                "ip address" : target,
                "status" : host.status,
                "registrar" : host.registrar,
                "emails" : host.emails,
                "name servers" : host.name_servers
            }
            print(dict_ip)

            num = 0
            for key, value in dict_ip.items() :     # Test if there is no more 3 None in dict
                if value == None: num += 1
                if num > 3 : console.print("Are you sure that you ip address is correct ?", style="bold #FFA500")

            return dict_ip

        elif self.checkDomain(target):   # For Domain Name
            print("Valid Domain Name: ",target)
            whoisData = whois.whois(target)

            try :
                host = socket.gethostbyname(target)
            except:
                host = None

            dict_domain = {
                "domain name": target,
                "ip address": host,
                "status": whoisData.status,
                "registrar": whoisData.registrar,
                "emails": whoisData.emails,
                "name servers": whoisData.name_servers,
            }
            print(dict_domain)
            num = 0
            for key, value in dict_domain.items() :
                if value == None: num += 1
                if num > 3 : console.print("Are you sure that you ip address is correct ?", style="bold #FFA500")
            return dict_domain
        else:
            console.print("Please enter a valid IP address or domain name", style="bold red")
            exit()

class ShodanUtils:
    """
        Class allowing the manipulation of Shodan API
    """
    _SHODAN_API_KEY = "yZ77YuFRvpdwn9ZCA3Uk8yJkmkyisi3k"
    class InternetDB:
        """
            Class allowing the manipulation of Shodan's InternetDB API
        """

        _SHODAN_API_KEY = "yZ77YuFRvpdwn9ZCA3Uk8yJkmkyisi3k"

        def __init__(self, proxies=None):
            self.base_url = "https://internetdb.shodan.io/"
            self._session = requests.Session()
            if proxies:
                self._session.proxies.update(proxies)
                self._session.trust_env = False
        
        def request(self, target):
            """General-purpose function to create web requests to InternetDB.

            Arguments:
                function  -- name of the function you want to execute
                params    -- dictionary of parameters for the function

            Returns
                A dictionary containing the function's results.

            """

            # Send the request
            try:
                data = self._session.get(self.base_url + target)
            except Exception:
                raise APIError('Unable to connect to InternetDB')

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
        
    def __init__(self, target: str):
        self.target = target
        self.internetdb = self.InternetDB()
        self.shodan = shodan.Shodan(ShodanUtils._SHODAN_API_KEY)
    
    def _request_data(self) -> dict():
        return (
            self.internetdb.request(self.target),
            self.shodan.host(self.target)
            )
    
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
                shodan_data["cpes"]+=service["cpe23"]
        
        for unless_data in ["city", "region_code", "latitude", "longitude", "isp", "asn"]:
            del shodan_data[unless_data]

        return shodan_data

    # _SHODAN_API_KEY = "yZ77YuFRvpdwn9ZCA3Uk8yJkmkyisi3k"

    # """
    # country + city
    # isp   
    # os
    # port
    # has_vuln
    # version

    # """

    # def __init__(self):
    #     self.api = shodan.Shodan(Shodan._SHODAN_API_KEY)
    
    # def getIpInfo(self):
    #     ipinfo = self.api.host("8.8.8.8")
    #     ports = [(port, self.getServiceName(port)) for port in ipinfo["ports"]]

    #     return {"countries": ipinfo["country_name"], "cities": ipinfo["city"], "services": ports}
    
    # def getServiceName(self, port):
    #     services = self.api.services()
    #     return services[f"{port}"]
        
    



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
