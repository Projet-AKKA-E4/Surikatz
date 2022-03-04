"""
    Module for using OSINT tools and databases to perform passives scans
"""
import re
import whois
import socket
from rich import print
from rich.console import Console

console = Console()

class TheHarvester:
    """
        Class allowing the manipulation of The Harvester tool and the parsing of its output
    """

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

    def whoIs(self, a):
        """
        Whois function get information about an Ip address or a domain name

        Parameters
        ----------
        a : str
            The IP address or the domain name
        """
        if self.checkIpAddress(a):  # For an ip Address
            print("Valid Ip address: ", a)

            host = whois.whois(a)
            dict_ip = {
                "domain name" : host.domain_name,
                "ip address" : a,
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

        elif self.checkDomain(a):   # For Domain Name
            print("Valid Domain Name: ",a)
            b= whois.whois(a)

            try :
                host = socket.gethostbyname(b.domain_name)
            except :
                host = None

            dict_domain = {
                "domain name": b.domain_name,
                "ip address": host,
                "status": b.status,
                "registrar": b.registrar,
                "emails": b.emails,
                "name servers": b.name_servers,
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

class Shodan:
    """
        Class allowing the manipulation of Shodan API
    """

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
