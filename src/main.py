#!/usr/bin/env python3

"""
    Surikatz

    A powerful tool for searching informations before pentest.

    Can be used as 3 way :
      * Passive : Only search on public sources (Shodan, TheHarvester, VeryLeaks...)
      * Discrete : Use Passsive technics and soft nmap scan, soft HTTrack...
      * Agressive : Use Passive and Discrete technics but more... agressive.
                   Use nmap NSE scrips for firewall, WAF, IDS detection and evasion, enumeration for kerberos...

    Usage:
        ./surikatz [IP/FQDN] [Options]

    Authors:
        Abdelmalik KERBADOU
        Théo PERESSE-GOURBIL
        Manon HERMANN
        Rayane BOUDJEMAA
        Nathan SAUCET
        Laurent DELATTE
"""

from surikatz.security_solution import SecuritySolution
from surikatz.leaks import Leaks
from surikatz.vulnerability import Vulnerability
from surikatz.enumeration import Enumeration
from surikatz.other import Other
from surikatz.nmap import Nmap
from surikatz.web_exploitation import WebExploitation
from surikatz.the_harvester import TheHarvester

if __name__ == '__main__':

    a = Enumeration()
    a.WhoIs() #class test hello world


    #b=Classes.MyNextClass()
    #b.greetAgain()



