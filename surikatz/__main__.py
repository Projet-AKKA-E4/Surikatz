#!/usr/bin/env python3

from enum import Enum
import click
from surikatz import osint
from rich.console import Console
from rich.markdown import Markdown

console = Console() # Console configuration for rich package allowing beautiful print

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

class ScanMode(Enum):
    PASSIVE = 0
    DISCRET = 1
    AGRESSIVE = 2

@click.command()
@click.argument("target")
@click.option("-a", "--agressive", "level", flag_value=ScanMode.AGRESSIVE, type=ScanMode, default=ScanMode.AGRESSIVE, help="Use Discret and vulerability scanner, ennumeration and bruteforce")
@click.option("-d", "--discret", "level", flag_value=ScanMode.DISCRET, type=ScanMode, default=ScanMode.AGRESSIVE, help="Use passive mode with soft scans")
@click.option("-p", "--passive", "level", flag_value=ScanMode.PASSIVE, type=ScanMode, default=ScanMode.AGRESSIVE, help="Use only OSINT technics to retrive data")
def launch(target, level):

    motd(0.1)

    if level == ScanMode.PASSIVE:
        console.print(Markdown("# Passive mode", style="white"), style="bold green")
        print("")
        passive_mode(target)
    if level == ScanMode.DISCRET:
        console.print(Markdown("# Discret mode", style="white"), style="bold orange")
        print("")
    if level == ScanMode.AGRESSIVE:
        console.print(Markdown("# Agressive mode", style="white"), style="bold red")
        print("")

def motd(version):
    console.print(f"""
         ,/****/*,,          
      (#%%%/,,,#%%##/*          _____               _  _           _        
   %(#%&@@@#*,,%&&&&(*/(&      / ____|             (_)| |         | |       
  .&&,,(&(/(%*#**,#(,.,&%.    | (___   _   _  _ __  _ | | __ __ _ | |_  ____
   ,#/(*/#%&&&&(//*,*.,.,      \___ \ | | | || '__|| || |/ // _` || __||_  /
     (##(%%%&%((%####((,       ____) || |_| || |   | ||   <| (_| || |_  / / 
     .(##%%###%%&%%#((/       |_____/  \__,_||_|   |_||_|\_\\\\__,_| \__|/___| v{version}
      ,(###%%%&%%%#(///      
        .#%%%%%%%&%*,/,...                               
    \n""", style="bold")

def passive_mode(target):

    console.rule("[bold]Whois information")
    console.print("")
    whoisAPI = osint.Whois()
    whoisData = whoisAPI.whoIs(target)
    console.print("\n")

    console.rule("[bold]TheHarvester information")
    console.print("")
    theHarvesterAPI = osint.TheHarvester(whoisData["domain name"])
    harvesterDATA = theHarvesterAPI.get_data()
 
    console.print("\n")
    
    console.rule("[bold]Shodan information")
    console.print("")
    shodanApi = osint.ShodanUtils(whoisData["ip address"])
    shodanData = shodanApi.get_data()
    del shodanData["data"]
    console.print(shodanData)
    console.print("\n")

if __name__ == '__main__':
    launch()
