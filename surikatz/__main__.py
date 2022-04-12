#!/usr/bin/env python3

from distutils.version import Version
from enum import Enum
import click
from surikatz import osint, utils, scan
from surikatz.utils import ConfManager
from rich.console import Console
from rich.markdown import Markdown
from surikatz.result import Analyze, Display

console = Console()  # Console configuration for rich package allowing beautiful print
conf = ConfManager()
surikatz_dict = {}

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
@click.option(
    "-a",
    "--agressive",
    "level",
    flag_value=ScanMode.AGRESSIVE,
    type=ScanMode,
    default=ScanMode.AGRESSIVE,
    help="Use Discret and vulerability scanner, ennumeration and bruteforce",
)
@click.option(
    "-d",
    "--discret",
    "level",
    flag_value=ScanMode.DISCRET,
    type=ScanMode,
    default=ScanMode.AGRESSIVE,
    help="Use passive mode with soft scans",
)
@click.option(
    "-p",
    "--passive",
    "level",
    flag_value=ScanMode.PASSIVE,
    type=ScanMode,
    default=ScanMode.AGRESSIVE,
    help="Use only OSINT technics to retrive data",
)
def launch(target, level):

    motd(0.1)
    utils.Checker.checkTime()
    utils.Checker.checkIPPublic()

    if level == ScanMode.PASSIVE:
        console.print(Markdown("# Passive mode", style="white"), style="bold green")
        print("")
        passive_mode(target)
    if level == ScanMode.DISCRET:
        console.print(Markdown("# Discret mode", style="white"), style="bold red")
        print("")
        discret_mode(target)
    if level == ScanMode.AGRESSIVE:
        console.print(Markdown("# Agressive mode", style="white"), style="bold red")
        print("")


def motd(version):
    console.print(
        f"""
         ,/****/*,,          
      (#%%%/,,,#%%##/*          _____               _  _           _        
   %(#%&@@@#*,,%&&&&(*/(&      / ____|             (_)| |         | |       
  .&&,,(&(/(%*#**,#(,.,&%.    | (___   _   _  _ __  _ | | __ __ _ | |_  ____
   ,#/(*/#%&&&&(//*,*.,.,      \___ \ | | | || '__|| || |/ // _` || __||_  /
     (##(%%%&%((%####((,       ____) || |_| || |   | ||   <| (_| || |_  / / 
     .(##%%###%%&%%#((/       |_____/  \__,_||_|   |_||_|\_\\\\__,_| \__|/___| v{version}
      ,(###%%%&%%%#(///      
        .#%%%%%%%&%*,/,...                               
    \n""",
        style="bold",
    )

def passive_mode(target):
    
    global surikatz_dict

    console.rule("[bold]Whois information")
    console.print("")
    whoisAPI = osint.Whois()
    whoisData = whoisAPI.whoIs(target)
    console.print("\n")
    surikatz_dict.update({**whoisData})

    console.rule("[bold]TheHarvester information")
    console.print("")
    theHarvesterAPI = osint.TheHarvester(whoisData["domain_name"])
    harvesterDATA = theHarvesterAPI.get_data()
    Analyze.get_clean_data_theHarvester(harvesterDATA.copy())
    console.print("\n")
    surikatz_dict.update({**harvesterDATA})

    console.rule("[bold]Shodan information")
    console.print("")
    shodanApi = osint.ShodanUtils(conf.getShodan())
    shodanData = shodanApi.get_data(whoisData["ip_address"])


    if shodanData is not None:
        cves = shodanData.pop("vulns")
        console.print(shodanData)
        console.print("\n")
        surikatz_dict.update({**shodanData})

        # CVSS Management
        for cve in cves:
            Analyze.get_cvss(cve)
            print("")

    if conf.getWappalyzer():
        console.rule("[bold]Wappalizer information")
        console.print("")
        wappalizerApi = osint.Wappalyser(conf.getWappalyzer())
        fqdns = shodanData["hostname"] if shodanData else [whoisData["ip_address"]]
        for fqdn in fqdns:
            wappalizerData = wappalizerApi.lookup(fqdn)
            console.print(wappalizerData)
            surikatz_dict.update({**wappalizerData})
        console.print("\n")

    clean_surikatz_dict = Analyze.clean_dict(surikatz_dict)

    console.rule("[bold]GLOBAL INFORMATION")
    console.print(clean_surikatz_dict)
    console.print("\n")

    

    Analyze.save_to_csv(clean_surikatz_dict)

    #Dict concat
    clean_surikatz_dict = {**whoisData, **shodanData}


def discret_mode(target):
    passive_mode(target)
    nm = scan.Nmap()
    nm.start_nmap(target, "-sV -sC -oN /tmp/scan", 1000)
    surikatz_dict.update({**nm.scan_result})
    console.rule("[bold]NMAP SCAN")
    with open("/tmp/scan","r") as file:
        console.print(file.read())

def json_output(dict_to_store):
    Analyze.save_to_json(dict_to_store)

if __name__ == "__main__":
    launch()