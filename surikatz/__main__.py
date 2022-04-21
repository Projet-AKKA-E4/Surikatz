#!/usr/bin/env python3

from distutils.log import error
from surikatz import utils, osint, scan, result, enumeration
import click
from rich import console, traceback, markdown
from enum import Enum
import os
from urllib.parse import urlparse
import surikatz
import shutil

from surikatz.error import APIError, AppNotInstalled

"""
    Surikatz

    A powerful tool for searching informations before pentest.

    Can be used as 3 way :
      * Passive : Only search on public sources (Shodan, TheHarvester, VeryLeaks...)
      * Discrete : Use Passsive technics and soft nmap surikatz.scan, soft HTTrack...
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

traceback.install(show_locals=True)
console = console.Console()  # Console configuration for rich package allowing beautiful print
conf = utils.ConfManager()
surikatz_dict = {}

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
    help="Use Discret and vulerability surikatz.scanner, ennumeration and bruteforce",
)
@click.option(
    "-d",
    "--discret",
    "level",
    flag_value=ScanMode.DISCRET,
    type=ScanMode,
    default=ScanMode.AGRESSIVE,
    help="Use passive mode with soft surikatz.scans",
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
def init(target, level):

    motd(0.2)
    utils.Checker.check_time()
    utils.Checker.check_ip_public()

    if level == ScanMode.PASSIVE:
        console.print(markdown.Markdown("# Passive mode", style="white"), style="bold green")
        print("")

    if level == ScanMode.DISCRET:
        console.print(markdown.Markdown("# Discret mode", style="white"), style="bold red")
        print("")

    if level == ScanMode.AGRESSIVE:
        console.print(markdown.Markdown("# Agressive mode", style="white"), style="bold red")
        print("")

    launch(target, level)


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

def launch(target, level):
    
    global surikatz_dict

    #############################################################################
    ############################### WHOIS #######################################
    #############################################################################

    if level.value >= ScanMode.PASSIVE.value:
        console.rule("[bold]Whois information")
        console.print("")
        whois = osint.Whois()
        whois_data = whois.whoIs(target)
        console.print("\n")
        surikatz_dict.update({"whois": whois_data})


    #############################################################################
    ######################### THE HARVESTER #####################################
    #############################################################################

    if level.value >= ScanMode.PASSIVE.value and whois_data["domain_name"]:
        console.rule("[bold]TheHarvester information")
        console.print("")
        if(type(whois_data["domain_name"])==list):
            the_harvester = osint.TheHarvester(whois_data["domain_name"][0])
        else:
            the_harvester = osint.TheHarvester(whois_data["domain_name"])
        try:
            harvester_data = the_harvester.get_data()
            if harvester_data:
                surikatz_dict.update({"thehaverster": harvester_data})
                result.Analyze.get_clean_data_theHarvester(harvester_data.copy())
                console.print("\n")
        except AppNotInstalled:
            harvester_data = None


    #############################################################################
    ############################### SHODAN ######################################
    #############################################################################

    if level.value >= ScanMode.PASSIVE.value:
        console.rule("[bold]Shodan information")
        console.print("")
        shodan_api = osint.ShodanUtils(conf.get_shodan())
        shodan_api = shodan_api.get_data(whois_data["ip_address"])

        if shodan_api is not None:
            cves = shodan_api.pop("vulns")
            console.print(shodan_api)
            console.print("\n")
            surikatz_dict.update({"shodan": shodan_api})

            # CVSS Management
            for cve in cves:
                result.Analyze.get_cvss(cve)
                print("")
        else:
            print(f"Shodan does not have any information for {target}\n")
    
    
    #############################################################################
    ################################# NMAP ######################################
    #############################################################################

    if level.value >= ScanMode.DISCRET.value:
        console.rule("[bold]NMAP SCAN")
        nm = scan.Nmap()
       
        try:

            leures = f"{surikatz_dict['theharvester']['ips'][0]},{surikatz_dict['theharvester']['ips'][1]}"
        except:
            leures = surikatz_dict["whois"]['ip_address']

        if os.geteuid() == 0:
            frag = "-f"
        else :
            frag = ""

        temps = ""
        if level == ScanMode.DISCRET:
            temps = "-T2"
        
        ports = ""
        scripts = ""
        if level == ScanMode.AGRESSIVE:
            ports = "-p-"
            scripts = "-sC"
        
        nm.start_nmap(utils.Checker.get_target(target), f"{frag} -D {leures} -sV -oN /tmp/nmap {temps} {ports} {scripts} -Pn", 1000)
        nmap_analyse = result.Analyze.analyse_nmap(nm.scan_result)
        surikatz_dict.update({**nmap_analyse})
        result.Display.display_txt("/tmp/nmap")


    #############################################################################
    #############################################################################
    ################################# HTTP ######################################
    #############################################################################
    #############################################################################

    if utils.Checker.service_exists("http",surikatz_dict):
        targets = []
        if surikatz_dict["shodan"]:
                for service in surikatz_dict["shodan"]["services"]:
                    if "http" in service["type"]:
                        targets += service["fqdn"] if service["fqdn"] else [f'{surikatz_dict["whois"]["ip_address"]}:{service["port"]}']

        if level.value >= ScanMode.DISCRET.value:
             for service in surikatz_dict["nmap"]:
                if service["type"] == "http":
                    targets.append(surikatz_dict["whois"]["ip_address"] + f":{service['port']}")
                        
        if not targets:
            print(f"No Web server exists for {target}")
            
        targets = list(set(targets))

    
        #############################################################################
        ########################## WAPPALYSER #######################################
        #############################################################################
        if level.value >= ScanMode.PASSIVE.value and conf.get_wappalyzer_key():
            
            console.rule("[bold]Wappalizer")
            console.print("")
            
            wappalyzer_api = osint.Wappalyser(conf.get_wappalyzer_key())
            surikatz_dict["wappalizer"] = []

            for tg in targets:
                wappalyzer_data = wappalyzer_api.lookup(tg)
                if wappalyzer_data==None:
                    console.print("API Key is no longer valid : Error 403")
                else: 
                    console.print(wappalyzer_data)
                    surikatz_dict["wappalizer"].append(wappalyzer_data)

            console.print("\n")

        #############################################################################
        ############################# HTTrack #######################################
        #############################################################################
        
        if level.value >= ScanMode.DISCRET.value:
            console.rule("[bold]HTTrack")

            targets = []
            for host in surikatz_dict["wappalizer"] :
                targets.append(host["url"])

            targets = list(set(targets))

            for tg in targets:
                console.print(f"HTTrack for {tg}")
                scan.HTTrak(tg, f"/tmp/{urlparse(tg).netloc}_httrack")
                try:
                    shutil.copytree(f"/tmp/{urlparse(tg).netloc}_httrack",f"./httrack/{urlparse(tg).netloc}_httrack")
                    console.print("Folder moved in current pwd", end="\n\n")
                    console.print(f"HTTrack finished. Output folder : ./httrack/{urlparse(tg).netloc}_httrack")
                except OSError:
                    console.print(f"Error while moving folding. Result is still available at /tmp/{urlparse(tg).netloc}_httrack", end="\n\n")


        #############################################################################
        ############################# NIKTO #########################################
        #############################################################################
        if level == ScanMode.AGRESSIVE:
            console.rule(f"[bold]Nikto")
            
            targets = []
            for host in surikatz_dict["wappalizer"] :
                targets.append(host["url"])

            for tg in targets:
                scan.Nikto(tg)
                console.print(f"Nikto for {tg}")
                result.Display.display_txt(f"/tmp/{tg}_nikto.txt")



        #############################################################################
        ############################## WafW00f ######################################
        #############################################################################

        if level == ScanMode.AGRESSIVE:
            console.rule(f"[bold]WafW00f")

            for tg in targets : 
                if urlparse(tg).scheme == "https":
                    console.print(f"WafWoof for {tg}")
                    scan.Wafwoof(tg, f"/tmp/{urlparse(tg).netloc}_wafwoof.json")
                    result.Display.display_json(f"/tmp/{urlparse(tg).netloc}_wafwoof.json")


        #############################################################################            
        ############################### DIRSEARCH ###################################
        #############################################################################
        
        if level == ScanMode.AGRESSIVE:
            console.rule("[bold]Dirsearch information")
            surikatz_dict["dirsearch"] = []
            for tg in targets:
                console.print(f"Diresearch for {tg}")
                dirsearch = enumeration.DirSearch(tg)
                try:
                    dirsearch_data = dirsearch.get_data(f"/tmp/{urlparse(tg).netloc}_dirsearch.json")
                except AppNotInstalled:
                    surikatz_dict["dirsearch"] += dirsearch_data
                    result.Analyze.get_clean_data_dirsearch(dirsearch_data)
                    break
                


    #############################################################################
    ############################ SAVE INTO FILE #################################
    #############################################################################

    surikatz_dict = result.Analyze.clean_dict(surikatz_dict)

    result.Analyze.save_to_csv(surikatz_dict)

def json_output(dict_to_store):
    result.Analyze.save_to_json(dict_to_store)

if __name__ == "__main__":
    init()
