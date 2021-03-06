#!/usr/bin/env python3
# Surikatz - A powerful tool for searching informations before pentest.
#
# This software is provided under GNU General Public License v3.0.
# See the accompanying LICENSE.md file for more information.
#
# Description:
#    It can be used in three different ways :
#        * Passive     : Only search on public sources (Shodan, TheHarvester, Wappalyzer...)
#        * Discrete    : Use Passsive technics and soft nmap scan, soft HTTrack, ...
#        * Aggressive  : Use Passive and Discrete technics but more ... aggressive. Use nmap NSE scrips, Dirsearch, Nikto, ...
#
#    Usage:
#        ./surikatz [IP|Domain] [Options]
#
# Authors:
#       Abdelmalik KERBADOU
#       Théo PERESSE-GOURBIL
#       Manon HERMANN
#       Rayane BOUDJEMAA
#       Nathan SAUCET
#       Laurent DELATTE

from distutils.log import error
from surikatz import SURIKATZ_PATH, utils, osint, scan, result, enumeration
import click
from rich import console, traceback, markdown, progress
from enum import Enum
import os
from urllib.parse import urlparse
import surikatz
import shutil
from pathlib import Path

from surikatz.error import APIError, AppNotInstalled

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
    "--aggressive",
    "level",
    flag_value=ScanMode.AGRESSIVE,
    type=ScanMode,
    default=ScanMode.AGRESSIVE,
    help="Use Passive and Discrete technics but more ... aggressive. Use nmap NSE scrips, Dirsearch, Nikto, ...",
)
@click.option(
    "-d",
    "--discret",
    "level",
    flag_value=ScanMode.DISCRET,
    type=ScanMode,
    default=ScanMode.AGRESSIVE,
    help="Use Passsive technics and soft nmap, soft HTTrack, ...",
)
@click.option(
    "-p",
    "--passive",
    "level",
    flag_value=ScanMode.PASSIVE,
    type=ScanMode,
    default=ScanMode.AGRESSIVE,
    help="Only search on public sources (Shodan, TheHarvester, Wappalyzer...)",
)

def init(target:str, level:ScanMode):
    motd(1.0)
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
    """Display of the Surikatz launch

    Args: 
        version: version number of the Surikatz program
    """
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
    """Launch of the Surikatz program

    Args: 
        target: IP address or domain name of the target
        level: program launch level (passive, discret, agressive)
    """
    
    global surikatz_dict

    #############################################################################
    ############################### WHOIS #######################################
    #############################################################################

    if level.value >= ScanMode.PASSIVE.value:
        console.rule("[bold]Whois information")
        console.print("")
        whois = osint.Whois()
        whois_data = whois.whoIs(target)
        result.Display.display_dict(whois_data)
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
                clean_data_theharvester, lens_data_theharvester = result.Analyze.get_clean_data_theHarvester(harvester_data.copy())
                result.Display.display_theharvester_data(clean_data_theharvester, lens_data_theharvester)

                console.print("\n")
            else:
                console.print("No informations on domain\n")
        except AppNotInstalled:
            harvester_data = None


    #############################################################################
    ############################### SHODAN ######################################
    #############################################################################

    if level.value >= ScanMode.PASSIVE.value:
        console.rule("[bold]Shodan information")
        console.print("")
        shodan_api = osint.ShodanUtils(conf.get_shodan_key())
        shodan_data = shodan_api.get_data(whois_data["ip_address"])

        if shodan_api is not None:
            cves = shodan_data.pop("vulns")
            result.Display.display_dict(shodan_data)
            console.print("\n")
            surikatz_dict.update({"shodan": shodan_data})

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
        
        nm.start_nmap(utils.Checker.get_target(target), f"{frag} -D {leures} -sV -oN {SURIKATZ_PATH / 'nmap' / target} {temps} {ports} {scripts} -Pn", 10000)
        nmap_analyse = result.Analyze.analyse_nmap(nm.scan_result)
        surikatz_dict.update({**nmap_analyse})
        result.Display.display_txt(SURIKATZ_PATH / "nmap" / target)


    #############################################################################
    #############################################################################
    ################################# HTTP ######################################
    #############################################################################
    #############################################################################

    if "services" in surikatz_dict["shodan"] and utils.Checker.service_exists("http", surikatz_dict):
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

            for tg in progress.track(targets, description="Processing...", total=len(targets)):
                wappalyzer_data = wappalyzer_api.lookup(tg)
                if wappalyzer_data == None:
                    console.print("API Key is no longer valid : Error 403")
                else:
                    console.print(wappalyzer_data)
                    surikatz_dict["wappalizer"].append(wappalyzer_data)

            console.print("\n")
            for host in surikatz_dict["wappalizer"] :
                if not urlparse(host["url"]) in targets:
                    targets.append(host["url"])

            target_with_schem = []
            target_without_scheme = []
            for tg in targets:
                if urlparse(tg).scheme:
                    target_with_schem.append(tg)
                else:
                    target_without_scheme.append(tg)

            for tgw in target_with_schem:
                if urlparse(tgw).netloc in target_without_scheme:
                    target_without_scheme.remove(urlparse(tgw).netloc)

            targets = target_with_schem + target_without_scheme
            targets = list(set(targets))

        #############################################################################
        ############################# HTTrack #######################################
        #############################################################################
        
        if level.value >= ScanMode.DISCRET.value:
            console.rule("[bold]HTTrack")

            for tg in targets:
                if urlparse(tg).scheme:
                    base_path = Path(f"{urlparse(tg).netloc.replace('-','_')}")
                    try : 
                        scan.HTTrak(tg, SURIKATZ_PATH / base_path)
                    except AppNotInstalled as e:
                        console.print(e)
                        break
                else:
                    base_path = Path(f"{tg.replace('-','_')}")
                    try:
                        scan.HTTrak(tg, SURIKATZ_PATH / base_path)
                    except AppNotInstalled as e:
                        console.print(e)
                        break
                try: 
                    shutil.copytree(SURIKATZ_PATH / base_path, Path().cwd() / "httrack" / base_path, dirs_exist_ok=True)
                    console.print("Folder moved in current pwd")
                    console.print(f"HTTrack finished. Output folder : {Path().cwd() / 'httrack' / base_path}", end="\n\n")
                except OSError:
                    console.print(f"Error while moving folding. Result is still available at {SURIKATZ_PATH / base_path}", end="\n\n")


        #############################################################################
        ############################# WPSCAN #########################################
        #############################################################################

        if "wappalizer" in surikatz_dict:
            console.rule("[bold]Wpscan information")
            console.print("")

            wpscan_data = {}
            flag = False
            count = 0

            for item in surikatz_dict["wappalizer"]:  # Check if there is a Wordpress CMS to analyse
                for techno in item["technologies"] :
                    if not techno["slug"] == "wordpress": console.print("There is no Worpress to analyze for "+ item["url"],
                                                                                        style="bold #FFA500")
                    wpscan_call = scan.WpScan(whois_data["domain_name"], conf.get_wpscan_key(), item)

                    if conf.get_wpscan_key() and whois_data["domain_name"]:
                        if level.value == ScanMode.PASSIVE.value:
                            wpscan_data = wpscan_call.passive_wp_scan()
                            result.Display.display_dict(wpscan_data)
                            flag = True
                            count+=1
                            break
                        if level.value == ScanMode.DISCRET.value:
                            wpscan_call.discret_wp_scan()
                            wpscan_data = wpscan_call.dict_concatenate()
                            flag = True
                            count+=1
                            break
                        if level.value == ScanMode.AGRESSIVE.value:
                            wpscan_call.aggressive_wp_scan()
                            wpscan_data = wpscan_call.dict_concatenate()
                            flag = True
                            count+=1
                            break
                surikatz_dict.update({"wpscan" : wpscan_data})
                if flag : break
            if count == 0:
                console.print("No wordpress or plugins detected")

        #############################################################################
        ############################## WafW00f ######################################
        #############################################################################

        if level == ScanMode.AGRESSIVE:
            console.rule(f"[bold]WafW00f")
            surikatz_dict["wafwoof"] = []
            count = 0
            for tg in targets:
                if urlparse(tg).scheme == "https":
                    try:
                        console.print(f"WafWoof for {tg}")
                        base_path = Path(f"{urlparse(tg).netloc.replace('-','_')}.json")
                        scan.Wafwoof(tg, SURIKATZ_PATH / "wafwoof" / base_path)
                        wafwoof_data = result.Display.display_json(SURIKATZ_PATH / "wafwoof" /base_path)
                        surikatz_dict["wafwoof"].append(wafwoof_data)
                        console.print("")
                        count +=1
                    except:
                        pass
            if count==0:
                console.print("No https for WAF analyse")

        #############################################################################            
        ############################### DIRSEARCH ###################################
        #############################################################################
        
        if level == ScanMode.AGRESSIVE:
            console.rule("[bold]Dirsearch information")
            surikatz_dict["dirsearch"] = []
            for tg in targets:
                console.print(f"Diresearch for {tg}")
                try:
                    dirsearch = enumeration.DirSearch(tg)
                except AppNotInstalled:
                    console.print(e)
                    break
                try:
                    if urlparse(tg).scheme:
                        base_path = Path(f"{urlparse(tg).netloc.replace('-','_')}.json")
                        dirsearch_data = dirsearch.get_data(SURIKATZ_PATH / "dirsearch" / base_path)
                    else:
                        base_path = Path(f"{tg.replace('-','_')}.json")
                        dirsearch_data = dirsearch.get_data(SURIKATZ_PATH / "dirsearch" / base_path)

                    if dirsearch_data == None:
                        continue

                    surikatz_dict["dirsearch"] += dirsearch_data
                    dirsearch_clean_data = result.Analyze.get_clean_data_dirsearch(dirsearch_data)
                    result.Display.display_Dirsearch_data(dirsearch_clean_data)
                except AppNotInstalled:
                    break

                
        #############################################################################
        ############################# NIKTO #########################################
        #############################################################################
        if level == ScanMode.AGRESSIVE:
            console.rule(f"[bold]Nikto")

            for tg in targets:
                if urlparse(tg).scheme:
                    base_path = Path(f"{urlparse(tg).netloc.replace('-','_')}_nikto.txt")
                    scan.Nikto(tg, SURIKATZ_PATH / base_path)
                else:
                    base_path = Path(f"{tg.replace('-','_')}_nikto.txt")
                    scan.Nikto(tg, SURIKATZ_PATH / base_path)
                try: 
                    shutil.copytree(SURIKATZ_PATH / base_path, Path().cwd() / "nikto" / base_path, dirs_exist_ok=True)
                    console.print("Folder moved in current pwd")
                    console.print(f"nikto finished. Output folder : {Path().cwd() / 'nikto' / base_path}", end="\n\n")
                except OSError:
                    console.print(f"Error while moving folder. Result is still available at {SURIKATZ_PATH / base_path}", end="\n\n")
                

    #############################################################################
    ############################ SAVE INTO FILE #################################
    #############################################################################

    surikatz_dict = result.Analyze.clean_dict(surikatz_dict)
    #result.Analyze.save_to_csv(surikatz_dict)
    result.Analyze.save_to_json(surikatz_dict)

if __name__ == "__main__":
    init()
