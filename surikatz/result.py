"""
    Module for manipulate the final JSON output obtained by the previous scans to extract remarkable information
"""

from surikatz import SURIKATZ_PATH
from surikatz.utils import APIClient
import json
import pandas as pd
from pathlib import Path
from rich import console, traceback

traceback.install(show_locals=True)
console = console.Console()

class Analyze:
    """
    Class for analysing the JSON, compare and eliminate obsolete data
    """

    @staticmethod
    def clean_dict(global_dict: dict) -> dict:
        """Clean dict data

        Args:
            global_dict: All concatenated data in python dict form

        Returns: 
            global_dict: Cleaned dictionary
        """
        if 'fqdns' in global_dict and 'hostnames' in global_dict:
            used = set()
            global_dict['fqdns'] = [x for x in global_dict['fqdns']+global_dict['hostnames'] if x not in used and (used.add(x) or True)]
            del global_dict['hostnames']

        global_dict.pop('ip', None)

        if 'domain_name' in global_dict and 'domains' in global_dict:
            used = set()
            global_dict['domain_name'] = [x for x in [global_dict['domain_name']]+global_dict['domains'] if x not in used and (used.add(x) or True)]
            del global_dict['domains']

        return global_dict

    @staticmethod
    def save_to_csv(dict_to_save: dict):
        """Transform dict data to a csv file

        Args:
            dict_to_save: All concatenated data in python dict form
        """
        df = pd.DataFrame(
            dict(
                [
                    (k, pd.Series(v, dtype=pd.StringDtype()))
                    for k, v in dict_to_save.items()
                ]
            )
        )
        filename = "final_data.csv"

        df.to_csv(SURIKATZ_PATH / filename, index=False, header=True)
        try:
            dest = Path().cwd() / filename
            dest.write_text(SURIKATZ_PATH.joinpath(filename).read_text())
        except OSError:
            print(
                "You don't have writing permission on current directory."
                f"The output file is written at {SURIKATZ_PATH / filename}"
            )
        console.print("Writing all data in final_data.csv", style="bold #008000")

    @staticmethod
    def save_to_json(dict_to_save: dict):
        """Transform dict data to a json file

        Args:
            dict_to_save: All concatenated data in python dict form
        """
        with open(Path.home() / "surikatz/final_data.json", "w") as fp:
            json.dump(dict_to_save, fp)
            console.print("Writing all data in final_data.json", style="bold #008000")

    @staticmethod
    def get_cvss(cve: str) -> dict:
        """Retrieves information of a CVE

        Args:
            cve: CVE ID
        
        Returns:
            Return a dictionnary with for one CVE, its ID, its CVSS score and its type
        """
        client = APIClient("https://cve.circl.lu/api/cve/")
        r = client.request(cve)
        try:
            result = {
                "cve": cve,
                "cvss": r["cvss"],
                "Type": r["cals -pec"][0]["name"] if r["capec"] else "Undefined",
            }
        except:
            result = None
        return result

    @staticmethod
    def get_clean_data_theHarvester(theharvester_data: dict):
        """Get clean data for TheHarvester and Display them.

        Args:
            parsed_data: TheHarvester parsed data.

        """
        interresting = [
            "test",
            "admin",
            "vpn",
            "login",
            "dev",
            "data",
            "gdpr",
            "rgpd",
            "backup",
            "contact",
            "internship",
            "apply",
            "recrut",
            "ftp",
            "info",
            "smtp",
            "imaps",
            "pop3",
            "file",
            "secret",
            "prod"
        ]
        # Gather lists length informations 
        lens = [
            len(theharvester_data["ips"]),
            len(theharvester_data["emails"]),
            len(theharvester_data["fqdns"]),
        ]
        # Get 10 first emails
        theharvester_data["emails"] = theharvester_data["emails"][:10]
        clean_fqdn = list()
        # For each fqdn try to see if one of the interresting string is in it
        # If so append it to clean_fqdn
        for fqdn in theharvester_data["fqdns"]:
            tmp_fqdn = next((fqdn for e in interresting if (e in fqdn.split(".")[0])),None)
            if tmp_fqdn:
                clean_fqdn.append(tmp_fqdn)
        # Get 10 first cleaned fqdn
        theharvester_data["fqdns"] = clean_fqdn[:10]
        # Get 10 first IP address
        theharvester_data["ips"] = theharvester_data["ips"][:10]
        # Display all informations
        Display.display_theharvester_data(theharvester_data, lens)

    @staticmethod
    def get_clean_data_dirsearch(parsed_data: list):
        """Get clean data for DirSearch and Display them.

        Args:
            parsed_data: DirSearch parsed data.
        """
        interresting = [
            "test",
            "admin",
            "vpn",
            "login",
            "dev",
            "data",
            "backup",
            ".txt",
            "passwd",
            "form",
            "api",
            ".log",
            "prod",
            "index"
        ]
        clean_data = list()
        # For each url try to see if one of the interresting string is in it
        # And don't have '/.ht' in it (because if maybe a false positive)
        # If so append it to clean_data
        for url in parsed_data:
            tmp_url = next((url for e in interresting if (e in url and not("/.ht" in url))),None)
            if tmp_url:
                clean_data.append(tmp_url)
        # Display only the first 10 elements
        Display.display_Dirsearch_data(clean_data[:10])

    @staticmethod
    def analyse_nmap(result: dict) -> dict:
        """Parse nmap result in order to extract 
            Args:
                result: raw result of nmap scan 

            Returns:
                Return a dictionnary containing for each host port its state, name of the product, version, cpe and protocol
        """
        dic = {'nmap':[]}
        for host in result['scan']:
            for port in result["scan"][host]["tcp"]:
                dic['nmap'].append(
                    {
                        "type": result['scan'][host]['tcp'][port]['name'],
                        "port": port,
                        "product": result['scan'][host]['tcp'][port]['product'],
                        "version": result['scan'][host]['tcp'][port]['version'],
                        "extrainfo": result['scan'][host]['tcp'][port]['extrainfo'],
                        "conf": result['scan'][host]['tcp'][port]['conf'],
                        "cpe": result['scan'][host]['tcp'][port]['cpe']
                    }
                )   
        return dic 


class Display:
    """
    Class for determining revelant information for pentest
    """

    @staticmethod
    def display_dict(data: dict, level=0):
        for field in data:
            if isinstance(data[field], list):
                console.print("\t"*level + f"{field} ({len(data[field])}):")
                for i, elm in enumerate(data[field]):
                    if isinstance(elm, dict):
                        Display.display_dict(elm, 1)
                        continue
                    console.print("\t"*level + f"\t{elm}")
                    if i == 9:
                        break
                if len(data[field]) > 10:
                    console.print("\t...")
                continue
            if isinstance(data[field], dict):
                Display.display_dict(data[field])
            else:
                console.print("\t"*level + f"{field}: {data[field]}")

    @staticmethod
    def display_CVSS(cve: str) -> None:
        """Display a CVE ID, CVSS score and type.

        Args:
            cve: Information of a CVE
        """
        if not cve:
            print("Error while getting this CVE information \n")
            return

        if int(cve["cvss"]) > 8:
            cvss_color = "red"
        elif int(cve["cvss"]) > 5:
            cvss_color = "dark_orange"
        else:
            cvss_color = "white"

        console.print(f"CVE : {cve['cve']}", style="bold " + cvss_color)
        console.print(f"Type : {cve['Type']}", style=cvss_color)
        console.print(f"CVSS : {cve['cvss']}", style=cvss_color)

    @staticmethod
    def display_theharvester_data(theharvester_data: dict, lens: list):
        """Display DirSearch cleaned data.

        Args:
            theharvester_data: TheHarvester cleaned data.
            lens : Length of of each list [len(ips), len(emails), len(fqdns)]
        """
        console.print("ips: ", lens[0], theharvester_data["ips"], style="bold")
        console.print("emails:", lens[1], theharvester_data["emails"], style="bold")
        console.print("fqdns:", lens[2], style="bold red")
        for fqdn in theharvester_data["fqdns"]:
            console.print(" - "+str(fqdn), style="red")
        if(lens[2]>10):
            console.print(" ... ", style="red")

    @staticmethod
    def display_txt(path: str):
        """Display txt file
            
            Args:
                path: path of the text file to be diplayed
        """
        with open(path) as file:
            console.print(file.read())

    @staticmethod
    def display_json(path: str):
        """Display json file
            
            Args:
                path: path of the json file to be diplayed
        """
        with open(path) as file:
            Display.display_dict(json.loads(file.read()))

    @staticmethod
    def display_Dirsearch_data(dirsearch_data: list):
        """Display DirSearch cleaned data.

        Args:
            dirsearch_data: DirSearch cleaned data.

        """
        console.print("Interesting URLs : ", style="bold red")
        for url in dirsearch_data:
            console.print(" - "+str(url), style="red")
        
