from rich.console import Console
from surikatz.utils import APIClient
from rich.markdown import Markdown
from rich.table import Table
import csv
import json
import pandas as pd

console = Console()
"""
    Module for manipulate the final JSON output obtained by the previous scans to extract remarkable information
"""

class Analyze:
    """
        Class for analysing the JSON, compare and eliminate obsolete data
    """
    @staticmethod
    def clean_dict(global_dict):
        console.print(global_dict)

    @staticmethod
    def save_to_csv(dict_to_save):
        """Transform dict data to a csv file
        Args:
            dict_to_save: All concatenated data in python dict form
        """
        df = pd.DataFrame(dict([ (k,pd.Series(v,dtype=pd.StringDtype())) for k,v in dict_to_save.items() ]))
        df.to_csv (r'final_data.csv', index = False, header=True)
        console.print("Writing all data in final_data.csv", style="bold #008000")

    @staticmethod
    def save_to_json(dict_to_save):
        """Transform dict data to a json file
        Args:
            dict_to_save: All concatenated data in python dict form
        """
        with open('final_data.json', 'w') as fp:
            json.dump(dict_to_save, fp)
            console.print("Writing all data in final_data.json", style="bold #008000")


    @staticmethod
    def get_cvss(cve):
        client = APIClient("https://cve.circl.lu/api/cve/")
        r = client.request(cve)
        try :
            result = {
                "cve":cve,
                "cvss":r["cvss"],
                "Type":r["capec"][0]["name"] if r["capec"] else ""
            }
        except :
            result = None

        colors = Select.display_CVSS(result)
        return colors

    @staticmethod
    def get_clean_data_theHarvester(theHarvesterDATA):
        interresting = ["test", "admin", "vpn", "login", "dev", "data", "gdpr", "rgpd", "backup", "contact", "internship", "stage", "apply", "recrut", "recrutement", "ftp", "info", "smtp", "imaps", "pop3", "administrateur", "administrator", "file", "secretariat", "secretary" ,"hr", "rh", "it", "drh"]
        lens = [len(theHarvesterDATA["ips"]), len(theHarvesterDATA["emails"]), len(theHarvesterDATA["FQDN"])]
        theHarvesterDATA["emails"] = theHarvesterDATA["emails"][:10]
        theHarvesterDATA["FQDN"] = [elt for elt in theHarvesterDATA["FQDN"] if elt.split(".")[0] in interresting]
        theHarvesterDATA["ips"] = theHarvesterDATA["ips"][:10]
        Select.display_TheHarvester_data(theHarvesterDATA, lens)


class Select:
    """
        Class for determining revelant information for pentest
    """
    @staticmethod
    def display_CVSS(cve):

        if not cve :
            print("Error while getting this CVE information \n")
            return

        if int(cve["cvss"]) > 8 :
            cvss_color = "red"
        elif int(cve["cvss"]) > 5 :
            cvss_color = "dark_orange"
        else :
            cvss_color = "white"

        console.print(f"CVE : {cve['cve']}", style="bold "+cvss_color)
        console.print(f"Type : {cve['Type']}", style=cvss_color)
        console.print(f"CVSS : {cve['cvss']}", style=cvss_color)
    

    @staticmethod
    def display_TheHarvester_data(theHarvesterDATA, lens):
        console.print("ips: ", lens[0], theHarvesterDATA["ips"], style="bold")
        console.print("emails:", lens[1], theHarvesterDATA["emails"], style="bold")
        console.print("fqdns:", lens[2], theHarvesterDATA["FQDN"], style="bold red")
