"""
    Module for manipulate the final JSON output obtained by the previous scans to extract remarkable information
"""

from click import style
from rich.console import Console
from surikatz.utils import APIClient
import json
import pandas as pd
from pathlib import Path

console = Console()
class Analyze:
    """
    Class for analysing the JSON, compare and eliminate obsolete data
    """

    @staticmethod
    def clean_dict(global_dict)->dict:
        """Clean dict data
        Args:
            global_dict: All concatenated data in python dict form
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
    def save_to_csv(dict_to_save):
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
        tmp_dest = Path("/tmp/surikatz")
        if not tmp_dest.exists():
            Path.mkdir(tmp_dest, parents=True, exist_ok=True)
        df.to_csv(tmp_dest / filename, index=False, header=True)
        try:
            dest = Path().cwd() / filename
            dest.write_text(tmp_dest.joinpath(filename).read_text())
        except OSError:
            print(
                "You don't have writing permission on current directory."
                f"The output file is written at {tmp_dest / filename}"
            )
        console.print("Writing all data in final_data.csv", style="bold #008000")

    @staticmethod
    def save_to_json(dict_to_save):
        """Transform dict data to a json file
        Args:
            dict_to_save: All concatenated data in python dict form
        """
        with open(Path.home() / "surikatz/final_data.json", "w") as fp:
            json.dump(dict_to_save, fp)
            console.print("Writing all data in final_data.json", style="bold #008000")

    @staticmethod
    def get_cvss(cve):
        client = APIClient("https://cve.circl.lu/api/cve/")
        r = client.request(cve)
        try:
            result = {
                "cve": cve,
                "cvss": r["cvss"],
                "Type": r["capec"][0]["name"] if r["capec"] else "Undefined",
            }
        except:
            result = None

    @staticmethod
    def save_to_csv(dict_to_save):
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
        tmp_dest = Path("/tmp/surikatz")
        if not tmp_dest.exists():
            Path.mkdir(tmp_dest, parents=True, exist_ok=True)
        df.to_csv(tmp_dest / filename, index=False, header=True)
        try:
            dest = Path().cwd() / filename
            dest.write_text(tmp_dest.joinpath(filename).read_text())
        except OSError:
            print(
                "You don't have writing permission on current directory."
                f"The output file is written at {tmp_dest / filename}"
            )
        console.print("Writing all data in final_data.csv", style="bold #008000")

    @staticmethod
    def save_to_json(dict_to_save):
        """Transform dict data to a json file
        Args:
            dict_to_save: All concatenated data in python dict form
        """
        with open(Path.home() / "surikatz/final_data.json", "w") as fp:
            json.dump(dict_to_save, fp)
            console.print("Writing all data in final_data.json", style="bold #008000")

    @staticmethod
    def get_cvss(cve):
        client = APIClient("https://cve.circl.lu/api/cve/")
        r = client.request(cve)
        try:
            result = {
                "cve": cve,
                "cvss": r["cvss"],
                "Type": r["capec"][0]["name"] if r["capec"] else "Undefined",
            }
        except:
            result = None

        colors = Display.display_CVSS(result)
        return colors

    @staticmethod
    def get_clean_data_theHarvester(theHarvesterDATA):
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
            "stage",
            "apply",
            "recrut",
            "recrutement",
            "ftp",
            "info",
            "smtp",
            "imaps",
            "pop3",
            "administrateur",
            "administrator",
            "file",
            "secretariat",
            "secretary",
            "hr",
            "rh",
            "it",
            "drh",
        ]
        lens = [
            len(theHarvesterDATA["ips"]),
            len(theHarvesterDATA["emails"]),
            len(theHarvesterDATA["fqdns"]),
        ]
        theHarvesterDATA["emails"] = theHarvesterDATA["emails"][:10]
        theHarvesterDATA["fqdns"] = [
            elt for elt in theHarvesterDATA["fqdns"] if elt.split(".")[0] in interresting
        ]
        theHarvesterDATA["ips"] = theHarvesterDATA["ips"][:10]
        Display.display_TheHarvester_data(theHarvesterDATA, lens)

class Display:
    """
    Class for determining revelant information for pentest
    """

    @staticmethod
    def display_CVSS(cve):

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
    def display_TheHarvester_data(theHarvesterDATA, lens):
        console.print("ips: ", lens[0], theHarvesterDATA["ips"], style="bold")
        console.print("emails:", lens[1], theHarvesterDATA["emails"], style="bold")
        console.print("fqdns:", lens[2], theHarvesterDATA["fqdns"], style="bold red")

    @staticmethod
    def display_wafwoof():
        with open("/tmp/wafwoof.json") as file:
            console.print(json.loads(file.read()))

    @staticmethod
    def display_nikto():
        with open("/tmp/nikto.txt","r") as file:
            console.print(file.read())