from rich.console import Console
from surikatz.utils import APIClient
from rich.markdown import Markdown
from rich.table import Table

"""
    Module for manipulate the final JSON output obtained by the previous scans to extract remarkable information
"""
console = Console()

class Analyze:

    @staticmethod
    def dict_clean(self, final_dict):
        console.print(final_dict)
        return self

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
        