from rich.console import Console
from surikatz.utils import APIClient
from rich.markdown import Markdown
from rich.table import Table
import csv
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
    def save_csv(dict_to_save):
        print(type(dict_to_save))

        df = pd.DataFrame.from_dict(dict_to_save, orient='index')
        print(df)
        df = df.transpose()
        print(df)
        df.to_csv (r'final.csv', index = False, header=True)

        # with open('mycsvfile.csv', 'w') as f:  # You will need 'wb' mode in Python 2.x
        #     w = csv.DictWriter(f, dict_to_save.keys())
        #     w.writeheader()
        #     w.writerow(dict_to_save)

            # x = list(dict_to_save.keys())
            # print(x)
            # print(type(x))
            # writer = csv.DictWriter(csv_file, fieldnames=x)
            # writer.writeheader()
            # for data in dict_to_save:
            #     writer.writerow(data)

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
