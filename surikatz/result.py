from rich.console import Console
"""
    Module for manipulate the final JSON output obtained by the previous scans to extract remarkable information
"""
console = Console()

class Analyze:
    def __init__(self,surikatz_dict):
        self.surikatz_dict = surikatz_dict



    def dict_clean(self, final_dict):
        console.print(final_dict)
        return self



class Select:
    """
    Class for determining revelant information for pentest
    """
