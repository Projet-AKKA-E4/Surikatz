from surikatz.error import ReadError 
from dotenv import load_dotenv
import os
import re

class ConfReader:

	def __init__(self):
		load_dotenv()

	def _getApiKey(self, api):
		try:
			key = os.getenv(api)
			if key=="":
				raise ReadError("Impossible to read API key value. Make sure you fill it in .env file")

		except:
			key = f"Error, no {api} API key fond in .env file"
		
		return key
		
	def getShodan(self):
		return self._getApiKey("SHODAN_API")

	def getRapid(self):
		return self._getApiKey("RAPID_API")


class Checker:
    @staticmethod
    def checkIpAddress(Ip):
        regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
    	# pass the regular expression
    	# and the string in search() method
        if(re.search(regex, Ip)):
            return True
        else:
            return False
            
    @staticmethod        
    def checkDomain(domain):
        regex= "^(?!-)[A-Za-z0-9-]+([\\-\\.]{1}[a-z0-9]+)*\\.[A-Za-z]{2,6}$"
        #a = input("Enter a domain name:")
        if re.search(regex, domain):
            return True

        else:
            return False

