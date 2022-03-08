from surikatz.error import ReadError 
from dotenv import load_dotenv
import os

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
