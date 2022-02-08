import re
import whois
from ipwhois import IPWhois


class Enumeration():
    def check_IP_Address(self,Ip):
        bool = 0
        regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
    # pass the regular expression
    # and the string in search() method
        if(re.search(regex, Ip)):
            print("Valid Ip address")
            return True
        else:
            return False


    def check_Domain(self,domain):
        regex= "^(?!-)[A-Za-z0-9-]+([\\-\\.]{1}[a-z0-9]+)*\\.[A-Za-z]{2,6}$"
        #a = input("Enter a domain name:")
        if(re.search(regex, domain)):
            return True

        else:
            return False

    def WhoIs(self):
        a = input("Enter an IP address or a domain name:")
        if(self.check_IP_Address(a)):
            print("Valid Ip address")
            b= IPWhois(a)
            results = b.lookup_whois()
            print(results)
        elif(self.check_Domain(a)):
            print("Valid Domain Name")
            b= whois.whois(a)
            print(b.text)
        else: 
            print("Please enter something that is valid")
    

            