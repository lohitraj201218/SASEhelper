#!/usr/bin/env python3

import logging
import requests
import xml.etree.ElementTree as ET
from lxml.etree import fromstring       # sudo apt-get install python3-lxml

logging.basicConfig(filename='sasehelper.log', filemode='a',
                    format='%(asctime)s - %(levelname)s - %(message)s')

logger=logging.getLogger()

logger.setLevel(logging.DEBUG)

# logger.warning('This message will get logged on to a file')
# logger.debug("This is just a harmless debug message")
# logger.info("This is just an information for you")
# logger.error("Have you try to divide a number by zero")
# logger.critical("The Internet is not working....")



payload={}
headers = {
  'Authorization': 'Basic bG9oaXQxOnZlcnNhMTIz'
}

class apiCall:
    def setRspCode(self, code):
        self.code = code

    def setStatus(self, status):
        self.status = status

class portal:
    def setFqdn(self, fqdn):
        self.fqdn = fqdn

    def setEnterprise(self, enterprise):
        self.enterprise = enterprise

    def setUser(self, user):
        self.user = user

    def setCacert(self, cert):
        self.cacert = cert

    def setStatus(self, status):
        self.status = status

    def register(self):
        api = apiCall()

        registerUrl = "https://vsa.gpversa.local/secure-access/services/portal?ent_name=versa&action=register&username=lohit1"
        response = requests.request("GET", registerUrl, headers=headers, data=payload, verify=False)
        
        logger.debug(response.text)
        
        t = fromstring(response.text.encode('utf-8'))
        rspCode = t.xpath('/versa-secure-access/register/code').pop()
        logger.debug("Response Code: %s", rspCode.text)
        api.code = rspCode.text
        api.status = "testSuccess"

        return rspCode.text
    
    
    def preRegister(self):
        api = apiCall()

        preregisterUrl = "https://vsa.gpversa.local/secure-access/services/portal?action=preregister&ent_name=versa&username=lohit1"
        response = requests.request("GET", preregisterUrl, verify=False)
        
        logger.debug("Preregister request,\n %s", response.text)
        
        t = fromstring(response.text.encode('utf-8'))
        rspCode = t.xpath('/versa-secure-access/preregister/code').pop()
        logger.debug("Response Code: %s", rspCode.text)
        api.code = rspCode.text
        api.status = "testSuccess"

        return rspCode.text
    
    def discover(self):
        api = apiCall()

        discoverUrl = "https://vsa.gpversa.local/secure-access/services/portal?ent_name=versa&action=discover&username=lohit1"
        response = requests.request("GET", discoverUrl, verify=False)
        
        logger.debug("Discover request,\n %s", response.text)
        
        t = fromstring(response.text.encode('utf-8'))
        rspCode = t.xpath('/versa-secure-access/discover/code').pop()
        logger.debug("Response Code: %s", rspCode.text)
        api.code = rspCode.text
        api.status = "testSuccess"

        return rspCode.text

    
class gateway:
    def setFqdn(self, fqdn):
        self.fqdn = fqdn

    def setStatus(self, status):
        self.status = status

    def login(self):
        api = apiCall()

        loginUrl = "https://vsa.gpversa.local/secure-access/services/gateway?action=login&ent_name=versa&username=lohit1&ep_protection=Windows+Defender&api_version=2&private_ip=10.192.45.250&eap_id=lohit1%40versa&detect_trusted_network=true "
        response = requests.request("GET", loginUrl, headers=headers, data=payload, verify=False)
        
        logger.debug("Login request,\n %s", response.text)
    
        t = fromstring(response.text.encode('utf-8'))
        rspCode = t.xpath('/versa-secure-access/login/code').pop()
        logger.debug("Response Code: %s", rspCode.text)
    
        rspCode = t.xpath('/versa-secure-access/tunnel-password').pop()
        logger.debug("Tunnel password: %s", rspCode.text)
        api.code = rspCode.text
        api.status = "testSuccess"

        return rspCode.text
    
    def preLogin(self):
        api = apiCall()

        preloginUrl = "https://vsa.gpversa.local/secure-access/services/gateway?action=prelogin&ent_name=versa&username=lohit1&api_version=2&device_mac=52-54-00-EE-A0-45&cb_url=com.versa.sase%3A%2F%2FsecureAccessClient&ipsec_profile_id=versa-vpn&private_ip=10.192.45.250&eap_id=lohit1%40versa&detect_trusted_network=true"
        response = requests.request("GET", preloginUrl, verify=False)
        
        logger.debug("Prelogin request,\n %s", response.text)
        
        t = fromstring(response.text.encode('utf-8'))
        rspCode = t.xpath('/versa-secure-access/prelogin/code').pop()
        logger.debug("Response Code: %s", rspCode.text)
        api.code = rspCode.text
        api.status = "testSuccess"

        return rspCode.text
    
    def discover(self):
        api = apiCall()

        discoverUrl = "https://vsa.gpversa.local/secure-access/services/gateway?action=discover&ent_name=versa&username=lohit1"
        response = requests.request("GET", discoverUrl, verify=False)
        
        logger.debug("Gateway discover request,\n %s", response.text)
        
        t = fromstring(response.text.encode('utf-8'))
        rspCode = t.xpath('/versa-secure-access/discover/code').pop()
        logger.debug("Response Code: %s", rspCode.text)
        api.code = rspCode.text
        api.status = "testSuccess"

        return rspCode.text

        
def main():
    p = portal()
    g = gateway()

    
    p.discover()
    p.preRegister()
    p.register()

    g.discover()
    g.preLogin()
    g.login()


if __name__ == '__main__':
    main()
