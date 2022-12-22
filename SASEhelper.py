#!/usr/bin/env python3

import logging
import requests
import xml.etree.ElementTree as ET
from lxml.etree import fromstring       # sudo apt-get install python3-lxml
from optparse import OptionParser
import os, sys

logging.basicConfig(filename='sasehelper.log', filemode='a',
                    format='%(asctime)s - %(levelname)s - %(message)s')

logger=logging.getLogger()

logger.setLevel(logging.DEBUG)

payload={}
headers = {
  'Authorization': 'Basic bG9oaXQxOnZlcnNhMTIz'
}

# Get command line arguments
def addOptions():
    o_parser = OptionParser()
    o_parser.add_option("-f", "--fqdn", dest="fqdn",
                        help="FQDN of the portal", metavar="<FQDN>")
    o_parser.add_option("-e", "--enterprise", dest="enterprise",
                        help="Enterprise name", metavar="<name>")
    o_parser.add_option("-u", "--user", dest="user",
                        help="Username", metavar="<name>")
    return o_parser


def validateArgs(c_options):
    if not c_options.fqdn or not c_options.enterprise or not c_options.user:
        print("try 'python3 SASEhelper.py --help'")
        sys.exit(1)


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

    def register(self, fqdn, org, user):
        api = apiCall()

        registerUrl = f"https://{fqdn}/secure-access/services/portal?ent_name={org}&action=register&username={user}"
        response = requests.request("GET", registerUrl, headers=headers, data=payload, verify=False)

        logger.debug(response.text)

        t = fromstring(response.text.encode('utf-8'))
        rspCode = t.xpath('/versa-secure-access/register/code').pop()
        logger.debug("Response Code: %s", rspCode.text)
        api.code = rspCode.text
        api.status = "testSuccess"

        return rspCode.text


    def preRegister(self, fqdn, org, user):
        api = apiCall()

        preregisterUrl = f"https://{fqdn}/secure-access/services/portal?action=preregister&ent_name={org}&username={user}"
        response = requests.request("GET", preregisterUrl, verify=False)

        logger.debug("Preregister request,\n %s", response.text)

        t = fromstring(response.text.encode('utf-8'))
        rspCode = t.xpath('/versa-secure-access/preregister/code').pop()
        logger.debug("Response Code: %s", rspCode.text)
        api.code = rspCode.text
        api.status = "testSuccess"

        return rspCode.text

    def discover(self, fqdn, org, user):
        api = apiCall()

        discoverUrl = f"https://{fqdn}/secure-access/services/portal?ent_name={org}&action=discover&username={user}"
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

    def login(self, fqdn, org, user):
        api = apiCall()

        loginUrl = f"https://vsa.gpversa.local/secure-access/services/gateway?action=login&ent_name={org}&username={user}&ep_protection=Windows+Defender&api_version=2&private_ip=10.192.45.250&eap_id=lohit1%40versa&detect_trusted_network=true "
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

    def preLogin(self, fqdn, org, user):
        api = apiCall()

        preloginUrl = f"https://vsa.gpversa.local/secure-access/services/gateway?action=prelogin&ent_name={org}&username={user}&api_version=2&device_mac=52-54-00-EE-A0-45&cb_url=com.versa.sase%3A%2F%2FsecureAccessClient&ipsec_profile_id=versa-vpn&private_ip=10.192.45.250&eap_id=lohit1%40versa&detect_trusted_network=true"
        response = requests.request("GET", preloginUrl, verify=False)

        logger.debug("Prelogin request,\n %s", response.text)

        t = fromstring(response.text.encode('utf-8'))
        rspCode = t.xpath('/versa-secure-access/prelogin/code').pop()
        logger.debug("Response Code: %s", rspCode.text)
        api.code = rspCode.text
        api.status = "testSuccess"

        return rspCode.text

    def discover(self, fqdn, org, user):
        api = apiCall()

        discoverUrl = f"https://vsa.gpversa.local/secure-access/services/gateway?action=discover&ent_name={org}&username={user}"
        response = requests.request("GET", discoverUrl, verify=False)

        logger.debug("Gateway discover request,\n %s", response.text)

        t = fromstring(response.text.encode('utf-8'))
        rspCode = t.xpath('/versa-secure-access/discover/code').pop()
        logger.debug("Response Code: %s", rspCode.text)
        api.code = rspCode.text
        api.status = "testSuccess"

        return rspCode.text


def main():
    o_parser = addOptions()
    (c_options, c_args) = o_parser.parse_args()
    validateArgs(c_options)

    print("FQDN      : ", c_options.fqdn)
    print("Enterprise: ", c_options.enterprise)
    print("User      : ", c_options.user)

    fqdn = c_options.fqdn
    org  = c_options.enterprise
    user = c_options.user

    p = portal()
    g = gateway()


    p.discover(fqdn, org, user)
    p.preRegister(fqdn, org, user)
    p.register(fqdn, org, user)

    g.discover(fqdn, org, user)
    g.preLogin(fqdn, org, user)
    g.login(fqdn, org, user)


if __name__ == '__main__':
    main()
