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
  'Authorization': 'Basic bG9oaXQxOnZlcnNhMTIz' # base64 encoded
}


def writeReport(p):
    VTY_HISTORY_PATH = "http://10.192.200.11/reports/SASEhelper-history.log"
    LOG_URL          = "http://10.192.200.11/reports/sasehelper.log"

    report = r"SASEhelper-report.html"

    try:
        rpt = open(report, 'w')
    except:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        logger.error("unable to open HTML file " + \
                    report + " for writing")
        logger.error(repr(traceback.format_exception_only(exc_type, exc_value)))
        sys.exit(1)

    rpt.write('<html>\n')
    rpt.write('  <head>\n')
    rpt.write('    <title>TEST RESULT SUMMARY</title>\n')
    rpt.write('    <style>\n')
    rpt.write('      a:hover {\n')
    rpt.write('        background-color: LightYellow;\n')
    rpt.write('        text-decoration: none\n')
    rpt.write('      }\n')
    rpt.write('\n')
    rpt.write('      a {\n')
    rpt.write('        text-decoration: none\n')
    rpt.write('      }\n')
    rpt.write('    </style>\n')
    rpt.write('  </head>\n')
    rpt.write('  <body>\n')
    rpt.write('    <div style="background-color: White;">\n')
    rpt.write('      <h1>\n')
    rpt.write('        <br>&nbsp; &nbsp;TEST RESULT SUMMARY <br>\n')
    rpt.write('        <br>\n')
    rpt.write('      </h1>\n')
    rpt.write('    </div>\n')
    rpt.write('    <br>\n')
    rpt.write('    <table border="1" cellpadding="4" bgcolor="White">\n')
    rpt.write('      <tr bgcolor="#82f58f">\n')
    rpt.write('        <td align="center">\n')
    rpt.write('          <b>SERVICE</b>\n')
    rpt.write('        </td>\n')
    rpt.write('        <td align="center">\n')
    rpt.write('          <b>ACTION</b>\n')
    rpt.write('        </td>\n')
    rpt.write('        <td align="center">\n')
    rpt.write('          <b>RESPONSE</b>\n')
    rpt.write('        </td>\n')
    rpt.write('        <td align="center">\n')
    rpt.write('          <b>COMMENTS</b>\n')
    rpt.write('        </td>\n')
    rpt.write('      </tr>\n')


    rpt.write('      <tr bgcolor="#82d5f5">\n')
    rpt.write('        <td colspan="6" align="lef">\n')
    rpt.write('          <b>PORTAL - %s</b>\n'% (p.getFqdn()))
    rpt.write('        </td>\n')
    rpt.write('      </tr>\n')


    rpt.write('      <tr>\n')
    rpt.write('        <td align="center"></td>\n')
    rpt.write('        <td align="center">\n')
    rpt.write(f'          <a href="{VTY_HISTORY_PATH}">\n')
    rpt.write('            <font color=GREEN>Discover</font>\n')
    rpt.write('          </a>\n')
    rpt.write('        </td>\n')
    rpt.write(f'        <td align="center">{p.discoverStatus.getRspCode()}</td>\n', )
    rpt.write(f'        <td align="center">{p.discoverStatus.getMsg()}</td>\n')
    rpt.write('      </tr>\n')
    rpt.write('      <tr>\n')
    rpt.write('        <td align="center"></td>\n')
    rpt.write('        <td align="center">\n')
    rpt.write(f'          <a href="{VTY_HISTORY_PATH}">\n')
    rpt.write('            <font color=GREEN>Pre-register</font>\n')
    rpt.write('          </a>\n')
    rpt.write('        </td>\n')
    rpt.write(f'        <td align="center">{p.preRegisterStatus.getRspCode()}</td>\n')
    rpt.write(f'        <td align="center">{p.preRegisterStatus.getMsg()}</td>\n')
    rpt.write('      </tr>\n')
    rpt.write('      <tr>\n')
    rpt.write('        <td align="center"></td>\n')
    rpt.write('        <td align="center">\n')
    rpt.write(f'          <a href="{VTY_HISTORY_PATH}">\n')
    rpt.write('            <font color=GREEN>Register</font>\n')
    rpt.write('          </a>\n')
    rpt.write('        </td>\n')
    rpt.write(f'        <td align="center">{p.registerStatus.getRspCode()}</td>\n')
    rpt.write(f'        <td align="center">{p.registerStatus.getMsg()}</td>\n')
    rpt.write('      </tr>\n')


    for gw in p.gateways:
        rpt.write('      <tr bgcolor="#82d5f5">\n')
        rpt.write('        <td colspan="6" align="lef">\n')
        rpt.write(f'          <b>GATEWAY - {gw.getName()}</b>\n')
        rpt.write('        </td>\n')
        rpt.write('      </tr>\n')


        rpt.write('      <tr>\n')
        rpt.write('        <td align="center"></td>\n')
        rpt.write('        <td align="center">\n')
        rpt.write(f'          <a href="{VTY_HISTORY_PATH}">\n',)
        rpt.write('            <font color=GREEN>Discover</font>\n')
        rpt.write('          </a>\n')
        rpt.write('        </td>\n')
        rpt.write(f'        <td align="center">{gw.discoverStatus.getRspCode()}</td>\n')
        rpt.write(f'        <td align="center">{gw.discoverStatus.getMsg()}</td>\n')
        rpt.write('      </tr>\n')
        rpt.write('      <tr>\n')
        rpt.write('        <td align="center"></td>\n')
        rpt.write('        <td align="center">\n')
        rpt.write(f'          <a href="{VTY_HISTORY_PATH}">\n')
        rpt.write('            <font color=GREEN>Pre-Login</font>\n')
        rpt.write('          </a>\n')
        rpt.write('        </td>\n')
        rpt.write(f'        <td align="center">{gw.preLoginStatus.getRspCode()}</td>\n')
        rpt.write(f'        <td align="center">{gw.preLoginStatus.getMsg()}</td>\n')
        rpt.write('      </tr>\n')
        rpt.write('      <tr>\n')
        rpt.write('        <td align="center"></td>\n')
        rpt.write('        <td align="center">\n')
        rpt.write(f'          <a href="{VTY_HISTORY_PATH}">\n')
        rpt.write('            <font color=GREEN>Login</font>\n')
        rpt.write('          </a>\n')
        rpt.write('        </td>\n')
        rpt.write(f'        <td align="center">{gw.loginStatus.getRspCode()}</td>\n')
        rpt.write(f'        <td align="center">{gw.loginStatus.getMsg()}</td>\n')
        rpt.write('      </tr>\n')

    rpt.write(f'    <br> Test Case Log : Click <a href={LOG_URL}>here</a> to access test case log <br>\n')
    rpt.write(f'    <br> Test Case VTY history : Click <a href={VTY_HISTORY_PATH}>here</a> to access test case VTY history output <br>\n')
    rpt.write('    <br> NOTICE: Internal Use Only - Versa Networks. All Rights Reserved. <br>\n')
    rpt.write('    <i>**This report is auto-generated at: 2022-12-14 11:22:06 </i>\n')

    rpt.write('    </table>\n')
    rpt.write('  </body>\n')
    rpt.write('</html>\n')
    return

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

def httpCodeStr(code):
    if  code == "200":
        return "Success"

    elif code == "401":
        return "Login required"

    elif code == "403" or code == "404":
        return "Client error"

    elif code == "500":
        return "Server failure"

    else:
        return "Failure for other reasons"

class status:
    def __inti__(self):
        self.code = "500"
        self.msg = "NA"

    def setRspCode(self, code):
        self.code = code

    def setMsg(self, msg):
        self.msg = msg

    def getRspCode(self):
        return self.code

    def getMsg(self):
        return self.msg


class portal:

    def __init__(self, fqdn):
        self.fqdn = fqdn
        self.gateways = []

    def setFqdn(self, fqdn):
        self.fqdn = fqdn

    def getFqdn(self):
        return self.fqdn

    def setEnterprise(self, enterprise):
        self.enterprise = enterprise

    def getEnterprise(self):
        return self.enterprise

    def setUser(self, user):
        self.user = user

    def getUser(self):
        return self.user

    def setCacert(self, cert):
        self.cacert = cert

    def getCacert(self):
        return self.cacert

    portalStatus = status()
    discoverStatus = status() 
    preRegisterStatus = status()
    registerStatus = status()

    def register(self, fqdn, org, user):
        logger.info("========== R E G I S T E R =============")
        registerUrl = f"https://{fqdn}/secure-access/services/portal?ent_name={org}&action=register&username={user}"
        response = requests.request("GET", registerUrl, headers=headers, data=payload, verify=False)

        logger.debug(response.text)

        t = fromstring(response.text.encode('utf-8'))
        rspCode = t.xpath('/versa-secure-access/register/code').pop()
        logger.debug("Response Code: %s", rspCode.text)

        if not rspCode.text == "200":
            logger.error("Invalid reponse, cannot proceed")
            return

        gws = t.find('gateways')
        for gw in gws.findall('gateway'):
            logger.debug("Found %s", gw.find('name').text)
            gwObj = gateway(gw.find('name').text,
                            gw.find('host').text,
                            gw.find('captive-portal').find('url').text,
                            gw)
            self.gateways.append(gwObj)

        self.registerStatus.setRspCode(rspCode.text)
        self.registerStatus.setMsg(httpCodeStr(rspCode.text))

        return rspCode.text


    def preRegister(self, fqdn, org, user):
        logger.info("========== P R E R E G I S T E R =============")
        preregisterUrl = f"https://{fqdn}/secure-access/services/portal?action=preregister&ent_name={org}&username={user}"
        response = requests.request("GET", preregisterUrl, verify=False)

        logger.debug("Preregister request,\n %s", response.text)

        t = fromstring(response.text.encode('utf-8'))
        rspCode = t.xpath('/versa-secure-access/preregister/code').pop()
        logger.debug("Response Code: %s", rspCode.text)

        self.preRegisterStatus.setRspCode(rspCode.text)
        self.preRegisterStatus.setMsg(httpCodeStr(rspCode.text))

        return rspCode.text

    def discover(self, fqdn, org, user):
        logger.info("========== D I S C O V E R =============")
        discoverUrl = f"https://{fqdn}/secure-access/services/portal?ent_name={org}&action=discover&username={user}"
        response = requests.request("GET", discoverUrl, verify=False)

        logger.debug("Discover request,\n %s", response.text)

        t = fromstring(response.text.encode('utf-8'))
        rspCode = t.xpath('/versa-secure-access/discover/code').pop()
        logger.debug("Response Code: %s", rspCode.text)

        self.discoverStatus.setRspCode(rspCode.text)
        self.discoverStatus.setMsg(httpCodeStr(rspCode.text))

        return rspCode.text


class gateway:
    def __init__(self, name, host, cp_url, gw):
        self.name = name
        self.host = host
        self.cp_url = cp_url
        self.gw = gw

    def setName(self, name):
        self.name = name

    def getName(self):
        return self.name

    def setHost(self, host):
        self.host = host

    def getHost(self):
        return self.host

    def setStatus(self, status):
        self.status = status

    def getStatus(self):
        return self.status

    def setTpasswd(self, pwd):
        self.tPasswd = pwd

    def getTpasswd(self):
        return self.tPasswd

    gatewayStatus = status()
    discoverStatus = status() 
    preLoginStatus = status()
    loginStatus = status()

    def login(self, cp_url, org, user):
        logger.info("========== L O G I N =============")
        loginUrl = f"{cp_url}?action=login&ent_name={org}&username={user}&ep_protection=Windows+Defender&api_version=2&private_ip=10.192.45.250&eap_id=lohit1%40versa&detect_trusted_network=true "
        response = requests.request("GET", loginUrl, headers=headers, data=payload, verify=False)

        logger.debug("Login request,\n %s", response.text)

        t = fromstring(response.text.encode('utf-8'))
        rspCode = t.xpath('/versa-secure-access/login/code').pop()
        logger.debug("Response Code: %s", rspCode.text)

        rspCode = t.xpath('/versa-secure-access/tunnel-password').pop()
        logger.debug("Tunnel password: %s", rspCode.text)
        self.setTpasswd(rspCode.text)

        self.loginStatus.setRspCode(rspCode.text)
        self.loginStatus.setMsg(httpCodeStr(rspCode.text))

        return rspCode.text

    def preLogin(self, cp_url, org, user):
        logger.info("========== P R E L O G I N =============")
        preloginUrl = f"{cp_url}?action=prelogin&ent_name={org}&username={user}&api_version=2&device_mac=52-54-00-EE-A0-45&cb_url=com.versa.sase%3A%2F%2FsecureAccessClient&ipsec_profile_id=versa-vpn&private_ip=10.192.45.250&eap_id=lohit1%40versa&detect_trusted_network=true"
        response = requests.request("GET", preloginUrl, verify=False)

        logger.debug("Prelogin request,\n %s", response.text)

        t = fromstring(response.text.encode('utf-8'))
        rspCode = t.xpath('/versa-secure-access/prelogin/code').pop()
        logger.debug("Response Code: %s", rspCode.text)

        self.preLoginStatus.setRspCode(rspCode.text)
        self.preLoginStatus.setMsg(httpCodeStr(rspCode.text))

        return rspCode.text

    def discover(self, cp_url, org, user):

        logger.info("========== D I S C O V E R =============")
        discoverUrl = f"{cp_url}?action=discover&ent_name={org}&username={user}"
        response = requests.request("GET", discoverUrl, verify=False)

        logger.debug("Gateway discover request,\n %s", response.text)

        t = fromstring(response.text.encode('utf-8'))
        rspCode = t.xpath('/versa-secure-access/discover/code').pop()
        logger.debug("Response Code: %s", rspCode.text)

        self.discoverStatus.setRspCode(rspCode.text)
        self.discoverStatus.setMsg(httpCodeStr(rspCode.text))

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

    p = portal(fqdn)

    p.discover(fqdn, org, user)
    if p.discoverStatus.getRspCode() != "200":
        logger.error("discover failed")
        writeReport(p)
        sys.exit(1)

    p.preRegister(fqdn, org, user)
    if p.preRegisterStatus.getRspCode() != "401":
        logger.error("preRegister failed")
        writeReport(p)
        sys.exit(1)

    p.register(fqdn, org, user)
    if p.registerStatus.getRspCode() != "200":
        logger.error("register failed")
        writeReport(p)
        sys.exit(1)

    if p.gateways:
        for gw in p.gateways:
            logger.debug("==============*********==============")
            gw.discover(gw.cp_url, org, user)
            gw.preLogin(gw.cp_url, org, user)
            gw.login(gw.cp_url, org, user)
            logger.debug("============== %s : %s ===============",
                         gw.getName(), gw.getTpasswd())

    writeReport(p)

if __name__ == '__main__':
    main()
