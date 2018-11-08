import sys
import boto.sts
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup
import warnings
from StringIO import StringIO
import pycurl
import urllib
warnings.filterwarnings("ignore")
import base64

# region: The default AWS region that this script will connect
# to for all API calls


def get_cerdentials(username, password, account_id, role_name, region = 'eu-central-1'):
    post_data = {'UserName': username, 'Password': password, 'AuthMethod':'FormsAuthentication'}
    postfields = urllib.urlencode(post_data)
    storage = StringIO()

    try:
        curl = pycurl.Curl()
        curl.setopt(pycurl.URL, "https://cloudsignin.win.azd.cloud.allianz/adfs/ls/IdpInitiatedSignOn.aspx?loginToRp=urn:amazon:webservices")
        curl.setopt(pycurl.SSL_VERIFYPEER, 1)
        curl.setopt(pycurl.SSL_VERIFYHOST, 2)
        curl.setopt(pycurl.POST, True)
        curl.setopt(pycurl.POSTFIELDS, postfields)
        curl.setopt(pycurl.CAINFO, "/etc/ssl/certs/saml.pem")
        curl.setopt(pycurl.WRITEFUNCTION, storage.write)
        curl.setopt(pycurl.FOLLOWLOCATION, 1)
        curl.setopt(pycurl.COOKIEJAR, '/tmp/saml_cookie.txt')
        #curl.setopt(pycurl.VERBOSE, True)
        curl.perform()
    except pycurl.error as er:
        print sys.exit('Connection Failed')
    else:
        response = storage.getvalue()
        curl.close()

    # Decode the response and extract the SAML assertion
    soup = BeautifulSoup(response.decode('utf8'), "html.parser")
    assertion = ''

    # Look for the SAMLResponse attribute of the input tag (determined by
    # analyzing the debug print lines above)
    for inputtag in soup.find_all('input'):
        if(inputtag.get('name') == 'SAMLResponse'):
            assertion = inputtag.get('value')

    try:
        root = ET.fromstring(base64.b64decode(assertion))
    except ET.ParseError as e:
        sys.exit("Login is not succeed")

    awsrole = None
    selected_role = None
    for saml2attribute in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
        if (saml2attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role'):
            for saml2attributevalue in saml2attribute.iter('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
                awsrole = saml2attributevalue.text
                if account_id in awsrole and role_name in awsrole:
                    selected_role = awsrole
                    break

    if not selected_role:
        return None, None, None

    role_arn = selected_role.split(',')[1]
    principal_arn = selected_role.split(',')[0]

    conn = boto.sts.connect_to_region(region, anon=True)
    token = conn.assume_role_with_saml(role_arn, principal_arn, assertion)
    return  token.credentials.access_key, token.credentials.secret_key, token.credentials.session_token
##################################################################################################################
'''
import getpass
domain = 'win\\'
# Get the federated credentials from the user
print "Username:",
username = raw_input()
username = domain + username
password = getpass.getpass()
print get_cerdentials(username, password, '966497653753', 'ADFS-PlatformOperator' )
'''
