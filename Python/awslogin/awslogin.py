#!/usr/bin/python
import sys
import boto.sts
import boto.iam
import getpass
import ConfigParser
import base64
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup
from os.path import expanduser, exists
#from requests_ntlm import HttpNtlmAuth
import argparse
import warnings
from StringIO import StringIO
import pycurl
import urllib
import requests
warnings.filterwarnings("ignore")
import os
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random
import datetime
import yaml

########### Variables #######################
ConfigParser.DEFAULTSECT = 'default'
# region: The default AWS region that this script will connect
# to for all API calls
region = 'eu-central-1'

# output format: The AWS CLI output format that will be configured in the
# saml profile (affects subsequent CLI calls)
outputformat = 'json'

# awsconfigfile: The file where this script will store the temp
# credentials under the saml profile
awsconfigfile = '/.aws/credentials'

# SSL certificate verification: Whether or not strict certificate
# verification is done, False should only be used for dev/test
sslverification = True

#if args.skip_verify:    sslverification = False
# idpentryurl: The initial URL that starts the authentication process.
idpentryurl = 'https://cloudsignin.win.azd.cloud.allianz/adfs/ls/IdpInitiatedSignOn.aspx?loginToRp=urn:amazon:webservices'

domain = 'win\\'

key = 'QQ7A8IR08Z8I4DGN3PWXP9N1'
#################################################################
# Functions
def get_accounts_informations(username, password):
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

    # Debug the response if needed
    #print (response.text)

    # Decode the response and extract the SAML assertion
    soup = BeautifulSoup(response.decode('utf8'), "html.parser")
    assertion = ''

    # Look for the SAMLResponse attribute of the input tag (determined by
    # analyzing the debug print lines above)
    for inputtag in soup.find_all('input'):
        if(inputtag.get('name') == 'SAMLResponse'):
            #print(inputtag.get('value'))
            assertion = inputtag.get('value')

    try:
        root = ET.fromstring(base64.b64decode(assertion))
    except ET.ParseError as e:
        sys.exit("Login is not succeed")

    payload = {'SAMLResponse': assertion}
    try:
        response = requests.post("https://signin.aws.amazon.com:443/saml", data=payload)
    except requests.exceptions.SSLError :
        sys.exit("Connection error")
    else:
        soup = BeautifulSoup(response.text, "html.parser")


    roles = []
    for saml2attribute in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
        if (saml2attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role'):
            for saml2attributevalue in saml2attribute.iter('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
                roles.append(saml2attributevalue.text)

    accounts = {}
    for saml_accout in soup.find_all("div", class_="saml-account", attrs={'id': None}):
        account_title =  saml_accout.find("div", class_= "saml-account-name").text
        account = {"account_title": account_title, "roles": []}
        account_name = find_between(account_title, "Account: ", " (")
        accounts[account_name] = account
        for rolelabel in saml_accout.find_all("label"):
            for awsrole in roles:
                role = rolelabel['for']
                if role in awsrole:
                    if account_name in accounts.keys():
                        accounts[account_name]["roles"].append({"account_name":account_name, "role_name": rolelabel.text, "role": awsrole})
                    roles.remove(awsrole)
    return accounts, assertion

def get_username_password(input_username):
     ### check login_user config file
    username = None
    password = None

    if exists(samlfile):
        samlconfig = ConfigParser.ConfigParser()
        samlconfig.read(samlfile)
        if input_username:
            if samlconfig.has_section(input_username):
                try:
                    password = samlconfig.get(input_username, config_pass_key)
                except ConfigParser.NoOptionError:
                    print  "Note: There is Config file (.samlapi) but doesn't have a 's_data' key "
                    print ''
            elif input_username == os.getlogin():
                try:
                    password = samlconfig.get(ConfigParser.DEFAULTSECT, config_pass_key)
                except ConfigParser.NoOptionError:
                    pass
        else:
            if samlconfig.has_section(os.getlogin()):
                try:
                    password = samlconfig.get(os.getlogin(), config_pass_key)
                except ConfigParser.NoOptionError:
                    pass
            else:
                try:
                    password = samlconfig.get(ConfigParser.DEFAULTSECT, config_pass_key)
                except ConfigParser.NoOptionError:
                    pass
        if password:
            m_u_p = decrypt(key, password)
            password = um_u_pass(m_u_p, os.getlogin())
            if not input_username:
                username = os.getlogin()
            else:
                username = input_username

    if not username:
        login_user = os.getlogin()
        print "Username("+login_user+"):",
        username = raw_input()
        if not username:
            username = login_user

    username = domain + username

    if not password:
        password = getpass.getpass()
    return username, password

def find_between( s, first, last ):
    try:
        start = s.index( first ) + len( first )
        end = s.index( last, start )
        return s[start:end]
    except ValueError:
        return ""

def encrypt(key, source, encode=True):
    key = SHA256.new(key).digest()  # use SHA-256 over our key to get a proper-sized AES key
    IV = Random.new().read(AES.block_size)  # generate IV
    encryptor = AES.new(key, AES.MODE_CBC, IV)
    padding = AES.block_size - len(source) % AES.block_size  # calculate needed padding
    source += chr(padding) * padding  # Python 2.x: source += chr(padding) * padding
    data = IV + encryptor.encrypt(source)  # store the IV at the beginning and encrypt
    return base64.b64encode(data).decode("latin-1") if encode else data

def decrypt(key, source, decode=True):
    if decode:
        source = base64.b64decode(source.encode("latin-1"))
    key = SHA256.new(key).digest()  # use SHA-256 over our key to get a proper-sized AES key
    IV = source[:AES.block_size]  # extract the IV from the beginning
    decryptor = AES.new(key, AES.MODE_CBC, IV)
    data = decryptor.decrypt(source[AES.block_size:])  # decrypt
    padding = ord(data[-1])  # pick the padding value from the end; Python 2.x: ord(data[-1])
    if data[-padding:] != chr(padding) * padding:  # Python 2.x: chr(padding) * padding
        raise ValueError("Invalid padding...")
    return data[:-padding]  # remove the padding
'''
en = encrypt(key, "Allianz")
de = decrypt(key, en)
sys.exit(de)
'''
def m_u_pass(u, p):
    m = ''
    u_i =0
    p_i=0
    for i in range(0, len(u)+len(p)):
        if i % 2 == 0:
            if u_i < len(u):
                m = m + u[u_i]
                u_i = u_i + 1
            else:
                m = m + p[p_i]
                p_i = p_i + 1
        else:
            if p_i < len(p):
                m = m + p[p_i]
                p_i = p_i + 1
            else:
                m = m + u[u_i]
                u_i = u_i + 1
    return m

def um_u_pass(m, u):
    p=''
    p_len = (len(m) - len(u))
    u_len = len(u)
    bool = u_len > p_len

    if bool:
        for i in range(0, p_len):
            index = i*2 +1
            p = p + m[index]
    else:
        for i in range(0, u_len):
            index =  i * 2
            m = m[:i] + m[i+1:]
        p = m
    return p

'''
mer = m_u_pass('feuk8fs', 'passwor')
print mer
print um_u_pass(mer, 'feuk8fs')
sys.exit()
'''
home = expanduser("~")
samlconfigfile = '/.samlapi'
samlfile = home + samlconfigfile
config_pass_key = 's_data'
###################################################
if len(sys.argv) < 2:
    sys.exit('Please, choose one command (create-config or login)')
if sys.argv[1] == '-h' or sys.argv[1] == '--help':
    print 'usage: awslogin [-h] [create-config] [login]'
    print ''
    print 'optional arguments:'

    print "{:<20} {:<30}".format('create-config','create a config file, where you can save your credentials')
    print "{:<20} {:<30}".format('login', 'login to aws')
    print "{:<20} {:<30}".format('-l', 'List of all Roles')
    sys.exit()
###############################################################################
elif sys.argv[1] == 'create-config':
    config_parser = argparse.ArgumentParser(prog='create-config')
    config_parser.add_argument('create-config', help=argparse.SUPPRESS)
    config_parser.add_argument('-u', '--username', help='AWS Login Username')
    #config_parser.add_argument('-pw', '--password', help='AWS Login Password')
    config_parser.add_argument("-f", '--force', action="store_true", help='change the old config file')
    args = config_parser.parse_args()
    samlfile_exists = exists(samlfile)
    config_profile = args.username
    if samlfile_exists:
        change = False
        config = ConfigParser.ConfigParser()
        config.read(samlfile)
        has_section = config.has_section(config_profile)
        if not args.force:
            if has_section:
                print 'User Credentials under Profile '+config_profile+' already exists in the config file, do you want to change it? yes(y,Y) :',
                answer = raw_input()
                if answer == 'y' or answer == 'Y':
                    change = True
            else:
                change = True
        else:
            change = True
        if change:
            #if args.password: password = args.password  else:
            password= getpass.getpass()
            m_p_u = m_u_pass(os.getlogin(), password)
            password = encrypt(key, m_p_u)
            if config_profile:
                if not has_section:
                    config.add_section(config_profile)
                config.set(config_profile, config_pass_key , password)
            else:
                config.set(ConfigParser.DEFAULTSECT, config_pass_key , password)

            with open(samlfile, 'w+') as configfile:
                try:
                    config.write(configfile)
                except:
                    print 'The Config File is not changed successfully'
                else:
                    print 'The Config File is changed successfully'
    else:
        #if args.password: password = args.password else:
        password= getpass.getpass()
        m_p_u = m_u_pass(os.getlogin(), password)
        password = encrypt(key, m_p_u)
        config = ConfigParser.ConfigParser()
        #config.set(ConfigParser.DEFAULTSECT, 'username', os.getlogin())
        if config_profile:
            config.add_section(config_profile)
            config.set(config_profile, config_pass_key , password)
        else:
            config.set(ConfigParser.DEFAULTSECT, config_pass_key , password)
        with open(samlfile, 'wb') as configfile:
            try:
                config.write(configfile)
            except:
                print 'The Config File is not created successfully'
            else:
                print 'The Config File is created successfully'
    sys.exit()
######################################################################
elif sys.argv[1] == 'login':
    parser = argparse.ArgumentParser(prog='login')
    parser.add_argument('login', help=argparse.SUPPRESS)
    #profile argument
    parser.add_argument('-p', '--profile', help='Profile name in Credentials file')
    #account_name argument
    parser.add_argument('-a', '--account', help='AWS Account name')
    #role_name argument
    parser.add_argument('-r', '--role', help='AWS Role name (with ADFS- or without)')
    #user_name argument
    parser.add_argument('-u', '--username', help='AWS Login Username')

    parser.add_argument("-f", '--force', action="store_true", help='change the old credentials file')
    #password argument
    #config_parser.add_argument('-pw', '--password', help='AWS Login Password')
    #parser.add_argument("--skip-verify", action="store_true")
    args = parser.parse_args()

    if args.profile:
        profile = args.profile
    else:
        profile = ConfigParser.DEFAULTSECT

    if args.account:
        selected_account = args.account
    else:
        selected_account= None

    if args.role:
        selected_role = args.role
    else:
        selected_role= None

    if args.username:
        input_username = args.username
    else:
        input_username= None

    #if args.password:  password = args.password  else:
    password= None

    if args.force:
        force = True
    else:
        force = False

    ##########################################################################
    # Get the federated credentials from the user
    username, password = get_username_password(input_username)
    ############################
    accounts, assertion = get_accounts_informations(username, password)

    # Overwrite and delete the credential variables, just for safety
    username = '##############################################'
    password = '##############################################'
    del username
    del password

    print ''

    if selected_account:
        selected_accounts = [ account_key for account_key in accounts.keys()if selected_account.lower() in account_key.lower()]
        if len(selected_accounts) == 0:
            sys.exit('There is no '+ selected_account + ' Account')

        if selected_role:
            #if "ADFS" not in selected_role:
                #selected_role = "ADFS-" + selected_role
            if len(selected_accounts)> 1:
                awsroles = []
                i = 0
                for selected_account in selected_accounts:
                    roles = [account_role for account_role in accounts[selected_account]['roles'] if selected_role.lower() in account_role['role_name'].lower()]
                    if len(roles) > 0:
                        print accounts[selected_account]['account_title']
                        for role in roles:
                            awsroles.append(role)
                            print '[' + str(i) + ']' , role['role_name']
                            i = i+1
                            print ''

                if len(awsroles) > 0:
                    print "Selection: ",
                    selectedroleindex = raw_input()
                    try:
                        selcted_index = int(selectedroleindex)
                    except ValueError as er:
                        sys.exit(er)
                    else:
                        if selcted_index > (len(awsroles) - 1):
                            print 'You selected an invalid role index, please try again'
                            sys.exit(0)
                        awsrole =awsroles[selcted_index]
                else:
                    sys.exit('There is no '+ selected_role + ' Role')

            else:
                selected_account = selected_accounts.pop()
                roles = [account_role for account_role in accounts[selected_account]["roles"] if selected_role.lower() in account_role['role_name'].lower()]
                if len(roles) == 0:
                     sys.exit('There is no '+ selected_role + ' Role')
                if len(roles) > 1:
                    print accounts[selected_account]['account_title']
                    for role in roles:
                        awsroles.append(role)
                        print '[' + str(i) + ']' , role['role_name']
                        i = i+1
                        print ''

                    print "Selection: ",
                    selectedroleindex = raw_input()
                    try:
                        selcted_index = int(selectedroleindex)
                    except ValueError as er:
                        sys.exit(er)
                    else:
                        if selcted_index > (len(awsroles) - 1):
                            print 'You selected an invalid role index, please try again'
                            sys.exit(0)
                        awsrole =awsroles[selcted_index]
                else:
                    awsrole = roles[0]

        else:
            if len(selected_accounts)> 1:
                i=0
                for selected_account in selected_accounts:
                    print accounts[selected_account]['account_title']
                    awsroles = accounts[selected_account]["roles"]
                    for account_role in awsroles:
                        print '[' + str(i) + ']' , account_role['role_name']
                        i = i+1
                    print ''
                print "Selection: ",
                selectedroleindex = raw_input()
                try:
                    selcted_index = int(selectedroleindex)
                except ValueError as er:
                    sys.exit(er)
                else:
                    if selcted_index > (len(awsroles) - 1):
                        print 'You selected an invalid role index, please try again'
                        sys.exit(0)
                    awsrole =awsroles[selcted_index]
            else:
                i=0
                selected_account = selected_accounts.pop()
                awsroles = accounts[selected_account]["roles"]
                print accounts[selected_account]['account_title']
                for account_role in awsroles:
                    print '[' + str(i) + ']' , account_role['role_name']
                    i = i+1
                print ''
                print "Selection: ",
                selectedroleindex = raw_input()
                try:
                    selcted_index = int(selectedroleindex)
                except ValueError as er:
                    sys.exit(er)
                else:
                    if selcted_index > (len(awsroles) - 1):
                        print 'You selected an invalid role index, please try again'
                        sys.exit(0)
                    awsrole =awsroles[selcted_index]
    else:
        if selected_role:
            #if "ADFS" not in selected_role:
                #selected_role = "ADFS-" + selected_role
            i=0
            awsroles = []
            for account in accounts.values():
                    roles = [account_role for account_role in account['roles'] if selected_role.lower() in account_role['role_name'].lower()]
                    if len(roles) > 0:
                        print account['account_title']
                        for role in roles:
                            awsroles.append(role)
                            print '[' + str(i) + ']' , role['role_name']
                            i = i+1
                            print ''
            if len(awsroles) > 0:
                print "Selection: ",
                selectedroleindex = raw_input()
                # Basic sanity check of input

                try:
                    selcted_index = int(selectedroleindex)
                except ValueError as er:
                    sys.exit(er)
                else:
                    if selcted_index > (len(awsroles) - 1):
                        print 'You selected an invalid role index, please try again'
                        sys.exit(0)
                    awsrole =awsroles[selcted_index]
            else:
                sys.exit('There is no '+ selected_role + ' Role')
        else:
            i=0
            awsroles = []
            for account in accounts.values():
                print account['account_title']
                for role in account['roles']:
                    awsroles.append(role)
                    print '[' + str(i) + ']' , role['role_name']
                    i = i+1
                    print ''

            print "Selection: ",
            selectedroleindex = raw_input()
            # Basic sanity check of input
            try:
                selcted_index = int(selectedroleindex)
            except ValueError as er:
                sys.exit(er)
            else:
                if selcted_index > (len(awsroles) - 1):
                    print 'You selected an invalid role index, please try again'
                    sys.exit(0)
                awsrole =awsroles[selcted_index]

    account_name = awsrole["account_name"]
    role = awsrole["role"]
    role_name = awsrole["role_name"]
    role_arn = role.split(',')[1]
    principal_arn = role.split(',')[0]


    # Use the assertion to get an AWS STS token using Assume Role with SAML
    conn = boto.sts.connect_to_region(region, anon=True)
    token = conn.assume_role_with_saml(role_arn, principal_arn, assertion)

    # Write the AWS STS token into the AWS credential file
    filename = home + awsconfigfile

    # Read in the existing config file
    config = ConfigParser.ConfigParser()

    if exists(filename):
        change = False
        config.read(filename)
        if not force:
            if config.has_section(profile) or config.has_option(profile, 'aws_access_key_id'):
                if config.has_option(profile, 'created_date'):
                    created_date = config.get(profile, 'created_date')
                else:
                    created_date = ' '
                print 'AWS Credentials under Profile '+profile+' (created_date: ' +created_date+') already exists in the ~/.aws/credentials file, do you want to change it? yes(y,Y) :',
                answer = raw_input()
                if answer == 'y' or answer == 'Y':
                    change = True
            else:
                change = True
        else:
            change = True

        if not change:
            sys.exit()
        # Put the credentials into a specific profile instead of clobbering
        # the default credentials

    if profile != ConfigParser.DEFAULTSECT:
        if not config.has_section(profile):
            config.add_section(profile)

    config.set(profile, 'created_date', datetime.datetime.utcnow())
    config.set(profile, 'output', outputformat)
    config.set(profile, 'region', region)
    config.set(profile, 'aws_access_key_id', token.credentials.access_key)
    config.set(profile, 'aws_secret_access_key', token.credentials.secret_key)
    config.set(profile, 'aws_session_token', token.credentials.session_token)

    # Write the updated config file
    with open(filename, 'w+') as configfile:
        try:
            config.write(configfile)
        except Exception as er:
            print er

    # Give the user some basic info as to what has just happened
    if not force:
        print '\n\n----------------------------------------------------------------'

        print 'Your new access key pair has been stored in the AWS configuration file {0} under the '.format(filename)+profile+' profile.'

        print 'Note that it will expire at {0}.'.format(token.credentials.expiration)

        print 'After this time you may safely rerun this script to refresh your access key pair.'

        print 'To use this credential call the AWS CLI with the --profile option (e.g. aws --profile saml ec2 describe-instances).'

        print '----------------------------------------------------------------nn'
    else:
        print 'AWSLogin: Profile: '+profile+'  updated for Account: '+account_name+', Role: '+ role_name


    profile_file = home + '/.aws/' + profile
    if not force:
        if exists(profile_file):
            stat = os.stat(profile_file)
            try:
                created_ts = stat.st_birthtime
            except AttributeError:
                # We're probably on Linux. No easy way to get creation dates here,
                # so we'll settle for when its content was last modified.
                created_ts = stat.st_mtime
            change = False
            created_date =  datetime.datetime.fromtimestamp(created_ts).strftime('%Y-%m-%d %H:%M:%S')
            print 'this file '+profile+' (created_date: ' + str(created_date)+') already exists in the ~/.aws/, do you want to change it? yes(y,Y) :',
            answer = raw_input()
            if answer == 'y' or answer == 'Y':
                change = True
        else:
            change = True
    else:
        change = True

    if change:
        profile_data = {'aws': {'region':region , 'aws_access_key':token.credentials.access_key, 'aws_secret_key':token.credentials.secret_key , 'security_token': token.credentials.session_token}}
        with open(profile_file, 'wb') as file:
            try:
                ##### use safe_dump instead of dump to remove python/unicode
                yaml.safe_dump(profile_data, file, default_flow_style=False)
            except Exception as er:
                print er
            else:
                if not force:
                    # Give the user some basic info as to what has just happened
                    print '\n\n----------------------------------------------------------------'
                    print 'Your new access key pair has also been stored in the file {0}'.format(profile_file) + '.'
                    print '----------------------------------------------------------------nn'
    sys.exit()
elif sys.argv[1] == '-l':
    #user_name argument
    parser = argparse.ArgumentParser(prog='list')
    parser.add_argument('-l', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('-u', '--username', help='AWS Login Username')
    args = parser.parse_args()

    if args.username:
        input_username = args.username
    else:
        input_username= None

    # Get the federated credentials from the user
    username, password = get_username_password(input_username)
    ############################
    accounts, assertion = get_accounts_informations(username, password)

    # Overwrite and delete the credential variables, just for safety
    username = '##############################################'
    password = '##############################################'
    del username
    del password

    i=0
    for account in accounts.values():
        for role in account['roles']:
            print '[' + str(i) + ']' , role['role_name'],',', account['account_title']
            i = i+1


else:
    sys.exit('invalid command')



