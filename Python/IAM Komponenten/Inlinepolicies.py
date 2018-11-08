#!/usr/bin/python
import ConfigParser
import boto3
from os.path import expanduser
import csv

#######################################################################################
import sys
import boto.sts
import boto.iam
import getpass
import ConfigParser
import base64
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup
from requests_ntlm import HttpNtlmAuth
import argparse
import warnings
from StringIO import StringIO
import pycurl
import urllib
import requests
warnings.filterwarnings("ignore")
import os
import base64
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random

# region: The default AWS region that this script will connect
# to for all API calls
region = 'eu-central-1'

# idpentryurl: The initial URL that starts the authentication process.
idpentryurl = 'https://cloudsignin.win.azd.cloud.allianz/adfs/ls/IdpInitiatedSignOn.aspx'
def get_cerdentials(username, passwort, account_id, role):
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
    for saml2attribute in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
        if (saml2attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role'):
            for saml2attributevalue in saml2attribute.iter('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
                awsrole = saml2attributevalue.text
                if account_id in awsrole and role in awsrole:
                    break

    if not awsrole:
        return

    role_arn = awsrole.split(',')[1]
    principal_arn = awsrole.split(',')[0]

    conn = boto.sts.connect_to_region(region)
    token = conn.assume_role_with_saml(role_arn, principal_arn, assertion)
    return  token.credentials.access_key, token.credentials.secret_key, token.credentials.session_token
########################################################################################################################
'''
home = expanduser("~")
def get_cerdentials(profile):
    awsconfigfile = '/.aws/credentials'
    filename = home + awsconfigfile
    config = ConfigParser.ConfigParser()
    config.read(filename)
    access_key= config.get(profile, 'aws_access_key_id')
    secret_key = config.get(profile, 'aws_secret_access_key')
    session_token= config.get(profile, 'aws_session_token')
    return access_key, secret_key, session_token
'''
#access_key, secret_key, session_token = get_cerdentials('saml')

def get_users(iam_client):
    response = iam_client.list_users()
    users = response['Users']
    is_truncated = response['IsTruncated']
    if is_truncated:
        marker = response['Marker']
    while is_truncated:
        response = iam_client.list_users(Marker= marker)
        users.extend(response['Users'])
        is_truncated = response['IsTruncated']
        if is_truncated:
            marker = response['Marker']
    return users

def get_roles(iam_client):
    response = iam_client.list_roles()
    roles = response['Roles']
    is_truncated = response['IsTruncated']
    if is_truncated:
        marker = response['Marker']
    while is_truncated:
        response = iam_client.list_roles(Marker= marker)
        roles.extend(response['Roles'])
        is_truncated = response['IsTruncated']
        if is_truncated:
            marker = response['Marker']
    return roles

def get_users_access_keys(iam_client, users):
    users_access_keys = []
    for user in users:
        username = user['UserName']
        user_access_keys = {username:get_user_access_keys(iam_client, username)}
        users_access_keys.append(user_access_keys)
    return users_access_keys

def get_user_access_keys(iam_client, username):
    response = iam_client.list_access_keys(UserName = username)
    user_access_keys = response['AccessKeyMetadata']
    is_truncated = response['IsTruncated']
    if is_truncated:
        marker = response['Marker']
    while is_truncated:
        response = iam_client.list_access_keys(UserName = username, Marker= marker)
        user_access_keys.extend(response['AccessKeyMetadata'])
        is_truncated = response['IsTruncated']
        if is_truncated:
            marker = response['Marker']
    return user_access_keys

def get_groups(iam_client):
    response = iam_client.list_groups()
    groups = response['Groups']
    is_truncated = response['IsTruncated']
    if is_truncated:
        marker = response['Marker']
    while is_truncated:
        response = iam_client.list_groups(Marker= marker)
        groups.extend(response['Groups'])
        is_truncated = response['IsTruncated']
        if is_truncated:
            marker = response['Marker']
    return groups

def get_policies(iam_client):
    response = iam_client.list_policies()
    policies = response['Policies']
    is_truncated = response['IsTruncated']
    if is_truncated:
        marker = response['Marker']
    while is_truncated:
        response = iam_client.list_policies(Marker= marker)
        policies.extend(response['Policies'])
        is_truncated = response['IsTruncated']
        if is_truncated:
            marker = response['Marker']
    return policies

def get_role_attached_policies(role_name):
    response = iam_client.list_attached_role_policies(RoleName = role_name)
    policies = response['AttachedPolicies']
    is_truncated = response['IsTruncated']
    if is_truncated:
        marker = response['Marker']
    while is_truncated:
        response = iam_client.list_attached_role_policies(RoleName = role_name, Marker= marker)
        policies.extend(response['AttachedPolicies'])
        is_truncated = response['IsTruncated']
        if is_truncated:
            marker = response['Marker']
    return policies

def get_role_policies(role_name):
    response = iam_client.list_role_policies(RoleName = role_name)
    policies = response['PolicyNames']
    is_truncated = response['IsTruncated']
    if is_truncated:
        marker = response['Marker']
    while is_truncated:
        response = iam_client.list_role_policies(RoleName = role_name, Marker= marker)
        policies.extend(response['PolicyNames'])
        is_truncated = response['IsTruncated']
        if is_truncated:
            marker = response['Marker']
    return policies

def get_group_policies(group_name):
    response = iam_client.list_group_policies(GroupName = group_name)
    policies = response['PolicyNames']
    is_truncated = response['IsTruncated']
    if is_truncated:
        marker = response['Marker']
    while is_truncated:
        response = iam_client.list_group_policies(GroupName = group_name, Marker= marker)
        policies.extend(response['PolicyNames'])
        is_truncated = response['IsTruncated']
        if is_truncated:
            marker = response['Marker']
    return policies

def get_user_attached_policies(user_name):
    response = iam_client.list_attached_user_policies(UserName = user_name)
    policies = response['AttachedPolicies']
    is_truncated = response['IsTruncated']
    if is_truncated:
        marker = response['Marker']
    while is_truncated:
        response = iam_client.list_attached_user_policies(UserName = user_name, Marker= marker)
        policies.extend(response['AttachedPolicies'])
        is_truncated = response['IsTruncated']
        if is_truncated:
            marker = response['Marker']
    return policies

def get_user_policies(user_name):
    response = iam_client.list_user_policies(UserName = user_name)
    policies = response['PolicyNames']
    is_truncated = response['IsTruncated']
    if is_truncated:
        marker = response['Marker']
    while is_truncated:
        response = iam_client.list_user_policies(UserName = user_name, Marker= marker)
        policies.extend(response['PolicyNames'])
        is_truncated = response['IsTruncated']
        if is_truncated:
            marker = response['Marker']
    return policies

def get_bastion_hosts(ec2_client):
    response = ec2_client.describe_instances(
        Filters=[{'Name': 'tag:aws:cloudformation:logical-id','Values': ['BastionHostInstance', 'BastionSrv']}]
    )
    instances = []
    reservations = response['Reservations']
    for reservation in reservations:
        instances.extend(reservation['Instances'])
    is_truncated = 'NextToken' in response.keys()
    if is_truncated:
        next_token = response['NextToken']
    while is_truncated:
        response = ec2_client.describe_instances(
                                Filters=[{'Name': 'tag:aws:cloudformation:logical-id',         'Values': [           'BastionHostInstance', 'BastionSrv'       ]        },    ],
                                    NextToken = next_token
                                )
        for reservation in reservations:
            instances.extend(reservation['Instances'])
        is_truncated = 'NextToken' in response.keys()
        if is_truncated:
            next_token = response['NextToken']
    return instances

domain = 'win\\'
# Get the federated credentials from the user
print "Username:",
username = raw_input()
username = domain + username
password = getpass.getpass()

accounts =  {'966497653753':'ADFS-PlatformOperator', '303747409146': 'ADFS-Audit', '430275495911': 'ADFS-PlatformOperator', '874233888769': 'ADFS-PlatformOperator'}
#accounts =  {'966497653753':'ADFS-PlatformOperator'}
all_users = []
all_roles = []
all_access_keys = []
all_policies = []
all_bastionhosts = []
all_groups=[]
with open("policy_role.csv",'w') as csvfile:
    fieldtitles = ['Policy','Role','Account_ID']
    writer = csv.DictWriter(csvfile, fieldnames = fieldtitles)
    writer.writeheader()
with open("policy_user.csv",'w') as csvfile:
    fieldtitles = ['Policy','User','Account_ID']
    writer = csv.DictWriter(csvfile, fieldnames = fieldtitles)
    writer.writeheader()            
with open("policy_group.csv",'w') as csvfile:
    fieldtitles = ['Policy','Group','Account_ID']
    writer = csv.DictWriter(csvfile, fieldnames = fieldtitles)
    writer.writeheader()            

for account_id, role in accounts.items():
    access_key, secret_key, session_token = get_cerdentials(username, password, account_id, role )
    session = boto3.Session(
        aws_access_key_id= access_key,
        aws_secret_access_key= secret_key,
        aws_session_token= session_token,
    )
    iam_client = session.client('iam')
    iam_resource = session.resource('iam')
    print account_id
    '''
    response = iam_client.list_saml_providers()
    saml_providers = response['SAMLProviderList']
    for saml_provider in saml_providers:
        resource_saml_provider = iam_resource.SamlProvider(saml_provider['Arn'])
        print resource_saml_provider.saml_metadata_document
        print resource_saml_provider.get_available_subresources()
        sys.exit()
    '''
    
    print '#############################Inline Policies for Roles#############################'
    with open("policy_role.csv",'a') as csvfile:
        fieldtitles = ['Policy','Role','Account_ID']
        writer = csv.DictWriter(csvfile, fieldnames = fieldtitles)
        for role in get_roles(iam_client) :
            role_name = role['RoleName']
            for policy in get_role_policies(role_name):
                print '[' + policy + ']', role_name
                writer.writerow({'Policy': policy, 'Role': role_name,'Account_ID': account_id})
    print '#############################Inline Policies for Users#############################'
    with open("policy_user.csv",'a') as csvfile:
        fieldtitles = ['Policy','User','Account_ID']
        writer = csv.DictWriter(csvfile, fieldnames = fieldtitles)
        for user in get_users(iam_client) :
            user_name = user['UserName']
            for policy in get_user_policies(user_name):
                print '[' + policy + ']', user_name
                writer.writerow({'Policy': policy, 'User': user_name,'Account_ID': account_id})
    print '#############################Inline Policies for Groups#############################'            
    with open("policy_group.csv",'a') as csvfile:
        fieldtitles = ['Policy','Group','Account_ID']
        writer = csv.DictWriter(csvfile, fieldnames = fieldtitles)
        for group in get_groups(iam_client) :
            group_name = group['GroupName']
            for policy in get_group_policies(group_name):
                print '[' + policy + ']', group_name
                writer.writerow({'Policy': policy, 'Group': group_name,'Account_ID': account_id})
