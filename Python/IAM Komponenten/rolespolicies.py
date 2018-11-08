#!/usr/bin/python
import sys
import ConfigParser
import boto3
from os.path import expanduser
#boto3.set_stream_logger('boto3.resources', logging.INFO)
import csv
from pyawslogin import get_cerdential
import getpass

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
accounts_roles = []
for account_id, role in accounts.items():
    access_key, secret_key, session_token = get_cerdentials(username, password, account_id, role )
    session = boto3.Session(
        aws_access_key_id= access_key,
        aws_secret_access_key= secret_key,
        aws_session_token= session_token,
    )
    iam_client = session.client('iam')
    iam_resource = session.resource('iam')
    '''
    response = iam_client.list_saml_providers()
    saml_providers = response['SAMLProviderList']
    for saml_provider in saml_providers:
        resource_saml_provider = iam_resource.SamlProvider(saml_provider['Arn'])
        print resource_saml_provider.saml_metadata_document
        print resource_saml_provider.get_available_subresources()
        sys.exit()
    '''
    account_roles = {'Account':account_id, 'Roles': []}
    accounts_roles.append(account_roles)
    for role in get_roles(iam_client) :
        role_name = role['RoleName']

        print 'Role Name:', role_name
        print '######### Managed Policies#########'
        manged_policies =  get_role_attached_policies(role_name)
        i = 0
        for m_policy in manged_policies:
            print '[' + str(i) + ']', m_policy
            i = i+ 1

        print '######### Inline Policies#########'
        i = 0
        inline_policies = get_role_policies(role_name)
        for policy in inline_policies:
            print '[' + str(i) + ']', policy
            i = i+ 1
        account_roles['Roles'].append({'RoleName': role_name, 'RoleId': role['RoleId'], 'MangedPolicies': manged_policies, 'InlinePolices': inline_policies })
        print ''
        print ''

with open("roles_policies.csv",'w') as csvfile:
    fieldtitles = ['Account', 'RoleName','RoleId', 'ManagedPolicyName', 'ManagedPolicyArn', 'InlinePolicy' ]
    writer = csv.DictWriter(csvfile, fieldnames = fieldtitles)
    writer.writeheader()
    for account in accounts_roles :
        for role in account['Roles']:
            for m_policy in role['MangedPolicies']:
                writer.writerow({'Account':account['Account'], 'RoleName': role['RoleName'],'RoleId': role['RoleId'], 'ManagedPolicyName': m_policy['PolicyName'] ,  'ManagedPolicyArn': m_policy['PolicyArn'], 'InlinePolicy':'' })
            for in_policy in role['InlinePolices']:
                 writer.writerow({'Account':account['Account'], 'RoleName': role['RoleName'],'RoleId': role['RoleId'], 'ManagedPolicyName':'' ,  'ManagedPolicyArn': '' ,  'InlinePolicy':in_policy })
'''
    for user in get_users(iam_client) :
        user_name = user['UserName']
        print 'User Name:', user_name
        print '######### Managed Policies#########'
        i = 0
        for m_policy in get_user_attached_policies(user_name):
            print '[' + str(i) + ']', m_policy
            i = i+ 1

        print '######### Inline Policies#########'
        i = 0
        for policy in get_user_policies(user_name):
            print '[' + str(i) + ']', policy
            i = i+ 1
        print '######### Access Keys #########'
        for access_key in get_user_access_keys(iam_client, user_name):
                print '[' + str(i) + ']', access_key['AccessKeyId']
                i = i+ 1
        print ''
        print ''
'''

sys.exit()

'''
    users = get_users(iam_client)
    all_users.extend(users)
    all_access_keys.extend(get_users_access_keys(iam_client, users))
    all_roles.extend( get_roles(iam_client))
    all_policies.extend(get_policies(iam_client))
'''
'''
    for policy in get_policies(iam_client):
        iam_policy = iam_resource.Policy(policy['Arn'])
        user_iterator = iam_policy.attached_users.all()
        for user in user_iterator:
            print user
        role_iterator = iam_policy.attached_roles.all()
        for role in role_iterator:
            print role
sys.exit()
'''

####### IAM Commands #####
'''
list_access_keys
list_attached_group_policies Managed Policies
list_attached_role_policies
list_attached_user_policies
list_entities_for_policy
list_group_policies inline Policies
list_groups
list_groups_for_user
list_policies
'''

########## ACCOUNTS #################
'''
organizations_client = boto3.client(
    'organizations',
    aws_access_key_id= access_key,
    aws_secret_access_key= secret_key,
    aws_session_token= session_token,
)

response =  organizations_client.list_accounts()
accounts = response['Accounts']
next_token = None
if 'NextToken' in response.keys():
    next_token = response['NextToken']
while next_token:
    response =  organizations_client.list_accounts(NextToken= next_token)
    accounts.append(response['Accounts'])
    if 'NextToken' in response.keys():
        next_token = response['NextToken']
    else:
        next_token = None

#accounts = iam_client.list_account_aliases()
print accounts
'''
#####################################



print ################ USERS #####################
i = 0
print 'Users', str(len(all_users))
for user in all_users:
    print '[' + str(i) + ']', user['UserName']
    i = i+ 1
print '############################################'
print '################ ACCESS KEYS #####################'
i = 0
print 'Access Keys', str(len(all_access_keys))
for acc in all_access_keys:
    print '[' + str(i) + ']', acc
    i = i+ 1
print '############################################'
print '################ ROLES #####################'
i = 0
print 'Roles', str(len(all_roles))
for role in all_roles:
    print '[' + str(i) + ']', role['RoleName']
    i = i+ 1
print '############################################'
print '################ POLICIES #####################'
print 'Policies', str(len(all_policies))
i = 0
for policy in all_policies:
    print '[' + str(i) + ']', policy['PolicyName']
    i = i+ 1
print '############################################'


