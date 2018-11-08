#!/usr/bin/python
import sys
import ConfigParser
import boto3
from os.path import expanduser
#boto3.set_stream_logger('boto3.resources', logging.INFO)
import csv
from pyawslogin import get_cerdentials
import getpass
import argparse
import json
from os.path import expanduser, exists
from os import makedirs
import datetime
#import str

home = expanduser("~")
iam_reports_dir = home + '/iam_reports/'
if not exists(iam_reports_dir):
    makedirs(iam_reports_dir)
################## ROLE FUNCTIONS ###################
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
###############################################
################ USERS FUNCTIONS ##############################
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
##############################################################
################ GROUP FUNCTIONS ##############################

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

def get_members(iam_client,group_name):
    response = iam_client.get_group(GroupName=group_name)
    members = response['Users']
    is_truncated = response['IsTruncated']
    if is_truncated:
        marker = response['Marker']
    while is_truncated:
        response = iam_client.list_groups(Marker= marker)
        members.extend(response['Users'])
        is_truncated = response['IsTruncated']
        if is_truncated:
            marker = response['Marker']
    return members 

def get_group_attached_policies(group_name):
    response = iam_client.list_attached_group_policies(GroupName = group_name)
    policies = response['AttachedPolicies']
    is_truncated = response['IsTruncated']
    if is_truncated:
        marker = response['Marker']
    while is_truncated:
        response = iam_client.list_attached_group_policies(GroupName = group_name, Marker= marker)
        policies.extend(response['AttachedPolicies'])
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

##################################################################################################
def get_ec2_instances(ec2_client):
    response = ec2_client.describe_instances(
        #Filters=[{'Name': 'tag:aws:cloudformation:logical-id','Values': ['BastionHostInstance', 'BastionSrv']}]
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
                                #Filters=[{'Name': 'tag:aws:cloudformation:logical-id',         'Values': [           'BastionHostInstance', 'BastionSrv'       ]        },    ],
                                    NextToken = next_token
                                )
        for reservation in reservations:
            instances.extend(reservation['Instances'])
        is_truncated = 'NextToken' in response.keys()
        if is_truncated:
            next_token = response['NextToken']
    return instances
def get_security_group_objects(ec2_client, security_group_id):
    try:
        response = ec2_client.describe_security_groups(Filters=[{'Name': 'group-id','Values': [security_group_id ,]}])
    except botocore.exceptions.ClientError:
        get_security_group_objects(ec2_client, security_group_id)
    security_groups = response['SecurityGroups']
    is_truncated = 'NextToken' in response.keys()
    if is_truncated:
        next_token = response['NextToken']
    while is_truncated:
        response = ec2_client.describe_security_groups(Filters=[{'Name': 'group-id','Values': [security_group_id ,]}])
        security_groups.extend(response['SecurityGroups'])
        is_truncated = 'NextToken' in response.keys()
        if is_truncated:
            next_token = response['NextToken']
    return security_groups
#################################################################################################
def get_username_password():
    domain = 'win\\'
    # Get the federated credentials from the user
    print "Username:",
    username = raw_input()
    username = domain + username
    password = getpass.getpass()
    return username, password
def get_accounts(prog_name):
    parser = argparse.ArgumentParser(prog=prog_name)
    parser.add_argument(prog_name, help=argparse.SUPPRESS)
    parser.add_argument("-a", '--accounts', type =str , help="The accounts that you want to get information from.for example {'966497653753':'ADFS-PlatformOperator', ....}", required=True)
    args = parser.parse_args()
    accounts = json.loads(args.accounts)
    return accounts
def get_boto_session(username, password, account_id, role):
    access_key, secret_key, session_token = get_cerdentials(username, password, account_id, role )
    if not access_key:
        sys.exit('you are not authorized to login to this account:'+ account_id)
    session = boto3.Session(
            aws_access_key_id= access_key,
            aws_secret_access_key= secret_key,
            aws_session_token= session_token,
        )
    return session
def get_iam_client(username, password, account_id, role):
    session = get_boto_session(username, password, account_id, role)
    iam_client = session.client('iam')
    return iam_client

def get_ec2_client(username, password, account_id, role):
    session = get_boto_session(username, password, account_id, role)
    ec2_client = session.client('ec2')
    return ec2_client
##################################################################################################################################################
if len(sys.argv) < 2:
    sys.exit('Please, choose one command ( group-policies, role-policies, user-policies, user-keys, inline-policies or bastionhosts, group-groupmembers, user-keys-last-used)')

if sys.argv[1] == 'group-policies':
    accounts = get_accounts('group-policies')
    username, password = get_username_password()
    #accounts_groups = []
    with open(iam_reports_dir + "groups_policies.csv",'w') as csvfile:
        fieldtitles = ['Account', 'GroupName','GroupId', 'ManagedPolicyName', 'ManagedPolicyArn', 'InlinePolicy' ]
        writer = csv.DictWriter(csvfile, fieldnames = fieldtitles)
        writer.writeheader()
        for account_id, role in accounts.items():
            iam_client = get_iam_client(username, password, account_id, role)
            #account_groups = {'Account':account_id, 'Groups': []}
            #accounts_groups.append(account_groups)
            for group in get_groups(iam_client) :
                group_name = group['GroupName']
                print 'Group Name:', group_name
                print '######### Managed Policies#########'
                manged_policies =  get_group_attached_policies(group_name)
                i = 0
                for m_policy in manged_policies:
                    print '[' + str(i) + ']', m_policy
                    writer.writerow({'Account':account_id, 'GroupName': group['GroupName'],'GroupId': group['GroupId'], 'ManagedPolicyName': m_policy['PolicyName'] ,  'ManagedPolicyArn': m_policy['PolicyArn'], 'InlinePolicy':'' })
                    i = i+ 1

                print '######### Inline Policies#########'
                i = 0
                inline_policies = get_group_policies(group_name)
                for in_policy in inline_policies:
                    print '[' + str(i) + ']', in_policy
                    writer.writerow({'Account':account_id, 'GroupName': group['GroupName'],'GroupId': group['GroupId'], 'ManagedPolicyName':'' ,  'ManagedPolicyArn': '' ,  'InlinePolicy':in_policy })
                    i = i+ 1
                #account_groups['Groups'].append({'GroupName': group_name, 'GroupId': group['GroupId'], 'MangedPolicies': manged_policies, 'InlinePolices': inline_policies })
                print ''
                print ''
    sys.exit()

#######################################################################
elif sys.argv[1] == 'role-policies':
    accounts = get_accounts('role-policies')
    username, password = get_username_password()
    #accounts_roles = []
    with open(iam_reports_dir + "roles_policies.csv",'w') as csvfile:
        fieldtitles = ['Account', 'RoleName','RoleId', 'ManagedPolicyName', 'ManagedPolicyArn', 'InlinePolicy' ]
        writer = csv.DictWriter(csvfile, fieldnames = fieldtitles)
        writer.writeheader()
        for account_id, role in accounts.items():
            iam_client = get_iam_client(username, password, account_id, role)
            #account_roles = {'Account':account_id, 'Roles': []}
            #accounts_roles.append(account_roles)
            for role in get_roles(iam_client) :
                role_name = role['RoleName']

                print 'Role Name:', role_name
                print '######### Managed Policies#########'
                manged_policies =  get_role_attached_policies(role_name)
                i = 0
                for m_policy in manged_policies:
                    print '[' + str(i) + ']', m_policy
                    writer.writerow({'Account':account_id, 'RoleName': role['RoleName'],'RoleId': role['RoleId'], 'ManagedPolicyName': m_policy['PolicyName'] ,  'ManagedPolicyArn': m_policy['PolicyArn'], 'InlinePolicy':'' })
                    i = i+ 1

                print '######### Inline Policies#########'
                i = 0
                inline_policies = get_role_policies(role_name)
                for in_policy in inline_policies:
                    print '[' + str(i) + ']', in_policy
                    writer.writerow({'Account':account_id, 'RoleName': role['RoleName'],'RoleId': role['RoleId'], 'ManagedPolicyName':'' ,  'ManagedPolicyArn': '' ,  'InlinePolicy':in_policy })
                    i = i+ 1
                #account_roles['Roles'].append({'RoleName': role_name, 'RoleId': role['RoleId'], 'MangedPolicies': manged_policies, 'InlinePolices': inline_policies })
                print ''
                print ''

    sys.exit()
########################################################################
elif sys.argv[1] == 'user-policies':
    accounts = get_accounts('user-policies')
    username, password = get_username_password()
    #accounts_users = []
    with open(iam_reports_dir + "users_policies.csv",'w') as csvfile:
        fieldtitles = ['Account', 'UserName','UserId', 'ManagedPolicyName', 'ManagedPolicyArn', 'InlinePolicy' ]
        writer = csv.DictWriter(csvfile, fieldnames = fieldtitles)
        writer.writeheader()
        for account_id, role in accounts.items():
            iam_client = get_iam_client(username, password, account_id, role)
            #account_users = {'Account':account_id, 'Users': []}
            #accounts_users.append(account_users)
            for user in get_users(iam_client) :
                user_name = user['UserName']
                print 'User Name:', user_name
                print '######### Managed Policies#########'
                manged_policies =  get_user_attached_policies(user_name)
                i = 0
                for m_policy in manged_policies:
                    print '[' + str(i) + ']', m_policy
                    writer.writerow({'Account':account_id, 'UserName': user['UserName'],'UserId': user['UserId'], 'ManagedPolicyName': m_policy['PolicyName'] ,  'ManagedPolicyArn': m_policy['PolicyArn'], 'InlinePolicy':'' })
                    i = i+ 1

                print '######### Inline Policies#########'
                i = 0
                inline_policies = get_user_policies(user_name)
                for in_policy in inline_policies:
                    print '[' + str(i) + ']', in_policy
                    writer.writerow({'Account':account_id, 'UserName': user['UserName'],'UserId': user['UserId'], 'ManagedPolicyName':'' ,  'ManagedPolicyArn': '' ,  'InlinePolicy':in_policy })
                    i = i+ 1
                #account_users['Users'].append({'UserName': user_name, 'UserId': user['UserId'], 'MangedPolicies': manged_policies, 'InlinePolices': inline_policies })
                print ''
                print ''

    sys.exit()

#########################################################################
elif sys.argv[1] == 'user-keys':
    accounts = get_accounts('user-keys')
    username, password = get_username_password()
    #accounts_users = []
    with open(iam_reports_dir + "users_keys.csv",'w') as csvfile:
        fieldtitles = ['Account', 'UserName','UserId', 'AccessKeys']
        writer = csv.DictWriter(csvfile, fieldnames = fieldtitles)
        writer.writeheader()
        for account_id, role in accounts.items():
            iam_client = get_iam_client(username, password, account_id, role)
            #account_users = {'Account':account_id, 'Users': []}
            #accounts_users.append(account_users)
            for user in get_users(iam_client) :
                user_name = user['UserName']
                print 'User Name:', user_name
                user_access_keys = get_user_access_keys(iam_client, user_name)
                user_access_keys_ids = [key_metadata['AccessKeyId'] for key_metadata in user_access_keys if 'AccessKeyId' in key_metadata]
                i = 0
                #account_users['Users'].append({'UserName': user_name, 'UserId': user['UserId'], 'AccessKeys': user_access_keys})

                writer.writerow({'Account':account_id, 'UserName': user_name,'UserId': user['UserId'], 'AccessKeys': user_access_keys_ids if len(user_access_keys_ids) > 0 else None })
                for access_key in user_access_keys:
                        print '[' + str(i) + ']', access_key['AccessKeyId']
                        i = i+ 1
                print ''
    sys.exit()

#########################################################################
elif sys.argv[1] == 'inline-policies':
    accounts = get_accounts('inline-policies')
    username, password = get_username_password()
    with open(iam_reports_dir + "roles_inline_policies.csv",'w') as csvfile:
        fieldtitles = ['Policy','Role','Account_ID']
        writer = csv.DictWriter(csvfile, fieldnames = fieldtitles)
        writer.writeheader()
    with open(iam_reports_dir + "users_inline_policies.csv",'w') as csvfile:
        fieldtitles = ['Policy','User','Account_ID']
        writer = csv.DictWriter(csvfile, fieldnames = fieldtitles)
        writer.writeheader()
    with open(iam_reports_dir + "groups_inline_policies.csv",'w') as csvfile:
        fieldtitles = ['Policy','Group','Account_ID']
        writer = csv.DictWriter(csvfile, fieldnames = fieldtitles)
        writer.writeheader()
    for account_id, role in accounts.items():
        iam_client = get_iam_client(username, password, account_id, role)
        print account_id
        print '#############################Inline Policies for Roles#############################'
        with open(iam_reports_dir + "roles_inline_policies.csv",'a') as csvfile:
            fieldtitles = ['Policy','Role','Account_ID']
            writer = csv.DictWriter(csvfile, fieldnames = fieldtitles)
            for role in get_roles(iam_client) :
                role_name = role['RoleName']
                for policy in get_role_policies(role_name):
                    print '[' + policy + ']', role_name
                    writer.writerow({'Policy': policy, 'Role': role_name,'Account_ID': account_id})
        print '#############################Inline Policies for Users#############################'
        with open(iam_reports_dir + "users_inline_policies.csv",'a') as csvfile:
            fieldtitles = ['Policy','User','Account_ID']
            writer = csv.DictWriter(csvfile, fieldnames = fieldtitles)
            for user in get_users(iam_client) :
                user_name = user['UserName']
                for policy in get_user_policies(user_name):
                    print '[' + policy + ']', user_name
                    writer.writerow({'Policy': policy, 'User': user_name,'Account_ID': account_id})
        print '#############################Inline Policies for Groups#############################'
        with open(iam_reports_dir + "groups_inline_policies.csv",'a') as csvfile:
            fieldtitles = ['Policy','Group','Account_ID']
            writer = csv.DictWriter(csvfile, fieldnames = fieldtitles)
            for group in get_groups(iam_client) :
                group_name = group['GroupName']
                for policy in get_group_policies(group_name):
                    print '[' + policy + ']', group_name
                    writer.writerow({'Policy': policy, 'Group': group_name,'Account_ID': account_id})
    sys.exit()
######################################################################################################
elif sys.argv[1] == 'bastionhosts':
    #accounts_instances = []
    accounts = get_accounts('inline-policies')
    username, password = get_username_password()
    with open(iam_reports_dir + "bastionhosts.csv",'w') as csvfile:
        fieldtitles = ['Account', 'InsatnceId','InsatnceName', 'Tags', 'SecurityGroup', 'FromPort', 'IpRanges']
        writer = csv.DictWriter(csvfile, fieldnames = fieldtitles)
        writer.writeheader()
        for account_id, role in accounts.items():
            ec2_client = get_ec2_client(username, password, account_id, role)
            print 'ACCOUNT ID:', account_id
            print ''
            ec2_instances = get_ec2_instances(ec2_client)
            #print len(ec2_instances)
            for ec2_instance in ec2_instances:
                security_groups = ec2_instance['SecurityGroups']
                for security_group in security_groups:
                    ip_list = []
                    security_group_objects = get_security_group_objects(ec2_client, security_group['GroupId'])
                    for sg_obj in security_group_objects:
                        ip_permissions = sg_obj['IpPermissions']
                        for ip_permission in ip_permissions:
                            if 'FromPort' in ip_permission.keys():
                                from_port = ip_permission['FromPort']
                                #print from_port
                                if from_port == 22:
                                    ip_ranges = ip_permission['IpRanges']
                                    for ip_range in ip_ranges:
                                        cidr_ip = ip_range['CidrIp']
                                        ip_list.append(cidr_ip)

                                    name=None
                                    if len(ip_list)> 0:
                                        if 'Tags' in ec2_instance.keys():
                                                names = [name_tag for name_tag in ec2_instance['Tags'] if name_tag['Key'] == 'Name']
                                                if len(names)> 0:
                                                    name = names[0]['Value']
                                                instance_tags = ec2_instance['Tags']

                                        insatnce_id = ec2_instance['InstanceId']

                                        instance = {'Account': account_id, 'InsatnceId':insatnce_id, 'InsatnceName': name, 'Tags': instance_tags, 'SecurityGroup': security_group['GroupName'], 'FromPort': from_port, 'IpRanges':ip_list}
                                        #accounts_instances.append(instance)
                                        writer.writerow(instance)
                                        print 'EC2 Name:', name
                                        print 'Security Group:', security_group['GroupName']
                                        print 'FROM Port: ', from_port
                                        for ip in ip_list:
                                            print ip
                                        print ''
    sys.exit()
#########################################################################################################
elif sys.argv[1] == 'user-keys-last-used':
    accounts = get_accounts('user-keys')
    username, password = get_username_password()
    #accounts_users = []
    with open(iam_reports_dir + "users_keys-last-used.csv",'w') as csvfile:
        fieldtitles = ['Account', 'UserName','UserId', 'AccessKeys','LastUsed']
        writer = csv.DictWriter(csvfile, fieldnames = fieldtitles)
        writer.writeheader()
        for account_id, role in accounts.items():
            iam_client = get_iam_client(username, password, account_id, role)
            #account_users = {'Account':account_id, 'Users': []}
            #accounts_users.append(account_users)
            for user in get_users(iam_client) :
                user_name = user['UserName']
                print 'User Name:', user_name
                user_access_keys = get_user_access_keys(iam_client, user_name)
                user_access_keys_ids = [key_metadata['AccessKeyId'] for key_metadata in user_access_keys if 'AccessKeyId' in key_metadata]
                lastused =[]
                if len(user_access_keys_ids) > 0:
                    for accessKey in user_access_keys_ids:
                        response=iam_client.get_access_key_last_used(AccessKeyId=accessKey)
                        test=response['AccessKeyLastUsed']
                        print response['AccessKeyLastUsed']
                        if 'LastUsedDate' in test.keys():
                            print test['LastUsedDate']
                            date= test['LastUsedDate']
                            lastused.append(date.strftime('%m/%d/%Y')) 
                i = 0
                #account_users['Users'].append({'UserName': user_name, 'UserId': user['UserId'], 'AccessKeys': user_access_keys})

                writer.writerow({'Account':account_id, 'UserName': user_name,'UserId': user['UserId'], 'AccessKeys': user_access_keys_ids if len(user_access_keys_ids) > 0 else None ,'LastUsed':lastused if len(lastused) > 0 else None })
                for access_key in user_access_keys:
                        print '[' + str(i) + ']', access_key['AccessKeyId']
                        i = i+ 1
                print ''
    sys.exit()
#########################################################################################################
elif sys.argv[1] == 'group-groupmembers':
    accounts = get_accounts('group-policies')
    username, password = get_username_password()
    #accounts_groups = []
    with open(iam_reports_dir + "groups_groupmembers.csv",'w') as csvfile:
        fieldtitles = ['Account', 'GroupName','GroupId', 'UserName','UserId','Arn' ]
        writer = csv.DictWriter(csvfile, fieldnames = fieldtitles)
        writer.writeheader()
        for account_id, role in accounts.items():
            iam_client = get_iam_client(username, password, account_id, role)
            #account_groups = {'Account':account_id, 'Groups': []}
            #accounts_groups.append(account_groups)
            for group in get_groups(iam_client) :
                group_name = group['GroupName']
                print 'Group Name:', group_name
                members = get_members(iam_client,group_name)
                for member in members:
                    print member['UserName']
                    print member['UserId']
                    print member['Arn']
                    writer.writerow({'Account':account_id, 'GroupName': group['GroupName'],'GroupId': group['GroupId'],'UserName': member['UserName'], 'UserId': member['UserId'], 'Arn': member['Arn']})             
    sys.exit()    
else:
    sys.exit('There is no command: '+ sys.argv[1])