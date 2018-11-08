#!/usr/bin/python
import sys
import ConfigParser
import boto3
from os.path import expanduser
import botocore
from botocore.exceptions import ClientError
#boto3.set_stream_logger('boto3.resources', logging.INFO)
import csv
from pyawslogin import get_cerdentials
import getpass
import argparse
import json
from os.path import expanduser, exists
from os import makedirs
import datetime
import xlsxwriter

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

def get_role_attached_policies(iam_client,role_name):
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

def get_role_policies(iam_client,role_name):
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

def get_user_attached_policies(iam_client,user_name):
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

def get_user_policies(iam_client,user_name):
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
        response = iam_client.get_group(GroupName=group_name,Marker= marker)
        members.extend(response['Users'])
        is_truncated = response['IsTruncated']
        if is_truncated:
            marker = response['Marker']
    return members 

def get_group_attached_policies(iam_client,group_name):
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

def get_group_policies(iam_client,group_name):
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
def get_list_policies(iam_client):
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
import json, ast
from pprint import pprint
def get_policy_description(iam_client,policy_arn,version):
    response = iam_client.get_policy_version(PolicyArn=policy_arn,VersionId=version)
    policy_version = response['PolicyVersion']
    #pprint (policy_version['Document'])
    policy_description = policy_version['Document']
    policy_description=ast.literal_eval(json.dumps(policy_description))
    pprint (policy_description)
    return policy_description

def get_group_policies_report(accounts,username,password,group_policies):
    #accounts_groups = []
    fieldtitles = ['Account', 'GroupName','GroupId', 'ManagedPolicyName', 'ManagedPolicyArn', 'InlinePolicy' ]
    colums = 0
    for titles in fieldtitles :
        group_policies.write(0, colums, titles)
        colums = colums + 1
    colums=0
    rows=1
    #add rowsssss    
    
    for account_id, role in accounts.items():
        iam_client = get_iam_client(username, password, account_id, role)
        for group in get_groups(iam_client) :
            group_name = group['GroupName']
            print 'Group Name:', group_name
            print '######### Managed Policies#########'
            manged_policies =  get_group_attached_policies(iam_client,group_name)
            for m_policy in manged_policies:
                group_policies.write(rows, 0, account_id)
                group_policies.write(rows, 1, group['GroupName'])
                group_policies.write(rows, 2, group['GroupId'])
                group_policies.write(rows, 3, m_policy['PolicyName'])
                group_policies.write(rows, 4, m_policy['PolicyArn'])
                group_policies.write(rows, 5, '')
                rows = rows + 1
            print '######### Inline Policies#########'
            inline_policies = get_group_policies(iam_client,group_name)
            for in_policy in inline_policies:
                group_policies.write(rows, 0, account_id)
                group_policies.write(rows, 1, group['GroupName'])
                group_policies.write(rows, 2, group['GroupId'])
                group_policies.write(rows, 3, '')
                group_policies.write(rows, 4, '')
                group_policies.write(rows, 5, in_policy)
                rows = rows + 1
            print ''
            print ''
def get_user_policies_report(accounts,username,password,user_policies):
    #accounts_users = []
    fieldtitles = ['Account', 'UserName','UserId', 'ManagedPolicyName', 'ManagedPolicyArn', 'InlinePolicy' ]
    colums = 0
    for titles in fieldtitles :
        user_policies.write(0, colums, titles)
        colums = colums + 1
    colums=0
    rows=1
    for account_id, role in accounts.items():
        iam_client = get_iam_client(username, password, account_id, role)
        for user in get_users(iam_client) :
            user_name = user['UserName']
            print 'User Name:', user_name
            print '######### Managed Policies#########'
            manged_policies =  get_user_attached_policies(iam_client,user_name)
            for m_policy in manged_policies:
                user_policies.write(rows, 0, account_id)
                user_policies.write(rows, 1, user['UserName'])
                user_policies.write(rows, 2, user['UserId'])
                user_policies.write(rows, 3, m_policy['PolicyName'])
                user_policies.write(rows, 4, m_policy['PolicyArn'])
                user_policies.write(rows, 5, '')
                rows = rows + 1
            print '######### Inline Policies#########'
            inline_policies = get_user_policies(iam_client,user_name)
            for in_policy in inline_policies:
                user_policies.write(rows, 0, account_id)
                user_policies.write(rows, 1, user['UserName'])
                user_policies.write(rows, 2, user['UserId'])
                user_policies.write(rows, 3, '')
                user_policies.write(rows, 4, '')
                user_policies.write(rows, 5, in_policy)
                rows = rows + 1
                #account_users['Users'].append({'UserName': user_name, 'UserId': user['UserId'], 'MangedPolicies': manged_policies, 'InlinePolices': inline_policies })
            print ''
            print ''

def get_role_policies_report(accounts,username,password,role_policies):
    #accounts_users = []
    fieldtitles = ['Account', 'RoleName','RoleId', 'ManagedPolicyName', 'ManagedPolicyArn', 'InlinePolicy' ]
    colums = 0
    for titles in fieldtitles :
        role_policies.write(0, colums, titles)
        colums = colums + 1
    colums=0
    rows=1
    for account_id, role in accounts.items():
        iam_client = get_iam_client(username, password, account_id, role)
        for role in get_roles(iam_client) :
            role_name = role['RoleName']
            print 'Role Name:', role_name
            print '######### Managed Policies#########'
            manged_policies =  get_role_attached_policies(iam_client,role_name)
            for m_policy in manged_policies:
                role_policies.write(rows, 0, account_id)
                role_policies.write(rows, 1, role['RoleName'])
                role_policies.write(rows, 2, role['RoleId'])
                role_policies.write(rows, 3, m_policy['PolicyName'])
                role_policies.write(rows, 4, m_policy['PolicyArn'])
                role_policies.write(rows, 5, '')
                rows = rows + 1
            print '######### Inline Policies#########'
            inline_policies = get_role_policies(iam_client,role_name)
            for in_policy in inline_policies:
                role_policies.write(rows, 0, account_id)
                role_policies.write(rows, 1, role['RoleName'])
                role_policies.write(rows, 2, role['RoleId'])
                role_policies.write(rows, 3, '')
                role_policies.write(rows, 4, '')
                role_policies.write(rows, 5, in_policy)
                rows = rows + 1
                print ''
                print ''
def get_user_keys_last_used_report(accounts,username,password,user_keys):
    fieldtitles = ['Account', 'UserName','UserId', 'AccessKeys','LastUsed']
    colums = 0
    for titles in fieldtitles :
        user_keys.write(0, colums, titles)
        colums = colums + 1
    colums=0
    rows=1
    for account_id, role in accounts.items():
        iam_client = get_iam_client(username, password, account_id, role)
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
                    else:
                        lastused.append('N/A') 
                i=0
                user_keys.write(rows, 0, account_id)
                user_keys.write(rows, 1, user_name)
                user_keys.write(rows, 2, user['UserId'])
                if len(user_access_keys_ids) > 0 :
                    user_keys.write(rows, 3, str(user_access_keys_ids))
                else:
                    user_keys.write(rows, 3,'')
                if len(lastused) > 0 :
                    user_keys.write(rows, 4, str(lastused))
                else:
                    user_keys.write(rows, 4, '')
                for access_key in user_access_keys:
                        print '[' + str(i) + ']', access_key['AccessKeyId']
                        i = i+ 1
                rows = rows + 1
                print ''
def get_group_groupmember_report(accounts,username,password,groups_groupmembers):
    fieldtitles = ['Account', 'GroupName','GroupId', 'UserName','UserId','Arn' ]
    colums = 0
    for titles in fieldtitles :
        groups_groupmembers.write(0, colums, titles)
        colums = colums + 1
    colums=0
    rows=1
    for account_id, role in accounts.items():
        iam_client = get_iam_client(username, password, account_id, role)
        for group in get_groups(iam_client) :
            group_name = group['GroupName']
            print 'Group Name:', group_name
            members = get_members(iam_client,group_name)
            for member in members:
                print member['UserName']
                print member['UserId']
                print member['Arn']
                groups_groupmembers.write(rows, 0, account_id)
                groups_groupmembers.write(rows, 1, group['GroupName'])
                groups_groupmembers.write(rows, 2, group['GroupId'])
                groups_groupmembers.write(rows, 3, member['UserName'])
                groups_groupmembers.write(rows, 4, member['UserId'])
                groups_groupmembers.write(rows, 5, member['Arn'])
                rows = rows + 1             
def get_bastionhost_report(accounts,username,password,bastionhost):
    fieldtitles = ['Account', 'InstanceId','InstanceName', 'Tags', 'SecurityGroup', 'FromPort', 'IpRanges']
    colum = 0
    for title in fieldtitles:
        bastionhost.write(0,colum,title)
        colum = colum + 1
    rows = 1
    for account_id, role in accounts.items():
        ec2_client = get_ec2_client(username, password, account_id, role)
        print 'ACCOUNT ID:', account_id
        print ''
        ec2_instances = get_ec2_instances(ec2_client)
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
                                    instance_id = ec2_instance['InstanceId']
                                    instance = {'Account': account_id, 'InstanceId':instance_id, 'InstanceName': name, 'Tags': instance_tags, 'SecurityGroup': security_group['GroupName'], 'FromPort': from_port, 'IpRanges':ip_list}
                                    bastionhost.write(rows,0,account_id)
                                    bastionhost.write(rows,1,instance_id)
                                    bastionhost.write(rows,2,name)
                                    bastionhost.write(rows,3,str(instance_tags))
                                    bastionhost.write(rows,4,security_group['GroupName'])
                                    bastionhost.write(rows,5,from_port)
                                    bastionhost.write(rows,6,str(ip_list))
                                    rows = rows + 1
                                    #writer.writerow(rows,0,instance)
                                    print 'EC2 Name:', name
                                    print 'Security Group:', security_group['GroupName']
                                    print 'FROM Port: ', from_port
                                    for ip in ip_list:
                                        print ip
                                    print ''
##################################################################################################################################################
if len(sys.argv) < 2:
    sys.exit('Please, choose one command ( group-policies, role-policies, user-policies, bastionhosts, group-groupmembers, user-keys-last-used' , 'policy-description','complete-report' , 'all')

if sys.argv[1] == 'group-policies':
    accounts = get_accounts('group-policies')
    username, password = get_username_password()
    workbook   = xlsxwriter.Workbook(iam_reports_dir + 'group_policies.xlsx')
    group_policies = workbook.add_worksheet('group_policies')
    get_group_policies_report(accounts,username,password,group_policies)
    sys.exit()
#######################################################################
elif sys.argv[1] == 'role-policies':
    accounts = get_accounts('role-policies')
    username, password = get_username_password()
    workbook   = xlsxwriter.Workbook(iam_reports_dir + 'role_policies.xlsx')
    role_policies = workbook.add_worksheet('role_policies')
    get_role_policies_report(accounts,username,password,role_policies)
    sys.exit()
########################################################################
#########################################################################################################
elif sys.argv[1] == 'user-keys-last-used':
    accounts = get_accounts('user-keys')
    username, password = get_username_password()
    workbook   = xlsxwriter.Workbook(iam_reports_dir + 'user_keys.xlsx')
    user_keys = workbook.add_worksheet('user_keys')
    get_user_keys_last_used_report(accounts,username,password,user_keys)
    sys.exit()

elif sys.argv[1] == 'user-policies':
    accounts = get_accounts('user-policies')
    username, password = get_username_password()
    workbook   = xlsxwriter.Workbook(iam_reports_dir + 'user_policies.xlsx')
    user_policies = workbook.add_worksheet('user_policies')
    get_user_policies_report(accounts,username,password,user_policies)
    sys.exit()
elif sys.argv[1] == 'group-groupmembers':
    accounts = get_accounts('group-groupmembers')
    username, password = get_username_password()
    workbook   = xlsxwriter.Workbook(iam_reports_dir + 'group_groupmembers.xlsx')
    group_groupmembers = workbook.add_worksheet('group_groupmembers')
    get_group_groupmember_report(accounts,username,password,group_groupmembers)
    sys.exit()

elif sys.argv[1] == 'all':
    workbook   = xlsxwriter.Workbook(iam_reports_dir + 'complete_report.xlsx')
    accounts = get_accounts('all')
    username, password = get_username_password()
    group_policies = workbook.add_worksheet('group_policies')
    get_group_policies_report(accounts,username,password,group_policies)
    role_policies = workbook.add_worksheet('role_policies')
    get_role_policies_report(accounts,username,password,role_policies)
    user_policies = workbook.add_worksheet('user_policies')
    get_user_policies_report(accounts,username,password,user_policies)
    user_keys =workbook.add_worksheet('user_keys')
    get_user_keys_last_used_report(accounts,username,password,user_keys)
    group_groupmembers = workbook.add_worksheet('group_groupmembers')
    get_group_groupmember_report(accounts,username,password,group_groupmembers)
    bastionhost = workbook.add_worksheet('bastionhost')
    get_bastionhost_report(accounts,username,password,bastionhost)
    sys.exit()                

#########################################################################

#########################################################################
######################################################################################################
elif sys.argv[1] == 'bastionhost':
    #accounts_instances = []
    accounts = get_accounts('BastionHost')
    username, password = get_username_password()
    workbook   = xlsxwriter.Workbook(iam_reports_dir + 'bastionhost.xlsx')
    bastionhost = workbook.add_worksheet('bastionhost')
    get_bastionhost_report(accounts,username,password,bastionhost)
    sys.exit()
#########################################################################################################
#############################################################################################################################################
elif sys.argv[1] == 'policy-description':
    fh = open(iam_reports_dir + "PolicyPermissions.doc","w")
   
    accounts = get_accounts('group-policies')
    username, password = get_username_password()
    with open(iam_reports_dir + "policy_description.csv",'w') as csvfile:
        fieldtitles = ['Account', 'PolicyName','PolicyArn','PolicyDescription' ]
        writer = csv.DictWriter(csvfile, fieldnames = fieldtitles)
        writer.writeheader()
        for account_id, role in accounts.items():
            iam_client = get_iam_client(username, password, account_id, role)
            for policy in get_list_policies(iam_client) :
                print 'Policy Name:', policy['PolicyName']
                fh.write(  'Policy Name: ' + policy['PolicyName'] +'\n')
                description = get_policy_description(iam_client,policy['Arn'],policy['DefaultVersionId'])
                #pprint.pyprint(description)
                fh.write( json.dumps(description, indent=4)) 
                fh.write('\n')
                #print description
                writer.writerow({'Account':account_id, 'PolicyName': policy['PolicyName'], 'PolicyArn': policy['Arn'], 'PolicyDescription': description})             
    fh.close()
    sys.exit()
########################################################################################################
elif sys.argv[1] == 'complete-report':
    accounts = get_accounts('complete-report')
    username,password = get_username_password()
    with open(iam_reports_dir + "complete_report.csv",'w') as csvfile:
        fieldtitles = ['Account','GroupName','GroupId','UserName','UserId','ManagedPolicyName','ManagedPolicyArn','InlinePolicy']
        writer = csv.DictWriter(csvfile, fieldnames = fieldtitles)
        writer.writeheader()
        for account_id, role in accounts.items():
            iam_client = get_iam_client(username,password,account_id,role)
            for group in get_groups(iam_client) :
                group_name = group['GroupName']
                print 'Group Name:', group_name
                members = get_members(iam_client,group_name)
                for user in members:
                    user_name = user['UserName']
                    print user['UserName']
                    print user['UserId']
                    print user['Arn']
                    print '######### Managed Policies#########'
                    manged_policies =  get_group_attached_policies(iam_client,group_name)
                    for gm_policy in manged_policies:
                        print gm_policy
                        writer.writerow({'Account':account_id,'GroupName': group['GroupName'],'GroupId': group['GroupId'], 'UserName': user['UserName'],'UserId': user['UserId'], 'ManagedPolicyName': gm_policy['PolicyName'] ,  'ManagedPolicyArn': gm_policy['PolicyArn'], 'InlinePolicy':'' })
                    print '######### Inline Policies#########'
                    inline_policies = get_group_policies(iam_client,group_name)
                    for gin_policy in inline_policies:
                        print  gin_policy
                        writer.writerow({'Account':account_id,'GroupName': group['GroupName'],'GroupId': group['GroupId'], 'UserName': user['UserName'],'UserId': user['UserId'], 'ManagedPolicyName':'' ,  'ManagedPolicyArn': '' ,  'InlinePolicy':gin_policy })
                    ##########################################################################################################
            for user in get_users(iam_client) :
                user_name = user['UserName']    
                manged_policies =  get_user_attached_policies(iam_client,user_name)
                for m_policy in manged_policies:
                    print  m_policy
                    writer.writerow({'Account':account_id,'GroupName': '','GroupId': '', 'UserName': user['UserName'],'UserId': user['UserId'], 'ManagedPolicyName': m_policy['PolicyName'] ,  'ManagedPolicyArn': m_policy['PolicyArn'], 'InlinePolicy':'' })                    
                print '######### Inline Policies#########'           
                inline_policies = get_user_policies(iam_client,user_name)
                for in_policy in inline_policies:
                    print  in_policy
                    writer.writerow({'Account':account_id,'GroupName': '','GroupId': '' , 'UserName': user['UserName'],'UserId': user['UserId'], 'ManagedPolicyName':'' ,  'ManagedPolicyArn': '' ,  'InlinePolicy':in_policy })        
                        #account_users['Users'].append({'UserName': user_name, 'UserId': user['UserId'], 'MangedPolicies': manged_policies, 'InlinePolices': inline_policies })
                print ''
                print ''

                    #writer.writerow({'Account':account_id, 'GroupName': group['GroupName'],'GroupId': group['GroupId'],'UserName': member['UserName'], 'UserId': member['UserId'], 'Arn': member['Arn']}) 
    sys.exit()
else:
    sys.exit('There is no command: '+ sys.argv[1])