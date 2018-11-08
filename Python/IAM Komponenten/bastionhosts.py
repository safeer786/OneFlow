#!/usr/bin/python
import sys
import ConfigParser
import boto3
from os.path import expanduser
#boto3.set_stream_logger('boto3.resources', logging.INFO)
import csv
from pyawslogin import get_cerdentials



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

import getpass
domain = 'win\\'
# Get the federated credentials from the user
print "Username:",
username = raw_input()
username = domain + username
password = getpass.getpass()

accounts =  {'966497653753':'ADFS-PlatformOperator', '303747409146': 'ADFS-Audit', '430275495911': 'ADFS-PlatformOperator', '874233888769': 'ADFS-PlatformOperator'}
accounts_instances = []
for account_id, role in accounts.items():
    access_key, secret_key, session_token = get_cerdentials(username, password, account_id, role )
    session = boto3.Session(
        aws_access_key_id= access_key,
        aws_secret_access_key= secret_key,
        aws_session_token= session_token,
    )

    print 'ACCOUNT ID:', account_id
    print ''

    ec2_client = session.client('ec2')
    '''
    response = ec2_client.describe_security_groups(
                Filters=[
                    {
                        'Name': 'group-id',
                        'Values': [
                            'sg-248f5c4f',
                        ]
                    },
                ]
            )
    security_group_objects = response['SecurityGroups']
    print security_group_objects
    sys.exit()
    '''
    #print '######### Bastion Host #########'
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

                            if len(ip_list)> 0:
                                if 'Tags' in ec2_instance.keys():
                                        names = [name_tag for name_tag in ec2_instance['Tags'] if name_tag['Key'] == 'Name']
                                        if len(names)> 0:
                                            name = names[0]['Value']
                                        instance_tags = ec2_instance['Tags']
                                else:
                                    name=None
                                insatnce_id = ec2_instance['InstanceId']

                                instance = {'Account': account_id, 'InsatnceId':insatnce_id, 'InsatnceName': name, 'Tags': instance_tags, 'SecurityGroup': security_group['GroupName'], 'FromPort': from_port, 'IpRanges':ip_list}
                                accounts_instances.append(instance)
                                print 'EC2 Name:', name
                                print 'Security Group:', security_group['GroupName']
                                print 'FROM Port: ', from_port
                                for ip in ip_list:
                                    print ip
                                print ''

with open("accounts_instances.csv",'w') as csvfile:
    fieldtitles = ['Account', 'InsatnceId','InsatnceName', 'Tags', 'SecurityGroup', 'FromPort', 'IpRanges']
    writer = csv.DictWriter(csvfile, fieldnames = fieldtitles)
    writer.writeheader()
    for accounts_instance in accounts_instances :
        writer.writerow(accounts_instance)

sys.exit()