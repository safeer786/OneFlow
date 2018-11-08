import datetime, dateutil.parser
from datetime import datetime, timedelta
from os import environ
import boto3
import json
import time

def lambda_handler(event, context):
    #instancesStr = environ['instances']
    #instances = json.loads(instancesStr)
    start_date = datetime.today() - timedelta(days=30)
    #startTime = datetime.strptime(start_date, '%Y-%m-%d')
    end_date = datetime.today()
    #endTime = datetime.strptime(end_date, '%Y-%m-%d')
    instances = get_instances(context)
    periods = get_instances_periods(instances,start_date, end_date) 
    make_csv(periods)
    send_email(event, context, periods)
    print(periods)
    return periods

# GET PERIODS
def get_instances_periods(instances, startTime, endTime):
    allperiod = convert_timedelta(endTime - startTime)
    print('allperiod:' + str(allperiod))
    instancestypes={}
    for instanceId, instance in instances.items(): 
        firstPeriod = 0
        stopPeriod = 0
        endPeriod = 0
        if 'events' in instance.keys(): 
            events = instance['events']

            stopEventTime = None
            for event in events:
                if 'RunInstances' == event['eventName'] :
                    runEventTime = dateutil.parser.parse(event['eventTime'])
                    firstPeriod =  convert_timedelta(runEventTime.replace(tzinfo=None) - startTime)
                    print('firstPeriod:' + str(firstPeriod))
                    continue
                if 'StopInstances' == event['eventName']: 
                    stopEventTime = dateutil.parser.parse(event['StopInstances'])
                    continue
                if 'StartInstances' == event['eventName']: 
                    startEventTime = dateutil.parser.parse(event['eventTime'])
                    stopPeriod += convert_timedelta(startEventTime - stopEventTime)
                    continue
                if 'TerminateInstances' == event['eventName']: 
                    terminateTime = dateutil.parser.parse(event['eventTime'])
                    endPeriod = convert_timedelta(endTime - terminateTime.replace(tzinfo=None)) 
                    print('endPeriod:' + str(endPeriod))

        activePeriod = allperiod - firstPeriod - stopPeriod - endPeriod
        if not instance['instanceType']:
            instance['instanceType'] = 'unknown'
        if instance['instanceType'] in instancestypes.keys() : 
            instancestypes[instance['instanceType']]['minutes'] += activePeriod
            instancestypes[instance['instanceType']]['count'] += 1
        else: 
            instancestypes[instance['instanceType']] = {'minutes':activePeriod, 'count': 1}
    return instancestypes
    
def convert_timedelta(duration):
    days, seconds = duration.days, duration.seconds
    hours = days * 24 + seconds // 3600
    minutes = (seconds % 3600) // 60
    total_minutes = hours * 60 + minutes
    return total_minutes
# END GET PERIODS

# GET INSTANCES
def get_instances(context):
    instances = get_logs_instances(context)
    active_instances = get_active_instances()
    active_instances.update(instances)
    return active_instances
    
    
    
# get logs instances
def get_logs_instances(context):
    client = boto3.client('logs')
    events = []
    token = None
    
    while True:
        response = getLogs(context, client, token)
        events.extend(response['events'])
        searchedCompletely = response['searchedLogStreams'][0]['searchedCompletely']
        if searchedCompletely or not 'nextToken' in response.keys():
            break
        else:
            token = response['nextToken']

    instances = getResult(context,client, events)
    return instances
    
    
def getResult(context, client, events):
    #instances = set()
    result = {}
    for event in events:
        instanceType = None
        message = event['message']
        messageJson = json.loads(message)
        if 'responseElements' in messageJson.keys() and messageJson['responseElements'] and 'instancesSet' in messageJson['responseElements'].keys() and messageJson['responseElements']['instancesSet'] and 'items' in messageJson['responseElements']['instancesSet'].keys() and messageJson['responseElements']['instancesSet']['items'] :
            items = messageJson['responseElements']['instancesSet']['items']
            for item in items:
                if 'instanceId' in item.keys() and item['instanceId']:
                    instanceId = item['instanceId']
                    
                    if 'instanceType' in item.keys() and item['instanceType']:
                        instanceType = item['instanceType']
                    
                    else:
                        instanceType = get_instance_type(context, client, instanceId)
                    
                    #instances.add(instanceId)
                    if not instanceId in result.keys():
                        result[instanceId] = {'instanceType': instanceType, 'events':[]}
                    result[instanceId]['events'].append({'eventName':messageJson['eventName'], 'eventTime':messageJson['eventTime'] })
    return result
    
def getTime():
	epoch = int(round(time.time() * 1000))
	return int(epoch)
	
    
def getLogs(context, client, token, pattern='{ $.eventName = "RunInstances" || $.eventName = "TerminateInstances" || $.eventName = "StartInstances" || $.eventName = "StopInstances"}'):
    
    account_id = context.invoked_function_arn.split(":")[4]
    logGroup = str(account_id)+'_CloudTrail_eu-central-1'
    logStartTime = getTime() - (30*24*60*60*1000)
    logEndTime =  getTime()
    #logStartTime = int(round(datetime.datetime(2017,3,14,0,0).timestamp() * 1000)) 
    #logEndTime = int(round(datetime.datetime(2017,3,19,0,0).timestamp() * 1000)) 
    response = {}
    if token:
        response = client.filter_log_events(
            logGroupName='CloudTrail/DefaultLogGroup',
            logStreamNames= [logGroup],
            startTime=logStartTime,
            endTime=logEndTime,
            filterPattern = pattern,
            nextToken = token
        	)
    else:
        response = client.filter_log_events(
            logGroupName='CloudTrail/DefaultLogGroup',
            logStreamNames= [logGroup],
        	startTime=logStartTime,
        	endTime=logEndTime,
        	filterPattern = pattern,
        	)
    return response
    
def get_instance_type(context, client, instanceId):
    pattern='{ $.eventName = "RunInstances" && $.responseElements.instancesSet.items[0].instanceId = "'+ instanceId +'" }'
    account_id = context.invoked_function_arn.split(":")[4]
    logGroup = str(account_id)+'_CloudTrail_eu-central-1'
    instanceType = None
    response = client.filter_log_events(
        logGroupName='CloudTrail/DefaultLogGroup',
        logStreamNames= [logGroup],
    	filterPattern = pattern,
    	limit = 1
    	)
    events = response['events']
    for event in events:
        message = event['message']
        messageJson = json.loads(message)
        if 'requestParameters' in messageJson.keys() and messageJson['requestParameters'] and 'instanceType' in messageJson['requestParameters'].keys() and messageJson['requestParameters']['instanceType'] :
                instanceType = messageJson['requestParameters']['instanceType']
    return instanceType

# END get logs instances


# get active instances
def get_active_instances():
    ec2 = boto3.client('ec2')
    instances = {}
    token =''
    while True:
        respone = ec2.describe_instances(Filters = [ {
            'Name': 'instance-state-name',
            'Values': [
                'running',
            ]
        },], NextToken = token)
        for reservation in respone['Reservations']:
            for instance in reservation['Instances']:
                instances[instance['InstanceId']] = {'instanceType': instance['InstanceType']}
        if not 'nextToken' in respone.keys() :
            break
        token = respone['nextToken']
        
    return instances
# END get active instances
# END GET INSTANCES


# SEND EMAIL
import os
#import boto3
import csv
from botocore.exceptions import ClientError
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication


def send_email(event, context, instances):
    
   
    
    # Replace sender@example.com with your "From" address.
    # This address must be verified with Amazon SES.
    SENDER = "extern.hanbo_johnny@allianz.de"
    
    account_id= context.invoked_function_arn.split(":")[4]
    sesArn= 'arn:aws:ses:us-east-1:'+ account_id +':identity/'+SENDER
    
    # Replace recipient@example.com with a "To" address. If your account 
    # is still in the sandbox, this address must be verified.
    if 'email' in event.keys():
        RECIPIENT = event['email']
    else:
        RECIPIENT = "extern.hanbo_johnny@allianz.de"
    
    # Specify a configuration set. If you do not want to use a configuration
    # set, comment the following variable, and the 
    # ConfigurationSetName=CONFIGURATION_SET argument below.
    CONFIGURATION_SET = "ConfigSet"
    
    # If necessary, replace us-west-2 with the AWS Region you're using for Amazon SES.
    AWS_REGION = "us-east-1"
    
    # The subject line for the email.
    SUBJECT = "Laufzeit von Instanzen"
    
    # The full path to the file that will be attached to the email.
    ATTACHMENT = "/tmp/test.csv"
    
    # The email body for recipients with non-HTML email clients.
    BODY_TEXT = "Hello,\r\nPlease see the attached file for a list of customers to contact."
    
    # The HTML body of the email.
    TABLE_BODY = ""
    for key, value in instances.items():
        TABLE_BODY += "<tr style= 'width:100%'><td align='center'>"+key+"</td><td align='center'>"+str(value['count'])+"</td><td align='center'>"+str(value['minutes'])+"</td></tr>"
    BODY_HTML = ("<html><head></head>"
        "<body><p>Account Id: "+account_id+"</p><br><table align='center' style= 'width:100%'><th>Instance Type</th><th>Count</th><th>In Min</th></tr>" + TABLE_BODY +
        "</table></body></html>")
    
    # The character encoding for the email.
    CHARSET = "utf-8"
    
    # Create a new SES resource and specify a region.
    client = boto3.client('ses',region_name=AWS_REGION)
    
    # Create a multipart/mixed parent container.
    msg = MIMEMultipart('mixed')
    # Add subject, from and to lines.
    msg['Subject'] = SUBJECT 
    msg['From'] = SENDER 
    msg['To'] = RECIPIENT
    
    # Create a multipart/alternative child container.
    msg_body = MIMEMultipart('alternative')
    
    # Encode the text and HTML content and set the character encoding. This step is
    # necessary if you're sending a message with characters outside the ASCII range.
    textpart = MIMEText(BODY_TEXT.encode(CHARSET), 'plain', CHARSET)
    htmlpart = MIMEText(BODY_HTML.encode(CHARSET), 'html', CHARSET)
    
    # Add the text and HTML parts to the child container.
    msg_body.attach(textpart)
    msg_body.attach(htmlpart)
    
    # Define the attachment part and encode it using MIMEApplication.
    att = MIMEApplication(open(ATTACHMENT, 'rb').read())
    
    # Add a header to tell the email client to treat this part as an attachment,
    # and to give the attachment a name.
    att.add_header('Content-Disposition','attachment',filename=os.path.basename(ATTACHMENT))
    
    # Attach the multipart/alternative child container to the multipart/mixed
    # parent container.
    msg.attach(msg_body)
    
    # Add the attachment to the parent container.
    msg.attach(att)
    #print(msg)
    try:
        #Provide the contents of the email.
        response = client.send_raw_email(
            Source=SENDER,
            Destinations=[
                RECIPIENT
            ],
            RawMessage={
                'Data':msg.as_string(),
            },
            SourceArn =sesArn,
        )
    # Display an error if something goes wrong.	
    except ClientError as e:
        print(e.response['Error']['Message'])
    else:
        print("Email sent! Message ID:"),
        print(response['ResponseMetadata']['RequestId'])
    
    
def read_csv(filename):
    with open('/tmp/test.csv') as csvfile:
        reader = csv.DictReader(csvfile)
        print(list(reader))
        
def make_csv(instances):
    with open("/tmp/test.csv",'w') as csvfile:
        fieldtitles = ['Instance_Type', 'Count', 'Min']
        writer = csv.DictWriter(csvfile, fieldnames = fieldtitles)
        writer.writeheader()
        for key, value in instances.items():
            writer.writerow({'Instance_Type': key, 'Count': value['count'], 'Min': value['minutes'] })


# END SEND EMAIL