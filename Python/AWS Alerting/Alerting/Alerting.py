import boto3
import os
import time
import datetime
from datetime import datetime, timedelta
from time import gmtime, strftime
import time
from os import environ
import json
import dateutil.parser
import traceback

delay = int(environ['delay']) #Timespan for logs to recieve from execution time in Minutes
snsArn = environ['snsArn']

to_email = environ['Receiver']
from_email = environ['Sender']


def lambda_handler(event, context):
    trigger = getTriggerArn(event)
    if not trigger:
        print('Es gibt Kein Trigger')
        return "Lambda isn't done"
    pattern = get_filter_pattern(trigger)
    
    account_id = context.invoked_function_arn.split(":")[4]
    logGroup = str(account_id)+'_CloudTrail_eu-central-1'
    try:
         events = get_events_delay(logGroup, delay, pattern)
         print('Events: '+ str(len(events)))
    except Exception as e:
        print(e)
        return "Lambda isn't done"
   
    subject = get_subject(trigger, account_id)
    sesArn = 'arn:aws:ses:us-east-1:'+account_id+':identity/' + from_email
    email, logmessage = build_email(events, trigger, account_id)
    if len(events) > 0:
        email_notification(subject,to_email,from_email,email,sesArn)
        result = 'Lambda done'
        #publish_sns(logmessage, snsArn, 'eu-central-1' )
    else:
        print('No matching logs in during this time span')
        result = 'No matching logs in during this time span'
    return result
def get_filter_pattern(trigger):
    pattern = None
    try:
        pattern = environ['filterPattern'+str(trigger)]
    except KeyError:
        print('Es gibt kein filterPattern' + str(trigger) + ' in den eviroment variables')
    return pattern
    
def get_subject(trigger, account_id):
    subject = 'AWS '+trigger+'-alert for account: ' + str(account_id)
    return subject

def build_email(events, trigger, account_id):
    email = buildEmailHeader(trigger, account_id)
    logmessage = 'The '+trigger+'-Alarm  on account '+str(getAccountName(account_id))+' ('+str(account_id)+') has been triggered because of following actions: \n \n'
    for event in events:
        messageStr = event['message']
        message = json.loads(messageStr)
        print(message)
        if 'type' in message['userIdentity'].keys():
        	requesttype = message['userIdentity']['type']
	        if requesttype == "AssumedRole":
	            print('User with ID '+getUserID(message) +' performed with role '+getRole(message)+' the action: '+getEventName(message) + ' at ' + getEventTime(message))
	            logmessage += str('User with ID '+ str(getUserID(message)) +' performed with role '+ str(getRole(message)) +' the action: '+ str(getEventName(message)) + ' at ' + str(getEventTime(message)) +'\n')
	            email += '<tr><td>'+str(getUserID(message))+'</td><td>'+str(getRole(message)) +'</td><td>'+str(getEventName(message)) +'</td><td>'+  str(getErrorCode(message))+'</td><td>'+ str(getErrorMessage(message)) +'</td><td>'+str(getEventTime(message))+'</td></tr>'
	        if requesttype == "IAMUser":
	            print('User with ID '+getUserName(message) +' the action: '+getEventName(message) + ' at ' + getEventTime(message))
	            logmessage += 'User with ID '+ str(getUserName(message)) +' the action: '+ str(getEventName(message)) + ' at ' + str(getEventTime(message)) +'\n'
	            email += '<tr><td>'+str(getUserName(message))+'</td><td></td><td>'+str(getEventName(message)) +'</td><td>'+  str(getErrorCode(message))+'</td><td>'+ str(getErrorMessage(message)) +'</td><td>'+str(getEventTime(message))+'</td></tr>'
        elif 'invokedBy' in message['userIdentity'].keys(): 
       	    print('Invoked by' + message['userIdentity']['invokedBy'] +' the action: '+getEventName(message) + ' at ' + getEventTime(message))
       	    logmessage += 'Invoked by' + message['userIdentity']['invokedBy'] +' the action: '+ str(getEventName(message)) + ' at ' + str(getEventTime(message)) +'\n'
       	    email += '<tr><td>'+ message['userIdentity']['invokedBy'] +'</td><td></td><td>'+str(getEventName(message)) +'</td><td>'+  str(getErrorCode(message))+'</td><td>'+ str(getErrorMessage(message)) +'</td><td>'+str(getEventTime(message))+'</td></tr>'
    email += "</table>"

    return email, logmessage
    
def buildEmailHeader(trigger, account_id):
    header = '<p><font size="4">Dear CloudOps-Team,</p>'
    header += '<p>this is an automated '+trigger+'-alert for the account '+str(getAccountName(account_id))+' ('+str(account_id)+') which was triggered because of the following actions:.<br> </p>'
    header += '<style> table {font-family: arial, sans-serif; border-collapse: collapse; width: 100%;} td, th { border: 1px solid #dddddd; text-align: center; padding: 8px;} </style><table>'
    header += '<th>ID/User</th><th>Role</th><th>Event/Action</th><th>Error</th><th>ErrorMessage</th><th>Time</th>'
    return header

    
    
    #email_notification(subject,to_email,from_email,email,sesArn)
def get_events_delay(logGroup, delay, pattern):
    logStartTime = getTime() - (delay*60*1000)
    logEndTime = getTime()
    events = get_events_period(logGroup, logStartTime, logEndTime, pattern)
    return events

def get_events_period(logGroup, logStartTime, logEndTime, pattern):
    client = boto3.client('logs')
    events = []
    response = client.filter_log_events(
        logGroupName='CloudTrail/DefaultLogGroup',
        logStreamNames= [logGroup],
        startTime=logStartTime,
        endTime=logEndTime,
        filterPattern= pattern)
    searchedCompletely = response['searchedLogStreams'][0]['searchedCompletely']
    if 'nextToken' in response.keys():
        token = response['nextToken']
    else:
        token = None
    events.extend(response['events'])
    while not searchedCompletely and token:
        response = client.filter_log_events(
            logGroupName='CloudTrail/DefaultLogGroup',
            logStreamNames= [logGroup],
            startTime=logStartTime,
            endTime=logEndTime,
            filterPattern= pattern,
            nextToken = token)
        events.extend(response['events'])
        searchedCompletely = response['searchedLogStreams'][0]['searchedCompletely']
        if 'nextToken' in response.keys():
            token = response['nextToken']
        else:
            token = None
    return events

def publish_sns(sns_message, sns_arn, rgn):

    sns_client = boto3.client('sns', region_name=rgn)

    print("Publishing message to SNS topic...")
    sns_client.publish(TargetArn=sns_arn, Message=sns_message)
    return

def email_notification(SUBJECT, TO, FROM, BODY, SESARN):
    client = boto3.client('ses',region_name='us-east-1')
    try:
        send_response = client.send_email(Source=FROM,
                                          Destination={'ToAddresses': [TO]},
                                          Message={
                                            'Subject': {
                                             'Charset': 'UTF-8',
                                             'Data': SUBJECT,
                                             },
                                            'Body': {
                                             'Html': {
                                              'Charset': 'UTF-8',
                                              'Data': BODY
                                              }
                                             }
                                           
                                            },										  
                                          SourceArn=SESARN
                                            )
        print('Successfuly send the email with message ID: ' + send_response['MessageId'])
    except:
        print('Failed to send email, check the stack trace below.')
        traceback.print_exc()
    
def getArn(message):
    arn = message['userIdentity']['arn']
    return arn

def getRole(message):
    arn = getArn(message)
    arnSplit = arn.split('/')
    role = arnSplit[1]
    return role
    
def getUserID(message):
    principalId = message['userIdentity']['principalId']
    userID = principalId.split(':')[1]
    return userID

def getUserName(message):
    userName = message['userIdentity']['userName']
    return userName

def getEventTime(message):
    eventTime =  message['eventTime']
    eventDateTime = dateutil.parser.parse(eventTime)
    eventDateTime = eventDateTime.strftime('%H:%M:%S (%Z)  %d.%m.%Y ')
    return eventDateTime

def getEventName(message):
    eventName = message['eventName']
    return eventName

def getErrorCode(message):
    if 'errorCode' in message.keys():
        code = message['errorCode']
    else:
        code = '(No Error)'
    return code

def getErrorMessage(message):
    if 'errorMessage' in message.keys():
        msg = message['errorMessage']
    else:
        msg = '(No Error)'
    return msg

def getTime():
    epoch = int(round(time.time() * 1000))
    return int(epoch)


def getTriggerArn(event):
    try:
        eventSubscriptionArn = event['Records'][0]['EventSubscriptionArn']
        list = eventSubscriptionArn.split(":")
        triggerArn = list[5]
        trigger = find_between(triggerArn, 'AZD-ALERTS-', '-' )
        if trigger:
            trigger = trigger.title()
    except:
        trigger = None
    return trigger
    
def find_between( s, first, last ):
    try:
        start = s.index( first ) + len( first )
        end = s.index( last, start )
        return s[start:end]
    except ValueError:
        return ""

def getAccountName(accountNo):
    if(accountNo=='874233888769'):
        return 'SBX'
    if(accountNo=='284894803213'):
        return 'PROD'
    if(accountNo=='784550693460'):
        return 'DEV'
    if(accountNo=='966497653753'):
        return 'POC'
    if(accountNo=='303747409146'):
        return 'CC'