import ConfigParser
import boto3

def get_cerdentials(profile):
    awsconfigfile = '/.aws/credentials'
    filename = home + awsconfigfile
    config = ConfigParser.ConfigParser()
    config.read(filename)
    access_key= config.get(profile, ''aws_access_key_id'')
    secret_key = config.get(profile, ''aws_secret_access_key'')
    session_token= config.get(profile, ''aws_session_token'')
    return access_key, secret_key, session_token