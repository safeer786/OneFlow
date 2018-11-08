#! /usr/bin/env python
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup
from  utils import input_username_password, find_between, exception_handle, get_root_logger, \
    get_config, create_path, __make_question_for_change
import requests
import urllib
import pycurl
from StringIO import StringIO
import base64
import os
import tempfile
from awsloginerror import AwsLoginError
from requests.exceptions import ProxyError, ConnectTimeout
import ConfigParser
import datetime
import yaml
import boto3
import botocore

ConfigParser.DEFAULTSECT = 'default'

logger = get_root_logger()


def get_accounts_information(assertion, aws_url):
    '''
    get more information about accounts and roles the the user has.
        input:
            assertion: a b64encoded text, you can get it from idpentryurl
            aws_url: normally https://signin.aws.amazon.com:443/saml
        output:
            accounts =  { account_id:{"account_name":account_name, "account_title": account_title, "roles": [{"account_name":account_name, "role_name": rolelabel.text, "role": awsrole}]}, account_id:{..}, .....}
    '''

    # get the HTML response from the aws_url page. Login using assertion
    soup = __call_aws(assertion, aws_url)
    # extract the roles (role arn and principal arn) from the assertion
    roles = get_roles(assertion)

    # merge the two information in one dictionary
    accounts = {}
    for saml_account in soup.find_all("div", class_ = "saml-account", attrs = {'id': None}):
        account_title = saml_account.find("div", class_ = "saml-account-name").text
        account_name = find_between(account_title, "Account: ", " (")
        account = {"account_name":account_name, "account_title": account_title, "roles": []}
        account_id = find_between(account_title, "(", ")")
        accounts[account_id] = account
        for rolelabel in saml_account.find_all("label"):
            role = rolelabel['for']
            for awsrole in roles:
                if role in awsrole and account_id in awsrole:
                    account["roles"].append({"account_name":account_name, "role_name": rolelabel.text, "role": awsrole})
                    roles.remove(awsrole)
    return accounts


def filter_accounts_information(assertion, aws_url, account, role):
    '''
        filter account depends on account , role or both
        input:
            assertion: b64encoded text
            aws_url: normally https://signin.aws.amazon.com:443/saml
            account: poc, prod ....
            role: operator, audit ....
        output:
            { account_id:{"account_name":account_name, "account_title": account_title, "roles": [{"account_name":account_name, "role_name": rolelabel.text, "role": awsrole}]}, account_id:{..}, .....}
    '''

    accounts = get_accounts_information(assertion, aws_url)
    selected_account = account
    selected_role = role
    if selected_account:
        selected_accounts = { account_key:account for account_key, account in accounts.items() if selected_account.lower() in account['account_name'].lower()}
        if len(selected_accounts) > 0:
            if selected_role:
                for account_id in selected_accounts.keys():
                    roles = [account_role for account_role in selected_accounts[account_id]['roles'] if selected_role.lower() in account_role['role_name'].lower()]
                    if len(roles) > 0:
                        selected_accounts[account_id]['roles'] = roles
                    else:
                        del selected_accounts[account_id]
    else:
        selected_accounts = {}
        if selected_role:
            for account_id, account in accounts.items():
                roles = [account_role for account_role in account['roles'] if selected_role.lower() in account_role['role_name'].lower()]
                if len(roles) > 0:
                    selected_account = {"account_name":account['account_name'], "account_title": account['account_title'], "roles": roles}
                    selected_accounts[account_id] = selected_account
        else:
            selected_accounts = accounts
    return selected_accounts


def get_token(awsrole, assertion, region, duration_seconds = 3600):
    '''
        connect STS(AWS Security Token Service) and get temporary access key , secret key and session token
        input:
            awsrole: login aws with this role
            assertion: b64encoded text
            region:  you want connect to
            duration_seconds: The duration, in seconds, of the role session.
        output:
            token: {'ResponseMetadata': {'RetryAttempts': 0, 'HTTPStatusCode': 200,'RequestId': '',
            'HTTPHeaders': {'x-amzn-requestid': '', 'date': 'Tue, 19 Jun 2018 09:19:02 GMT', 'content-length': '1426', 'content-type': 'text/xml'}},
             u'SubjectType': 'persistent',u'AssumedRoleUser': {u'AssumedRoleId': '', u'Arn':''},
             u'Audience': 'https://signin.aws.amazon.com/saml',
             u'NameQualifier': '',
             u'Credentials': {u'SecretAccessKey': '', u'SessionToken': '', u'Expiration': datetime.datetime(2018, 6, 19, 10, 19, 3, tzinfo=tzlocal()), u'AccessKeyId': ''},
              u'Subject': '', u'Issuer': ''}

        '''
    from botocore.config import Config

    token = None
    if awsrole is not None:
        role_arn = awsrole.split(',')[1]
        principal_arn = awsrole.split(',')[0]
        # connect sts(AWS Security Token Service)
        # conn = boto3.client("sts", region_name = region, config = Config(proxies = {'https': 'https://surf.proxy.agis.allianz:8080', 'http':'http://surf.proxy.agis.allianz:8080'}))
        conn = boto3.client("sts", region_name = region)
        if conn is None:
            raise AwsLoginError('AWS STS Connection failed')
        token = None
        try:
            token = conn.assume_role_with_saml(RoleArn = role_arn, PrincipalArn = principal_arn, SAMLAssertion = assertion, DurationSeconds = duration_seconds)
        except botocore.exceptions.EndpointConnectionError as er:
            raise AwsLoginError('Connection Failed ', er)
        except botocore.exceptions.ClientError:
            print " NOTE: The requested DurationSeconds exceeds the MaxSessionDuration set for this role. The Command is executed with the default duration( 3600 seconds) "
            token = conn.assume_role_with_saml(RoleArn = role_arn, PrincipalArn = principal_arn, SAMLAssertion = assertion)
    return  token


def get_assertion(username, password , idpentryurl, cert_path, sslverification, cookies_file):
    ''' using AD credentials get the assertion from idpentryurl, if sslverification is True, cert_path would be required '''
    response = __call_saml_page(username, password, idpentryurl , cert_path, sslverification, cookies_file)
    assertion = __get_assertion(response)
    return assertion


def get_roles(assertion):
    ''' extract roles that the user has, through b64decode (assertion) '''
    root = __get_root(assertion)
    roles = __get_roles(root)
    return roles


def __get_roles(root):
    # extract roles from the decoded text of assertion
    roles = []
    for saml2attribute in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
        if (saml2attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role'):
            for saml2attributevalue in saml2attribute.iter('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
                roles.append(saml2attributevalue.text)
    return roles


def __get_root(assertion):
    ''' b64decode assertion '''
    root = None
    try:
        decoded_assertion = base64.b64decode(assertion)
        root = ET.fromstring(decoded_assertion)
    except Exception as e:
        raise AwsLoginError('Login is not succeed', e)
    return root


def __get_assertion(response):
    ''' Decode the response and extract the SAML assertion '''
    if response is None:
        raise AwsLoginError('Response must be not None')
    soup = BeautifulSoup(response.decode('utf8'), "html.parser")
    assertion = None
    # Look for the SAMLResponse attribute of the input tag (determined by
    # analyzing the debug print lines above)
    inputtag = soup.find('input', {"name": "SAMLResponse"})
    if inputtag is not None:
        assertion = inputtag.get('value')
    return assertion


def __call_saml_page(username, password, idpentryurl, cert_path, sslverification, cookies_file):
    ''' using AD credentials to get HTML Page that should contain the SAML assertion, if sslverification is True, cert_path would be required '''
    if idpentryurl is None:
        raise AwsLoginError('idpentryurl must be not None')
    post_data = {'UserName': username, 'Password': password, 'AuthMethod':'FormsAuthentication'}
    postfields = urllib.urlencode(post_data)
    storage = StringIO()
    curl = pycurl.Curl()
    response = None
    try:
        curl.setopt(pycurl.URL, idpentryurl)
        if sslverification:
            if cert_path is None or not os.path.exists(cert_path):
                raise AwsLoginError('certificate does not exist')
            curl.setopt(pycurl.SSL_VERIFYPEER, 1)
            curl.setopt(pycurl.SSL_VERIFYHOST, 2)
            curl.setopt(pycurl.CAINFO, cert_path)
        else:
            curl.setopt(pycurl.SSL_VERIFYPEER, 0)
            curl.setopt(pycurl.SSL_VERIFYHOST, 0)
        curl.setopt(pycurl.POST, True)
        curl.setopt(pycurl.POSTFIELDS, postfields)

        curl.setopt(pycurl.WRITEFUNCTION, storage.write)
        curl.setopt(pycurl.FOLLOWLOCATION, 1)
        curl.setopt(pycurl.COOKIEJAR, cookies_file)
        # curl.setopt(pycurl.VERBOSE, True)
        curl.perform()
        response = storage.getvalue()
    except pycurl.error as er:
        exception_handle('Connection Failed', er)
    finally:
        curl.close()
    return response


def __call_aws(assertion, aws_url):
    ''' get the HTML response from the aws_url page. Login using assertion '''
    if assertion is None: raise AwsLoginError('Assertion must be not None')
    if aws_url is None: raise AwsLoginError('AWS URL must be not None')
    payload = {'SAMLResponse': assertion}
    try:
        response = requests.post(aws_url, data = payload)
    except requests.exceptions.SSLError as er:
        exception_handle('Connection Failed', er)
    except ProxyError as per:
        exception_handle('Proxy Error', per)
    except requests.ConnectionError as cer:
        exception_handle('Connection Failed', cer)
    else:
        soup = BeautifulSoup(response.text, "html.parser")
    return soup


def write_in_credentials_file(token, profile, aws_credentials_path, region, account_name, role_name, force = True):
    ''' write the temporary credentials in the AWS credentials file(aws_credentials_path) under the profile(profile) '''
    if token is None: return False
    if aws_credentials_path is None: raise AwsLoginError('AWS Credentials path is requierd')
    if profile is None: raise AwsLoginError('Profile is None')

    config = ConfigParser.ConfigParser()

    if os.path.exists(aws_credentials_path):
        change = False
        # Read in the existing config file
        config.read(aws_credentials_path)
        if not force:
            if config.has_section(profile) or config.has_option(profile, 'aws_access_key_id'):
                if config.has_option(profile, 'created_date'):
                    created_date = config.get(profile, 'created_date')
                else:
                    created_date = ' '
                change = __make_question_for_change('AWS Credentials under Profile ' + profile + ' (created_date: ' + created_date + ') already exists in the ~/.aws/credentials file, do you want to change it?')
            else:
                change = True
        else:
            change = True

        if not change:
            return False
        # Put the credentials into a specific profile instead of clobbering
        # the default credentials
    else:
        create_path(aws_credentials_path)

    if profile != ConfigParser.DEFAULTSECT:
        if not config.has_section(profile):
            config.add_section(profile)
    config.set(profile, 'region', region)
    config.set(profile, 'role_name', role_name)
    config.set(profile, 'account_name', account_name)
    config.set(profile, 'aws_access_key_id', token['Credentials']['AccessKeyId'])
    config.set(profile, 'aws_secret_access_key', token['Credentials']['SecretAccessKey'])
    config.set(profile, 'aws_session_token', token['Credentials']['SessionToken'])
    config.set(profile, 'created_date', datetime.datetime.utcnow())
    config.set(profile, 'expiration_date', token['Credentials']['Expiration'])

    # Write the updated credentials file
    with open(aws_credentials_path, 'w+') as configfile:
        try:
            config.write(configfile)
        except Exception as er:
            exception_handle('Credentials File: ', er)
        else:
            return True

    return False


def write_config_file(token, profile, aws_config_dir, region, force = True):
    if aws_config_dir is None: raise AwsLoginError('AWS Config directory is requierd')
    if token is None: return
    if profile is None: raise AwsLoginError('Profile is None')
    aws_config_file = os.path.join(aws_config_dir, profile)
    if os.path.exists(aws_config_file):
        if not force:
            stat = os.stat(aws_config_file)
            try:
                created_ts = stat.st_birthtime
            except AttributeError:
                # We're probably on Linux. No easy way to get creation dates here,
                # so we'll settle for when its content was last modified.
                created_ts = stat.st_mtime
            change = False
            created_date = datetime.datetime.fromtimestamp(created_ts).strftime('%Y-%m-%d %H:%M:%S')
            change = __make_question_for_change('this file ' + profile + ' (created_date: ' + str(created_date) + ') already exists in the ~/.aws/, do you want to change it? yes(y,Y) :')
        else:
            change = True
    else:
        create_path(aws_config_file)
        change = True

    if change:
        profile_data = {'aws': {'region':region , 'aws_access_key':token['Credentials']['AccessKeyId'], 'aws_secret_key':token['Credentials']['SecretAccessKey'], 'security_token': token['Credentials']['SessionToken']}}
        try:
            with open(aws_config_file, 'wb') as aws_config:
                try:
                    ##### use safe_dump instead of dump to remove python/unicode
                    yaml.safe_dump(profile_data, aws_config, default_flow_style = False)
                except Exception as er:
                    exception_handle('Config File(Yaml  File): ', er)
                else:
                    return True
        except IOError as er:
            raise AwsLoginError('AWS Config file error', er)

    return False


def __main():
    domain = get_config('DOMAIN', config_file_path = '../config.ini')
    SAML_URI = get_config('SAML_URI', config_file_path = '../config.ini')
    DEFAULT_HOST = get_config('DEFAULT_HOST', config_file_path = '../config.ini')
    idpentryurl = "".join([DEFAULT_HOST, SAML_URI])
    DEFAULT_CERT_PATH = "../certs/saml.pem"
    DEFAULT_COOKIES_FILE_NAME = get_config('DEFAULT_COOKIES_FILE_NAME', config_file_path = '../config.ini')
    DEFAULT_COOKIES_FILE = os.path.join(tempfile.gettempdir(), DEFAULT_COOKIES_FILE_NAME)
    DEFAULT_REGION = get_config('DEFAULT_REGION', config_file_path = '../config.ini')
    DEFAULT_USERNAME = os.getlogin() if get_config('DEFAULT_USERNAME', config_file_path = '../config.ini') is None else get_config('DEFAULT_USERNAME', config_file_path = '../config.ini')
    username, password = input_username_password(DEFAULT_USERNAME)
    username = "".join([domain, '\\', username])
    assertion = get_assertion(username, password, idpentryurl, DEFAULT_CERT_PATH, True, DEFAULT_COOKIES_FILE)
    print assertion
    roles = get_roles(assertion)
    print get_token(roles[0], assertion, DEFAULT_REGION)
    print ''
    AWS_URL = get_config('AWS_URL')
    print get_accounts_information(assertion, AWS_URL)
    '''
    selected_accounts = filter_accounts_information(assertion, 'cc', 'audit')
    for selected_account in selected_accounts.values():
        print selected_account['account_title']
        for role in  selected_account['roles']:
            print role['role_name']
    '''


if __name__ == "__main__": __main()

