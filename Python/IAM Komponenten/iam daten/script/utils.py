from functools import wraps
import getpass
import logging
import traceback
import tempfile
from awsloginerror import AwsLoginError
import ConfigParser
import os.path
import sys
import os

awslogin_dir = ".awslogin"
awslogin_dir_path = os.path.join(os.path.expanduser('~'), awslogin_dir)
AWSLOGIN_CONFIG_FILE_PATH = os.path.join (awslogin_dir_path, 'config.ini')


def create_awslogin_config_file(config_file_path = AWSLOGIN_CONFIG_FILE_PATH):
    '''create awslogin config (config.ini) , if it doesn't exist, using default values'''
    section_name = "awslogin"
    config = ConfigParser.ConfigParser()
    config.add_section(section_name)
    config.set(section_name, 'DOMAIN', "win")
    config.set(section_name, 'SAML_URI', "/adfs/ls/IdpInitiatedSignOn.aspx?loginToRp=urn:amazon:webservices")
    config.set(section_name, 'DEFAULT_HOST', "https://cloudsignin.win.azd.cloud.allianz")
    config.set(section_name, 'DEFAULT_REGION', "eu-central-1")
    config.set(section_name, 'AWS_URL', "https://signin.aws.amazon.com:443/saml")
    config.set(section_name, 'DEFAULT_SSL_VERIFICATION', True)
    config.set(section_name, 'KEY', "QQ7A8IR08Z8I4DGN3PWXP9N1")
    config.set(section_name, 'DEFAULT_CERT_PATH', "/etc/ssl/certs/saml.pem")
    config.set(section_name, 'DEFAULT_COOKIES_FILE_NAME', "saml_cookie.txt")
    config.set(section_name, 'DEFAULT_DURATION', 3600)
    config.set(section_name, 'DEFAULT_USERNAME', os.getlogin())

    with (open(config_file_path, "w+")) as config_file:
        try:
            config.write(config_file)
        except Exception as er:
            exception_handle('Awslogin Config File: ', er)


def get_config_dict(section_name = 'awslogin', config_file_path = AWSLOGIN_CONFIG_FILE_PATH):
    ''' retrieve all values from the file confing.ini as a dictionary '''
    exists = os.path.exists(config_file_path)
    config_dict = {}
    if exists:
        config = ConfigParser.ConfigParser()
        config.read(config_file_path)
        config_dict = config._sections[section_name]
    return config_dict


def get_config(option, default_value = None, section_name = 'awslogin', config_file_path = AWSLOGIN_CONFIG_FILE_PATH):
    ''' get the value of a option from the config.ini file '''
    exists = os.path.exists(config_file_path)
    option_value = default_value
    if exists:
        config = ConfigParser.ConfigParser()
        config.read(config_file_path)
        try:
            option_value = config.get(section_name, option)
        except:
            pass
    return option_value


DEFAULT_LOGS_PATH = os.path.join(tempfile.gettempdir(), 'awslogin_errors.log')


def exception_handle(message, er = None):
    raise AwsLoginError(message, er)


def get_root_logger(logs_path = DEFAULT_LOGS_PATH):
    logger = logging.getLogger()
    logger.setLevel(logging.ERROR)  # or whatever
    handler = logging.FileHandler(logs_path , 'w', 'utf-8')  # or whatever
    handler.setFormatter = logging.Formatter('%(name)s %(message)s')  # or whatever
    logger.addHandler(handler)
    # logger = logging.getLogger("main_logger").addHandler(logging.NullHandler())
    return logger


def log_error(logger):

    def decorated(f):

        @wraps(f)
        def wrapped(*args, **kwargs):
            try:
                return f(*args, **kwargs)
            except AwsLoginError as e:
                print e
                sys.exit()
            except Exception as e:
                print 'internal error:', e
                traceback.print_exc(file = sys.stdout)
                if logger: logger.info(e)
                sys.exit()

        return wrapped

    return decorated


def find_between(s, first, last):
    """
    >>> find_between("abcd", "b", "d")
    c
    """
    try:
        start = s.index(first) + len(first)
        end = s.index(last, start)
        return s[start:end]
    except ValueError:
        return ""


def __make_question_for_change(question):
    change = False
    print question , ' yes(y,Y) :',
    try:
        answer = raw_input()
        if answer == 'y' or answer == 'Y':
            change = True
    except KeyboardInterrupt as er:
        exception_handle('\noperation cancelled by user')
    return change


def get_username(login_user):
    print "Username(" + login_user + "):",
    try:
        username = raw_input()
        username = username.strip()
        if not username:
            username = login_user
    except KeyboardInterrupt as er:
        exception_handle('\noperation cancelled by user')
    return username


def get_password():
    password = getpass.getpass()
    password = password.strip()
    return password


def input_username_password(login_user):
    username = get_username(login_user)
    password = get_password()
    return username, password


def get_role_index(text):
    ''' select a role '''
    print text,
    try:
        index = raw_input()
        selcted_index = int(index)
    except KeyboardInterrupt as ker:
        exception_handle('\noperation cancelled by user')
    except ValueError as er:
        exception_handle('Invalid Input: ', er)
    return selcted_index


def create_path(path):
    ''' create path if it dosen't exist '''
    if not (path.endswith('\\') or path.endswith('/')):
        path = os.path.dirname(path)
    if not os.path.exists(path):
        try:
            os.makedirs(path)
        except OSError as exc:
            import errno
            if exc.errno != errno.EEXIST:
                raise AwsLoginError('the path: ' + path + ' could not be created.', exc)
