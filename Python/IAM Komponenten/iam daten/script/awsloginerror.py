'''
Created on 25.04.2018
encapsulation the exceptions in the program.
@author: feuk8fs
'''


class AwsLoginError(Exception):

    def __init__(self, msg, original_exception = None):
        if original_exception is None:
            super(AwsLoginError, self).__init__(msg)
        else:
            super(AwsLoginError, self).__init__(msg + (": %s" % original_exception))
            self.original_exception = original_exception
