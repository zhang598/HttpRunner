# -*- coding: utf-8 -*
import json
import os
import random
import string
import time
import base64
import unittest
import subprocess
import sys
from httprunner import loader, parser, logger
from httprunner.api import HttpRunner

ADMIN_USER_NAME = os.environ['AdminUserName']
ADMIN_PASSWORD = os.environ['AdminPassword']
BASE_URL = os.environ['BaseURL']
TOKEN_KIND = os.environ['TokenKind']


##### public functions #####
def base64Token(usr, password):
    if sys.version_info > (3, 0):
        text = usr + ":" + password
        return "Basic " + base64.b64encode(text.encode()).decode()
    else:
        return "Basic " + base64.b64encode("%s:%s"%(usr, password))

def getBaseURL():
    return BASE_URL

def checkSSLCertificate():
    try:
        SSL_VERIFY = os.environ['SSLVerify']
        if SSL_VERIFY == True or SSL_VERIFY == 'true':
            return True
    except:
        logger.log_error("Cannot confirm whether to check SSL certificate！ Default no to check SSL certification.")
        logger.logging.exception(e)
    finally:
        return False

def getToken(usr=ADMIN_USER_NAME, password=ADMIN_PASSWORD):
    if  TOKEN_KIND == 'oauth':
        # 使用oauth获取tokne
        return getTokenFromHodor(usr, password)
    else:
        return base64Token(usr, password)

def getTokenFromHodor(user, password):
    try:
        project_working_directory = os.getcwd()
        goFileToGetToken = os.path.join(project_working_directory, "aleo-go/src/aleo-e2e/cmd/hodor-auth")
        newGoEnvPATH = os.path.join(project_working_directory, "aleo-go")

        whole_cmd = 'go run {} --url {} --user {} --password {}'.format(
            goFileToGetToken, BASE_URL, user, password)
        s = subprocess.Popen(whole_cmd, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, shell=True,
                             env={"GOPATH": newGoEnvPATH})

        error = s.stderr.read().decode('utf8')

        if error:
            logger.log_info(
                'cannot get the token, error message is {}'.format(error))
            raise Exception()

        result = s.stdout.read().decode('utf8')
        token = result.split('\n')[-2]
        logger.log_info('the token is {}'.format(token))

    except Exception as e:
            logger.log_error("cannot get hodor token")
            logger.logging.exception(e)

    return "Bearer " + token

def hookPrint(msg):
    print (msg)

def hookFunction(testcase_path, variables):
    testcase_path = os.path.join(os.getcwd(), testcase_path)

    runner = HttpRunner(failfast=True)
    tests_mapping = loader.load_tests(testcase_path)

    # to add variables into tests_mapping.teststeps
    tests_mapping['apis'][0]['variables'] = variables

    parsed_tests_mapping = parser.parse_tests(tests_mapping)
    runner.run(parsed_tests_mapping)

def genRandomString(str_len=8):
    random_char_list = []
    for _ in range(str_len):
        random_char = random.choice(string.ascii_lowercase + string.digits)
        random_char_list.append(random_char)

    random_string = ''.join(random_char_list)
    return random_string

def assertSum(a, b):
    return sum([a, b])

def getDefaultRequest():
    return {
        "base_url": BASE_URL,
        "headers": {
            "content-type": "application/json"
        }
    }

def skiptTestInProductionEnv():
    os.environ["TEST_ENV"] = "PRODUCTION"
    """ skip this test in production environment
    """
    return os.environ["TEST_ENV"] == "PRODUCTION"

##### app private functions ######

##### resource private functions ######

##### auth private functions ######

##### insight private functions ######

##### develops private functions ######

##### net private functions ######