# coding=utf-8
"""
Module containing the ExpaApi class
"""
from __future__ import unicode_literals, print_function
import requests
import time
import urllib
import calendar
from bs4 import BeautifulSoup

from future.standard_library import install_aliases
install_aliases()

from urllib.parse import urlparse, urlencode, unquote
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class APIUnavailableException(Exception):
    """
        This error is raised whenever the EXPA API is not working as expected.
    """
    def __init__(self, response, error_message):
        self.response = response
        self.error_message = error_message


class PyEXPAException(Exception):
    """
        This error is raised whenever this module is not working as expected. If it shows up, it should be treated as a bug.
    """
    def __init__(self, error_message):
        self.error_message = error_message


class ExpaApi(object):
    """
    This class is meant to encapsulate and facilitate the development of
    methods that extract information from the GIS API. Whenever a new object of
    this class is created, it generates a new access token which will be used
    for all method calls.
    As such tokens expire two hours after being obtained, it is recommended to
    generate a new ExpaApi object if your scripts take too long to complete.
    """

    AUTH_URL = "https://auth.aiesec.org/users/sign_in"
    # AUTH_URL = "https://experience.aiesec.org"
    # This dict takes the first letter of a program to decide whether this
    # API's methods should look for information about opportunities or about
    # people
    API_ENDPOINT = "https://gis-api.aiesec.org/"
    ioDict = {'i': 'opportunity', 'o': 'person'}
    # This dict takes the other letters to know whether it is a global
    # volunteer or a global internship program
    programDict = {
        'gv': 1, 'gt': 2, 'get': [2, 5],
        'gx': [1, 2, 5], 'cx': [1, 2, 5], 'ge': 5}

    def __init__(self, username=None, password=None, token=None, fail_attempts=1, fail_interval=10):
        """
        Default method initialization.
        params?
        username: the username for authentication
        password: The password for autentication
        token: If provided, it will skip the authentication process
        fail_attempts: Defines how many times will this instance try to redo a failed request before failing and throwing an EXPA error.
        fail_interval: Defines the time this instance will wait before trying to redo a failed request.
        """
        self.fail_attempts = fail_attempts
        self.fail_interval = fail_interval
        if token:
            self.token = token
            return
        params = {
            'user[email]': username,
            'user[password]':password,
            }
        s = requests.Session()
        token_response = s.get("https://experience.aiesec.org").text
        soup = BeautifulSoup(token_response, 'html.parser')
        token = soup.find("form").find(attrs={'name': 'authenticity_token'}).attrs['value']  # name="authenticity_token").value
        params['authenticity_token'] = token
        response = s.post(self.AUTH_URL, data=params)
        try:

            self.token = response.history[-1].cookies['expa_token']
            print(self.token)
        except KeyError:
            raise PyEXPAException("Error obtaining the authentication token")

    def _build_query(self, routes, query_params=None, version='v2'):
        """
        Builds a well-formed GIS API query

        version: The version of the API being used. Can be v1 or v2.
        routes: A list of the URI path to the required API REST resource.
        queryParams: A dictionary of query parameters, for GET requests
        """
        if query_params is None:
            query_params = {}
        base_url = self.API_ENDPOINT + "{version}/{routes}?{params}"
        query_params['access_token'] = self.token
        return base_url.format(version=version, routes="/".join(routes), params=urlencode(query_params, True))

    def make_query(self, routes, query_params=None, version='v2', method='get'):
        """
        This method both builds a query and executes it using the requests module. If it doesn't work because of EXPA issues, it will retry an amount of times equal to the 'fail_attempts' attribute before raising an APIUnavailableException
        """
        if method == "get":
            query = self._build_query(routes, query_params, version)
        else:
            query = self._build_query(routes, None, version)
        print(query)
        fail_attempts = self.fail_attempts
        # Tries the request until it works
        while fail_attempts > 0:
            try:
                if method == "get":
                    response = requests.get(query, timeout=80)
                elif method == "patch":
                    print(query_params)
                    response = requests.patch(query, json=query_params, timeout=20)
                if response.status_code == 200:  # TODO: Check if the answer is a 200
                    data = response.json()
                    return data  # This returns the method and avoids it reaching the end stage and raising an APIUnavailableException.
                else:  # TODO: Check if the answer is a service unavailable, back end server at capacity
                    fail_attempts = fail_attempts - 1
                    error_message = "The request has failed with error code %s and error message %s. Remaining attempts: %s" % (response.status_code, response.text, fail_attempts)
                    print(error_message)
                    if fail_attempts > 0:
                        time.sleep(self.fail_interval)
            except Exception as e:
                fail_attempts = fail_attempts - 1
                error_message = "The request has failed because of an unexpected exception"
                print(error_message)
                print(e)
                if fail_attempts > 0:
                    time.sleep(self.fail_interval)

        raise APIUnavailableException(response, error_message)
