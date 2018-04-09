# coding=utf-8
"""
Module containing the ExpaApi class
"""
from __future__ import unicode_literals, print_function
import json
import requests
import time
import urllib
import base64
import calendar
from datetime import datetime, timedelta
from bs4 import BeautifulSoup
from . import tools, settings, models

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


class DjangoEXPAException(Exception):
    """
        This error is raised whenever the EXPA API is not working as expected.
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
    ioDict = {'i': 'opportunity', 'o': 'person'}
    # This dict takes the other letters to know whether it is a global
    # volunteer or a global internship program
    programDict = {
        'gv': 1, 'gt': 2, 'get': [2, 5],
        'gx': [1, 2, 5], 'cx': [1, 2, 5], 'ge': 5}

    def __init__(self, account=None, fail_attempts=1, fail_interval=10, pwd=None):
        """
        Default method initialization.
        params?
        account: If this argument is provided, and the account is present in
        the database, the expa API will try to use this account to authenticate
        and obtain the auth token. Otherwise it will use the default account in
        the settings file
        fail_attempts: Defines how many times will this instance try to redo a failed request before failing and throwing an EXPA error.
        fail_interval: Defines the time this instance will wait before trying to redo a failed request.
        """
        if account and pwd:
            password = base64.b64encode(pwd.encode())
        else:
            if account is None:
                account = settings.DEFAULT_ACCOUNT
            password = models.LoginData.objects.get(email=account).password
        params = {
            'user[email]': account,
            'user[password]': base64.b64decode(password).decode('utf-8'),
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
            raise DjangoEXPAException("Error obtaining the authentication token")
        self.fail_attempts = fail_attempts
        self.fail_interval = fail_interval

    def _buildQuery(self, routes, queryParams=None, version='v2'):
        """
        Builds a well-formed GIS API query

        version: The version of the API being used. Can be v1 or v2.
        routes: A list of the URI path to the required API REST resource.
        queryParams: A dictionary of query parameters, for GET requests
        """
        if queryParams is None:
            queryParams = {}
        baseUrl = "https://gis-api.aiesec.org/{version}/{routes}?{params}"
        queryParams['access_token'] = self.token
        return baseUrl.format(version=version, routes="/".join(routes), params=urlencode(queryParams, True))

    def make_query(self, routes, query_params=None, version='v2', method='get'):
        """
        This method both builds a query and executes it using the requests module. If it doesn't work because of EXPA issues, it will retry an amount of times equal to the 'fail_attempts' attribute before raising an APIUnavailableException
        """
        if method == "get":
            query = self._buildQuery(routes, query_params, version)
        else:
            query = self._buildQuery(routes, None, version)
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
                error_message = "The request has failed because of an exception"
                print(error_message)
                print(e)
                if fail_attempts > 0:
                    time.sleep(self.fail_interval)
                print(error_message)
                if fail_attempts > 0:
                    time.sleep(self.fail_interval)

        raise APIUnavailableException(response, error_message)

    def getPerson(self, person_id):
        """
        Returns the bare JSON data of a person, as obtained from the API
        """
        return self.make_query(['people', person_id])

    def update_person(self, person_id, new_data):
        """
        Returns the bare JSON data of a person, as obtained from the API
        params
        person_id: the id of the person to be updated
        new_data: a dictionary consisting of the fields and values that will be updated in that person
        """
        return self.make_query(['people', person_id], {"person": new_data}, method="patch")

    def getOpportunity(self, opID):
        """
        Returns the bare JSON data of an opportunity, as obtained from the GIS API.
        """
        response = requests.get(self._buildQuery(['opportunities', opID]))
        return response

    def get_application(self, app_ID):
        """
        Returns the bare JSON data of an opportunity, as obtained from the GIS API.
        """
        response = self.make_query(['applications', app_ID])
        return response

    def test(self, **kwargs):
        """
        Test method. Has one keyword argument, 'testArg', to be used when necessary
        """
        print(self)
        return kwargs['testArg']

    def getManagedEPs(self, expaID):
        """
        Devuelve a todos los EPs que son administrados por el EP manager cuya EXPA ID entra como parámetro
       """
        response = self.make_query(['people.json'], {'filters[managers][]': [expaID]})
        return response

    def getCountryEBs(self, mcID):
        """
        Este método busca dentro de todas las oficinas locales de un MC a los VPs de cada una de ellas para el término 2016
        """
        response = requests.get(self._buildQuery(['committees', '%s.json' % mcID])).text
        lcs = json.loads(response)['suboffices']
        ans = []
        for lc in lcs:
            newLC = {'nombre':lc['full_name'], 'expaID':lc['id']}
            data = self.getLCEBContactList(str(lc['id']))
            newLC['cargos'] = data
            ans.append(newLC)
        return ans

    def getLCEBContactList(self, lcID):
        """
        Este método retorna un diccionario con las personas que conforman la junta ejecutiva del LC cuya ID entra como parámetro, para el periodo 2016
        """
        ans = []
        data = self.make_query(['committees', str(lcID), 'terms.json'])
        #recorre todos los periodos hasta encontrar el del 2016
        for term in data['data']:
            if term['short_name'] == '2017':
                info = requests.get(self._buildQuery(['committees', str(lcID), 'terms', str(term['id']) + '.json'])).text
                info = json.loads(info)
                #recorre todos los equipos del periodo hasta encontrar el de la EB
                for team in info['teams']:
                    if team["team_type"] == "eb":
                        for position in team['positions']:
                            person = {}
                            if position['person'] is not None:
                                person = tools.getContactData(self.make_query(['people', str(position['person']['id']) + '.json']))
                            person['cargo'] = position['name']
                            ans.append(person)
                        break
                break
        return ans

    def getOPManagersData(self, opID):
        """
        Éste método devuelve un diccionario con todos los EP Managers y sus datos de contacto de la oportunidad cuya ID entra como parámetro
        """
        #hace un request GET sobre la oportunidad con la ID dada, obtiene el texto, o lo transforma de json a un objeto de python
        opportunity = self.make_query(['opportunities', opID])
        managerData = opportunity["managers"]
        managers = []
        for manager in managerData:
            managers.append(tools.getContactData(manager))
        return managers

    def get_stats(self, officeID, program, start_date, end_date):
        """
        Este método extrae las estadísticas, para una oficina dada y un periodo de tiempo dado. Es un método maestro, y todos los otros métodos que obtengan dichas estadísticas deberían llamar a este.
        """
        queryArgs = {
            'basic[home_office_id]': officeID,
            'basic[type]': self.ioDict[program[0].lower()],
            'end_date': end_date,
            'programmes[]': self.programDict[program[1:].lower()],
            'start_date': start_date,
        }
        try:
            response = self.make_query(['applications', 'analyze.json'], queryArgs)['analytics']
            return {
                'applications': response['total_applications']['doc_count'],
                'applicants': response['total_applications']['applicants']['value'],
                'accepted': response['total_matched']['unique_profiles']['value'],
                'approved': response['total_approvals']['doc_count'],
                'realized': response['total_realized']['doc_count'],
                'completed': response['total_completed']['doc_count'],
            }
        except APIUnavailableException:
            return {
                'applications': "EXPA ERROR",
                'accepted': "EXPA ERROR",
                'approved':" EXPA ERROR",
                'realized': "EXPA ERROR",
                'completed': "EXPA ERROR",
            }


    def get_past_stats(self, days, program, officeID):
        """
        Extrae el approved/realized de un mes específico, en un año específico, para un comité y uno de los 4 programas
        """
        now = datetime.now()
        start_date = (now - timedelta(days=days)).strftime('%Y-%m-%d')
        end_date = now.strftime('%Y-%m-%d')
        return self.get_stats(officeID, program, start_date, end_date)

    def getMonthStats(self, month, year, program, officeID):
        """
        Extrae el approved/realized de un mes específico, en un año específico, para un comité y uno de los 4 programas
        """
        start_date = '%d-%02d-01' % (year, month)
        end_date = '%d-%02d-%02d' % (year, month, calendar.monthrange(year, month)[1])

        return self.get_stats(officeID, program, start_date, end_date)

    def getWeekStats(self, week, year, program, lc=1395):
        """
            Extrae el ip/ma/re de un mes específico, en un año específico, para un comité y uno de los 4 programas
        """
        if week == 0:
            start_date = "%d-01-01" % year
        else:
            start_date = datetime.strptime('%d %d 1' % (year, week), '%Y %W %w').strftime('%Y-%m-%d')

        end_date = datetime.strptime('%d %d 0' % (year, week), '%Y %W %w').strftime('%Y-%m-%d')

        return self.get_stats(officeID, program, start_date, end_date)

    def getLCWeeklyPerformance(self, lc=1395):
        """
        Returns the weekly performance of an LC for a given year, and all four programs

        returns: A dictionary with the following structure:
        {
            'igcdp': *weeklyPerformance for igcdp*,
            ... and so on for all four programs
        }
        """
        answer = {}
        for io in ['i', 'o']:
            for program in ['gv', 'get']:
                answer[io+program] = self.getProgramWeeklyPerformance(io+program, lc)
        return answer

    def getProgramWeeklyPerformance(self, program, office=1395):
        """
        For a given AIESEC office and program, returns its weekly performance, plus its total one during the year. Week 1 starts the first monday of a month.

        Returns: The following dictionary structure:
        {'totals': {
            'MATOTAL': *Total matches in the year*,
            'RETOTAL': *Total realizations in the year*
            },
        'weekly': {
            'MA':[*matches week 0*, *matches week 1*, ...],
            'RE':[*realizations week 0*, *realizations week 1*, ...],
        }
        """
        now = datetime.now()
        currentWeek = int(now.strftime('%W'))
        currentYear = int(now.strftime('%Y'))
        ma = []
        re = []
        maTotal = 0
        reTotal = 0
        for i in range(currentWeek + 1):
            try:
                weekData = self.getWeekStats(i, currentYear, program, office)
                ma.append(weekData['MA'])
                maTotal += weekData['MA']
                re.append(weekData['RE'])
                reTotal += weekData['RE']
            except TypeError:
                break
        totals = {'MATOTAL':maTotal, 'RETOTAL':reTotal}
        weekly = {'MA': ma, 'RE': re}
        return {'totals': totals, 'weekly': weekly}

    def getProgramMonthlyPerformance(self, program, office=1395):
        """
        For a given AIESEC office and program, returns its monthly performance, plus its total one during the year.

        Returns: The following dictionary structure:
        {'totals': {
            'MATOTAL': *Total matches in the year*,
            'RETOTAL': *Total realizations in the year*
            },
        'monthly': {
            'MA':[*matches month 1*, *matches month 2*, ...],
            'RE':[*realizations month 0*, *realizations month 1*, ...],
        }
        """
        now = datetime.now()
        currentMonth = int(now.strftime('%m'))
        currentYear = int(now.strftime('%Y'))
        ma = []
        re = []
        maTotal = 0
        reTotal = 0
        for i in range(currentMonth):
            monthData = self.getMonthStats(i + 1, currentYear, program, office)
            ma.append(monthData['MA'])
            maTotal += monthData['MA']
            re.append(monthData['RE'])
            reTotal += monthData['RE']
        totals = {'MATOTAL': maTotal, 'RETOTAL': reTotal}
        monthly = {'MA': ma, 'RE': re}
        return {'totals': totals, 'monthly': monthly}

    def getLCYearlyPerformance(self, year, lc=1395):
        """
        Returna el desempeño en matches y realizaciones de un LC en un año dado, separado por mes, para los cuatro programas
        """
        answer = {}
        for io in ['i', 'o']:
            for program in ['gcdp', 'gip']:
                ma = []
                re = []
                for i in range(1, 13):
                    monthData = self.getMonthStats(i, year, io+program, lc)
                    ma.append(monthData['MA'])
                    re.append(monthData['RE'])
                answer[io+program] = {'MA': ma, 'RE': re}
        return answer

#Métodos relacionados con el año actual
    def getCurrentYearStats(self, program, officeID=1395):
        """
        Extrae el ma/re de el año actual, para una oficina y uno de los 4 programas
        """
        now = datetime.now()
        currentYear = int(now.strftime('%Y'))
        start_date = "%d-01-01" % currentYear
        end_date = now.strftime('%Y-%m-%d')
        return self.get_stats(officeID, program, start_date, end_date)

    def getCountryCurrentYearStats(self, program, lc):
        """
        Extrae el ma/re de el año actual, para un comité y uno de los 4 programas
        """
        now = datetime.now()
        current_year = int(now.strftime('%Y'))
        if int(now.strftime('%m')) < 2:
            current_year -= 1
        start_date = "%d-02-01" % current_year

        end_date = now.strftime('%Y-%m-%d')
        return self.getCountryStats(program, lc, start_date, end_date)

    def getCountryStats(self, program, officeID, start_date, end_date):
        """
        Extrae el ma/re entre dos fechas específicas, para un comité nacional y uno de los 4 programas
        start_date: Una fecha de inicio en formato "%Y-%m-%d"
        """

        queryArgs = {
            'basic[home_office_id]':officeID,
            'basic[type]':self.ioDict[program[0].lower()],
            'end_date':end_date,
            'programmes[]':self.programDict[program[1:].lower()],
            'start_date':start_date
        }
        mcData = self.make_query(['applications', 'analyze.json'], queryArgs)['analytics']
        lcData = mcData['children']['buckets']
        response = {
            officeID:{
                'approved': mcData['total_approvals']['doc_count'],
                'realized': mcData['total_realized']['doc_count'],
                'completed': mcData['total_completed']['doc_count'],
            }
        }
        for lc in lcData:
            #Guarda la respuesta en un diccionario cuya llave es el office_id del LC, y cuyo valor son los approved y las realizaciones
            response[lc['key']] = {
                'approved': lc['total_approvals']['doc_count'],
                'realized': lc['total_realized']['doc_count'],
                'completed': mcData['total_completed']['doc_count'],
            }
        return response

#Listas de MCs, LCs, regiones y similares

    def getRegions(self):
        """
            Gets the information of all AIESEC regions. 1626 is the EXPA id of AIESEC INTERNATIONAL; all regions appear as suboffices
        """
        query = self._buildQuery(['committees', '1626.json'])
        return json.loads(requests.get(query).text)['suboffices']

    def getMCs(self, region):
        """
        Gets the information of all countries inside a given AIESEC region, whose ID enters as a parameter
        """
        query = self._buildQuery(['committees', '%d.json' % region])
        return json.loads(requests.get(query).text)['suboffices']

    def getSuboffices(self, subofficeID):
        """
        Gets the information of all countries inside a given AIESEC region, whose ID enters as a parameter
        """
        query = self._buildQuery(['committees', '%d.json' % subofficeID])
        return json.loads(requests.get(query).text)['suboffices']

####################
############ Analytics sobre people, que permitan obtener personas que cumplen o no cumplen ciertos criterios
####################

    def getUncontactedEPs(self, officeID):
        """
        Returns all EPs belonging to the office given as parameter who have not been contacted yet, up to 150. It also returns the total number.
        """
        data = self.make_query(['people.json',], {
            'filters[contacted]': 'false',
            'filters[registered[from]]':'2016-01-01',
            'filters[home_committee]':officeID,
            'page':1,
            'per_page':150
        })
        totals = {}
        totals['total'] = data['paging']['total_items']
        totals['eps'] = data['data']
        return totals

    def get_matchable_EPs(self, officeID):
        """
        Returns all EPs belonging to the office given as parameter who are available for match with other entities, up to 300. It also returns their total number.
        """
        data = self.make_query(['people.json',], {
            'filters[interviewed]': 'true',
            'filters[home_committee]':officeID,
            'filters[statuses][]':['open', 'applied'],
            'page':1,
            'per_page':300
        })
        totals = {}
        totals['total'] = data['paging']['total_items']
        totals['eps'] = data['data']
        return totals

    def getWeekRegistered(self, officeID, week=None, year=None):
        """
        Extrae a las personas, y el número de personas, que se registraron en EXPA desde el lunes anterior. If no week or year arguments are given, uses the current week

        returns: A dictionary with the following structure:
            {'total': *number of people who registered that week*,
             'eps': *the eps who registered*}
        """
        if week == None or year == None:
            now = datetime.now()
            week = int(now.strftime('%W'))
            year = int(now.strftime('%Y'))

        if week == 0:
            weekStart = "%d-01-01" % year
        else:
            weekStart = datetime.strptime('%d %d 1' % (year, week), '%Y %W %w').strftime('%Y-%m-%d')

        weekEnd = datetime.strptime('%d %d 0' % (year, week), '%Y %W %w').strftime('%Y-%m-%d')

        data = self.make_query(['people.json',], {
            'filters[registered[from]]':weekStart,
            'filters[registered[to]]':weekEnd,
            'page':1,
            'per_page':150,
            'filters[home_committee]':officeID,
        })
        totals = {}
        totals['total'] = data['paging']['total_items']
        totals['eps'] = data['data']
        return totals

    def getWeekContacted(self, officeID, week=None, year=None):
        """
        Extrae a las personas, y el número de personas, que han sido contactadas en EXPA desde el lunes anterior. If no week or year arguments are given, uses the current week

        returns: A dictionary with the following structure:
            {'total': *number of people who registered that week*,
             'eps': *the eps who registered*}
        """
        if week == None or year == None:
            now = datetime.now()
            week = int(now.strftime('%W'))
            year = int(now.strftime('%Y'))

        if week == 0:
            weekStart = "%d-01-01" % year
        else:
            weekStart = datetime.strptime('%d %d 1' % (year, week), '%Y %W %w').strftime('%Y-%m-%d')

        weekEnd = datetime.strptime('%d %d 0' % (year, week), '%Y %W %w').strftime('%Y-%m-%d')

        data = self.make_query(['people.json',], {
            'filters[contacted_at[from]]':weekStart,
            'filters[contacted_at[to]]':weekEnd,
            'filters[home_committee]':officeID,
            'page':1,
            'per_page':150
        })
        totals = {}
        totals['total'] = data['paging']['total_items']
        totals['eps'] = data['data']
        return totals


#################
###Utils for getting events that have happened past a certain amount of time. Useful for cronjobs, or other actions that require periodic updates
##############
    def get_past_interactions(self, interaction, days, officeID, today=True, program='ogx', filters=None):
        if not filters:
            filters = {}
        now = datetime.now()
        start_date = (now - timedelta(days=days)).strftime('%Y-%m-%d')
        if not today:
            now = now - timedelta(days=1)
        end_date = now.strftime('%Y-%m-%d')
        return self.get_interactions(interaction, officeID, program, start_date, end_date, filters)

    def get_interactions(self, interaction, officeID, program, start_date, end_date=None, filters=None):
        if not filters:
            filters = {}
        inter_dict = {
            'registered': 'person',
            'contacted': 'person',
            'applied': 'application',
            'accepted': 'application',
            'an_signed': 'application',
            'approved': 'application',
            'realized': 'application',
            'finished': 'application',
            }

        interaction_type = inter_dict[interaction]
        if end_date is None:
            end_date = datetime.now().strftime('%Y-%m-%d')
            
        if interaction_type == 'person':
            return self.get_person_interactions(interaction, officeID, program, start_date, end_date, filters)
        elif interaction_type == 'application':
            return self.get_application_interactions(interaction, officeID, program, start_date, end_date, filters)

    def get_person_interactions(self, interaction, officeID, program, start_date, end_date, filters):
        """
        This method queries the API for the people who have interacted with EXPA and the OP in some way, such as signing in, being contacted or being interviewed.
        params:
            interaction: The kind of interaction you are polling for. If it is not in the interactions dict, this method will raise an error
            days: How many days further back you want to poll EXPA and get data from
            office: The AIESEC office you want to filter for
            today: Whether you want to include today's date or not
        """
        if not filters:
            filters = {}
        inter_dict = {
            'registered': 'registered',
            'contacted': 'contacted_at',
            }
        query_args = {
            'filters[%s[from]]' % inter_dict[interaction]:start_date,
            'filters[%s[to]]' % inter_dict[interaction]:end_date,
            'filters[home_committee]':officeID,
            'page':1,
            'per_page':500,
        }
        query_args.update(filters)
        data = self.make_query(['people.json',], query_args)
        totals = {}
        totals['total'] = data['paging']['total_items']
        totals['items'] = data['data']
        return totals


###########################
#Methods that deal with extracting information from the applications API
###########################
    def get_application_interactions(self, interaction, officeID, program, start_date, end_date, filters):
        """
        This method queries the API for the people who have interacted with EXPA and the OP in some way, such as signing in, being contacted or being interviewed.
        params:
            interaction: The kind of interaction you are polling for. If it is not in the interactions dict, this method will raise an error
            days: How many days further back you want to poll EXPA and get data from
            office: The AIESEC office you want to filter for
            today: Whether you want to include today's date or not
        """
        if not filters:
            filters = {}
        inter_dict = {
            'applied': 'created_at',
            'accepted': 'date_matched',
            'an_signed': 'date_an_signed',
            'approved': 'date_approved',
            'realized': 'date_realized',
            'finished': 'experience_end_date',
            }
        query_args = {
            'filters[%s[from]]' % inter_dict[interaction]: start_date,
            'filters[%s[to]]' % inter_dict[interaction]: end_date,
            'filters[programmes][]': self.programDict[program[1:]],
            'page': 1,
            'per_page': 500,
        }
        query_args.update(filters)
        if program[0] == 'o':
            query_args['filters[for]'] = 'people'
            query_args['filters[person_committee]'] = officeID
        elif program[0] == 'i':
            query_args['filters[opportunity_committee]'] = officeID
        data = self.make_query(['applications.json',], query_args)
        totals = {}
        totals['total'] = data['paging']['total_items']
        totals['items'] = data['data']
        return totals

### Utils para el MC. Mayor obtención de datos, y el año comienza desde julio
    def getCurrentMCYearStats(self, program, office_id):
        """
        Extrae el ma/re de el año MC actual (comenzando el anterior 1 de Julio, para un comité y uno de los 4 programas
        """
        now = datetime.now()
        currentYear = int(now.strftime('%Y'))
        if int(now.strftime('%m')) < 8:
            currentYear -= 1
        start_date = "%d-08-01" % currentYear
        end_date = now.strftime('%Y-%m-%d')

        return self.get_stats(office_id, program, start_date, end_date)

    def getCountryCurrentMCYearStats(self, program, mc=1551):
        """
        Extrae el ma/re de el año actual, para un comité y uno de los 4 programas
        """
        now = datetime.now()
        currentYear = int(now.strftime('%Y'))
        if int(now.strftime('%m')) < 6:
            currentYear -= 1
        startDate = "%d-07-01" % currentYear

        endDate = now.strftime('%Y-%m-%d')

        queryArgs = {
            'basic[home_office_id]':mc,
            'basic[type]':self.ioDict[program[0].lower()],
            'end_date':endDate,
            'programmes[]':self.programDict[program[1:].lower()],
            'start_date':startDate
        }
        query = self._buildQuery(['applications', 'analyze.json'], queryArgs)
        try:
            mcData = json.loads(requests.get(query).text)['analytics']
            lcData = mcData['children']['buckets']
            response = {}
            for lc in lcData:
                response[lc['key']] = {
                    'applications': lc['total_applications']['doc_count'],
                    'accepted': lc['total_matched']['doc_count'],
                    'approved': lc['total_approvals']['doc_count'],
                    'realized': lc['total_realized']['doc_count'],
                    'completed': lc['total_completed']['doc_count'],
		}
            response[mc] = {
                    'applications': mcData['total_applications']['doc_count'],
                    'accepted': mcData['total_matched']['doc_count'],
                    'approved': mcData['total_approvals']['doc_count'],
                    'realized': mcData['total_realized']['doc_count'],
                    'completed': mcData['total_completed']['doc_count'],
                }

        except KeyError as e:
            print("Error de llave:")
            print(e)
            print(json.loads(requests.get(query).text))
            raise e
        return response

    def get_companies(self, officeID, program, start_date, end_date):
        """
        This method is still on progress
        TODO: FInish it
        """
        query_args = {
            'filters[registered[from]]':start_date,
            'filters[registered[to]]':end_date,
            'page':1,
            'per_page':500,
        }
        if program is not None:
            query_args['filters[programmes][]']=self.programDict[program],
        data = self.make_query(['organisations.json'], query_args)
        totals = {}
        totals['total'] = data['paging']['total_items']
        totals['items'] = data['data']
        return totals

    def lda_report(self, id, id_type, *args, **kwargs):
        data = self.make_query(['ldm', 'report'], {id_type: id})
        return data
        
