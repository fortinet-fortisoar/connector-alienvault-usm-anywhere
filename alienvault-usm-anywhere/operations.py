""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import requests
import base64
from datetime import datetime
from urllib.parse import urlencode
from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('alienvault-usm-anywhere')

sort_type_dict = {
    "Priority": "priority",
    "Alarm Status": "status",
    "Intent": "rule_intent",
    "Strategy": "rule_strategy",
    "Method": "rule_method",
    "Time Created": "timestamp_occured",
    "Username": "username",
    "Event Name": "event_name"
}

order_dict = {
    "Ascending": "asc",
    "Descending": "desc"
}

status_dict = {
    "Open": "open",
    "Closed": "closed",
    "In Review": "in review"
}


class AlienvaultUSM(object):

    def __init__(self, config):
        self.username = config.get('username')
        self.hostname = config.get('host')
        self.password = config.get('password')
        if not self.hostname.startswith('https://') and not self.hostname.startswith('http://'):
            self.hostname = 'https://{0}'.format(self.hostname)
        self.url = "{0}/api/2.0/".format(self.hostname)
        self.sslVerify = config.get('verify_ssl')
        self.access_token = self.generate_token()

    def generate_token(self):
        url = "oauth/token?grant_type=client_credentials"
        usrPass = self.username + ":" + self.password
        usrPass = usrPass.encode()
        b64Val = base64.b64encode(usrPass)
        temp = 'Basic {0}'.format(b64Val.decode("utf-8"))
        headers = {
            'Authorization': temp,
            'Content-Type': 'application/json'
        }
        response = self.make_rest_call(url=url, method='POST', header=headers)
        access_token = response.get('access_token')
        return access_token

    def make_rest_call(self, url, method='GET', data=None, header=None):
        try:
            endpoint = self.url + url
            logger.debug("url: {0}".format(endpoint))
            if not header:
                header = {"Authorization": "Bearer {0}".format(self.access_token)}
            response = requests.request(method, endpoint, headers=header, verify=self.sslVerify, data=data)
            if response.ok:
                logger.info('Successfully got response for url {0}'.format(url))
                if 'json' in str(response.headers):
                    return response.json()
                else:
                    return response.content
            elif response.status_code == 401:
                if 'json' in str(response.headers):
                    if response.json()['error'] == 'invalid_token':
                        self.generate_token()
                        return self.make_rest_call(url, method, data)
                    else:
                        raise ConnectorError({'status_code': response.status_code, 'message': 'Unauthorized'})
                else:
                    raise ConnectorError({'status_code': response.status_code, 'message': response.content})
            else:
                logger.error(response.content)
                raise ConnectorError({'status_code': response.status_code, 'message': response.content})
        except requests.exceptions.SSLError:
            raise ConnectorError('SSL certificate validation failed')
        except requests.exceptions.ConnectTimeout:
            raise ConnectorError('The request timed out while trying to connect to the server')
        except requests.exceptions.ReadTimeout:
            raise ConnectorError(
                'The server did not send any data in the allotted amount of time')
        except requests.exceptions.ConnectionError:
            raise ConnectorError('Invalid endpoint or credentials')
        except Exception as err:
            raise ConnectorError(str(err))


def convert_time_to_timestamp(input_date):
    try:
        logger.info(input_date)
        i = datetime.strptime(str(input_date), '%Y-%m-%dT%H:%M:%S.%fZ')
        timestamp = str(int(i.timestamp() * 1000))
        return timestamp
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def get_alarms(config, params):
    usm_obj = AlienvaultUSM(config)
    sort = sort_type_dict.get(params.get('sort'), 'timestamp_occured')
    sort_by = order_dict.get(params.pop('sort_order', ''), 'asc')
    params['sort'] = '{},{}'.format(sort, sort_by)
    params['status'] = status_dict.get(params.get('status'))

    if params.get("timestamp_occured_gte"):
        params['timestamp_occured_gte'] = convert_time_to_timestamp(params.get("timestamp_occured_gte"))
    if params.get("timestamp_occured_lte"):
        params['timestamp_occured_lte '] = convert_time_to_timestamp(params.get("timestamp_occured_lte"))
        params['timestamp_occured_lte'] = ''

    params_dict = {k: v for k, v in params.items() if v is not None and v != ''}
    logger.info('final param dict {0}'.format(params_dict))
    endpoint = 'alarms?{0}'.format(urlencode(params_dict))
    return usm_obj.make_rest_call(endpoint)


def str_to_list(input_str):
    if isinstance(input_str, str) and len(input_str) > 0:
        return [x.strip() for x in input_str.split(',')]
    elif isinstance(input_str, list):
        return input_str
    else:
        return []


def get_alarm_details(config, params):
    usm_obj = AlienvaultUSM(config)
    alarm_ids = params.get('alarmId')
    alarms_ids_list = str_to_list(alarm_ids)
    final_result = []
    for id in alarms_ids_list:
        endpoint = 'alarms/{0}'.format(id)
        res = usm_obj.make_rest_call(endpoint)
        final_result.append(res)
    return final_result


def get_alarm_labels(config, params):
    usm_obj = AlienvaultUSM(config)
    endpoint = 'alarms/{0}/labels'.format(params.get('alarmId'))
    return usm_obj.make_rest_call(endpoint)


def get_events(config, params):
    usm_obj = AlienvaultUSM(config)
    sort = sort_type_dict.get(params.get('sort'), 'timestamp_occured')
    sort_by = order_dict.get(params.pop('sort_order', ''), 'asc')
    params['sort'] = '{0},{1}'.format(sort, sort_by)
    params['account_name'] = params.get('accountName', '')
    params['event_name'] = params.get('eventName', '')
    params['source_name'] = params.get('sourceName', '')
    params['sensor_uuid'] = params.get('sensorUUID', '')
    params['source_username'] = params.get('sourceUsername', '')
    if params.get("timestamp_occured_gte"):
        params['timestamp_occured_gte'] = convert_time_to_timestamp(params.get("timestamp_occured_gte"))
    if params.get("timestamp_occured_lte"):
        params['timestamp_occured_lte'] = convert_time_to_timestamp(params.get("timestamp_occured_lte"))

    params_dict = {k: v for k, v in params.items() if v is not None and v != ''}
    logger.info('final param dict {0}'.format(params_dict))

    endpoint = 'events?{0}'.format(urlencode(params_dict))
    return usm_obj.make_rest_call(endpoint)


def get_event_details(config, params):
    usm_obj = AlienvaultUSM(config)
    endpoint = 'events/{eventId}'.format(eventId=params.get('eventId'))
    return usm_obj.make_rest_call(endpoint)


def add_alarm_label(config, params):
    usm_obj = AlienvaultUSM(config)
    endpoint = 'alarms/{alarmId}/labels/{labelId}'.format(alarmId=params.get('alarmId'),
                                                          labelId=params.get('labelId'))
    usm_obj.make_rest_call(endpoint, "PUT")
    return {'status': 'success', 'message': 'Label added successfully'}


def delete_alarm_label(config, params):
    usm_obj = AlienvaultUSM(config)
    endpoint = 'alarms/{alarmId}/labels/{labelId}'.format(alarmId=params.get('alarmId'),
                                                          labelId=params.get('labelId'))
    usm_obj.make_rest_call(endpoint, "DELETE")
    return {'status': 'success', 'message': 'Label deleted successfully'}


def _check_health(config):
    try:
        usm_obj = AlienvaultUSM(config)
        token = usm_obj.generate_token()
        if token:
            return True
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


operations = {
    'get_alarms': get_alarms,
    'get_alarm_details': get_alarm_details,
    'get_alarm_labels': get_alarm_labels,
    'add_alarm_label': add_alarm_label,
    'delete_alarm_label': delete_alarm_label,
    'get_events': get_events,
    'get_event_details': get_event_details
}
