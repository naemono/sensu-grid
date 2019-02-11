import logging
import requests
import six

from datetime import datetime, timedelta
from functools import partial
from multiprocessing.dummy import Pool as ThreadPool

from gridcheck import check_stash
from jwt import JWT


LOGGER = logging.getLogger(__name__)


def get_namespaces(timeout, dc, jwt=None):
    namespaces = list()
    r = None
    data = None
    LOGGER.debug("Retrieving namespaces for datacenter: {0}".format(dc['name']))
    url = '{0}://{1}:{2}/api/core/v2/namespaces'.format(
        dc.get('scheme', 'http'), dc['url'], dc['port'])
    jwt = ensure_jwt(timeout, dc, jwt=jwt)
    if not jwt:
        return namespaces
    try:
        headers = {'Authorization': jwt.access_token}
        r = requests.get(url, timeout=timeout, headers=headers)
        r.raise_for_status()
    except Exception as ex:
        LOGGER.error(
            "Got exception while filtering on clients: {0}".format(str(ex)))
        pass
    finally:
        if r:
            data = r.json()
            r.close()
        else:
            LOGGER.error("no reponse")

    if data:
        for namespace in data:
            if namespace['name'] not in namespaces:
                namespaces.append(namespace['name'])
    else:
        LOGGER.error("No response data")
    LOGGER.debug(
        "Namespace retrieval for datacenter {0} complete".format(dc['name']))
    return namespaces


def ensure_jwt(timeout, dc, jwt=None):
    r = None
    now = datetime.utcnow()
    now_int = int(now.strftime("%s"))
    now_plus_5_min = now + timedelta(seconds=60*5)

    if jwt and jwt.expires_at is not None and (int(jwt.expires_at) > int(now_plus_5_min.strftime("%s"))):
        return jwt

    auth_url = '{0}://{1}:{2}/auth'.format(
        dc.get('scheme', 'http'), dc['url'], dc['port'])
    if not jwt:
        try:
            r = requests.get(auth_url, auth=(
                dc['user'], dc['password']), timeout=timeout)
            r.raise_for_status()
        except Exception as ex:
            LOGGER.error(
                "Got exception while retrieving jwt for dc: {0} ex: {1}".format(dc, str(ex)))
            pass
        finally:
            if r:
                data = r.json()
                jwt = JWT(data['access_token'], data['expires_at'], data['refresh_token'])
                r.close()
                return jwt
            else:
                LOGGER.error("no reponse")
        return None
    # if jwt expires in 5 mins...
    if jwt and jwt.expires_at is not None and (int(jwt.expires_at) < int(now_plus_5_min.strftime("%s"))):
        try:
            r = requests.get(auth_url, auth=(
                dc['user'], dc['password']), timeout=timeout)
            r.raise_for_status()
        except Exception as ex:
            LOGGER.error(
                "Got exception while retrieving jwt for dc: {0} ex: {1}".format(dc, str(ex)))
            pass
        finally:
            if r:
                data = r.json()
                jwt = JWT(data['access_token'],
                          data['expires_at'], data['refresh_token'])
                r.close()
                return jwt
            else:
                LOGGER.error("no reponse")
        return None
    return None


def filter_data(timeout, dc, jwt=None):
    filter_data = list()
    all_data = list()
    for namespace in get_namespaces(timeout, dc, jwt=jwt):
        r = None
        LOGGER.debug("Retrieving filters namespace {0} for datacenter: {1}".format(namespace, dc['name']))
        url='{0}://{1}:{2}/api/core/v2/namespaces/{3}/entities'.format(
            dc.get('scheme', 'http'), dc['url'], dc['port'], namespace)
        jwt = ensure_jwt(timeout, dc, jwt=jwt)
        if not jwt:
            return filter_data
        try:
            headers = {'Authorization': jwt.access_token}
            r = requests.get(url, timeout=timeout, headers=headers)
            r.raise_for_status()
        except Exception as ex:
            LOGGER.error("Got exception while filtering on clients: {0}".format(str(ex)))
            pass
        finally:
            if r:
                all_data.extend(r.json())
                r.close()
            else:
                LOGGER.error("no reponse")

    if all_data:
        for i in all_data:
            for s in i['subscriptions']:
                if s not in filter_data:
                    # Strip off the 'entity:' piece.
                    if s.startswith('entity:'):
                        s = s[7:]
                    filter_data.append(s)
    else:
        LOGGER.error("No response data")
    LOGGER.debug("Filter Retrieval for datacenter {0} complete".format(dc['name']))
    return filter_data


def get_filter_data(dcs, timeout):
    aggregated = list()
    final_aggregated_filter_data = []
    pool = ThreadPool(len(dcs))
    func = partial(filter_data, timeout)
    try:
        aggregated = pool.map(func, dcs)
        assert type(aggregated) == list
        for filterdata in aggregated:
            if filterdata not in final_aggregated_filter_data:
                final_aggregated_filter_data.append(filterdata)

    except Exception as e:
        LOGGER.error("unable to get filter data, ex: {0}".format(e))
    finally:
        pool.close()

    return final_aggregated_filter_data[0]


def get_data(dc, timeout, jwt=None):
    data = list()
    for namespace in get_namespaces(timeout, dc, jwt=jwt):
        r = None
        LOGGER.debug("Retrieving data for namespace {0} in datacenter: {1}".format(namespace, dc['name']))
        url = '{0}://{1}:{2}/api/core/v2/namespaces/{3}/events'.format(
            dc.get('scheme', 'http'), dc['url'], dc['port'], namespace)
        
        
        jwt = ensure_jwt(timeout, dc, jwt=jwt)
        if not jwt:
            return data 
        try:
            headers = {'Authorization': jwt.access_token}
            r = requests.get(url, timeout=timeout, headers=headers)
            r.raise_for_status()
        except Exception as ex:
            LOGGER.error("Got exception while retrieving data for dc: {0} ex: {1}".format(dc, str(ex)))
            pass
        finally:
            if r:
                data.extend(r.json())
                r.close()
            else:
                LOGGER.error("no reponse")

    LOGGER.debug("Data Retrieval for datacenter {0} complete".format(dc['name']))
    return data


def get_clients(dc, timeout):
    LOGGER.debug("Retrieving clients for datacenter: {0}".format(dc['name']))
    url = '{0}://{1}:{2}/clients'.format(
        dc.get('scheme', 'http'), dc['url'], dc['port'])
    data = None
    r = None

    try:
        if 'user' and 'password' in dc:
            r = requests.get(url, auth=(dc['user'], dc['password']), timeout=timeout)
            r.raise_for_status()
            data = r.json()
        else:
            r = requests.get(url, timeout=timeout)
            data = r.json()
    except Exception as ex:
        LOGGER.error(
            "Got exception while retrieving clients for dc: {0} ex: {1}".format(dc, str(ex)))
        pass
    finally:
        if r:
            r.close()
        else:
            LOGGER.error("no reponse")

    LOGGER.debug("Client Retrieval for datacenter {0} complete".format(dc['name']))
    return data


def get_stashes(dc, timeout, jwt=None):
    data = list()
    for namespace in get_namespaces(timeout, dc, jwt=jwt):
        LOGGER.debug("Retrieving stashes in namespace {0} for datacenter: {1}".format(namespace, dc['name']))
        url = '{0}://{1}:{2}/api/core/v2/namespaces/{3}/silenced'.format(
            dc.get('scheme', 'http'), dc['url'], dc['port'], namespace)
        r = None
        jwt = ensure_jwt(timeout, dc, jwt=jwt)
        if not jwt:
            return data
        try:
            headers = {'Authorization': jwt.access_token}
            r = requests.get(url, timeout=timeout, headers=headers)
            data.extend(r.json())
        except Exception as ex:
            LOGGER.error(
                "Got exception while retrieving stashes for dc: {0} ex: {1}".format(dc, str(ex)))
            pass
        finally:
            if r:
                r.close()
            else:
                LOGGER.error("no reponse")

        LOGGER.debug("Stash Retrieval for datacenter {0} complete".format(dc['name']))
    return data


def filter_object(obj, search):
    if type(obj) == dict:
        for k, value in obj.iteritems():
            if filter_object(value, search):
                return True
    elif type(obj) == list:
        for value in obj:
            if filter_object(value, search):
                return True
    else:
        LOGGER.debug("search type {0} // obj type {1}".format(type(search), type(obj)))
        try:
            return six.u(search) in six.b(obj)
        except TypeError as e:
            LOGGER.warn("filter_object exception (PY2 vs PY3 unicode/str): {0}".format(e))
            try:
                return unicode(search) in unicode(obj)
            except Exception as e:
                LOGGER.error("filter_object exception: {0}".format(e))

    return False


def filter_events(filters):
    def filter_event(event):
        for f in filters:
            if filter_object(event, f):
                return True
        return False

    return filter_event


def get_events(dc, timeout, filters=[]):
    LOGGER.debug("Retrieving events for datacenter: {0}".format(dc['name']))
    url = '{0}://{1}:{2}/events'.format(dc.get('scheme', 'http'), dc['url'], dc['port'])

    data = []
    r = None

    try:
        if 'user' and 'password' in dc:
            r = requests.get(url, auth=(dc['user'], dc['password']), timeout=timeout)
            r.raise_for_status()
            data = r.json()
        else:
            r = requests.get(url, timeout=timeout)
            data = r.json()
    except Exception as ex:
        LOGGER.error(
            "Got exception while retrieving events for dc: {0} ex: {1}".format(dc, str(ex)))
        pass
    finally:
        if r:
            r.close()

    LOGGER.debug("Events Retrieval for datacenter {0} complete".format(dc['name']))
    if len(filters) > 0:
        return filter(filter_events(filters), data)
    else:
        return data


def agg_data(dc, data, stashes, client_data=None, filters=None):
    """
    Aggregates json data and returns count of ok, warn, crit
    :param data: raw json data
    :return: dc_name, l_ok, l_warn, l_crit
    """
    ok = 0
    warn = 0
    crit = 0
    down = 0
    ack = 0
    _filtered = []

    if filters and len(filters) > 0:
        filters = filters.split(',')

    if filters is not None and client_data is not None:
        for c in client_data:
            for sub in c['subscriptions']:
                if sub in filters:
                    _filtered.append(c['name'])

    if data:
        for i in data:

            entity_name = i['entity']['metadata']['name']
            check_name = i['check']['metadata']['name']
            if len(_filtered) > 0:

                if entity_name in _filtered:

                    if i['check']['status'] == 0 and not check_name == "keepalive":
                        ok += 1
                    if i['check']['status'] == 1 and not check_name == "keepalive":
                        if not check_stash(stashes, entity_name, check_name):
                            warn += 1
                        else:
                            ack += 1
                    if i['check']['status'] == 2 and not check_name == "keepalive":
                        if not check_stash(stashes, entity_name, check_name):
                            crit += 1
                        else:
                            ack += 1

                    if check_name == "keepalive" and i['check']['status'] == 2:
                        if not check_stash(stashes, entity_name, check_name):
                            # we cannot currently apply filters as keepalive checks do
                            # not have subscribers/subscriptions
                            down += 1
                        else:
                            ack += 1

            elif filters is None:
                if i['check']['status'] == 0 and not check_name == "keepalive":
                    ok += 1

                if i['check']['status'] == 1 and not check_name == "keepalive":
                    if not check_stash(stashes, entity_name, check_name):
                        warn += 1
                    else:
                        ack += 1

                if i['check']['status'] == 2 and not check_name == "keepalive":
                    if not check_stash(stashes, entity_name, check_name):
                        crit += 1
                    else:
                        ack += 1

                if check_name == "keepalive" and i['check']['status'] == 2:
                    if not check_stash(stashes, entity_name, check_name):
                        # we cannot currently apply filters as keepalive checks do not have subscribers/subscriptions
                        down += 1
                    else:
                        ack += 1

    return {"name": dc['name'], "ok": ok, "warning": warn, "critical": crit, "down": down, "ack": ack}


def agg_host_data(data, stashes, client_data=None, filters=None):
    """
    returns: a dict of {"hostname": [list,of,alert,statuses], "hostname2": [list,of,alert,statuses]}
    """

    _data = data
    _stashes = stashes
    _clients = client_data
    retdata = {}

    if filters and len(filters) > 0:
        filters = filters.split(',')

    if _clients is not None:
        for c in _clients:
            if filters and len(filters) > 0:
                for f in filters:
                    if f in c['subscriptions']:
                        _host = c['name']
                        retdata[_host] = []
                        break
            else:
                _host = c['name']
                retdata[_host] = []
    else:
        for check in _data:
            _host = check['client']
            retdata[_host] = []

    for check in _data:
        _host = check['client']
        if check['check']['status'] and check['check']['name'] != 'keepalive':
            if _host in retdata:
                if not check_stash(_stashes, _host, check['check']['name']):
                    retdata[_host].append(check['check']['status'])

        if check['check']['status'] and check['check']['name'] == 'keepalive':
            if _host in retdata:
                retdata[_host].append(-1)

    assert type(retdata) == dict

    return retdata
