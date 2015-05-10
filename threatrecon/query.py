"""
Copyright (C) 2014 by Wapack Labs Corporation
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.
You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
"""

import json
import requests
import requests_cache
import logging
logger = logging.getLogger(__name__)
from datetime import datetime
from dateutil import parser
from api import API_FIELDS, APIError

###########RAW QUERY############################################
################################################################

def raw_query_threat_recon_json(indicator, api_key,
        enable_cache=False, cache_expire_after=604800, tr_cache_file='/tmp/threat_recon.cache'):
    """
    Uses an indicator and the api key to query the threat recon
    database. Returns Raw json.
    """
    # NOTE: results will have mixed-case keys. In general, these
    # should not be used directly - the TRIndicator objects use
    # lower-case attributes (and generate dicts with lower-case keys).

    try:
        params = {'api_key': api_key, 'indicator': indicator}
        if enable_cache is True:
    	    requests_cache.install_cache()
            requests_cache.install_cache(tr_cache_file, backend='sqlite', expire_after=cache_expire_after, allowable_methods=('GET', 'POST'))
	logger.debug('params = ' + str(params))
        f = requests.post("https://api.threatrecon.co/api/v1/search", data=params)
	logger.debug('f = ' + str(f))
	logger.debug(f.headers)
	## FIXME! need to delete from cache when responseCode is invalid
        if enable_cache is True and f.from_cache is True:
            logger.info("from cache indicator=[%s]", indicator)
	if f.status_code == 200:
            return f.content
        else:
            logger.error("Invalid status code for " + indicator + ": " + f.status_code)
    except:
        logger.error("Error for " + indicator + ": " + str(f))
        raise APIError(f)

def raw_query_threat_recon(indicator, api_key,
        enable_cache=False, cache_expire_after=604800, tr_cache_file='/tmp/threat_recon.cache'):
    """
    Uses an indicator and the api key to query the threat recon
    database. Returns a list of python dicts corresponding to
    the JSON output from the server (results only). If no results,
    returns an empty list.

    Will throw APIError exception if the ResponseCode < 0.

    """
    # NOTE: results will have mixed-case keys. In general, these
    # should not be used directly - the TRIndicator objects use
    # lower-case attributes (and generate dicts with lower-case keys).

    f = raw_query_threat_recon_json(indicator, api_key,
        enable_cache=False, cache_expire_after=604800, tr_cache_file='/tmp/threat_recon.cache')
    data = json.load(f)
    response = data.get("ResponseCode", -99)
    if response < 0:
        raise APIError(response)

    results = data.get("Results", [])
    lowerresults = []
    if results:         # can be None, so make sure to check
        for r in results:
            lowerresults.append({k.lower(): v for k, v in r.items()})

    return lowerresults


def query_threat_recon(indicator, api_key):
    """
    Calls _raw_query_threat_recon and returns a list of TRIndicator
    objects with appropriate attributes set.
    """
    results = []
    for r in raw_query_threat_recon(indicator, api_key):
        i = TRIndicator(**r)
        i._query_root = (
            i.rootnode == '' and
            i.indicator == indicator
        )

        results.append(i)
    return results


###########ATTRIBUTION QUERY####################################
################################################################

def raw_query_threat_recon_attribution(indicator, api_key,
        enable_cache=False, cache_expire_after=604800, tr_cache_file='/tmp/threat_recon.cache'):
    """
    Uses an indicator and the api key to query the threat recon
    database. Returns a list of python dicts corresponding to
    the JSON output from the server (results only). If no results,
    returns an empty list.

    Will throw APIError exception if the ResponseCode < 0.

    """
    # NOTE: results will have mixed-case keys. In general, these
    # should not be used directly - the TRIndicator objects use
    # lower-case attributes (and generate dicts with lower-case keys).

    params = {'api_key': api_key, 'attribution': indicator}
    f = requests.get("https://api.threatrecon.co/api/v1/search/attribution", params=params)
    if enable_cache is True:
    	requests_cache.install_cache()
        requests_cache.install_cache(tr_cache_file, backend='sqlite', expire_after=cache_expire_after)
    data = json.load(f)
    response = data.get("ResponseCode", -99)
    if response < 0:
        raise APIError(response)

    results = data.get("Results", [])
    lowerresults = []
    if results:         # can be None, so make sure to check
        for r in results:
            lowerresults.append({k.lower(): v for k, v in r.items()})

    return lowerresults


def query_threat_recon_attribution(indicator, api_key):
    """
    Calls _raw_query_threat_recon and returns a list of TRIndicator
    objects with appropriate attributes set.
    """
    results = []
    for r in raw_query_threat_recon_attribution(indicator, api_key):
        i = TRIndicator(**r)
        i._query_root = (
            i.rootnode == '' and
            i.indicator == indicator
        )

        results.append(i)
    return results


###########REFERENCE QUERY####################################
################################################################

def raw_query_threat_recon_reference(indicator, api_key,
        enable_cache=False, cache_expire_after=604800, tr_cache_file='/tmp/threat_recon.cache'):
    """
    Uses an indicator and the api key to query the threat recon
    database. Returns a list of python dicts corresponding to
    the JSON output from the server (results only). If no results,
    returns an empty list.

    Will throw APIError exception if the ResponseCode < 0.

    """
    # NOTE: results will have mixed-case keys. In general, these
    # should not be used directly - the TRIndicator objects use
    # lower-case attributes (and generate dicts with lower-case keys).

    params = {'api_key': api_key, 'reference': indicator}
    f = requests.get("https://api.threatrecon.co/api/v1/search/reference", params=params)
    if enable_cache is True:
    	requests_cache.install_cache()
        requests_cache.install_cache(tr_cache_file, backend='sqlite', expire_after=cache_expire_after)
    data = json.load(f)
    response = data.get("ResponseCode", -99)
    if response < 0:
        raise APIError(response)

    results = data.get("Results", [])
    lowerresults = []
    if results:         # can be None, so make sure to check
        for r in results:
            lowerresults.append({k.lower(): v for k, v in r.items()})

    return lowerresults


def query_threat_recon_reference(indicator, api_key):
    """
    Calls _raw_query_threat_recon and returns a list of TRIndicator
    objects with appropriate attributes set.
    """
    results = []
    for r in raw_query_threat_recon_reference(indicator, api_key):
        i = TRIndicator(**r)
        i._query_root = (
            i.rootnode == '' and
            i.indicator == indicator
        )

        results.append(i)
    return results


###########COMMENT QUERY########################################
################################################################

def raw_query_threat_recon_comment(indicator, api_key,
        enable_cache=False, cache_expire_after=604800, tr_cache_file='/tmp/threat_recon.cache'):
    """
    Uses an indicator and the api key to query the threat recon
    database. Returns a list of python dicts corresponding to
    the JSON output from the server (results only). If no results,
    returns an empty list.

    Will throw APIError exception if the ResponseCode < 0.

    """
    # NOTE: results will have mixed-case keys. In general, these
    # should not be used directly - the TRIndicator objects use
    # lower-case attributes (and generate dicts with lower-case keys).

    params = {'api_key': api_key, 'comment': indicator}
    f = requests.get("https://api.threatrecon.co/api/v1/search/comment", params=params)
    if enable_cache is True:
    	requests_cache.install_cache()
        requests_cache.install_cache(tr_cache_file, backend='sqlite', expire_after=cache_expire_after)
    data = json.load(f)
    response = data.get("ResponseCode", -99)
    if response < 0:
        raise APIError(response)

    results = data.get("Results", [])
    lowerresults = []
    if results:         # can be None, so make sure to check
        for r in results:
            lowerresults.append({k.lower(): v for k, v in r.items()})

    return lowerresults


def query_threat_recon_comment(indicator, api_key):
    """
    Calls _raw_query_threat_recon and returns a list of TRIndicator
    objects with appropriate attributes set.
    """
    results = []
    for r in raw_query_threat_recon_comment(indicator, api_key):
        i = TRIndicator(**r)
        i._query_root = (
            i.rootnode == '' and
            i.indicator == indicator
        )

        results.append(i)
    return results


################################################################


class TRIndicator(object):
    """
    Default class for Threat Recon Indicator objects.
    """
    # replaces Result object

    def __repr__(self):
        return "TRIndicator %s [id %d type %s confidence %d%s]" % (
            self.indicator,
            self.id,
            self.type,
            self.confidence,
            " ***QUERY ROOT***" if self._query_root else ""
        )

    @property
    def verbose(self):
        r = "\n"
        for i in API_FIELDS:
            r += "%s: %s\n" % (i, getattr(self, i, None))
        if self._query_root:
            r += "***This is the query root record***\n"

        return r

    @property
    def as_dict(self):
        return {name: getattr(self, name, None) for name in API_FIELDS}

    def __init__(self, *args, **kwargs):
        kwargsl = {k.lower(): v for k, v in kwargs.items()}
        for i in API_FIELDS:
            if i in kwargsl:
                v = kwargsl[i]
                if (i == 'firstseen') or (i == 'lastseen'):
                    try:
                        v = parser.parse(v)
                    except TypeError:
                        v = datetime.min
            else:
                v = None
            setattr(self, i, v)
