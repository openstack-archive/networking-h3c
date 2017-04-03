# Copyright 2016 Hangzhou H3C Technologies Co. Ltd. All rights reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

import json
import logging as syslog
import requests
import traceback

from oslo_config import cfg
from oslo_log import log as logging
from oslo_serialization import jsonutils
from oslo_utils import excutils

from neutron_lib import exceptions as q_exc

from networking_h3c._i18n import _LE
from networking_h3c.common import exceptions

LOG = logging.getLogger(__name__)


class RestClient(object):
    def __init__(self):
        self.base_url = cfg.CONF.VCFCONTROLLER.url
        self.output_json_log = cfg.CONF.VCFCONTROLLER.output_json_log
        self.white_list = cfg.CONF.VCFCONTROLLER.white_list
        if self.white_list is True:
            self.client = RestClientNoAuth()
        else:
            self.client = RestClientTokenAuth()
        if self.output_json_log is True:
            try:
                self.json_logger = self.set_json_logger()
            except Exception as e:
                LOG.error(_LE("Failed to open json logger, error is %s"), e)

    @staticmethod
    def set_json_logger():
        json_logger = syslog.getLogger(__name__ + '_json_log')
        json_logger.setLevel(syslog.DEBUG)
        if not json_logger.handlers:
            log_dir = cfg.CONF.log_dir if cfg.CONF.log_dir \
                else '/var/log/neutron'
            log_file = log_dir + '/json.output'
            fh = syslog.handlers.WatchedFileHandler(log_file)
            formatter = syslog.Formatter(
                '%(asctime)s.%(msecs)d %(process)d %(message)s',
                '%Y-%m-%d %H:%M:%S')
            fh.setFormatter(formatter)
            json_logger.addHandler(fh)
        return json_logger

    @staticmethod
    def urljoin(base, path):
        if not base:
            return path
        if not path:
            return base
        if base.endswith('/'):
            base = base[:-1]
        if path.startswith('/'):
            path = path[1:]
        return "%s/%s" % (base, path)

    def rest_call(self, path, method, body=None, params=None):
        url = self.urljoin(self.base_url, path)
        data = jsonutils.dumps(body) if body is not None else None
        if hasattr(self, 'json_logger'):
            try:
                msg = "%s : %s\n\n%s\n\n\n\n\n\n" % (method, url, json.dumps(
                    body, indent=4))
                self.json_logger.debug(msg)
            except Exception as e:
                LOG.error(_LE("Failed to write json log, error is %s"), e)
        return self.client.rest_call(url, method, data, params)


class RestClientTokenAuth(object):
    def __init__(self):
        self.base_url = cfg.CONF.VCFCONTROLLER.url
        self.auth_payload = {
            "login":
                {'user': cfg.CONF.VCFCONTROLLER.username,
                 'password': cfg.CONF.VCFCONTROLLER.password,
                 'domain': cfg.CONF.VCFCONTROLLER.domain
                 }
        }
        self.timeout = cfg.CONF.VCFCONTROLLER.timeout
        self.retry = cfg.CONF.VCFCONTROLLER.retry
        self.token = None
        try:
            self.renew_token(0)
        except Exception as e:
            LOG.error(_LE("initialize token error: %s"), e)

    def renew_token(self, timeout=None):
        if self.token:
            self._delete_token()
        url = self.urljoin(self.base_url, "/sdn/v2.0/auth")
        data = json.dumps(self.auth_payload)
        code, result = self.rest_call_no_refresh(url, "POST", data,
                                                 timeout=timeout)
        self.token = result['record']['token']

    def _delete_token(self):
        url = self.urljoin(self.base_url, "/sdn/v2.0/auth")
        try:
            self.rest_call_no_refresh(url, "DELETE")
        except requests.exceptions.HTTPError as e:
            LOG.debug("Ignore HTTPError: %s", e)
        finally:
            self.token = None

    @staticmethod
    def urljoin(base, path):
        if not base:
            return path
        if not path:
            return base
        if base.endswith('/'):
            base = base[:-1]
        if path.startswith('/'):
            path = path[1:]
        return "%s/%s" % (base, path)

    def rest_call(self, url, method, data=None, params=None):
        code, result = self._rest_request(method, url, data, params)
        if code == requests.codes.unauthorized:
            self.renew_token()
            code, result = self._rest_request(method, url, data, params)
            if code == requests.codes.unauthorized:
                raise exceptions.HttpNotAuthError()
        # Because data can be deleted on VCFC ui.
        # We return 204 for such situation.
        if code == requests.codes.not_found:
            if method == "DELETE":
                code = requests.codes.no_content
            elif method != 'GET':
                code = requests.codes.all_good
        if method != 'GET' and not (requests.codes.ok <=
                                    code < requests.codes.multiple_choices):
            msg = (_LE("Failed %(method)s operation on %(url)s "
                   "status code: %(code)s") %
                   {"method": method,
                    "url": url,
                    "code": code})
            LOG.exception(msg)
            raise q_exc.BadRequest(resource=method,
                                   msg="invalid response status code!!")
        return code, result

    def rest_call_no_refresh(self, url, method, data=None, params=None,
                             timeout=None):
        return self._rest_request(method, url, data, params, timeout=timeout)

    def _rest_request(self, method, url, data, params, timeout=None):
        if timeout is None:
            timeout = float(self.timeout)
        retry = self.retry
        resp = None
        result = None
        headers = {'Content-Type': 'application/json',
                   'Accept': 'application/json',
                   'Cache-Control': 'no-cache',
                   'X-Auth-Token': self.token}
        while True:
            try:
                resp = requests.request(method,
                                        url,
                                        headers=headers,
                                        data=data,
                                        params=params,
                                        timeout=timeout,
                                        verify=False)
                break
            except Exception as e:
                with excutils.save_and_reraise_exception(
                        reraise=False) as ctxt:
                    LOG.error(_LE("Exception %(exc)s: VCFC exception, "
                                  "traceback: %(tb)s"),
                              {'exc': e, 'tb': traceback.format_exc()})
                    retry -= 1
                    if retry < 0:
                        ctxt.reraise = True
        code = resp.status_code
        if method != "DELETE" and code != requests.codes.not_found:
            try:
                result = resp.json()
            except Exception:
                raise exceptions.JsonDecodingError(
                    resource="%s %s" % (method, url))
        return code, result


class RestClientNoAuth(object):
    def __init__(self):
        self.timeout = cfg.CONF.VCFCONTROLLER.timeout
        self.retry = cfg.CONF.VCFCONTROLLER.retry

    def rest_call(self, url, method, data=None, params=None):
        code, result = self._rest_request(method, url, data, params)
        if code == requests.codes.unauthorized:
            raise exceptions.HttpNotAuthError()
        # Because data can be deleted on VCFC ui.
        # We return 204 for such situation.
        if code == requests.codes.not_found:
            if method == "DELETE":
                code = requests.codes.no_content
            elif method != 'GET':
                code = requests.codes.all_good
        if method != 'GET' and not (requests.codes.ok <=
                                    code < requests.codes.multiple_choices):
            msg = (_LE("Failed %(method)s operation on %(url)s "
                   "status code: %(code)s") %
                   {"method": method,
                    "url": url,
                    "code": code})
            LOG.exception(msg)
            raise q_exc.BadRequest(resource=method,
                                   msg="invalid response status code!!")
        return code, result

    def _rest_request(self, method, url, data, params):
        retry = self.retry
        resp = None
        result = None
        headers = {'Content-Type': 'application/json',
                   'Accept': 'application/json',
                   'Cache-Control': 'no-cache'}
        while True:
            try:
                resp = requests.request(method,
                                        url,
                                        headers=headers,
                                        data=data,
                                        params=params,
                                        timeout=float(self.timeout),
                                        verify=False)
                break
            except Exception as e:
                with excutils.save_and_reraise_exception(
                        reraise=False) as ctxt:
                    LOG.error(_LE("Exception %(exc)s: VCFC exception, "
                                  "traceback: %(tb)s"),
                              {'exc': e, 'tb': traceback.format_exc()})
                    retry -= 1
                    if retry < 0:
                        ctxt.reraise = True
        code = resp.status_code
        if method != "DELETE" and code != requests.codes.not_found:
            try:
                result = resp.json()
            except Exception:
                raise exceptions.JsonDecodingError(
                    resource="%s %s" % (method, url))
        return code, result
