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

import logging
from mock import Mock
from mock import patch
from networking_h3c.common import config  # noqa
from networking_h3c.common.rest_client import RestClient
from neutron.tests import base
from oslo_config import cfg  # noqa


class RestClientTestCase(base.BaseTestCase):

    def setUp(self):
        super(RestClientTestCase, self).setUp()

    @patch('logging.Formatter')
    @patch('logging.handlers.WatchedFileHandler')
    @patch('logging.getLogger')
    def test_set_json_logger(self, getLogger, WatchedFileHandler, Formatter):
        logger = getLogger.return_value = Mock()
        logger.handlers = []
        handler = WatchedFileHandler.return_value = Mock()
        formatter = Formatter.return_value = Mock()
        RestClient.set_json_logger()
        logger.setLevel.assert_called_once_with(logging.DEBUG)
        handler.setFormatter.assert_called_once_with(formatter)
        logger.addHandler.assert_called_once_with(handler)

    @patch('logging.handlers.WatchedFileHandler')
    @patch('logging.getLogger')
    def test_set_json_logger_already_set(self, getLogger, WatchedFileHandler):
        logger = getLogger.return_value = Mock()
        logger.handlers = [Mock()]
        RestClient.set_json_logger()
        WatchedFileHandler.assert_not_called()


class RestClientTokenAuthTestCase(base.BaseTestCase):

    def setUp(self):
        super(RestClientTokenAuthTestCase, self).setUp()


class RestClientNoAuthTestCase(base.BaseTestCase):
    def setUp(self):
        super(RestClientNoAuthTestCase, self).setUp()
