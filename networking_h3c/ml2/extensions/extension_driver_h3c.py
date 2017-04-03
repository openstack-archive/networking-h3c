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

from oslo_log import log as logging
from neutron.plugins.ml2 import driver_api as api
from networking_h3c._i18n import _

LOG = logging.getLogger(__name__)


class ExtensionDriverH3C(api.ExtensionDriver):
    _supported_extension_alias = 'port-extensions'

    def initialize(self):
        LOG.info(_("H3CML2ExtensionDriver initialization complete"))

    @property
    def extension_alias(self):
        return self._supported_extension_alias

    def process_update_port(self, plugin_context, data, result):
        if 'port_extensions' in data:
            result['port_extensions'] = data['port_extensions']
