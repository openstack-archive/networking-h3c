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

import mock

from networking_h3c.extensions import portextensions as pext
from networking_h3c.ml2.extensions import extension_driver_h3c
from neutron.tests.unit.plugins.ml2 import test_plugin

fake_libvirt_spawn_update_port = {
    'name': 'tapb26ecaf3-88',
    'port_extensions': {'virt_type': 'kvm',
                        'domain': '86c306ef-7526-47a5-8706-731a99da0bac'}}


class TestML2ExtensionDriverH3C(test_plugin.Ml2PluginV2TestCase):
    def test_process_update_port(self):
        for db_data in (fake_libvirt_spawn_update_port, {}):
            response_data = {}
            session = mock.Mock()
            driver = extension_driver_h3c.ExtensionDriverH3C()
            driver.process_update_port(session, db_data, response_data)
            if pext.PORTEXTENSIONS in db_data:
                self.assertEqual(response_data[pext.PORTEXTENSIONS],
                                 db_data[pext.PORTEXTENSIONS])
            else:
                self.assertEqual(response_data, {})
