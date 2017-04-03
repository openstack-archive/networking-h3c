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

import copy
import uuid

from mock import call
from mock import Mock
from mock import patch

import requests
from oslo_config import cfg
from oslo_db import exception as db_exc

from neutron.common import exceptions as q_exc
from neutron.db.common_db_mixin import CommonDbMixin
from neutron.db.l3_db import L3_NAT_db_mixin
from neutron.db.l3_db import L3_NAT_dbonly_mixin
from neutron.db.l3_db import L3RpcNotifierMixin
from neutron.db.l3_dvr_db import L3_NAT_with_dvr_db_mixin
from neutron.db.l3_hamode_db import L3_HA_NAT_db_mixin
from neutron.tests import base

from networking_h3c.common import constants as h_const
from networking_h3c.common import exceptions as h_exc
from networking_h3c.common import rest_client
from networking_h3c.db.h3c_l3_vxlan_db import H3CL3VxlanDriver
from networking_h3c.l3_router.h3c_l3_router_plugin import \
    H3CL3RouterPlugin

fake_vds_id = '0b580f78-4125-4938-88db-578d43fa9317'
fake_vds_name = 'VDS2'
fake_vds_resp = {'vds': [{'uuid': fake_vds_id, 'name': fake_vds_name}]}

fake_tenant_id = '7cfa58406d9945a9a1ca2c3bc8e03eb2'
fake_router_uuid = '3595d437-81a9-4655-b478-ed1161a6d176'
fake_router_name = 'test_router'
fake_router_object = {'router': {'name': fake_router_name,
                                 'external_gateway_info': None,
                                 'admin_state_up': True,
                                 'tenant_id': fake_tenant_id}}

fake_network_id = 'eedba9f3-54dd-4aab-9163-b2f92be0ec41'
fake_router_external_info = {'external_gateway_info':
                             {'network_id': fake_network_id,
                              'enable_snat': False}}
fake_router_external_fixed_ip_address = '17.0.0.3'
fake_router_external_fixed_ips = {
    'external_fixed_ips': [{
        'subnet_id': 'b6c7f66e-1e19-4d93-967a-3953272e9a5a',
        'ip_address': fake_router_external_fixed_ip_address}]}
fake_same_route_dict = {'nexthop': '40.0.1.1', 'destination': '168.1.1.0/24'}
fake_current_route_dict = {'nexthop': '41.0.1.1',
                           'destination': '172.2.0.0/16'}
fake_different_route_dict = {'nexthop': '50.0.1.1',
                             'destination': '172.2.0.0/16'}
fake_router_routes_info = {'routes': [fake_same_route_dict,
                                      fake_different_route_dict]}
fake_same_route_entry_dict = {"id": '49d46fd5-ce8d-49d7-b8f3-6ff1f1662f48',
                              'routetable_id': fake_router_uuid,
                              "cidr": "168.1.1.0/24",
                              'next_hop_type': 'IPv4',
                              "next_hop": "40.0.1.1"}
fake_current_route_entry_dict = {"id": '2c619fa3-4dcb-4415-9582-d1037e85f975',
                                 'routetable_id': fake_router_uuid,
                                 "cidr": "172.2.0.0/16",
                                 'next_hop_type': 'IPv4',
                                 "next_hop": "41.0.1.1"}
fake_different_route_entry_dict = {
    "id": 'e8f792e2-a020-4542-99af-99c9b0f7202a',
    'routetable_id': fake_router_uuid,
    "cidr": "172.2.0.0/16",
    'next_hop_type': 'IPv4',
    "next_hop": "50.0.1.1"}
fake_route_entries = {"route_entries": [fake_same_route_entry_dict,
                                        fake_current_route_entry_dict]}

fake_port_id = 'a491f67d-9981-466a-bc8c-f96e90f5dafc'
fake_subnet_id = 'b6c7f66e-1e19-4d93-967a-3953272e9a5a'
fake_port = {'id': fake_port_id,
             'network_id': fake_network_id,
             'fixed_ips': [{'ip_address': '17.0.0.4',
                            'prefixlen': 24,
                            'subnet_id': fake_subnet_id}],
             'subnets': [{'id': fake_subnet_id,
                          'cidr': '17.0.0.0/24',
                          'gateway_ip': '17.0.0.1'}]}

fake_floatingip_id = '2f5ecaae-166b-439b-a9f5-e2a82b23f283'
fake_internal_port_id = '15d18a9c-4e12-4278-a7e5-aeb755514aa7'
fake_floatingip_info = {'floatingip': {'subnet_id': None,
                                       'tenant_id': fake_tenant_id,
                                       'floating_network_id': fake_network_id,
                                       'fixed_ip_address': None,
                                       'floating_ip_address': '17.0.0.10',
                                       'port_id': fake_internal_port_id}}
fake_floatingip_db = {'floating_network_id': fake_network_id,
                      'router_id': fake_router_uuid,
                      'fixed_ip_address': '171.1.1.10',
                      'floating_ip_address': '17.0.0.10',
                      'tenant_id': fake_tenant_id,
                      'status': 'ACTIVE',
                      'port_id': fake_internal_port_id,
                      'id': fake_floatingip_id}

fake_interface_add = {'subnet_id': fake_subnet_id}
fake_interface_port_id = '824acfac-318d-4c8b-8cf4-3cc4a4c14322'
fake_interface_remove = {'subnet_id': fake_subnet_id,
                         'port_id': fake_interface_port_id}
fake_add_interface_resp = {'port_id': fake_interface_port_id,
                           'subnet_id': fake_subnet_id}
fake_interface_port_resp_body = {
    'port': {
        'id': fake_interface_port_id,
        'network_id': fake_network_id,
        'status': 'UP',
        'tenant_id': str(uuid.UUID(fake_tenant_id)),
        'fixed_ips': [
            {
                'subnet_id': fake_subnet_id,
                'ip_address': '17.0.0.1'
            }]}}
fake_interface_port_mac = 'fa:16:3e:e3:27:e9'
fake_interface_port_info = {
    'port': {
        'id': fake_interface_port_id,
        'name': '',
        'mac_address': fake_interface_port_mac,
        'device_owner': 'network:router_interface',
        'device_id': fake_router_uuid,
        'admin_state_up': True,
        'network_id': fake_network_id,
        'status': 'ACTIVE',
        'tenant_id': fake_tenant_id,
        'fixed_ips': [
            {
                'subnet_id': fake_subnet_id,
                'ip_address': '17.0.0.1'
            }]
    }
}

fake_router_db = {'id': fake_router_uuid,
                  'name': fake_router_name,
                  'admin_state_up': True,
                  'tenant_id': fake_tenant_id,
                  'external_gateway_info': None,
                  'distributed': 'distributed',
                  'ha': True,
                  'routes': [fake_same_route_dict, fake_current_route_dict]}

fake_segmentation_id = 10068

fake_routetables_object = {'routetables': [{'id': fake_router_uuid,
                                            'name': fake_router_name,
                                            'router_id': fake_router_uuid}]}


class TestH3CL3RouterPlugin(base.BaseTestCase):
    """Test cases to test H3C Driver and VCFC.

    Tests all methods.
    """

    def setUp(self):
        super(TestH3CL3RouterPlugin, self).setUp()
        cfg.CONF.set_override('vds_name', fake_vds_name, 'VCFCONTROLLER')
        cfg.CONF.set_override('enable_l3_vxlan', True, 'VCFCONTROLLER')
        cfg.CONF.set_override('enable_l3_router_rpc_notify', True,
                              'VCFCONTROLLER')
        cfg.CONF.set_override('vendor_rpc_topic', 'H3C_PLUGIN',
                              'VCFCONTROLLER')
        cfg.CONF.set_override('service_plugins',
                              'h3c_l3_router,firewall,lbaas,vpnaas')
        cfg.CONF.set_override('enable_metadata', True, 'VCFCONTROLLER')
        self.vxlan_init_patcher = patch.object(H3CL3VxlanDriver, 'initialize')
        self.vxlan_init_patcher.start()

    def tearDown(self):
        super(TestH3CL3RouterPlugin, self).tearDown()
        self.vxlan_init_patcher.stop()

    @patch.object(rest_client.RestClient, 'rest_call')
    def test_get_vds_id_from_vcfc(self, mock_rest_call):
        path = "%s?name=%s" % (h_const.VDS_RESOURCE, fake_vds_name)
        mock_rest_call.return_value = (requests.codes.all_good, fake_vds_resp)
        l3_router = H3CL3RouterPlugin()
        vds_id = l3_router.get_vds_id_from_vcfc(fake_vds_name)
        mock_rest_call.assert_called_once_with(path, 'GET')
        self.assertEqual(fake_vds_id, vds_id)

    @patch.object(rest_client.RestClient, 'rest_call')
    def test_process_create_router(self, mock_rest_call):
        router_db = copy.deepcopy(fake_router_db)
        router_db['provider:segmentation_id'] = fake_segmentation_id
        body = {'routers': [{
            'id': fake_router_db['id'],
            'name': fake_router_db['name'],
            'tenant_id': fake_router_db['tenant_id'],
            'provider:domain': fake_vds_id,
            'provider:segmentation_id': router_db['provider:segmentation_id'],
            'disable_internal_l3flow_offload': True
        }]}
        get_path = "%s?name=%s" % (h_const.VDS_RESOURCE, fake_vds_name)
        path = h_const.ROUTERS_RESOURCE
        mock_rest_call.side_effect = [(requests.codes.all_good, fake_vds_resp),
                                      (requests.codes.all_good, body)]
        l3_router = H3CL3RouterPlugin()
        l3_router.process_create_router(router_db)
        mock_rest_call.assert_has_calls([call(get_path, "GET"),
                                         call(path, "POST", body)])

    @patch.object(rest_client.RestClient, 'rest_call')
    def test_process_update_router(self, mock_rest_call):
        router_db = copy.deepcopy(fake_router_db)
        router_db.update(fake_router_external_info)
        router_db['external_gateway_info'].update(
            fake_router_external_fixed_ips)
        body = {
            'name': fake_router_db['name'],
            'external_gateway_info': [{
                'network_id': fake_network_id,
                'enable_snat': fake_router_external_info[
                    'external_gateway_info']['enable_snat'],
                'external_fixed_ips': [{
                    'subnet_id': fake_subnet_id,
                    'ip': fake_router_external_fixed_ip_address
                }]}]
        }
        l3_router = H3CL3RouterPlugin()
        l3_router.process_update_router(router_db)
        path = h_const.ROUTER_RESOURCE % router_db['id']
        mock_rest_call.assert_called_once_with(path, "PUT", body)

    @patch.object(rest_client.RestClient, 'rest_call')
    def test_process_delete_router(self, mock_rest_call):
        router_db = copy.deepcopy(fake_router_db)
        l3_router = H3CL3RouterPlugin()
        l3_router.process_delete_router(router_db)
        path = h_const.ROUTER_RESOURCE % router_db['id']
        mock_rest_call.assert_called_once_with(path, "DELETE")

    @patch.object(rest_client.RestClient, 'rest_call')
    @patch.object(H3CL3RouterPlugin, 'process_create_router')
    @patch.object(H3CL3VxlanDriver, 'create_l3_segments')
    @patch.object(L3_NAT_db_mixin, 'create_router')
    def test_create_router_success(self,
                                   mock_create_router_db,
                                   mock_create_l3_segments,
                                   mock_process_create_router,
                                   mock_rest_call):
        router_info = copy.deepcopy(fake_router_object)
        context = Mock()
        router_for_creation = copy.deepcopy(fake_router_db)
        router_for_creation['provider:segmentation_id'] = fake_segmentation_id
        routers_body = {'routers': [{
            'id': fake_router_db['id'],
            'name': fake_router_db['name'],
            'tenant_id': fake_router_db['tenant_id'],
            'provider:domain': fake_vds_id,
            'provider:segmentation_id': fake_segmentation_id,
            'disable_internal_l3flow_offload': True
        }]}
        routers_body_with_routetable = copy.deepcopy(routers_body)
        routers_body_with_routetable['route_table_id'] = fake_router_uuid
        mock_create_router_db.return_value = fake_router_db
        mock_create_l3_segments.return_value = fake_segmentation_id
        mock_process_create_router.return_value = (requests.codes.all_good,
                                                   routers_body)
        mock_rest_call.side_effect = [(requests.codes.all_good,
                                       fake_routetables_object),
                                      (requests.codes.all_good,
                                       routers_body_with_routetable)]
        l3_router = H3CL3RouterPlugin()
        l3_router.create_router(context, router_info)
        mock_create_router_db.assert_called_once_with(context, router_info)
        mock_create_l3_segments.assert_called_once_with(context,
                                                        fake_router_uuid)
        mock_process_create_router.assert_called_once_with(router_for_creation)
        path = h_const.ROUTER_RESOURCE % fake_router_uuid

        mock_rest_call.assert_has_calls([call(h_const.ROUTETABLES_RESOURCE,
                                              'POST', fake_routetables_object),
                                         call(path, 'PUT', {
                                             'route_table_id': fake_router_uuid
                                         })])

    @patch.object(rest_client.RestClient, 'rest_call')
    @patch.object(H3CL3RouterPlugin, 'process_update_router')
    @patch.object(H3CL3RouterPlugin, 'process_create_router')
    @patch.object(H3CL3VxlanDriver, 'create_l3_segments')
    @patch.object(L3_NAT_db_mixin, 'create_router')
    def test_create_router_gw_success(self,
                                      mock_create_router_db,
                                      mock_create_l3_segments,
                                      mock_process_create_router,
                                      mock_process_update_router,
                                      mock_rest_call):
        router_info = copy.deepcopy(fake_router_object)
        router_external_info = copy.deepcopy(fake_router_external_info)
        router_info['router'].update(router_external_info)
        context = Mock()
        router_db = copy.deepcopy(fake_router_db)
        router_db_external_info = copy.deepcopy(fake_router_external_info)
        router_db_external_info['external_gateway_info'].update(
            fake_router_external_fixed_ips)
        router_db.update(router_db_external_info)
        router_for_creation = copy.deepcopy(router_db)
        router_for_creation['provider:segmentation_id'] = fake_segmentation_id
        create_body = {'routers': [{
            'id': router_db['id'],
            'name': router_db['name'],
            'tenant_id': router_db['tenant_id'],
            'provider:domain': fake_vds_id,
            'provider:segmentation_id': fake_segmentation_id,
            'disable_internal_l3flow_offload': True
        }]}
        update_body = {
            'name': router_db['name'],
            'external_gateway_info': [{
                'network_id': fake_network_id,
                'enable_snat': fake_router_external_info[
                    'external_gateway_info']['enable_snat'],
                'external_fixed_ips': [{
                    'subnet_id': fake_subnet_id,
                    'ip': fake_router_external_fixed_ip_address
                }]}]
        }
        routers_body_with_routetable = copy.deepcopy(create_body)
        routers_body_with_routetable['route_table_id'] = fake_router_uuid
        mock_create_router_db.return_value = router_db
        mock_create_l3_segments.return_value = fake_segmentation_id
        mock_process_create_router.return_value = (requests.codes.all_good,
                                                   create_body)
        mock_process_update_router.return_value = (requests.codes.all_good,
                                                   update_body)
        mock_rest_call.side_effect = [(requests.codes.all_good,
                                       fake_routetables_object),
                                      (requests.codes.all_good,
                                       routers_body_with_routetable)]
        l3_router = H3CL3RouterPlugin()
        l3_router.create_router(context, router_info)
        mock_create_router_db.assert_called_once_with(context, router_info)
        mock_create_l3_segments.assert_called_once_with(context,
                                                        fake_router_uuid)
        mock_process_create_router.assert_called_once_with(router_for_creation)
        mock_process_update_router.assert_called_once_with(router_db)
        path = h_const.ROUTER_RESOURCE % fake_router_uuid
        mock_rest_call.assert_has_calls([call(h_const.ROUTETABLES_RESOURCE,
                                              'POST', fake_routetables_object),
                                         call(path, 'PUT', {
                                             'route_table_id': fake_router_uuid
                                         })])

    @patch.object(L3_HA_NAT_db_mixin, 'delete_router')
    @patch.object(H3CL3VxlanDriver, 'create_l3_segments')
    @patch.object(L3_NAT_db_mixin, 'create_router')
    def test_create_router_seg_failure(self,
                                       mock_create_router_db,
                                       mock_create_l3_segments,
                                       mock_delete_router_db):
        router_info = copy.deepcopy(fake_router_object)
        context = Mock()
        mock_create_router_db.return_value = fake_router_db
        mock_create_l3_segments.side_effect = db_exc.ColumnError()
        l3_router = H3CL3RouterPlugin()
        self.assertRaises(db_exc.ColumnError, l3_router.create_router,
                          context, router_info)
        mock_create_router_db.assert_called_once_with(context, router_info)
        mock_create_l3_segments.assert_called_once_with(context,
                                                        fake_router_uuid)
        mock_delete_router_db.assert_called_once_with(context,
                                                      fake_router_db['id'])

    @patch.object(L3_HA_NAT_db_mixin, 'delete_router')
    @patch.object(H3CL3VxlanDriver, 'release_segment')
    @patch.object(H3CL3RouterPlugin, 'process_create_router')
    @patch.object(H3CL3VxlanDriver, 'create_l3_segments')
    @patch.object(L3_NAT_db_mixin, 'create_router')
    def test_create_router_failure(self,
                                   mock_create_router_db,
                                   mock_create_l3_segments,
                                   mock_process_create_router,
                                   mock_release_segment,
                                   mock_delete_router_db):
        router_info = copy.deepcopy(fake_router_object)
        context = Mock()
        router_for_creation = copy.deepcopy(fake_router_db)
        router_for_creation['provider:segmentation_id'] = fake_segmentation_id
        mock_create_router_db.return_value = fake_router_db
        mock_create_l3_segments.return_value = fake_segmentation_id
        mock_process_create_router.side_effect = q_exc.BadRequest(
            resource="POST", msg="invalid response status code!!")
        l3_router = H3CL3RouterPlugin()
        self.assertRaises(q_exc.BadRequest, l3_router.create_router,
                          context, router_info)
        mock_create_router_db.assert_called_once_with(context, router_info)
        mock_create_l3_segments.assert_called_once_with(context,
                                                        fake_router_uuid)
        mock_process_create_router.assert_called_once_with(router_for_creation)
        mock_release_segment.assert_called_once_with(context.session,
                                                     fake_router_db['id'])
        mock_delete_router_db.assert_called_once_with(context,
                                                      fake_router_db['id'])

    @patch.object(L3_HA_NAT_db_mixin, 'delete_router')
    @patch.object(H3CL3VxlanDriver, 'release_segment')
    @patch.object(H3CL3RouterPlugin, 'process_delete_router')
    @patch.object(H3CL3RouterPlugin, 'process_update_router')
    @patch.object(H3CL3RouterPlugin, 'process_create_router')
    @patch.object(H3CL3VxlanDriver, 'create_l3_segments')
    @patch.object(L3_NAT_db_mixin, 'create_router')
    def test_create_router_gw_failure(self,
                                      mock_create_router_db,
                                      mock_create_l3_segments,
                                      mock_process_create_router,
                                      mock_process_update_router,
                                      mock_process_delete_router,
                                      mock_release_segment,
                                      mock_delete_router_db):
        router_info = copy.deepcopy(fake_router_object)
        router_external_info = copy.deepcopy(fake_router_external_info)
        router_info['router'].update(router_external_info)
        context = Mock()
        router_db = copy.deepcopy(fake_router_db)
        router_db_external_info = copy.deepcopy(fake_router_external_info)
        router_db_external_info['external_gateway_info'].update(
            fake_router_external_fixed_ips)
        router_db.update(router_db_external_info)
        router_for_creation = copy.deepcopy(router_db)
        router_for_creation['provider:segmentation_id'] = fake_segmentation_id
        create_body = {'routers': [{
            'id': router_db['id'],
            'name': router_db['name'],
            'tenant_id': router_db['tenant_id'],
            'provider:domain': fake_vds_id,
            'provider:segmentation_id': fake_segmentation_id,
            'disable_internal_l3flow_offload': True
        }]}
        mock_create_router_db.return_value = router_db
        mock_create_l3_segments.return_value = fake_segmentation_id
        mock_process_create_router.return_value = (requests.codes.all_good,
                                                   create_body)
        mock_process_update_router.side_effect = q_exc.BadRequest(
            resource="PUT", msg="invalid response status code!!")
        l3_router = H3CL3RouterPlugin()
        self.assertRaises(q_exc.BadRequest, l3_router.create_router,
                          context, router_info)
        mock_create_router_db.assert_called_once_with(context, router_info)
        mock_create_l3_segments.assert_called_once_with(context,
                                                        fake_router_uuid)
        mock_process_create_router.assert_called_once_with(router_for_creation)
        mock_process_update_router.assert_called_once_with(router_db)
        mock_process_delete_router.assert_called_once_with(router_db)
        mock_release_segment.assert_called_once_with(context.session,
                                                     router_db['id'])
        mock_delete_router_db.assert_called_once_with(context, router_db['id'])

    def test_get_create_route_entries_list(self):
        routes_info = copy.deepcopy(fake_router_routes_info)
        route_entries = copy.deepcopy(fake_route_entries)
        create_route_list = [fake_different_route_dict]
        l3_router = H3CL3RouterPlugin()
        route_list = l3_router.get_create_route_entries_list(
            routes_info['routes'], route_entries['route_entries'])
        self.assertEqual(create_route_list, route_list)

    def test_get_delete_route_entries_list(self):
        routes_info = copy.deepcopy(fake_router_routes_info)
        route_entries = copy.deepcopy(fake_route_entries)
        delete_route_list = [fake_current_route_entry_dict['id']]
        l3_router = H3CL3RouterPlugin()
        route_list = l3_router.get_delete_route_entries_list(
            routes_info['routes'], route_entries['route_entries'])
        self.assertEqual(delete_route_list, route_list)

    @patch.object(H3CL3RouterPlugin, 'get_create_route_entries_list')
    @patch.object(H3CL3RouterPlugin, 'get_delete_route_entries_list')
    @patch.object(rest_client.RestClient, 'rest_call')
    def test_sync_vcfc_route_entries(self,
                                     mock_rest_call,
                                     mock_get_delete_route_entries_list,
                                     mock_get_create_route_entries_list):
        context = Mock()
        router_info = {'router': fake_router_routes_info}
        routetables = copy.deepcopy(fake_routetables_object)
        route_entries = copy.deepcopy(fake_route_entries)
        create_route_list = [fake_different_route_dict]
        delete_route_list = [fake_current_route_entry_dict['id']]
        get_routetable_path = h_const.ROUTETABLE_RESOURCE % fake_router_uuid
        get_route_entries_path = (h_const.ROUTE_ENTRIES_IN_ROUTETABLE_RESOURCE
                                  % fake_router_uuid)
        create_body = {
            'route_entries': [
                {'routetable_id': fake_router_uuid,
                 'cidr': fake_different_route_dict['destination'],
                 'next_hop_type': 'IPv4',
                 'next_hop': fake_different_route_dict['nexthop']
                 }]}
        delete_path = (h_const.ROUTE_ENTRY_RESOURCE %
                       fake_current_route_entry_dict['id'])
        mock_rest_call.side_effect = [(requests.codes.all_good, routetables),
                                      (requests.codes.all_good, route_entries),
                                      (requests.codes.all_good, create_body),
                                      requests.codes.all_good]
        mock_get_delete_route_entries_list.return_value = delete_route_list
        mock_get_create_route_entries_list.return_value = create_route_list
        l3_router = H3CL3RouterPlugin()
        l3_router.sync_vcfc_route_entries(context, fake_router_uuid,
                                          router_info)
        mock_rest_call.assert_has_calls(
            [call(get_routetable_path, 'GET'),
             call(get_route_entries_path, 'GET'),
             call(h_const.ROUTE_ENTRIES_RESOURCE, 'POST', create_body),
             call(delete_path, 'DELETE')])
        mock_get_delete_route_entries_list.assert_called_once_with(
            router_info['router']['routes'], route_entries['route_entries'])
        mock_get_create_route_entries_list.assert_called_once_with(
            router_info['router']['routes'], route_entries['route_entries'])

    @patch.object(H3CL3RouterPlugin, 'get_create_route_entries_list')
    @patch.object(H3CL3RouterPlugin, 'get_delete_route_entries_list')
    @patch.object(L3_NAT_db_mixin, 'get_router')
    @patch.object(rest_client.RestClient, 'rest_call')
    def test_sync_vcfc_route_entries_no_routetable(
            self,
            mock_rest_call,
            mock_get_router_db,
            mock_get_delete_route_entries_list,
            mock_get_create_route_entries_list):
        context = Mock()
        router_info = {'router': fake_router_routes_info}
        router_db = copy.deepcopy(fake_router_db)
        routetables = copy.deepcopy(fake_routetables_object)
        route_entries = copy.deepcopy(fake_route_entries)
        create_route_list = [fake_different_route_dict]
        delete_route_list = [fake_current_route_entry_dict['id']]
        get_routetable_path = h_const.ROUTETABLE_RESOURCE % fake_router_uuid
        get_route_entries_path = (h_const.ROUTE_ENTRIES_IN_ROUTETABLE_RESOURCE
                                  % fake_router_uuid)
        create_routetables_body = {
            'routetables': [{'id': fake_router_uuid,
                             'name': router_db['name'],
                             'router_id': router_db['id']}]}
        update_router_path = h_const.ROUTER_RESOURCE % fake_router_uuid
        update_router_body = {'route_table_id': fake_router_uuid}
        create_body = {
            'route_entries': [
                {'routetable_id': fake_router_uuid,
                 'cidr': fake_different_route_dict['destination'],
                 'next_hop_type': 'IPv4',
                 'next_hop': fake_different_route_dict['nexthop']
                 }]}
        delete_path = (h_const.ROUTE_ENTRY_RESOURCE %
                       fake_current_route_entry_dict['id'])
        mock_rest_call.side_effect = [(requests.codes.not_found, None),
                                      (requests.codes.all_good, routetables),
                                      (requests.codes.all_good,
                                       update_router_body),
                                      (requests.codes.all_good, route_entries),
                                      (requests.codes.all_good, create_body),
                                      requests.codes.all_good]
        mock_get_router_db.return_value = router_db
        mock_get_delete_route_entries_list.return_value = delete_route_list
        mock_get_create_route_entries_list.return_value = create_route_list
        l3_router = H3CL3RouterPlugin()
        l3_router.sync_vcfc_route_entries(context, fake_router_uuid,
                                          router_info)
        mock_rest_call.assert_has_calls(
            [call(get_routetable_path, 'GET'),
             call(h_const.ROUTETABLES_RESOURCE, 'POST',
                  create_routetables_body),
             call(update_router_path, 'PUT', update_router_body),
             call(get_route_entries_path, 'GET'),
             call(h_const.ROUTE_ENTRIES_RESOURCE, 'POST', create_body),
             call(delete_path, 'DELETE')])
        mock_get_delete_route_entries_list.assert_called_once_with(
            router_info['router']['routes'], route_entries['route_entries'])
        mock_get_create_route_entries_list.assert_called_once_with(
            router_info['router']['routes'], route_entries['route_entries'])

    @patch.object(L3RpcNotifierMixin, 'notify_router_updated')
    @patch.object(H3CL3RouterPlugin,
                  '_update_router_without_check_rescheduling')
    @patch.object(L3_NAT_db_mixin, 'get_router')
    def test_update_router_success(self,
                                   mock_get_router_db,
                                   mock_update_router_db,
                                   mock_notify_router_updated):
        router_info = {'router': fake_router_external_info}
        context = Mock()
        router_current = copy.deepcopy(fake_router_db)
        router_db = copy.deepcopy(fake_router_db)
        router_db.update(fake_router_external_info)
        router_db['external_gateway_info'].update(
            fake_router_external_fixed_ips)
        update_body = {
            'name': router_db['name'],
            'external_gateway_info': [{
                'network_id': fake_network_id,
                'enable_snat': fake_router_external_info[
                    'external_gateway_info']['enable_snat'],
                'external_fixed_ips': [{
                    'subnet_id': fake_subnet_id,
                    'ip': fake_router_external_fixed_ip_address
                }]}]
        }
        payload = {'gw_exists': True}
        mock_get_router_db.return_value = router_current
        mock_update_router_db.return_value = router_db
        with patch.object(H3CL3RouterPlugin, 'process_update_router',
                          return_value=(requests.codes.all_good,
                                        update_body)) \
                as mock_process_update_router:
            l3_router = H3CL3RouterPlugin()
            l3_router.update_router(context, fake_router_uuid, router_info)
        mock_process_update_router.assert_called_once_with(router_db)
        mock_notify_router_updated.assert_called_once_with(context,
                                                           fake_router_uuid,
                                                           payload)

    @patch.object(H3CL3RouterPlugin,
                  '_update_router_without_check_rescheduling')
    @patch.object(L3_NAT_db_mixin, 'get_router')
    def test_update_router_failure(self,
                                   mock_get_router_db,
                                   mock_update_router_db):
        router_info = {'router': fake_router_external_info}
        context = Mock()
        router_current = copy.deepcopy(fake_router_db)
        router_db = copy.deepcopy(fake_router_db)
        router_db.update(fake_router_external_info)
        router_db['external_gateway_info'].update(
            fake_router_external_fixed_ips)
        router_rollback_info = {'router': {'external_gateway_info': None}}
        mock_get_router_db.return_value = router_current
        mock_update_router_db.side_effect = [router_db, router_current]
        with patch.object(H3CL3RouterPlugin, 'process_update_router',
                          side_effect=q_exc.BadRequest(
                              resource="PUT",
                              msg="invalid response status code!!")) \
                as mock_process_update_router:
            l3_router = H3CL3RouterPlugin()
            self.assertRaises(q_exc.BadRequest, l3_router.update_router,
                              context, fake_router_uuid, router_info)
        mock_process_update_router.assert_called_once_with(router_db)
        mock_update_router_db.assert_called_with(context,
                                                 fake_router_uuid,
                                                 router_rollback_info)

    @patch.object(L3_HA_NAT_db_mixin, 'delete_router')
    @patch.object(H3CL3VxlanDriver, 'release_segment')
    @patch.object(H3CL3RouterPlugin, 'process_delete_router')
    @patch.object(rest_client.RestClient, 'rest_call')
    @patch.object(CommonDbMixin, '_get_tenant_id_for_create')
    @patch.object(H3CL3RouterPlugin,
                  '_ensure_router_not_attached_to_firewall')
    @patch.object(L3_NAT_db_mixin, 'get_router')
    @patch.object(L3_NAT_dbonly_mixin, '_ensure_router_not_in_use')
    def test_delete_router_success(self,
                                   mock_ensure_router_not_in_use,
                                   mock_get_router_db,
                                   mock_ensure_router_not_attached_to_fw,
                                   mock_get_tenant_id_for_create,
                                   mock_rest_call,
                                   mock_process_delete_router,
                                   mock_release_segment,
                                   mock_delete_router_db):
        router_id = fake_router_uuid
        context = Mock()
        router_current = copy.deepcopy(fake_router_db)
        update_path = h_const.ROUTER_RESOURCE % fake_router_uuid
        update_body = {"route_table_id": None}
        delete_path = h_const.ROUTETABLE_RESOURCE % fake_router_uuid
        mock_get_router_db.return_value = router_current
        mock_get_tenant_id_for_create.return_value = fake_tenant_id
        mock_rest_call.side_effect = [(requests.codes.all_good, update_body),
                                      requests.codes.all_good]
        l3_router = H3CL3RouterPlugin()
        l3_router.delete_router(context, router_id)
        mock_ensure_router_not_in_use.assert_called_once_with(context,
                                                              router_id)
        mock_ensure_router_not_attached_to_fw.assert_called_once_with(
            context, router_current)
        mock_rest_call.assert_has_calls(
            [call(update_path, 'PUT', update_body),
             call(delete_path, 'DELETE')])
        mock_process_delete_router.assert_called_once_with(router_current)
        mock_release_segment.assert_called_once_with(context.session,
                                                     router_id)
        mock_delete_router_db.assert_called_once_with(context, router_id)

    @patch.object(L3_HA_NAT_db_mixin, 'delete_router')
    @patch.object(H3CL3VxlanDriver, 'release_segment')
    @patch.object(H3CL3RouterPlugin, 'process_delete_router')
    @patch.object(rest_client.RestClient, 'rest_call')
    @patch.object(H3CL3RouterPlugin, 'update_router')
    @patch.object(CommonDbMixin, '_get_tenant_id_for_create')
    @patch.object(H3CL3RouterPlugin,
                  '_ensure_router_not_attached_to_firewall')
    @patch.object(L3_NAT_db_mixin, 'get_router')
    @patch.object(L3_NAT_dbonly_mixin, '_ensure_router_not_in_use')
    def test_delete_router_gw_success(self,
                                      mock_ensure_router_not_in_use,
                                      mock_get_router_db,
                                      mock_ensure_router_not_attached_to_fw,
                                      mock_get_tenant_id_for_create,
                                      mock_update_router,
                                      mock_rest_call,
                                      mock_process_delete_router,
                                      mock_release_segment,
                                      mock_delete_router_db):
        router_id = fake_router_uuid
        context = Mock()
        router_current = copy.deepcopy(fake_router_db)
        router_current.update(fake_router_external_info)
        router_current['external_gateway_info'].update(
            fake_router_external_fixed_ips)
        router_db = copy.deepcopy(fake_router_db)
        router_delete_gw_info = {'router': {'external_gateway_info': {}}}
        update_path = h_const.ROUTER_RESOURCE % fake_router_uuid
        update_body = {"route_table_id": None}
        delete_path = h_const.ROUTETABLE_RESOURCE % fake_router_uuid
        mock_get_router_db.return_value = router_current
        mock_get_tenant_id_for_create.return_value = fake_tenant_id
        mock_update_router.return_value = router_db
        mock_rest_call.side_effect = [(requests.codes.all_good, update_body),
                                      requests.codes.all_good]
        l3_router = H3CL3RouterPlugin()
        l3_router.delete_router(context, router_id)
        mock_ensure_router_not_in_use.assert_called_once_with(context,
                                                              router_id)
        mock_ensure_router_not_attached_to_fw.assert_called_once_with(
            context, router_current)
        mock_update_router.assert_called_once_with(context, router_id,
                                                   router_delete_gw_info)
        mock_rest_call.assert_has_calls(
            [call(update_path, 'PUT', update_body),
             call(delete_path, 'DELETE')])
        mock_process_delete_router.assert_called_once_with(router_current)
        mock_release_segment.assert_called_once_with(context.session,
                                                     router_id)
        mock_delete_router_db.assert_called_once_with(context, router_id)

    @patch.object(H3CL3RouterPlugin,
                  '_ensure_router_not_attached_to_firewall')
    @patch.object(L3_NAT_db_mixin, 'get_router')
    @patch.object(L3_NAT_dbonly_mixin, '_ensure_router_not_in_use')
    def test_delete_router_exist_bind(self,
                                      mock_ensure_router_not_in_use,
                                      mock_get_router_db,
                                      mock_ensure_router_not_attached_to_fw):
        router_id = fake_router_uuid
        context = Mock()
        router_current = copy.deepcopy(fake_router_db)
        mock_get_router_db.return_value = router_current
        mock_ensure_router_not_attached_to_fw.side_effect = \
            h_exc.H3CRouterBindFirewall()
        l3_router = H3CL3RouterPlugin()
        self.assertRaises(h_exc.H3CRouterBindFirewall, l3_router.delete_router,
                          context, router_id)
        mock_ensure_router_not_in_use.assert_called_once_with(context,
                                                              router_id)
        mock_ensure_router_not_attached_to_fw.assert_called_once_with(
            context, router_current)

    @patch.object(L3_NAT_db_mixin, 'notify_router_interface_action')
    @patch.object(CommonDbMixin, '_get_tenant_id_for_create')
    @patch.object(L3_NAT_db_mixin, 'get_router')
    @patch.object(H3CL3RouterPlugin, 'add_router_port')
    @patch.object(H3CL3RouterPlugin, '_core_plugin')
    @patch.object(rest_client.RestClient, 'rest_call')
    @patch.object(H3CL3RouterPlugin, '_add_interface_by_subnet')
    @patch.object(L3_NAT_with_dvr_db_mixin, '_get_device_owner')
    @patch.object(L3_NAT_dbonly_mixin, '_get_router')
    @patch.object(L3_NAT_dbonly_mixin, '_validate_interface_info')
    def test_add_router_interface_success(self,
                                          mock_validate_interface_info,
                                          mock_get_router,
                                          mock_get_device_owner,
                                          mock_add_interface_by_subnet,
                                          mock_rest_call,
                                          mock_core_plugin,
                                          mock_add_router_port,
                                          mock_get_router_db,
                                          mock_get_tenant_id_for_create,
                                          mock_notify_router_interface_action):
        context = Mock()
        interface_info = copy.deepcopy(fake_interface_add)
        router = Mock(tenant_id=fake_tenant_id, id=fake_router_uuid,
                      name=fake_router_name, status='ACTIVE',
                      admin_state_up=True, gw_port_id=None,
                      standard_attr_id=36675, enable_snat=False)
        subnets = [{'tenant_id': fake_tenant_id, 'id': fake_subnet_id}]
        update_path = h_const.ROUTER_ADD_INTERFACE_RESOURCE % fake_router_uuid
        update_resp = (requests.codes.all_good, fake_add_interface_resp)
        get_path = h_const.PORT_RESOURCE % fake_interface_port_id
        interface_port_body = copy.deepcopy(fake_interface_port_resp_body)
        get_resp = (requests.codes.all_good, interface_port_body)
        interface_port_info = copy.deepcopy(fake_interface_port_info)
        router_interface_info = {'id': fake_router_uuid,
                                 'tenant_id': subnets[0]['tenant_id'],
                                 'port_id': fake_interface_port_id,
                                 'subnet_id': fake_subnet_id}
        router_db = copy.deepcopy(fake_router_db)
        port_update_path = (h_const.PORT_RESOURCE
                            % interface_port_body['port']['id'])
        port_update_body = {
            'port': {
                'id': interface_port_body['port']['id'],
                'mac_address': interface_port_info['port']['mac_address']}}
        port_update_resp = (requests.codes.all_good, port_update_body)
        mock_validate_interface_info.return_value = (False, True)
        mock_get_router.return_value = router
        mock_get_device_owner.return_value = "network:router_interface"
        mock_add_interface_by_subnet.return_value = subnets
        mock_rest_call.side_effect = [update_resp, get_resp, port_update_resp]
        mock_core_plugin._generate_mac.return_value = fake_interface_port_mac
        mock_get_router_db.return_value = router_db
        mock_get_tenant_id_for_create.return_value = fake_tenant_id
        l3_router = H3CL3RouterPlugin()
        l3_router.add_router_interface(context, fake_router_uuid,
                                       interface_info)
        mock_rest_call.assert_has_calls(
            [call(update_path, 'PUT', interface_info), call(get_path, 'GET'),
             call(port_update_path, 'PUT', port_update_body)])
        mock_core_plugin.create_port.assert_called_once_with(
            context, interface_port_info)
        mock_add_router_port.assert_called_once_with(
            context, fake_interface_port_id, fake_router_uuid)
        mock_notify_router_interface_action.assert_called_once_with(
            context, router_interface_info, 'add')

    @patch.object(L3_NAT_dbonly_mixin, '_validate_interface_info')
    def test_add_router_interface_failure(self, mock_validate_interface_info):
        context = Mock()
        interface_info = {'port_id': fake_interface_port_id}
        mock_validate_interface_info.return_value = (True, False)
        l3_router = H3CL3RouterPlugin()
        self.assertRaises(
            h_exc.IpNotSupportAssigned, l3_router.add_router_interface,
            context, fake_router_uuid, interface_info)

    @patch.object(L3_NAT_db_mixin, 'notify_router_interface_action')
    @patch.object(H3CL3RouterPlugin, '_core_plugin')
    @patch.object(rest_client.RestClient, 'rest_call')
    @patch.object(CommonDbMixin, '_get_tenant_id_for_create')
    @patch.object(L3_NAT_db_mixin, 'get_router')
    @patch.object(H3CL3RouterPlugin, 'remove_interface_by_port')
    @patch.object(L3_NAT_with_dvr_db_mixin, '_get_device_owner')
    @patch.object(L3_NAT_dbonly_mixin, '_validate_interface_info')
    def test_remove_router_interface_success(self,
                                             mock_validate_interface_info,
                                             mock_get_device_owner,
                                             mock_remove_interface_by_port,
                                             mock_get_router_db,
                                             mock_get_tenant_id_for_create,
                                             mock_rest_call,
                                             mock_core_plugin,
                                             mock_notify_router_int_action):
        context = Mock()
        interface_info = copy.deepcopy(fake_interface_remove)
        port_db = {'tenant_id': fake_tenant_id, 'id': fake_interface_port_id}
        subnets = [{'tenant_id': fake_tenant_id, 'id': fake_subnet_id}]
        router_interface_info = {'id': fake_router_uuid,
                                 'tenant_id': subnets[0]['tenant_id'],
                                 'port_id': fake_interface_port_id,
                                 'subnet_id': fake_subnet_id}
        router_db = copy.deepcopy(fake_router_db)
        body = {'subnet_id': subnets[0]['id']}
        path = h_const.ROUTER_REMOVE_INTERFACE_RESOURCE % fake_router_uuid
        mock_validate_interface_info.return_value = (True, True)
        mock_get_device_owner.return_value = "network:router_interface"
        mock_remove_interface_by_port.return_value = (port_db, subnets)
        mock_rest_call.return_value = (requests.codes.all_good, body)
        mock_get_router_db.return_value = router_db
        mock_get_tenant_id_for_create.return_value = fake_tenant_id
        l3_router = H3CL3RouterPlugin()
        l3_router.remove_router_interface(context, fake_router_uuid,
                                          interface_info)
        mock_rest_call.assert_called_once_with(path, 'PUT', body)
        mock_core_plugin.delete_port.assert_called_once_with(
            context, port_db['id'], l3_port_check=False)
        mock_notify_router_int_action.assert_called_once_with(
            context, router_interface_info, 'remove')

    @patch.object(L3_NAT_db_mixin, 'notify_router_interface_action')
    @patch.object(H3CL3RouterPlugin, '_core_plugin')
    @patch.object(rest_client.RestClient, 'rest_call')
    @patch.object(CommonDbMixin, '_get_tenant_id_for_create')
    @patch.object(L3_NAT_db_mixin, 'get_router')
    @patch.object(H3CL3RouterPlugin, 'remove_interface_by_subnet')
    @patch.object(L3_NAT_with_dvr_db_mixin, '_get_device_owner')
    @patch.object(L3_NAT_dbonly_mixin, '_validate_interface_info')
    def test_remove_router_interface_by_subnet(self,
                                               mock_validate_interface_info,
                                               mock_get_device_owner,
                                               mock_remove_interface_by_subnet,
                                               mock_get_router_db,
                                               mock_get_tenant_id_for_create,
                                               mock_rest_call,
                                               mock_core_plugin,
                                               mock_notify_router_int_action):
        context = Mock()
        interface_info = {'subnet_id': fake_subnet_id}
        port_db = {'tenant_id': fake_tenant_id, 'id': fake_interface_port_id}
        subnets = [{'tenant_id': fake_tenant_id, 'id': fake_subnet_id}]
        router_interface_info = {'id': fake_router_uuid,
                                 'tenant_id': subnets[0]['tenant_id'],
                                 'port_id': fake_interface_port_id,
                                 'subnet_id': fake_subnet_id}
        router_db = copy.deepcopy(fake_router_db)
        body = {'subnet_id': subnets[0]['id']}
        path = h_const.ROUTER_REMOVE_INTERFACE_RESOURCE % fake_router_uuid
        mock_validate_interface_info.return_value = (False, True)
        mock_get_device_owner.return_value = "network:router_interface"
        mock_remove_interface_by_subnet.return_value = (port_db, subnets)
        mock_rest_call.return_value = (requests.codes.all_good, body)
        mock_get_router_db.return_value = router_db
        mock_get_tenant_id_for_create.return_value = fake_tenant_id
        l3_router = H3CL3RouterPlugin()
        l3_router.remove_router_interface(context, fake_router_uuid,
                                          interface_info)
        mock_rest_call.assert_called_once_with(path, 'PUT', body)
        mock_core_plugin.delete_port.assert_called_once_with(
            context, port_db['id'], l3_port_check=False)
        mock_notify_router_int_action.assert_called_once_with(
            context, router_interface_info, 'remove')

    @patch.object(rest_client.RestClient, 'rest_call')
    @patch.object(L3_NAT_with_dvr_db_mixin, 'create_floatingip')
    def test_create_floatingip_success(self,
                                       mock_create_floatingip_db,
                                       mock_rest_call):
        context = Mock()
        floatingip_info = copy.deepcopy(fake_floatingip_info)
        floatingip_db = copy.deepcopy(fake_floatingip_db)
        floatingip_dict = copy.deepcopy(floatingip_db)
        del floatingip_dict['fixed_ip_address']
        body = {'floatingips': [floatingip_dict]}
        mock_create_floatingip_db.return_value = floatingip_db
        mock_rest_call.return_value = (requests.codes.all_good, body)
        l3_router = H3CL3RouterPlugin()
        l3_router.create_floatingip(context, floatingip_info)
        mock_rest_call.assert_called_once_with(h_const.FLOATINGIPS_RESOURCE,
                                               'POST', body)

    @patch.object(L3_NAT_with_dvr_db_mixin, 'delete_floatingip')
    @patch.object(rest_client.RestClient, 'rest_call')
    @patch.object(L3_NAT_with_dvr_db_mixin, 'create_floatingip')
    def test_create_floatingip_failure(self,
                                       mock_create_floatingip_db,
                                       mock_rest_call,
                                       mock_delete_floatingip_db):
        context = Mock()
        floatingip_info = copy.deepcopy(fake_floatingip_info)
        floatingip_db = copy.deepcopy(fake_floatingip_db)
        floatingip_dict = copy.deepcopy(floatingip_db)
        del floatingip_dict['fixed_ip_address']
        body = {'floatingips': [floatingip_dict]}
        mock_create_floatingip_db.return_value = floatingip_db
        mock_rest_call.side_effect = q_exc.BadRequest(
            resource="POST", msg="invalid response status code!!")
        l3_router = H3CL3RouterPlugin()
        self.assertRaises(q_exc.BadRequest, l3_router.create_floatingip,
                          context, floatingip_info)
        mock_rest_call.assert_called_once_with(h_const.FLOATINGIPS_RESOURCE,
                                               'POST', body)
        mock_delete_floatingip_db.assert_called_once_with(context,
                                                          floatingip_db['id'])

    @patch.object(L3_NAT_with_dvr_db_mixin, 'update_floatingip')
    @patch.object(rest_client.RestClient, 'rest_call')
    @patch.object(L3_NAT_dbonly_mixin, 'get_floatingip')
    def test_update_floatingip(self,
                               mock_get_floatingip_db,
                               mock_rest_call,
                               mock_update_floatingip_db):
        context = Mock()
        port_id = '465bf65c-54f0-4278-8639-373f346f4a34'
        floatingip_info = {'floatingip': {'port_id': port_id}}
        floatingip_current = copy.deepcopy(fake_floatingip_db)
        path = h_const.FLOATINGIP_RESOURCE % fake_floatingip_id
        body = {'floatingip': {'port_id': None}}
        floatingip_db = copy.deepcopy(fake_floatingip_db)
        floatingip_db.update({'port_id': port_id})
        mock_get_floatingip_db.return_value = floatingip_current
        mock_rest_call.side_effect = [
            (requests.codes.all_good, body),
            (requests.codes.all_good, floatingip_info)]
        mock_update_floatingip_db.return_value = floatingip_db
        l3_router = H3CL3RouterPlugin()
        l3_router.update_floatingip(context, fake_floatingip_id,
                                    floatingip_info)
        mock_rest_call.assert_has_calls([call(path, 'PUT', body),
                                         call(path, 'PUT', floatingip_info)])

    @patch.object(rest_client.RestClient, 'rest_call')
    @patch.object(L3_NAT_with_dvr_db_mixin, 'delete_floatingip')
    def test_delete_floatingip(self,
                               mock_delete_floatingip_db,
                               mock_rest_call):
        context = Mock()
        path = h_const.FLOATINGIP_RESOURCE % fake_floatingip_id
        mock_rest_call.return_value = requests.codes.all_good
        l3_router = H3CL3RouterPlugin()
        l3_router.delete_floatingip(context, fake_floatingip_id)
        mock_delete_floatingip_db.assert_called_once_with(context,
                                                          fake_floatingip_id)
        mock_rest_call.assert_called_once_with(path, 'DELETE')
