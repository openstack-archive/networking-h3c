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

import requests
from mock import call
from mock import Mock
from mock import patch
from networking_h3c.common import constants as h_const
from networking_h3c.common import rest_client
from networking_h3c.ml2 import mechanism_h3c as md
from neutron.db.securitygroups_db import SecurityGroupDbMixin
from neutron.extensions import providernet as provider
from neutron.tests import base
from neutron_lbaas.db.loadbalancer import loadbalancer_db
from oslo_config import cfg

fake_vds_id = '0b580f78-4125-4938-88db-578d43fa9317'
fake_vds_name = 'VDS2'
fake_vds_resp = {'vds': [{'uuid': fake_vds_id, 'name': fake_vds_name}]}

fake_tenant_id = '7cfa58406d9945a9a1ca2c3bc8e03eb2'

fake_network_id = '60fd2fa0-88b5-486f-92d1-de2697609c37'
fake_segment_id = 316
fake_network_object = {'provider:physical_network': 'external',
                       'provider:network_type': 'vlan',
                       'id': fake_network_id,
                       'router:external': False,
                       'shared': True,
                       'status': 'ACTIVE',
                       'subnets': [],
                       'provider:segmentation_id': fake_segment_id,
                       'name': 'test_net',
                       'admin_state_up': True,
                       'tenant_id': fake_tenant_id}
fake_network_original = {'id': fake_network_id,
                         'router:external': False,
                         'shared': True,
                         'status': 'ACTIVE',
                         'subnets': [],
                         'name': 'test',
                         'admin_state_up': True,
                         'tenant_id': fake_tenant_id}

fake_subnet_id = '42de0869-7f1e-4acc-916f-4e688df7614b'
fake_subnet_object = {'allocation_pools': [{'start': '31.0.0.2',
                                            'end': '31.0.0.254'}],
                      'host_routes': [],
                      'cidr': '31.0.0.0/24',
                      'id': fake_subnet_id,
                      'subnetpool_id': None,
                      'name': 'test_subnet',
                      'enable_dhcp': True,
                      'network_id': fake_network_id,
                      'tenant_id': fake_tenant_id,
                      'gateway_ip': '31.0.0.1',
                      'ip_version': 4,
                      'shared': True}
dhcp_lease_time = 365
fake_dhcp_port_id = 'bf4a2bbd-ee05-4161-a116-779e1175e002'
fake_dhcp_port_object = {'status': 'ACTIVE',
                         'binding:host_id': 'network',
                         'allowed_address_pairs': [],
                         'extra_dhcp_opts': [],
                         'device_owner': 'network:dhcp',
                         'binding:profile': {},
                         'fixed_ips': [{'subnet_id': fake_subnet_id,
                                        'ip_address': '31.0.0.2'}],
                         'id': fake_dhcp_port_id,
                         'security_groups': [],
                         'device_id': 'dhcpdevice',
                         'name': '',
                         'admin_state_up': True,
                         'network_id': fake_network_id,
                         'dns_name': None,
                         'binding:vif_details': {'port_filter': True,
                                                 'ovs_hybrid_plug': True},
                         'binding:vnic_type': 'normal',
                         'binding:vif_type': 'ovs',
                         'tenant_id': fake_tenant_id,
                         'mac_address': 'fa:16:3e:6d:9c:c0'}
fake_dhcp_port_unbound = {'status': 'DOWN',
                          'binding:host_id': 'network',
                          'allowed_address_pairs': [],
                          'extra_dhcp_opts': [],
                          'device_owner': 'network:dhcp',
                          'binding:profile': {},
                          'port_security_enabled': False,
                          'fixed_ips': [{'subnet_id': fake_subnet_id,
                                         'ip_address': '31.0.0.2'}],
                          'id': fake_dhcp_port_id,
                          'security_groups': [],
                          'device_id': 'dhcpdevice',
                          'name': '',
                          'admin_state_up': True,
                          'network_id': fake_network_id,
                          'dns_name': None,
                          'binding:vif_details': {},
                          'binding:vnic_type': 'normal',
                          'binding:vif_type': 'unbound',
                          'tenant_id': fake_tenant_id,
                          'mac_address': 'fa:16:3e:6d:9c:c0'}
fake_segments = [{'segmentation_id': fake_segment_id,
                  'physical_network': 'external',
                  'id': 'f01c5b5e-b2f8-46a4-9794-7f6360054a77',
                  'network_type': 'vlan'}]
fake_dhcp_port_agents = [{'binary': 'neutron-openvswitch-agent'},
                         {'binary': 'neutron-metadata-agent'},
                         {'binary': 'neutron-dhcp-agent'}]
fake_instance_port_id = '3ca711e7-ecca-41dc-bd7d-6ea6bb599a61'
fake_instance_tenant_id = '9b9cbd12-8ecc-4650-b412-19b70136e70d'
fake_sg_id = '5922f5ad-b903-4764-9383-5aedb007fdd5'
fake_sg_name = 'test_sg'
fake_def_sg_id = '94c978b3-ba26-4727-bb75-b6f82df31814'
fake_security_group_ids = [fake_sg_id, fake_def_sg_id]
fake_other_sg_id = 'b1f8ece5-339f-4350-ac68-a189cfc4914f'
fake_sg_rule_v4 = {'direction': 'egress',
                   'protocol': 'icmp',
                   'port_range_max': 0,
                   'id': '3f025ba9-8b74-47c5-b98b-22c0c2eaac5c',
                   'remote_group_id': None,
                   'remote_ip_prefix': '31.0.0.0/24',
                   'security_group_id': fake_sg_id,
                   'tenant_id': fake_instance_tenant_id,
                   'port_range_min': 8,
                   'ethertype': 'IPv4'}
fake_sg_rule_v4_rem = {'direction': 'egress',
                       'protocol': None,
                       'port_range_max': None,
                       'id': '888a34e7-6b55-4c5e-9b23-d9b4d0dc2771',
                       'remote_group_id': fake_def_sg_id,
                       'remote_ip_prefix': None,
                       'security_group_id': fake_sg_id,
                       'tenant_id': fake_instance_tenant_id,
                       'port_range_min': None,
                       'ethertype': 'IPv4'}
fake_sg_rule_v6 = {'direction': 'egress',
                   'protocol': None,
                   'port_range_max': None,
                   'id': 'c9878888-de02-43ba-ae8a-cc66829a4324',
                   'remote_group_id': None,
                   'remote_ip_prefix': None,
                   'security_group_id': fake_sg_id,
                   'tenant_id': fake_instance_tenant_id,
                   'port_range_min': None,
                   'ethertype': 'IPv6'}
fake_sg_rules = [fake_sg_rule_v4, fake_sg_rule_v4_rem, fake_sg_rule_v6]
fake_sg_object = {'tenant_id': fake_instance_tenant_id,
                  'id': fake_sg_id,
                  'security_group_rules': fake_sg_rules,
                  'name': fake_sg_name}
fake_sg_dict = {'port_security': {'name': fake_sg_name,
                                  'empty_rule_action': 'deny',
                                  'denyflow_age': '300',
                                  'ip_mac_binding': True,
                                  'id': fake_sg_id,
                                  'isDefault': False}}
fake_sg_rule_v4_dict = {'securityrules': [{'icmp_code': 0,
                                           'direction': 'egress',
                                           'protocol': 'icmp',
                                           'name': '',
                                           'tenant_id':
                                               fake_instance_tenant_id,
                                           'ipprefix': '31.0.0.0/24',
                                           'portsecurity_id': fake_sg_id,
                                           'ip_version': '4',
                                           'icmp_type': 8,
                                           'description': ''}]}
fake_sg_rule_v4_rem_dict = {'securityrules': [{'direction': 'egress',
                                               'protocol': None,
                                               'name': '',
                                               'portrange_max': None,
                                               'portrange_min': None,
                                               'tenant_id':
                                                   fake_instance_tenant_id,
                                               'ipprefix': '31.0.0.3/32',
                                               'portsecurity_id': fake_sg_id,
                                               'ip_version': '4',
                                               'description': ''}]}
fake_def_sg_dict = {'port_security': {'name': 'default',
                                      'empty_rule_action': 'deny',
                                      'denyflow_age': '300',
                                      'ip_mac_binding': True,
                                      'id': fake_def_sg_id,
                                      'isDefault': True}}
fake_def_sg_rule = {'direction': 'ingress',
                    'protocol': 'tcp',
                    'description': '',
                    'port_range_max': 80,
                    'id': 'e58b186b-d52b-4efd-9635-9ff8e06d2d75',
                    'remote_group_id': None,
                    'remote_ip_prefix': None,
                    'security_group_id': fake_def_sg_id,
                    'tenant_id': fake_instance_tenant_id,
                    'port_range_min': 53,
                    'ethertype': 'IPv4'}
fake_def_sg_rule_dict = {'id': 'bba21781-3ae3-40f4-9a04-f8261efdc524',
                         'name': '',
                         'portsecurity_id': fake_def_sg_id,
                         'description': '',
                         'direction': 'ingress',
                         'ip_version': '4',
                         'ipprefix': None,
                         'protocol': 'tcp',
                         'portrange_max': 80,
                         'portrange_min': 53,
                         'icmp_type': None,
                         'icmp_code': None,
                         'tenant_id': fake_instance_tenant_id}
fake_def_sg_rule_cre = {'direction': 'ingress',
                        'protocol': None,
                        'description': '',
                        'port_range_max': None,
                        'id': '7b01501f-69db-4975-96f7-7a1bc6820f42',
                        'remote_group_id': fake_other_sg_id,
                        'remote_ip_prefix': None,
                        'security_group_id': fake_def_sg_id,
                        'tenant_id': fake_instance_tenant_id,
                        'port_range_min': None,
                        'ethertype': 'IPv4'}
fake_def_sg_rule_cre_dict = {
    "securityrules": [{'direction': 'ingress',
                       'protocol': None,
                       'name': '',
                       'portrange_max': None,
                       'portrange_min': None,
                       'tenant_id': fake_instance_tenant_id,
                       'ipprefix': '31.0.0.4/32',
                       'portsecurity_id': fake_def_sg_id,
                       'ip_version': '4',
                       'description': ''}]}
fake_def_sg_rule_del_id = 'd14bb267-67ee-4714-bad7-bee4fb20ae33'
fake_def_sg_rule_del_dict = {'id': fake_def_sg_rule_del_id,
                             'name': '',
                             'portsecurity_id': fake_def_sg_id,
                             'description': '',
                             'direction': 'ingress',
                             'ip_version': '4',
                             'ipprefix': None,
                             'protocol': None,
                             'portrange_max': None,
                             'portrange_min': None,
                             'icmp_type': None,
                             'icmp_code': None,
                             'tenant_id': fake_instance_tenant_id}
fake_def_sg_rules = [fake_def_sg_rule, fake_def_sg_rule_cre]
fake_def_sg_object = {'tenant_id': fake_instance_tenant_id,
                      'id': fake_sg_id,
                      'security_group_rules': fake_def_sg_rules,
                      'name': 'default'}
fake_def_sg_rules_dict = {'securityrules': [fake_def_sg_rule_dict,
                                            fake_def_sg_rule_del_dict]}
fake_other_sg_rule = {'direction': 'egress',
                      'protocol': None,
                      'port_range_max': None,
                      'id': '7ea073bc-c705-4428-a5eb-1258387df844',
                      'remote_group_id': fake_def_sg_id,
                      'remote_ip_prefix': None,
                      'security_group_id': fake_other_sg_id,
                      'tenant_id': fake_instance_tenant_id,
                      'port_range_min': None,
                      'ethertype': 'IPv4'}
fake_sg_rules_all = [fake_other_sg_rule, fake_sg_rule_v4, fake_sg_rule_v4_rem,
                     fake_sg_rule_v6, fake_def_sg_rule, fake_def_sg_rule_cre]

fake_nova_device_id = '73f54944-658e-4837-bb55-cada9f37ee64'
fake_instance_port_unbound = {'status': 'DOWN',
                              'binding:host_id': 'compute1',
                              'allowed_address_pairs': [],
                              'extra_dhcp_opts': [{'ip_version': 4,
                                                   'opt_name': 'mtu',
                                                   'opt_value': '1400'}],
                              'device_owner': 'compute:nova',
                              'binding:profile': {},
                              'port_security_enabled': True,
                              'fixed_ips': [{'subnet_id': fake_subnet_id,
                                             'ip_address': '31.0.0.3'}],
                              'id': fake_instance_port_id,
                              'security_groups': fake_security_group_ids,
                              'device_id': fake_nova_device_id,
                              'name': '',
                              'admin_state_up': True,
                              'network_id': fake_network_id,
                              'dns_name': None,
                              'binding:vif_details': {},
                              'binding:vnic_type': 'normal',
                              'binding:vif_type': 'unbound',
                              'tenant_id': fake_instance_tenant_id,
                              'mac_address': 'fa:16:3e:62:14:17'}
fake_instance_port_object = {'allowed_address_pairs': [],
                             'extra_dhcp_opts': [{'ip_version': 4,
                                                  'opt_name': 'mtu',
                                                  'opt_value': '1400'}],
                             'device_owner': 'compute:nova',
                             'port_security_enabled': True,
                             'binding:profile': {},
                             'fixed_ips': [{'subnet_id': fake_subnet_id,
                                            'ip_address': '31.0.0.3'}],
                             'id': fake_instance_port_id,
                             'security_groups': fake_security_group_ids,
                             'binding:vif_details': {},
                             'binding:vif_type': 'ovs',
                             'mac_address': 'fa:16:3e:62:14:17',
                             'status': 'ACTIVE',
                             'binding:host_id': 'compute1',
                             'description': '',
                             'device_id': fake_nova_device_id,
                             'name': 'tap3ca711e7-ec',
                             'admin_state_up': True,
                             'network_id': fake_network_id,
                             'dns_name': None,
                             'binding:vnic_type': 'normal',
                             'tenant_id': fake_instance_tenant_id}
fake_instance_port_agents = [{'binary': 'neutron-s1020v-openvswitch-agent'}]
fake_interface_port_id = '6f119003-fb91-4e31-8ae2-3078147332fb'
fake_router_id = '5848c8d6-634f-4c6c-8ee9-a41c37c01ec3'
fake_interface_port_object = {'allowed_address_pairs': [],
                              'extra_dhcp_opts': [],
                              'device_owner': 'network:router_interface',
                              'binding:profile': {},
                              'port_security_enabled': False,
                              'fixed_ips': [{'subnet_id': fake_subnet_id,
                                             'ip_address': '31.0.0.1'}],
                              'id': fake_interface_port_id,
                              'security_groups': [],
                              'binding:vif_details': {},
                              'binding:vif_type': 'unbound',
                              'mac_address': 'fa:16:3e:d5:8a:54',
                              'status': 'ACTIVE',
                              'binding:host_id': '',
                              'device_id': fake_router_id,
                              'name': '',
                              'admin_state_up': True,
                              'network_id': fake_network_id,
                              'dns_name': None,
                              'binding:vnic_type': 'normal',
                              'tenant_id': fake_tenant_id}


class TestH3CMechanismDriver(base.BaseTestCase):
    def setUp(self):
        super(TestH3CMechanismDriver, self).setUp()
        cfg.CONF.set_override('vds_name', fake_vds_name, 'VCFCONTROLLER')
        cfg.CONF.set_override('hybrid_vnic', True, 'VCFCONTROLLER')
        cfg.CONF.set_override('dhcp_lease_time', dhcp_lease_time,
                              'VCFCONTROLLER')
        cfg.CONF.set_override('enable_subnet_dhcp', False, 'VCFCONTROLLER')
        cfg.CONF.set_override('enable_metadata', True, 'VCFCONTROLLER')
        cfg.CONF.set_override('enable_security_group', True, 'VCFCONTROLLER')
        cfg.CONF.set_override('ip_mac_binding', True, 'VCFCONTROLLER')
        cfg.CONF.set_override('denyflow_age', 300, 'VCFCONTROLLER')
        cfg.CONF.set_override('empty_rule_action', 'deny', 'VCFCONTROLLER')
        self.driver = md.H3CMechanismDriver()

    def tearDown(self):
        super(TestH3CMechanismDriver, self).tearDown()

    @patch.object(rest_client.RestClient, 'rest_call')
    def test_get_vds_id_from_vcfc(self, mock_rest_call):
        path = "%s?name=%s" % (h_const.VDS_RESOURCE, fake_vds_name)
        mock_rest_call.return_value = (requests.codes.all_good, fake_vds_resp)
        vds_id = self.driver.get_vds_id_from_vcfc(fake_vds_name)
        mock_rest_call.assert_called_once_with(path, 'GET')
        self.assertEqual(fake_vds_id, vds_id)

    @patch.object(rest_client.RestClient, 'rest_call')
    @patch.object(md.H3CMechanismDriver, 'get_vds_id_from_vcfc')
    def test_create_network_postcommit(self,
                                       mock_get_vds_id_from_vcfc,
                                       mock_rest_call):
        context = Mock()
        network = copy.deepcopy(fake_network_object)
        plugin = Mock()
        mech_context = Mock(current=network, _plugin_context=context,
                            _plugin=plugin)
        path = "vds/1.0/networks"
        network_dict = copy.deepcopy(network)
        network_dict[provider.NETWORK_TYPE] = 'vxlan'
        network_dict['provider:domain'] = fake_vds_id
        body = {'networks': [network_dict]}
        mock_get_vds_id_from_vcfc.return_value = fake_vds_id
        mock_rest_call.return_value = (requests.codes.all_good, body)
        self.driver.create_network_postcommit(mech_context)
        mock_rest_call.assert_called_once_with(path, 'POST', body)

    @patch.object(rest_client.RestClient, 'rest_call')
    def test_update_network_postcommit(self, mock_rest_call):
        network = copy.deepcopy(fake_network_object)
        network.update({'shared': False})
        network_orig = copy.deepcopy(fake_network_original)
        mech_context = Mock(current=network, original=network_orig)
        path = "vds/1.0/networks/%s" % network_orig['id']
        network_dict = copy.deepcopy(network)
        network_dict['provider:network_type'] = 'vxlan'
        body = {'network': network_dict}
        mock_rest_call.return_value = (requests.codes.all_good, body)
        self.driver.update_network_postcommit(mech_context)
        mock_rest_call.assert_called_once_with(path, 'PUT', body)

    @patch.object(rest_client.RestClient, 'rest_call')
    def test_delete_network_precommit(self, mock_rest_call):
        network = copy.deepcopy(fake_network_object)
        mech_context = Mock(current=network)
        path = "vds/1.0/networks/%s" % network['id']
        mock_rest_call.return_value = requests.codes.all_good
        self.driver.delete_network_precommit(mech_context)
        mock_rest_call.assert_called_once_with(path, 'DELETE')

    @patch.object(rest_client.RestClient, 'rest_call')
    @patch.object(md.H3CMechanismDriver, 'get_vds_id_from_vcfc')
    def test_create_subnet_postcommit(self,
                                      mock_get_vds_id_from_vcfc,
                                      mock_rest_call):
        context = Mock()
        subnet = copy.deepcopy(fake_subnet_object)
        mech_context = Mock(current=subnet, _plugin_context=context)
        mock_get_vds_id_from_vcfc.return_value = fake_vds_id
        subnet_dict = copy.deepcopy(subnet)
        subnet_dict['domain'] = fake_vds_id
        subnet_dict['leaseTime'] = {'day': dhcp_lease_time}
        subnet_dict['enable_dhcp'] = False
        path = "vds/1.0/subnets"
        body = {'subnets': [subnet_dict]}
        mock_rest_call.return_value = (requests.codes.all_good, body)
        self.driver.create_subnet_postcommit(mech_context)
        mock_rest_call.assert_called_once_with(path, 'POST', body)

    @patch.object(rest_client.RestClient, 'rest_call')
    def test_update_subnet_precommit(self, mock_rest_call):
        subnet = copy.deepcopy(fake_subnet_object)
        subnet.update({'enable_dhcp': False})
        subnet_dict = copy.deepcopy(fake_subnet_object)
        body = {'subnet': subnet_dict}
        mech_context = Mock(current=subnet)
        mock_rest_call.return_value = (requests.codes.all_good, body)
        self.assertRaises(Exception, self.driver.update_subnet_precommit,
                          mech_context)

    @patch.object(rest_client.RestClient, 'rest_call')
    def test_update_subnet_postcommit(self, mock_rest_call):
        context = Mock()
        subnet = copy.deepcopy(fake_subnet_object)
        plugin = Mock()
        mech_context = Mock(current=subnet, _plugin_context=context,
                            _plugin=plugin)
        subnet_dict = copy.deepcopy(subnet)
        host_routes = {
            'nexthop': fake_dhcp_port_object['fixed_ips'][0]['ip_address'],
            'destination': '169.254.169.254/32'}
        subnet_dict['host_routes'].append(host_routes)
        path = "vds/1.0/subnets/%s" % (subnet['id'])
        body = {'subnet': subnet_dict}
        plugin.get_ports.return_value = [fake_dhcp_port_object]
        mock_rest_call.return_value = (requests.codes.all_good, body)
        self.driver.update_subnet_postcommit(mech_context)
        mock_rest_call.assert_called_once_with(path, 'PUT', body)

    @patch.object(rest_client.RestClient, 'rest_call')
    def test_delete_subnet_postcommit(self, mock_rest_call):
        context = Mock()
        subnet = copy.deepcopy(fake_subnet_object)
        mech_context = Mock(current=subnet, _plugin_context=context,)
        path = "vds/1.0/subnets/%s" % subnet['id']
        mock_rest_call.return_value = requests.codes.all_good
        self.driver.delete_subnet_postcommit(mech_context)
        mock_rest_call.assert_called_once_with(path, 'DELETE')

    @patch.object(rest_client.RestClient, 'rest_call')
    def test_get_host_from_vcfc(self, mock_rest_call):
        host_ip = '172.1.1.31'
        resp_body = {'host': [{'uuid': '740855f9-b612-4c1f-9ff4-c3a7a3726559',
                               'name': None,
                               'ip': '99.0.36.131'}]}
        path = "%s?ip=%s" % (h_const.AGENTS_RESOURCE, host_ip)
        resp_host = resp_body['host'][0]
        mock_rest_call.return_value = (requests.codes.all_good, resp_body)
        host = self.driver.get_host_from_vcfc(host_ip)
        self.assertEqual(resp_host, host)
        mock_rest_call.assert_called_once_with(path, 'GET')

    @patch.object(rest_client.RestClient, 'rest_call')
    def test_get_host_from_vcfc_no_content(self, mock_rest_call):
        host_ip = '172.1.1.32'
        path = "%s?ip=%s" % (h_const.AGENTS_RESOURCE, host_ip)
        mock_rest_call.return_value = (requests.codes.no_content, None)
        host = self.driver.get_host_from_vcfc(host_ip)
        self.assertEqual(None, host)
        mock_rest_call.assert_called_once_with(path, 'GET')

    def test_bind_port_dhcp(self):
        context = Mock(current=fake_dhcp_port_unbound)
        context.network.current = fake_network_object
        context.network.network_segments = fake_segments
        context._plugin.get_agents.return_value = fake_dhcp_port_agents
        vif_details = {'port_filter': True, 'ovs_hybrid_plug': True}
        self.driver.bind_port(context)
        context.set_binding.assert_called_once_with(fake_segments[0]['id'],
                                                    'ovs', vif_details,
                                                    status='ACTIVE')

    def test_bind_port_instance(self):
        context = Mock(current=fake_instance_port_unbound)
        context.network.current = fake_network_object
        context.network.network_segments = fake_segments
        context._plugin.get_agents.return_value = fake_instance_port_agents
        self.driver.bind_port(context)
        context.set_binding.assert_called_once_with(fake_segments[0]['id'],
                                                    'ovs', {}, status='ACTIVE')

    @patch('socket.gethostbyname')
    @patch.object(md.H3CMechanismDriver, 'get_host_from_vcfc')
    def test_bind_port_instance_dvs(self,
                                    mock_get_host_from_vcfc,
                                    mock_gethostbyname):
        context = Mock(current=fake_instance_port_unbound)
        context.network.current = fake_network_object
        context.network.network_segments = fake_segments
        context._plugin.get_agents.return_value = []
        mock_gethostbyname.return_value = '172.1.1.31'
        mock_get_host_from_vcfc.return_value = None
        self.driver.bind_port(context)
        context.set_binding.assert_called_once_with(fake_segments[0]['id'],
                                                    'dvs', {}, status='ACTIVE')

    def test_create_port_postcommit(self):
        self.create_router_interface_port()
        self.create_instance_port()
        self.create_dhcp_port()

    def create_router_interface_port(self):
        port = copy.deepcopy(fake_interface_port_object)
        context = Mock()
        plugin = Mock()
        mech_context = Mock(current=port, _plugin_context=context,
                            _plugin=plugin)
        self.driver.create_port_postcommit(mech_context)

    @patch.object(SecurityGroupDbMixin, 'get_security_group_rules')
    @patch.object(md.H3CMechanismDriver, 'get_ip_prefixs_security_group')
    @patch.object(rest_client.RestClient, 'rest_call')
    def create_instance_port(self,
                             mock_rest_call,
                             mock_get_ip_pref_sg,
                             mock_get_sg_rules):
        port = copy.deepcopy(fake_instance_port_object)
        context = Mock()
        plugin = Mock()
        mech_context = Mock(current=port, _plugin_context=context,
                            _plugin=plugin)
        mech_context._network_context._network = fake_network_object
        sg_get_path = "%s/%s" % (h_const.SECURITY_PORT_GROUPS_RESOURCE,
                                 fake_sg_id)
        def_sg_get_path = "%s/%s" % (h_const.SECURITY_PORT_GROUPS_RESOURCE,
                                     fake_def_sg_id)
        sg_objects = {fake_sg_id: fake_sg_object,
                      fake_def_sg_id: fake_def_sg_object}
        sg_create_path = h_const.SECURITY_PORT_GROUPS_RESOURCE
        sg_create_body = {'port_securities': [{'empty_rule_action': 'deny',
                                               'denyflow_age': 300,
                                               'ip_mac_binding': True,
                                               'id': fake_sg_id,
                                               'name': fake_sg_name}]}
        ip_prefixes_dict = {
            fake_def_sg_id: [
                (ip['ip_address'] + '/32') for ip in port['fixed_ips']],
            fake_sg_id: [
                (ip['ip_address'] + '/32') for ip in port['fixed_ips']],
            fake_other_sg_id: ['31.0.0.4/32']}
        sg_rule_create_path = h_const.SECURITY_GROUP_RULES_RESOURCE
        def_sg_rules_get_path = "%s?portsecurity_id=%s" % (
            h_const.SECURITY_GROUP_RULES_RESOURCE, fake_def_sg_id)
        def_sg_rule_del_path = "%s/%s" % (
            h_const.SECURITY_GROUP_RULES_RESOURCE, fake_def_sg_rule_del_id)
        other_sg_get_path = "%s/%s" % (h_const.SECURITY_PORT_GROUPS_RESOURCE,
                                       fake_other_sg_id)
        sg_rules_get_path = "%s?portsecurity_id=%s" % (
            h_const.SECURITY_GROUP_RULES_RESOURCE, fake_sg_id)
        sg_rule_v4_dict = copy.deepcopy(
            fake_sg_rule_v4_dict['securityrules'][0])
        sg_rule_v4_rem_dict = copy.deepcopy(
            fake_sg_rule_v4_rem_dict['securityrules'][0])
        sg_rule_v4_dict.update({'id': '9c84ea96-5525-4d7c-845c-a5ac863f7908'})
        sg_rule_v4_rem_dict.update(
            {'id': '6771fa8d-0100-4e47-ad2d-cfb9d5e41e1c'})
        sg_rules_dict = {
            'securityrules': [sg_rule_v4_dict, sg_rule_v4_rem_dict]}
        instance_port_dict = {
            'status': fake_instance_port_object['status'],
            'binding:host_id': fake_instance_port_object['binding:host_id'],
            'device_owner': fake_instance_port_object['device_owner'],
            'fixed_ips': [
                {
                    'subnet_id': subnet['subnet_id'],
                    'ip_address': subnet['ip_address']
                } for subnet in fake_instance_port_object['fixed_ips']
                ],
            'id': fake_instance_port_object['id'],
            'device_id': fake_instance_port_object['device_id'],
            'name': fake_instance_port_object['name'],
            'admin_state_up': fake_instance_port_object['admin_state_up'],
            'network_id': fake_instance_port_object['network_id'],
            'tenant_id': fake_instance_port_object['tenant_id'],
            'binding:vif_type': '',
            'mac_address': fake_instance_port_object['mac_address'],
            'port_securities': [
                {"port_security": sg_id}
                for sg_id in fake_instance_port_object['security_groups']],
            'dhcp_options': {'interface_mtu': 1400}
        }
        port_create_path = "vds/1.0/ports"
        port_create_body = {'ports': [instance_port_dict]}
        mock_rest_call.side_effect = [
            (requests.codes.not_found, None),
            (requests.codes.all_good, sg_create_body),
            (requests.codes.all_good, fake_sg_rule_v4_dict),
            (requests.codes.all_good, fake_sg_rule_v4_rem_dict),
            (requests.codes.all_good, fake_def_sg_dict),
            (requests.codes.all_good, fake_def_sg_rules_dict),
            requests.codes.all_good,
            (requests.codes.all_good, fake_def_sg_rule_cre_dict),
            (requests.codes.not_found, None),
            (requests.codes.all_good, fake_sg_dict),
            (requests.codes.all_good, sg_rules_dict),
            (requests.codes.all_good, port_create_body)]
        plugin.get_security_group.side_effect = lambda c, i: sg_objects.get(i)
        mock_get_ip_pref_sg.side_effect = \
            lambda c, i: ip_prefixes_dict.get(i, [])
        mock_get_sg_rules.return_value = fake_sg_rules_all
        plugin.get_security_group_rules.side_effect = \
            self.driver.get_security_group_rules
        self.driver.create_port_postcommit(mech_context)
        mock_rest_call.assert_has_calls(
            [call(sg_get_path, 'GET'),
             call(sg_create_path, 'POST', sg_create_body),
             call(sg_rule_create_path, 'POST', fake_sg_rule_v4_dict),
             call(sg_rule_create_path, 'POST', fake_sg_rule_v4_rem_dict),
             call(def_sg_get_path, 'GET'),
             call(def_sg_rules_get_path, 'GET'),
             call(def_sg_rule_del_path, 'DELETE'),
             call(sg_rule_create_path, 'POST', fake_def_sg_rule_cre_dict),
             call(other_sg_get_path, 'GET'),
             call(sg_get_path, 'GET'),
             call(sg_rules_get_path, 'GET'),
             call(port_create_path, 'POST', port_create_body)])

    @patch.object(rest_client.RestClient, 'rest_call')
    def create_dhcp_port(self, mock_rest_call):
        port = copy.deepcopy(fake_dhcp_port_object)
        context = Mock()
        plugin = Mock()
        mech_context = Mock(current=port, _plugin_context=context,
                            _plugin=plugin)
        mech_context._network_context._network = fake_network_object
        subnet = copy.deepcopy(fake_subnet_object)
        plugin.get_subnet.return_value = subnet
        subnet_dict = copy.deepcopy(subnet)
        host_routes = {
            'nexthop': fake_dhcp_port_object['fixed_ips'][0]['ip_address'],
            'destination': '169.254.169.254/32'}
        subnet_dict['host_routes'].append(host_routes)
        update_path = "vds/1.0/subnets/%s" % (subnet['id'])
        update_body = {'subnet': subnet_dict}
        plugin.get_ports.return_value = [fake_dhcp_port_object]
        create_path = "vds/1.0/ports"
        create_body = {'ports': [{
            'status': fake_dhcp_port_object['status'],
            'binding:host_id': fake_dhcp_port_object['binding:host_id'],
            'device_owner': fake_dhcp_port_object['device_owner'],
            'fixed_ips': [
                {
                    'subnet_id': sn['subnet_id'],
                    'ip_address': sn['ip_address']
                } for sn in fake_dhcp_port_object['fixed_ips']
                ],
            'id': fake_dhcp_port_object['id'],
            'device_id': fake_dhcp_port_object['device_id'],
            'name': fake_dhcp_port_object['name'],
            'admin_state_up': fake_dhcp_port_object['admin_state_up'],
            'network_id': fake_dhcp_port_object['network_id'],
            'tenant_id': fake_dhcp_port_object['tenant_id'],
            'binding:vif_type': '',
            'mac_address': fake_dhcp_port_object['mac_address'],
            'port_securities': [
                {"port_security": sg_id}
                for sg_id in fake_dhcp_port_object['security_groups']],
            'dhcp_options': None
        }]}
        mock_rest_call.side_effect = [(requests.codes.all_good, update_body),
                                      (requests.codes.all_good, create_body)]
        self.driver.create_port_postcommit(mech_context)
        mock_rest_call.assert_has_calls(
            [call(update_path, 'PUT', update_body),
             call(create_path, 'POST', create_body)])

    def test_update_port_postcommit(self):
        self.update_dhcp_port_remove_all_ips()
        self.update_dhcp_port_add_ips_from_none()
        self.update_lb_member_port_power_on_off()
        self.update_instance_port_spawn()
        self.update_instance_port_modify_sg()
        self.update_instance_port_add_fixed_ip()
        self.update_instance_port_remove_fixed_ip()

    def update_dhcp_port_remove_all_ips(self):
        port = copy.deepcopy(fake_dhcp_port_object)
        port.update({'fixed_ips': []})
        port_orig = copy.deepcopy(fake_dhcp_port_object)
        plugin = Mock()
        context = Mock()
        mech_context = Mock(current=port, original=port_orig, _plugin=plugin,
                            _plugin_context=context)
        self.driver.update_port_postcommit(mech_context)

    @patch.object(rest_client.RestClient, 'rest_call')
    def update_dhcp_port_add_ips_from_none(self, mock_rest_call):
        port = copy.deepcopy(fake_dhcp_port_object)
        port_orig = copy.deepcopy(fake_dhcp_port_object)
        port_orig.update({'fixed_ips': []})
        plugin = Mock()
        context = Mock()
        mech_context = Mock(current=port, original=port_orig, _plugin=plugin,
                            _plugin_context=context)
        path = "vds/1.0/ports"
        body = {'ports': [{
            'status': port['status'],
            'binding:host_id': port['binding:host_id'],
            'device_owner': port['device_owner'],
            'fixed_ips': [
                {
                    'subnet_id': subnet['subnet_id'],
                    'ip_address': subnet['ip_address']
                } for subnet in port['fixed_ips']
                ],
            'id': port['id'],
            'device_id': port['device_id'],
            'name': port['name'],
            'admin_state_up': port['admin_state_up'],
            'network_id': port['network_id'],
            'tenant_id': port['tenant_id'],
            'binding:vif_type': port['binding:vif_type'],
            'mac_address': port['mac_address'],
            'port_securities': [],
            'dhcp_options': None
        }]}
        mock_rest_call.return_value = (requests.codes.all_good, body)
        self.driver.update_port_postcommit(mech_context)
        mock_rest_call.assert_called_once_with(path, 'POST', body)

    @patch.object(loadbalancer_db, 'Member')
    @patch.object(loadbalancer_db, 'LoadBalancerPluginDb')
    def _update_lb_member_port_action(self, action, mock_lb, mock_member):
        port = copy.deepcopy(fake_instance_port_object)
        port.update({'port_extensions': {
            'member_status': {'action': action,
                              'tenant_id': fake_instance_tenant_id,
                              'ip_address': '31.0.0.3'}}})
        port_orig = copy.deepcopy(fake_instance_port_object)
        plugin = Mock()
        context = Mock()
        mech_context = Mock(current=port, original=port_orig, _plugin=plugin,
                            _plugin_context=context)
        lb_member = {'tenant_id': fake_instance_tenant_id,
                     'id': 'd2cb4a65-951f-4aee-86df-30e44222d68b',
                     'status': 'ACTIVE', 'status_description': None,
                     'pool_id': 'e8e0cea3-c4ea-42e6-999a-fea2a8cf5726',
                     'address': '31.0.0.3', 'protocol_port': 80, 'weight': 20,
                     'admin_state_up': True}
        context.session.query().filter_by().first.return_value = lb_member
        self.driver.update_port_postcommit(mech_context)
        if action == 'power_on':
            mock_lb().update_status.assert_called_once_with(
                context, mock_member, lb_member['id'], 'ACTIVE')
        else:
            mock_lb().update_status.assert_called_once_with(
                context, mock_member, lb_member['id'], 'INACTIVE')

    def update_lb_member_port_power_on_off(self):
        self._update_lb_member_port_action('power_on')
        self._update_lb_member_port_action('power_off')

    @patch.object(rest_client.RestClient, 'rest_call')
    def update_instance_port_spawn(self, mock_rest_call):
        port = copy.deepcopy(fake_instance_port_object)
        port.update({'name': 'tap3ca711e7-ec',
                     'port_extensions': {
                         'virt_type': 'kvm',
                         'domain': '86c306ef-7526-47a5-8706-731a99da0bac'}})
        port_orig = copy.deepcopy(fake_instance_port_object)
        plugin = Mock()
        context = Mock()
        mech_context = Mock(current=port, original=port_orig, _plugin=plugin,
                            _plugin_context=context)
        get_path = "%s/%s" % ("vds/1.0/ports", port['id'])
        get_resp = {'port': {'id': port['id'], 'qos': None}}
        path = "vds/1.0/ports/%s" % (port['id'])
        port_dict = copy.deepcopy(port)
        port_dict.update({
            'port_securities': [
                {"port_security": sg_id}
                for sg_id in port['security_groups']],
            'domain': port['port_extensions']['domain'],
            'dhcp_options': {'interface_mtu': 1400},
            'qos': get_resp['port']['qos']
        })
        for key in ('security_groups', 'port_extensions', 'status',
                    'binding:host_id', 'tenant_id', 'binding:vif_type',
                    'device_id', 'device_owner', 'extra_dhcp_opts'):
            del port_dict[key]
        body = {'port': port_dict}
        mock_rest_call.side_effect = [(requests.codes.all_good, get_resp),
                                      (requests.codes.all_good, body)]
        self.driver.update_port_postcommit(mech_context)
        mock_rest_call.assert_has_calls([call(get_path, 'GET'),
                                         call(path, 'PUT', body)])

    @patch.object(SecurityGroupDbMixin, '_get_port_security_group_bindings')
    @patch.object(SecurityGroupDbMixin, 'get_security_group_rules')
    @patch.object(md.H3CMechanismDriver, 'get_ip_prefixs_security_group')
    @patch.object(rest_client.RestClient, 'rest_call')
    def update_instance_port_modify_sg(self,
                                       mock_rest_call,
                                       mock_get_ip_pref_sg,
                                       mock_get_sg_rules,
                                       mock_get_port_sg_bindings):
        port_orig = copy.deepcopy(fake_instance_port_object)
        port_orig.update({'security_groups': [fake_def_sg_id]})
        port = copy.deepcopy(port_orig)
        port.update({'security_groups': [fake_sg_id]})
        plugin = Mock()
        context = Mock()
        mech_context = Mock(current=port, original=port_orig, _plugin=plugin,
                            _plugin_context=context)
        sg_objects = {fake_sg_id: fake_sg_object,
                      fake_def_sg_id: fake_def_sg_object}
        sg_get_path = "%s/%s" % (h_const.SECURITY_PORT_GROUPS_RESOURCE,
                                 fake_sg_id)
        sg_create_path = h_const.SECURITY_PORT_GROUPS_RESOURCE
        sg_create_body = {'port_securities': [{'empty_rule_action': 'deny',
                                               'denyflow_age': 300,
                                               'ip_mac_binding': True,
                                               'id': fake_sg_id,
                                               'name': fake_sg_name}]}
        ip_prefixes_dict = {
            fake_sg_id: [
                (ip['ip_address'] + '/32') for ip in port['fixed_ips']],
            fake_other_sg_id: ['31.0.0.4/32']}
        sg_rule_create_path = h_const.SECURITY_GROUP_RULES_RESOURCE
        port_get_path = "%s/%s" % ("vds/1.0/ports", port['id'])
        port_get_resp = {'port': {'id': port['id'], 'qos': None}}
        port_update_path = "vds/1.0/ports/%s" % (port['id'])
        port_dict = copy.deepcopy(port)
        port_dict.update({
            'port_securities': [
                {"port_security": sg_id}
                for sg_id in port['security_groups']],
            'dhcp_options': {'interface_mtu': 1400},
            'qos': port_get_resp['port']['qos']
        })
        for key in ('security_groups', 'status', 'binding:host_id',
                    'tenant_id', 'binding:vif_type', 'device_id',
                    'device_owner', 'extra_dhcp_opts'):
            del port_dict[key]
        port_update_body = {'port': port_dict}
        port_sg_bindings = [{'port_id': fake_instance_port_id,
                             'security_group_id': fake_sg_id}]
        def_sg_rules_get_path = "%s?portsecurity_id=%s" % (
            h_const.SECURITY_GROUP_RULES_RESOURCE, fake_def_sg_id)
        def_sg_rules_dict = {'securityrules': [fake_def_sg_rule_dict]}
        def_sg_rule_delete_path = "%s/%s" % (
            h_const.SECURITY_GROUP_RULES_RESOURCE, fake_def_sg_rule_dict['id'])
        def_sg_delete_path = "%s/%s" % (h_const.SECURITY_PORT_GROUPS_RESOURCE,
                                        fake_def_sg_id)
        sg_rules_get_path = "%s?portsecurity_id=%s" % (
            h_const.SECURITY_GROUP_RULES_RESOURCE, fake_sg_id)
        sg_rule_v4_dict = copy.deepcopy(
            fake_sg_rule_v4_dict['securityrules'][0])
        sg_rule_v4_dict.update({'id': '9c84ea96-5525-4d7c-845c-a5ac863f7908'})
        sg_rules_dict = {'securityrules': [sg_rule_v4_dict]}
        mock_rest_call.side_effect = [
            (requests.codes.not_found, None),
            (requests.codes.not_found, sg_create_body),
            (requests.codes.all_good, fake_sg_rule_v4_dict),
            (requests.codes.all_good, port_get_resp),
            (requests.codes.all_good, port_update_body),
            (requests.codes.all_good, def_sg_rules_dict),
            requests.codes.all_good,
            requests.codes.all_good,
            (requests.codes.not_found, None),
            (requests.codes.all_good, fake_sg_dict),
            (requests.codes.all_good, sg_rules_dict)]
        plugin.get_security_group.side_effect = lambda c, i: sg_objects.get(i)
        mock_get_ip_pref_sg.side_effect = \
            lambda c, i: ip_prefixes_dict.get(i, [])
        mock_get_sg_rules.return_value = fake_sg_rules_all
        plugin.get_security_group_rules.side_effect = \
            self.driver.get_security_group_rules
        mock_get_port_sg_bindings.side_effect = \
            lambda c, f: [[b for b in port_sg_bindings if b[k] in f[k]]
                          for k in f.keys()][0]
        other_sg_get_path = "%s/%s" % (
            h_const.SECURITY_PORT_GROUPS_RESOURCE, fake_other_sg_id)
        self.driver.update_port_postcommit(mech_context)
        mock_rest_call.assert_has_calls(
            [call(sg_get_path, 'GET'),
             call(sg_create_path, 'POST', sg_create_body),
             call(sg_rule_create_path, 'POST', fake_sg_rule_v4_dict),
             call(port_get_path, 'GET'),
             call(port_update_path, 'PUT', port_update_body),
             call(def_sg_rules_get_path, 'GET'),
             call(def_sg_rule_delete_path, 'DELETE'),
             call(def_sg_delete_path, 'DELETE'),
             call(other_sg_get_path, 'GET'),
             call(sg_get_path, 'GET'),
             call(sg_rules_get_path, 'GET')])

    @patch.object(SecurityGroupDbMixin, 'get_security_group_rules')
    @patch.object(md.H3CMechanismDriver, 'get_ip_prefixs_security_group')
    @patch.object(rest_client.RestClient, 'rest_call')
    def update_instance_port_add_fixed_ip(self,
                                          mock_rest_call,
                                          mock_get_ip_pref_sg,
                                          mock_get_sg_rules):
        port_orig = copy.deepcopy(fake_instance_port_object)
        port_orig.update({'security_groups': [fake_sg_id]})
        port = copy.deepcopy(port_orig)
        fixed_ip_add = {
            'subnet_id': '31f0a423-4e9b-4e6c-9707-3c055203aa03',
            'ip_address': '41.0.0.3'}
        port['fixed_ips'].append(fixed_ip_add)
        plugin = Mock()
        context = Mock()
        mech_context = Mock(current=port, original=port_orig, _plugin=plugin,
                            _plugin_context=context)
        sg_get_path = "%s/%s" % (h_const.SECURITY_PORT_GROUPS_RESOURCE,
                                 fake_sg_id)
        mock_get_sg_rules.return_value = fake_sg_rules_all
        ip_prefixes_dict = {
            fake_sg_id: [
                (ip['ip_address'] + '/32') for ip in port['fixed_ips']],
            fake_other_sg_id: ['31.0.0.4/32']}
        sg_rules_get_path = "%s?portsecurity_id=%s" % (
            h_const.SECURITY_GROUP_RULES_RESOURCE, fake_sg_id)
        sg_rule_v4_dict = copy.deepcopy(
            fake_sg_rule_v4_dict['securityrules'][0])
        sg_rule_v4_dict.update({'id': '9c84ea96-5525-4d7c-845c-a5ac863f7908'})
        sg_rules_dict = {'securityrules': [sg_rule_v4_dict]}
        port_get_path = "%s/%s" % ("vds/1.0/ports", port['id'])
        port_get_resp = {'port': {'id': port['id'], 'qos': None}}
        port_update_path = "vds/1.0/ports/%s" % (port['id'])
        port_dict = copy.deepcopy(port)
        port_dict.update({
            'port_securities': [
                {"port_security": sg_id}
                for sg_id in port['security_groups']],
            'dhcp_options': {'interface_mtu': 1400},
            'qos': port_get_resp['port']['qos']
        })
        for key in ('security_groups', 'status', 'binding:host_id',
                    'tenant_id', 'binding:vif_type', 'device_id',
                    'device_owner', 'extra_dhcp_opts'):
            del port_dict[key]
        port_update_body = {'port': port_dict}
        mock_rest_call.side_effect = [
            (requests.codes.all_good, fake_sg_dict),
            (requests.codes.all_good, sg_rules_dict),
            (requests.codes.all_good, port_get_resp),
            (requests.codes.all_good, port_update_body)]
        plugin.get_security_group_rules.side_effect = \
            self.driver.get_security_group_rules
        mock_get_ip_pref_sg.side_effect = \
            lambda c, i: ip_prefixes_dict.get(i, [])
        self.driver.update_port_postcommit(mech_context)
        mock_rest_call.assert_has_calls(
            [call(sg_get_path, 'GET'),
             call(sg_rules_get_path, 'GET'),
             call(port_get_path, 'GET'),
             call(port_update_path, 'PUT', port_update_body)])

    @patch.object(SecurityGroupDbMixin, 'get_security_group_rules')
    @patch.object(md.H3CMechanismDriver, 'get_ip_prefixs_security_group')
    @patch.object(rest_client.RestClient, 'rest_call')
    @patch.object(SecurityGroupDbMixin, '_get_port_security_group_bindings')
    def update_instance_port_remove_fixed_ip(self,
                                             mock_get_port_sg_bindings,
                                             mock_rest_call,
                                             mock_get_ip_pref_sg,
                                             mock_get_sg_rules):
        port = copy.deepcopy(fake_instance_port_object)
        port.update({'security_groups': [fake_sg_id]})
        port_orig = copy.deepcopy(port)
        fixed_ip_add = {
            'subnet_id': '31f0a423-4e9b-4e6c-9707-3c055203aa03',
            'ip_address': '41.0.0.3'}
        port_orig['fixed_ips'].append(fixed_ip_add)
        plugin = Mock()
        context = Mock()
        mech_context = Mock(current=port, original=port_orig, _plugin=plugin,
                            _plugin_context=context)
        port_sg_bindings = [{'port_id': fake_instance_port_id,
                             'security_group_id': fake_sg_id}]
        sg_get_path = "%s/%s" % (h_const.SECURITY_PORT_GROUPS_RESOURCE,
                                 fake_sg_id)
        mock_get_sg_rules.return_value = fake_sg_rules_all
        ip_prefixes_dict = {
            fake_sg_id: [
                (ip['ip_address'] + '/32') for ip in port['fixed_ips']],
            fake_other_sg_id: ['31.0.0.4/32']}
        sg_rules_get_path = "%s?portsecurity_id=%s" % (
            h_const.SECURITY_GROUP_RULES_RESOURCE, fake_sg_id)
        sg_rule_v4_dict = copy.deepcopy(
            fake_sg_rule_v4_dict['securityrules'][0])
        sg_rule_v4_dict.update({'id': '9c84ea96-5525-4d7c-845c-a5ac863f7908'})
        sg_rules_dict = {'securityrules': [sg_rule_v4_dict]}
        port_get_path = "%s/%s" % ("vds/1.0/ports", port['id'])
        port_get_resp = {'port': {'id': port['id'], 'qos': None}}
        port_update_path = "vds/1.0/ports/%s" % (port['id'])
        port_dict = copy.deepcopy(port)
        port_dict.update({
            'port_securities': [
                {"port_security": sg_id}
                for sg_id in port['security_groups']],
            'dhcp_options': {'interface_mtu': 1400},
            'qos': port_get_resp['port']['qos']
        })
        for key in ('security_groups', 'status', 'binding:host_id',
                    'tenant_id', 'binding:vif_type', 'device_id',
                    'device_owner', 'extra_dhcp_opts'):
            del port_dict[key]
        port_update_body = {'port': port_dict}
        mock_get_port_sg_bindings.side_effect = \
            lambda c, f: [[b for b in port_sg_bindings if b[k] in f[k]]
                          for k in f.keys()][0]
        mock_rest_call.side_effect = [
            (requests.codes.all_good, fake_sg_dict),
            (requests.codes.all_good, sg_rules_dict),
            (requests.codes.all_good, port_get_resp),
            (requests.codes.all_good, port_update_body)]
        plugin.get_security_group_rules.side_effect = \
            self.driver.get_security_group_rules
        mock_get_ip_pref_sg.side_effect = \
            lambda c, i: ip_prefixes_dict.get(i, [])
        self.driver.update_port_postcommit(mech_context)
        mock_rest_call.assert_has_calls(
            [call(sg_get_path, 'GET'),
             call(sg_rules_get_path, 'GET'),
             call(port_get_path, 'GET'),
             call(port_update_path, 'PUT', port_update_body)])

    def test_delete_port_postcommit(self):
        self.delete_router_interface_port()
        self.delete_dhcp_port()
        self.delete_instance_port()

    def delete_router_interface_port(self):
        port = copy.deepcopy(fake_interface_port_object)
        plugin = Mock()
        context = Mock()
        mech_context = Mock(current=port, _plugin=plugin,
                            _plugin_context=context)
        self.driver.delete_port_postcommit(mech_context)

    @patch.object(rest_client.RestClient, 'rest_call')
    def delete_dhcp_port(self, mock_rest_call):
        port = copy.deepcopy(fake_dhcp_port_object)
        plugin = Mock()
        context = Mock()
        mech_context = Mock(current=port, _plugin=plugin,
                            _plugin_context=context)
        subnet = copy.deepcopy(fake_subnet_object)
        plugin.get_subnet.return_value = subnet
        subnet_dict = copy.deepcopy(subnet)
        update_path = "vds/1.0/subnets/%s" % (subnet['id'])
        update_body = {'subnet': subnet_dict}
        path = "vds/1.0/ports/%s" % (port['id'])
        plugin.get_ports.return_value = []
        mock_rest_call.side_effect = [(requests.codes.all_good, update_body),
                                      requests.codes.all_good]
        mech_context._network_context._network = fake_network_object
        self.driver.delete_port_postcommit(mech_context)
        mock_rest_call.assert_has_calls([call(update_path, 'PUT', update_body),
                                         call(path, 'DELETE')])

    @patch.object(md.H3CMechanismDriver, 'get_ip_prefixs_security_group')
    @patch.object(SecurityGroupDbMixin, 'get_security_group_rules')
    @patch.object(SecurityGroupDbMixin, '_get_port_security_group_bindings')
    @patch.object(rest_client.RestClient, 'rest_call')
    def delete_instance_port(self, mock_rest_call, mock_get_port_sg_bindings,
                             mock_get_sg_rules, mock_get_ip_pref_sg):
        port = copy.deepcopy(fake_instance_port_object)
        plugin = Mock()
        context = Mock()
        mech_context = Mock(current=port, _plugin=plugin,
                            _plugin_context=context)
        port_del_path = "vds/1.0/ports/%s" % (port['id'])
        port_sg_bindings = [{'port_id': '5d552fb4-cd3b-4ab4-8b37-41a33594cd43',
                             'security_group_id': fake_def_sg_id}]
        sg_rules_path = "%s?portsecurity_id=%s" % (
            h_const.SECURITY_GROUP_RULES_RESOURCE, fake_sg_id)
        sg_rule_v4_dict = copy.deepcopy(
            fake_sg_rule_v4_dict['securityrules'][0])
        sg_rule_v4_dict_id = '9c84ea96-5525-4d7c-845c-a5ac863f7908'
        sg_rule_v4_dict.update({'id': sg_rule_v4_dict_id})
        sg_rules_dict = {'securityrules': [sg_rule_v4_dict]}
        sg_rule_v4_del_path = "%s/%s" % (
            h_const.SECURITY_GROUP_RULES_RESOURCE, sg_rule_v4_dict_id)
        sg_del_path = "%s/%s" % (h_const.SECURITY_PORT_GROUPS_RESOURCE,
                                 fake_sg_id)
        def_sg_get_path = "%s/%s" % (h_const.SECURITY_PORT_GROUPS_RESOURCE,
                                     fake_def_sg_id)
        ip_prefixes_dict = {fake_other_sg_id: ['31.0.0.4/32']}
        def_sg_rules_path = "%s?portsecurity_id=%s" % (
            h_const.SECURITY_GROUP_RULES_RESOURCE, fake_def_sg_id)
        def_sg_rule_del_path = "%s/%s" % (
            h_const.SECURITY_GROUP_RULES_RESOURCE, fake_def_sg_rule_del_id)
        sg_rule_create_path = h_const.SECURITY_GROUP_RULES_RESOURCE
        other_sg_get_path = "%s/%s" % (h_const.SECURITY_PORT_GROUPS_RESOURCE,
                                       fake_other_sg_id)
        sg_get_path = "%s/%s" % (h_const.SECURITY_PORT_GROUPS_RESOURCE,
                                 fake_sg_id)
        mock_rest_call.side_effect = [
            requests.codes.all_good,
            (requests.codes.all_good, sg_rules_dict),
            requests.codes.all_good,
            requests.codes.all_good,
            (requests.codes.all_good, fake_def_sg_dict),
            (requests.codes.all_good, fake_def_sg_rules_dict),
            requests.codes.all_good,
            (requests.codes.all_good, fake_def_sg_rule_cre_dict),
            (requests.codes.not_found, None),
            (requests.codes.not_found, None)]
        mock_get_port_sg_bindings.side_effect = \
            lambda c, f: [[b for b in port_sg_bindings if b[k] in f[k]]
                          for k in f.keys()][0]
        mock_get_sg_rules.return_value = fake_sg_rules_all
        plugin.get_security_group_rules.side_effect = \
            self.driver.get_security_group_rules
        mock_get_ip_pref_sg.side_effect = \
            lambda c, i: ip_prefixes_dict.get(i, [])
        mech_context._network_context._network = fake_network_object
        plugin.get_ports_count.return_value = 0
        self.driver.delete_port_postcommit(mech_context)
        mock_rest_call.assert_has_calls(
            [call(port_del_path, 'DELETE'),
             call(sg_rules_path, 'GET'),
             call(sg_rule_v4_del_path, 'DELETE'),
             call(sg_del_path, 'DELETE'),
             call(def_sg_get_path, 'GET'),
             call(def_sg_rules_path, 'GET'),
             call(def_sg_rule_del_path, 'DELETE'),
             call(sg_rule_create_path, 'POST', fake_def_sg_rule_cre_dict),
             call(other_sg_get_path, 'GET'),
             call(sg_get_path, 'GET')])
