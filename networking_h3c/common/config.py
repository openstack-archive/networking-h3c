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

from networking_h3c._i18n import _
from oslo_config import cfg

CONTROLLER_OPTS = [
    cfg.StrOpt('url', default='https://127.0.0.1:8443',
               help=_('The H3C vcf controller api base url')),
    cfg.StrOpt('username', default='sdn',
               help=_('Controller username')),
    cfg.StrOpt('password', default='skyline',
               help=_('Controller password')),
    cfg.StrOpt('domain', default='sdn',
               help=_('Controller domain')),
    cfg.StrOpt('timeout', default=1800,
               help=_('Controller timeout')),
    cfg.IntOpt('retry', default=5,
               help=_('The retry times for connecting controller')),
    cfg.StrOpt('vnic_type', default='ovs',
               help=_('port binding vnic_type default is ovs')),
    cfg.BoolOpt('hybrid_vnic', default=True,
                help=_('Plug-in working in hybrid_vnic mode')),
    cfg.BoolOpt('ip_mac_binding', default=True,
                help=_('ipmac binding')),
    cfg.IntOpt('denyflow_age', default=300,
               help=_('denyflow_age')),
    cfg.BoolOpt('white_list', default=False,
                help=_('white_list')),
    cfg.BoolOpt('auto_create_tenant_to_vcfc', default=True,
                help=_('auto create tenant to vcfc')),
    cfg.BoolOpt('router_binding_public_vrf', default=False,
                help=_('router_binding_public_vrf')),
    cfg.BoolOpt('enable_subnet_dhcp', default=True,
                help=_('enable_subnet_dhcp')),
    cfg.IntOpt('dhcp_lease_time', default=365,
               help=_('dhcp_lease_time')),
    cfg.StrOpt('lb_type', default='GATEWAY',
               help=_('Loadbalancer type')),
    cfg.StrOpt('firewall_type', default='GATEWAY',
               help=_('firewall_type')),
    cfg.StrOpt('resource_mode', default='NFV',
               help=_('resource_mode')),
    cfg.BoolOpt('auto_delete_tenant_to_vcfc', default=True,
                help=_('auto_delete_tenant_to_vcfc')),
    cfg.BoolOpt('auto_create_resource', default=True,
                help=_('auto_create_resource')),
    cfg.BoolOpt('nfv_ha', default=True,
                help=_('nfv_ha')),
    cfg.StrOpt('vds_name', default='VDS1',
               help=_('vds_name')),
    cfg.BoolOpt('enable_metadata', default=False,
                help=_('plugin enable metadata ability')),
    cfg.BoolOpt('use_neutron_credential', default=False,
                help=_('use_neutron_credential')),
    cfg.BoolOpt('enable_security_group', default=True,
                help=_('enable_security_group')),
    cfg.BoolOpt('disable_internal_l3flow_offload', default=True,
                help=_('disable_internal_l3flow_offload')),
    cfg.BoolOpt('firewall_force_audit', default=False,
                help=_('firewall_force_audit')),
    cfg.BoolOpt('enable_l3_router_rpc_notify', default=False,
                help=_('enable_l3_router_rpc_notify')),
    cfg.BoolOpt('output_json_log', default=False,
                help=_('output_json_log')),
    cfg.BoolOpt('lb_enable_snat', default=False,
                help=_('lb_enable_snat')),
    cfg.StrOpt('empty_rule_action', default='deny',
               help=_('empty_rule_action')),
    cfg.BoolOpt('enable_l3_vxlan', default=False,
                help=_('enable_l3_vxlan')),
    cfg.ListOpt('l3_vni_ranges', default=[],
                help=_('l3_vni_ranges')),
    cfg.StrOpt('vendor_rpc_topic', default='VENDOR_PLUGIN',
               help=_('vendor_rpc_topic')),
    cfg.StrOpt('vsr_descriptor_name', default='VSR_IRF',
               help=_('vsr_descriptor_name')),
    cfg.StrOpt('vlb_descriptor_name', default='VLB_IRF',
               help=_('vlb_descriptor_name')),
    cfg.StrOpt('vfw_descriptor_name', default='VFW_IRF',
               help=_('vfw_descriptor_name'))
]

cfg.CONF.register_opts(CONTROLLER_OPTS, "VCFCONTROLLER")
