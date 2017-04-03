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
import json
import oslo_messaging
import socket
import threading
import uuid
from keystoneclient import session
from keystoneclient.auth.identity import v3
from keystoneclient.v3 import client as k_client
from networking_h3c._i18n import _LE
from networking_h3c.common import config  # noqa
from networking_h3c.common import constants as h_const
from networking_h3c.common import exceptions  # noqa
from networking_h3c.common import rest_client
from networking_h3c.common import topics as h3c_topics
from neutron.agent import rpc as agent_rpc
from neutron.agent import securitygroups_rpc
from neutron.common import constants
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.db import db_base_plugin_v2
from neutron.db import models_v2
from neutron.db import securitygroups_db as sg_db
from neutron.extensions import external_net
from neutron.extensions import multiprovidernet as mpnet
from neutron.extensions import providernet as provider
from neutron.extensions import securitygroup as ext_sg
from neutron.plugins.common import constants as common_constants
from neutron.plugins.ml2 import driver_api
from neutron.plugins.ml2 import driver_context
from neutron_lib import context as neutron_context
from neutron_lib.api import attributes
from neutron_lib.api.definitions import portbindings
from oslo_config import cfg
from oslo_log import log as logging
from oslo_serialization import jsonutils

LOG = logging.getLogger(__name__)

NIC_NAME_LEN = 14
LOOP_INTERVAL = 120


class H3CResourceApi(object):
    """From agent side of plugin to agent RPC API."""

    def __init__(self, topic):
        target = oslo_messaging.Target(topic=topic, version='1.0')
        self.client = n_rpc.get_client(target)
        super(H3CResourceApi, self).__init__()

    def notify_resource_changed(self, context, action, body, tenant_id):
        """Make a RPC to notify service of a resource changed ."""
        cctxt = self.client.prepare()
        return cctxt.cast(context, 'notify_resource_changed',
                          action=action,
                          body=body,
                          tenant_id=tenant_id)


class FakeSubnetContext(driver_context.MechanismDriverContext):
    def __init__(self, plugin, plugin_context, subnet, original_subnet=None):
        super(FakeSubnetContext, self).__init__(plugin, plugin_context)
        self._subnet = subnet
        self._original_subnet = original_subnet

    @property
    def current(self):
        return self._subnet

    @property
    def original(self):
        return self._original_subnet


class NeutronDB(db_base_plugin_v2.NeutronDbPluginV2,
                sg_db.SecurityGroupDbMixin):
    """Access to Neutron DB.

    Provides access to Neutron db for ML2 mechanism driver of H3C
    """

    def __init__(self):
        super(NeutronDB, self).__init__()


class H3CMechanismDriver(driver_api.MechanismDriver):
    """ML2 Mechanism driver for H3C.

    """

    # history
    #   1.0 Initial version
    #   1.1 Support Security Group RPC
    target = oslo_messaging.Target(version='1.2')

    def __init__(self):
        super(H3CMechanismDriver, self).__init__()

        # init for for h3c neutron ml2 plugin
        self.client = rest_client.RestClient()
        self.neutron_db = NeutronDB()
        self.sg_enabled = securitygroups_rpc.is_firewall_enabled()
        self.vif_details = {portbindings.CAP_PORT_FILTER: self.sg_enabled,
                            portbindings.OVS_HYBRID_PLUG: self.sg_enabled}
        self.keystone_client = None
        self.vds_id = None

        self.vnic_type = cfg.CONF.VCFCONTROLLER.vnic_type
        self.hybrid_vnic = cfg.CONF.VCFCONTROLLER.hybrid_vnic
        self.ip_mac_binding = cfg.CONF.VCFCONTROLLER.ip_mac_binding
        self.denyflow_age = cfg.CONF.VCFCONTROLLER.denyflow_age
        self.enable_subnet_dhcp = cfg.CONF.VCFCONTROLLER.enable_subnet_dhcp
        self.nfv_ha = cfg.CONF.VCFCONTROLLER.nfv_ha
        self.enable_security_group = \
            cfg.CONF.VCFCONTROLLER.enable_security_group
        self.dhcp_lease_time = cfg.CONF.VCFCONTROLLER.dhcp_lease_time
        self.enable_metadata = cfg.CONF.VCFCONTROLLER.enable_metadata
        self.empty_rule_action = cfg.CONF.VCFCONTROLLER.empty_rule_action
        self.admin_context = neutron_context.get_admin_context()
        self.h3c_agent_rpc = H3CResourceApi(h3c_topics.RESOURCE_DRIVER_TOPIC)

        self.setup_rpc()

        self.sg_sync_mutex_lock = threading.Lock()

    def initialize(self):
        """Perform driver initialization.

        Called after all drivers have been loaded and the database has
        been initialized. No abstract methods defined below will be
        called prior to this method being called.
        """
        pass

    def security_groups_rule_updated(self, context, **kwargs):
        """Callback for security group rule update."""
        security_groups = kwargs.get('security_groups', [])
        LOG.debug("Security group rule updated: %s", security_groups)

        if not self.enable_security_group:
            return

        try:
            self.sg_sync_mutex_lock.acquire()
            # sync exist secruity group with vcfc
            for security_group_id in security_groups:
                self._sync_security_group_rules(
                    context, self, security_group_id)
        except Exception as e:
            LOG.error(_LE("Failed to security group sync, "
                          "update_port_postcommit, exception is %(excep)s"),
                      {'excep': str(e)})
        finally:
            self.sg_sync_mutex_lock.release()

    def security_groups_member_updated(self, context, **kwargs):
        """Callback for security group member update."""
        security_groups = kwargs.get('security_groups', [])
        LOG.debug("Security group member updated: %s", security_groups)

    def security_groups_provider_updated(self, context, **kwargs):
        """Callback for security group provider update."""
        LOG.debug("Provider rule updated")

    def get_keystone_client(self):

        username = cfg.CONF.keystone_authtoken.username
        password = cfg.CONF.keystone_authtoken.password
        project_name = cfg.CONF.keystone_authtoken.project_name
        auth_url = cfg.CONF.keystone_authtoken.auth_url
        if not auth_url.endswith('/v3'):
            auth_url += '/v3'
        user_domain_name = cfg.CONF.keystone_authtoken.user_domain_name
        project_domain_name = cfg.CONF.keystone_authtoken.project_domain_name
        auth = v3.Password(auth_url=auth_url,
                           username=username,
                           password=password,
                           project_name=project_name,
                           user_domain_name=user_domain_name,
                           project_domain_name=project_domain_name)
        sess = session.Session(auth=auth)
        keystone_client = k_client.Client(session=sess)

        return keystone_client

    def get_vds_id_from_vcfc(self, vds_name):
        """Get vds from vcfc.

        :param vds_name: used for filter vds
        """
        vds_uuid = None
        get_path = "%s?name=%s" % (h_const.VDS_RESOURCE, vds_name)
        try:
            resp_status, resp_dict = self.client.rest_call(get_path, 'GET')
            vds_uuid = resp_dict['vds'][0]['uuid']
        except Exception as e:
            LOG.error(_LE("H3C driver get vds id exception: %s"), e)
        LOG.debug("H3C driver get vds id %s by vdsname %s", vds_uuid, vds_name)
        return vds_uuid

    def setup_rpc(self):
        """Define the listening consumers for the agent"""
        if self.enable_security_group is True:
            self.topic = topics.AGENT
            self.endpoints = [self]
            consumers = [[topics.SECURITY_GROUP, topics.UPDATE]]
            self.connection = agent_rpc.create_consumers(self.endpoints,
                                                         self.topic,
                                                         consumers)

    def get_security_group_rules(self, context, filters):
        """get security_groups for sync"""
        security_group_rules = \
            self.neutron_db.get_security_group_rules(context, filters)
        for key in filters.keys():
            security_group_rules = [sg_rule for sg_rule in security_group_rules
                                    if sg_rule[key] in filters[key]]
        return security_group_rules

    def get_security_group_rule(self, context, security_group_id):
        """get security_groups for sync"""
        security_group_rules = self.neutron_db. \
            get_security_group_rules(context, {'security_group_id': [id]})
        return security_group_rules

    def _process_provider_create(self, context, network):

        segment = network
        """if there are more than one segments, we only support one."""
        if attributes.is_attr_set(network.get(mpnet.SEGMENTS)):
            segment = network.get(mpnet.SEGMENTS)[0]

        physical_network = 0
        network_type = segment.get(provider.NETWORK_TYPE)
        segmentation_id = segment.get(provider.SEGMENTATION_ID)

        network_type_set = attributes.is_attr_set(network_type)
        segmentation_id_set = attributes.is_attr_set(segmentation_id)

        network_type = 'vxlan'
        if not (network_type_set or segmentation_id_set):
            segmentation_id = None

        hasExternalPara = network.get(external_net.EXTERNAL)
        "external network only should be vlan in vcfc"
        if hasExternalPara and hasExternalPara is True:
            network_type = 'vlan'

        return network_type, physical_network, segmentation_id

    def create_network_postcommit(self, mech_context):
        LOG.debug("H3C ML2 plugin create_network_postcommit called")

        network = copy.deepcopy(mech_context.current)
        context = mech_context._plugin_context

        LOG.debug("context = %s", context.__dict__)
        LOG.debug("network from ml2 is %s", network)

        delete_shared_flag = True
        if network.get(external_net.EXTERNAL) is False:
            if network[provider.NETWORK_TYPE] == 'vlan':
                if self.hybrid_vnic is True:
                    network[provider.NETWORK_TYPE] = 'vxlan'
                    delete_shared_flag = False
            else:
                delete_shared_flag = False

        if delete_shared_flag is True and 'shared' in network:
            del network['shared']

        resource_path = "vds/1.0/networks"

        if self.vds_id is None:
            self.vds_id = \
                self.get_vds_id_from_vcfc(cfg.CONF.VCFCONTROLLER.vds_name)
        network['provider:domain'] = self.vds_id

        request_dic = {"networks": [network]}
        response_status, resp_body = self.client.rest_call(resource_path,
                                                           "POST", request_dic)

        LOG.debug("after create network the resp_body from vcfc is %s",
                  resp_body)
        LOG.debug("after create network the resp_status from vcfc is %s",
                  response_status)

        LOG.debug("H3C ML2 plugin create_network_postcommit exited")

    def update_network_postcommit(self, mech_context):
        LOG.debug("H3C ML2 plugin update_network_postcommit called")

        current_network = mech_context.current
        original_network = mech_context.original

        delete_shared_flag = True
        if current_network.get(external_net.EXTERNAL) is False:
            if current_network[provider.NETWORK_TYPE] == 'vlan':
                if self.hybrid_vnic is True:
                    current_network[provider.NETWORK_TYPE] = 'vxlan'
                    delete_shared_flag = False
            else:
                delete_shared_flag = False

        if delete_shared_flag is True and 'shared' in current_network:
            del current_network['shared']

        LOG.debug("network from ml2 is %s", current_network)

        resource_path = "vds/1.0/networks/%s" % (original_network['id'])
        request_dic = {"network": current_network}

        response_status, resp_body = \
            self.client.rest_call(resource_path, "PUT", request_dic)
        LOG.debug("after update network the resp_body from vcfc is %s",
                  resp_body)
        LOG.debug("after update network the resp_status from vcfc is %s",
                  response_status)

        LOG.debug("H3C ML2 plugin update_network_postcommit exited")

    def delete_network_precommit(self, mech_context):
        """Delete Network from the plugin specific database table."""
        network = mech_context.current

        LOG.debug("H3C ML2 plugin delete_network_precommit called")

        LOG.debug("network_id from ml2 is %s", network['id'])
        resource_path = "vds/1.0/networks/%s" % (network['id'])
        response_status = self.client.rest_call(resource_path, "DELETE")

        LOG.debug("after delete networks the resp_status from vcfc is %s",
                  response_status)
        LOG.debug('H3C ML2 plugin network %s deleted', network['id'])

        LOG.debug("H3C ML2 plugin delete_network_precommit exited")

    def _reduce_create_subnet_parameter_for_vcf(self, subnet):
        reduced_subnet = subnet
        if 'allocation_pools' in reduced_subnet:
            if (reduced_subnet['allocation_pools'] ==
                    attributes.ATTR_NOT_SPECIFIED):
                LOG.debug("Create subnet allocation_pools = "
                          "ATTR_NOT_SPECIFIED")
                del reduced_subnet['allocation_pools']

        if 'enable_dhcp' in reduced_subnet:
            if reduced_subnet['enable_dhcp'] == attributes.ATTR_NOT_SPECIFIED:
                LOG.debug("Create subnet enable_dhcp = ATTR_NOT_SPECIFIED")
                del reduced_subnet['enable_dhcp']

        return reduced_subnet

    def create_subnet_postcommit(self, mech_context):
        subnet = mech_context.current
        context = mech_context._plugin_context

        LOG.debug("H3C ML2 plugin create_subnetwork_postcommit called")

        LOG.debug("context = %s", context.__dict__)
        LOG.debug("subnet from ml2 is %s", subnet)

        subnet_to_vcf = self._reduce_create_subnet_parameter_for_vcf(subnet)

        if self.vds_id is None:
            self.vds_id = \
                self.get_vds_id_from_vcfc(cfg.CONF.VCFCONTROLLER.vds_name)
        subnet_to_vcf['domain'] = self.vds_id

        subnet_to_vcf['leaseTime'] = {'day': self.dhcp_lease_time}
        if self.enable_subnet_dhcp is False:
            subnet_to_vcf['enable_dhcp'] = False
        request_dic = {"subnets": [subnet_to_vcf]}
        resource_path = "vds/1.0/subnets"

        LOG.debug("subnet to vcfc is %s", subnet_to_vcf)
        response_status, resp_body = \
            self.client.rest_call(resource_path, "POST", request_dic)
        LOG.debug("after create subnet the resp_body from vcfc is %s",
                  resp_body)
        LOG.debug("after create subnet the resp_status from vcfc is %s",
                  response_status)

        LOG.debug("H3C ML2 plugin create_subnetwork_postcommit exited")

    def update_subnet_precommit(self, mech_context):
        LOG.debug("H3C ML2 plugin update_subnet_precommit called")
        subnet = mech_context.current
        resource_path = "vds/1.0/subnets/%s" % (mech_context.current['id'])
        response_status, resp_body = \
            self.client.rest_call(resource_path, "GET")
        if resp_body['subnet']['enable_dhcp'] != subnet['enable_dhcp']:
            raise Exception("The DHCP field couldn't be changed")
        LOG.debug("H3C ML2 plugin update_subnet_precommit exited")

    def update_subnet_postcommit(self, mech_context):
        subnet = mech_context.current
        context = mech_context._plugin_context
        plugin = mech_context._plugin

        LOG.debug("H3C ML2 plugin update_subnet_postcommit called")

        LOG.debug("context = %s", context.__dict__)
        LOG.debug("subnet from ml2 is %s", subnet)

        if self.enable_metadata:
            port_filter = {'fixed_ips': {'subnet_id': [subnet['id']]},
                           'device_owner': ['network:dhcp']}
            ports = plugin.get_ports(context, port_filter)
            for port in ports:
                host_routes = {'nexthop': port['fixed_ips'][0]['ip_address'],
                               'destination': '169.254.169.254/32'}
                subnet['host_routes'].append(host_routes)

        resource_path = "vds/1.0/subnets/%s" % (subnet['id'])
        request_dic = {"subnet": subnet}
        response_status, resp_body = self.client.rest_call(resource_path,
                                                           "PUT", request_dic)
        LOG.debug("after update subnet the resp_body from vcfc is %s",
                  resp_body)
        LOG.debug("after update subnet the resp_status from vcfc is %s",
                  response_status)

        LOG.debug("H3C ML2 plugin update_subnet_postcommit exited")

    def delete_subnet_postcommit(self, mech_context):
        subnet = mech_context.current
        context = mech_context._plugin_context
        LOG.debug("H3C ML2 plugin delete_subnetwork_postcommit called")

        LOG.debug("context is %s", context.__dict__)
        LOG.debug("subnet id from ml2 is %s", subnet['id'])

        resource_path = "vds/1.0/subnets/%s" % (subnet['id'])
        self.client.rest_call(resource_path, "DELETE")
        LOG.debug("H3C ML2 plugin subnet %s deleted", subnet['id'])
        LOG.debug("H3C ML2 plugin delete_subnetwork_postcommit exited")

    def _construct_port_for_vcfc_create(self, port):
        result = {
            "status": port['status'],
            "binding:host_id": port['binding:host_id'],
            "device_owner": port['device_owner'],
            "fixed_ips": [
                {
                    "subnet_id": subnet['subnet_id'],
                    "ip_address": subnet['ip_address']
                } for subnet in port['fixed_ips']
                ],
            "id": port['id'],
            "device_id": port['device_id'],
            "name": port['name'],
            "admin_state_up": port['admin_state_up'],
            "network_id": port['network_id'],
            "tenant_id": port['tenant_id'],
            "binding:vif_type": port['binding:vif_type'],
            "mac_address": port['mac_address']
        }
        if self.enable_security_group and "security_groups" in port:
            if len(port['security_groups']) != 0:
                result['port_securities'] = [{"port_security": sg_id}
                                             for sg_id
                                             in port['security_groups']]
            else:
                result['port_securities'] = []

        extra_dhcp_opts = port.get('extra_dhcp_opts', [])
        result['dhcp_options'] = None
        for extra_dhcp_opt in extra_dhcp_opts:
            if extra_dhcp_opt['opt_name'] == 'mtu' \
                    and extra_dhcp_opt['ip_version'] == 4:
                result['dhcp_options'] = {}
                result['dhcp_options']['interface_mtu'] = \
                    int(extra_dhcp_opt['opt_value'])
                del port['extra_dhcp_opts']
                break

        return result

    def _process_port_binding_create(self, context, attrs):
        if attrs is not None:
            attrs['binding:vif_type'] = ''

    def _constructive_port_for_updation(self, current_port, original_port):
        if self.enable_security_group and "security_groups" in current_port:
            if len(current_port['security_groups']) != 0:
                current_port['port_securities'] = \
                    [{"port_security": sg_id}
                     for sg_id in current_port['security_groups']]
            else:
                current_port['port_securities'] = []
            del current_port['security_groups']

        # port_extensions may store in original_port
        if 'port_extensions' in current_port:
            port_extension = current_port['port_extensions']
            current_port['domain'] = port_extension['domain']
            del current_port['port_extensions']

        # extra_dhcp_opts may store in current_port
        extra_dhcp_opts = current_port.get('extra_dhcp_opts', [])
        current_port['dhcp_options'] = None
        for extra_dhcp_opt in extra_dhcp_opts:
            if extra_dhcp_opt['opt_name'] == 'mtu' \
                    and extra_dhcp_opt['ip_version'] == 4:
                current_port['dhcp_options'] = {}
                current_port['dhcp_options']['interface_mtu'] = int(
                    extra_dhcp_opt['opt_value'])
                break

        # get port qos info for updating port
        resource_path = "%s/%s" % ("vds/1.0/ports", current_port['id'])
        resp_status, resp_body = self.client.rest_call(resource_path, "GET")
        if resp_status != 404:
            port_vcfc = resp_body["port"]
            LOG.debug("port info is %s", port_vcfc)
            # construct port qos info, super update port will filter qos field,
            # so we can use 'port' directly
            if "qos" in port_vcfc:
                current_port['qos'] = port_vcfc['qos']

        try:
            del current_port['status']
            del current_port['binding:host_id']
            del current_port['tenant_id']
            del current_port['binding:vif_type']
            del current_port['device_id']
            del current_port['device_owner']
            del current_port['extra_dhcp_opts']
        except Exception as e:
            LOG.error(_LE("Failed to _constructive_port_for_updation "
                          "for port %(port)s, exception is %(exc)s"),
                      {'port': current_port, 'exc': str(e)})

        return {"port": current_port}

    def get_host_from_vcfc(self, host_ip):
        LOG.debug("H3C ML2 plugin get_host_from_vcfc called")
        LOG.debug("host_ip=%s", host_ip)

        host = None
        resource_path = "%s?ip=%s" % (h_const.AGENTS_RESOURCE, host_ip)
        resp_status, resp_body = self.client.rest_call(resource_path, "GET")
        LOG.debug("after get_host_from_vcfc the resp_body from vcfc is %s",
                  resp_body)
        LOG.debug("after get_host_from_vcfc the resp_status from vcfc is %s",
                  resp_status)
        if resp_status == 200:
            if resp_body['host']:
                host = resp_body['host'][0]

        LOG.debug("H3C ML2 plugin get_host_from_vcfc exited")
        return host

    def bind_port(self, context):
        LOG.debug("Attempting to bind port %s on network %s",
                  context.current['id'],
                  context.network.current['id'])

        vif_details = {}
        vif_type = 'ovs'

        for segment in context.network.network_segments:
            if self.check_segment(segment):
                binding_agents = \
                    context._plugin.get_agents(context._plugin_context,
                                               filters={
                                                   'host':
                                                       [context._binding.host]
                                               })

                if not binding_agents:
                    host = self.get_host_from_vcfc(
                        socket.gethostbyname(context._binding.host))
                    if host is None:
                        vif_type = 'dvs'
                else:
                    binding_agent = binding_agents[0]
                    if binding_agent['binary'] == 'neutron-openvswitch-agent':
                        vif_details = self.vif_details

                context.set_binding(segment[driver_api.ID],
                                    vif_type,
                                    vif_details,
                                    status=constants.PORT_STATUS_ACTIVE)
                LOG.debug("Bound using segment: %s", segment)
                return
            else:
                LOG.debug("Refusing to bind port for segment ID %s, "
                          "segment %s, phys net %s, and network type %s",
                          segment[driver_api.ID],
                          segment[driver_api.SEGMENTATION_ID],
                          segment[driver_api.PHYSICAL_NETWORK],
                          segment[driver_api.NETWORK_TYPE])

    def check_segment(self, segment):
        """Verify a segment is valid for the OpenDaylight MechanismDriver.

        Verify the requested segment is supported by ODL and return True or
        False to indicate this to callers.
        """
        network_type = segment[driver_api.NETWORK_TYPE]
        return network_type in [common_constants.TYPE_VLAN,
                                common_constants.TYPE_VXLAN]

    def create_port_postcommit(self, mech_context):
        LOG.debug("H3C ML2 plugin create_port_postcommit called")

        port = copy.deepcopy(mech_context.current)
        context = mech_context._plugin_context
        plugin = mech_context._plugin

        LOG.debug("context = %s", context.__dict__)
        LOG.debug("port from ml2 is %s", port)
        device_owner = port.get('device_owner', None)
        filter_device_owner = ['network:floatingip',
                               'network:router_interface',
                               'network:router_gateway',
                               'network:vsm_router_interface']
        if device_owner is not None and device_owner in filter_device_owner:
            LOG.debug("H3C ML2 plugin return for careless device_owner "
                      "%s port %s", device_owner, port)
            return

        if device_owner == 'network:dhcp':
            subnet_id = port['fixed_ips'][0]['subnet_id']
            subnet = plugin.get_subnet(context, subnet_id)
            subnet_mech_context = FakeSubnetContext(plugin,
                                                    context,
                                                    subnet)
            self.update_subnet_postcommit(subnet_mech_context)

        if self.enable_security_group:
            # create security group
            self.create_security_group_rule_for_ip_add(context,
                                                       plugin,
                                                       port)

        self._process_port_binding_create(context, port)

        port_to_vcfc = self._construct_port_for_vcfc_create(port)
        request_dic = {"ports": [port_to_vcfc]}
        resource_path = "vds/1.0/ports"
        LOG.debug("create port the request content is %s", request_dic)
        response_status, resp_body = \
            self.client.rest_call(resource_path, "POST", request_dic)
        LOG.debug("H3C ML2 plugin create port is %s", resp_body)

        LOG.debug("H3C ML2 plugin create_port_postcommit exited")

    def update_port_postcommit(self, mech_context):
        LOG.debug("H3C ML2 plugin update_port_postcommit called")

        current_port = copy.deepcopy(mech_context.current)
        original_port = copy.deepcopy(mech_context.original)
        plugin = mech_context._plugin
        context = mech_context._plugin_context

        filter_device_owner = ['network:floatingip',
                               'network:router_interface',
                               'network:router_gateway',
                               'network:vsm_router_interface']

        device_owner = current_port.get('device_owner', None)
        if device_owner == 'network:dhcp':
            if not current_port['fixed_ips']:
                return
            elif (current_port['fixed_ips'] != [] and
                    original_port['fixed_ips'] == []):
                resource_path = "vds/1.0/ports"
                port_to_vcfc = self._construct_port_for_vcfc_create(
                    current_port)
                request_dic = {"ports": [port_to_vcfc]}
                self.client.rest_call(resource_path, "POST", request_dic)
                return

        if (current_port["device_owner"] not in filter_device_owner and
                ("binding:host_id" not in current_port or
                 'port_extensions' in original_port or
                 ("binding:host_id" in current_port and
                  original_port["binding:host_id"] ==
                  current_port["binding:host_id"]))):
            if self.enable_security_group:
                self.create_sg_for_update_port(plugin,
                                               context,
                                               current_port,
                                               original_port)

            # update port
            LOG.debug("current port is %s", json.dumps(current_port, indent=4))
            self._process_port_binding_create(context, current_port)
            request_dic = self._constructive_port_for_updation(
                current_port, original_port)
            resource_path = "vds/1.0/ports/%s" % (current_port['id'])

            LOG.debug("update port to vcfc is %s", request_dic)
            response_status, resp_body = self.client.rest_call(
                resource_path, "PUT", request_dic)
            LOG.debug("after update port the resp_body from vcfc is %s",
                      resp_body)
            LOG.debug("after update port the resp_status from vcfc is %s",
                      response_status)

            if self.enable_security_group:
                current_port = copy.deepcopy(mech_context.current)
                original_port = copy.deepcopy(mech_context.original)
                self.delete_sg_for_update_port(plugin,
                                               context,
                                               current_port,
                                               original_port)

        LOG.debug("H3C ML2 plugin update_port_postcommit exited")

    def create_sg_for_update_port(self,
                                  plugin,
                                  context,
                                  current_port,
                                  original_port):
        LOG.debug("H3C ML2 plugin update_port_postcommit called")

        # create security group
        cur_sgids = current_port[ext_sg.SECURITYGROUPS]
        ori_sgids = original_port[ext_sg.SECURITYGROUPS]
        cur_fixed_ip = current_port['fixed_ips']
        ori_fixed_ip = original_port['fixed_ips']
        try:
            self.sg_sync_mutex_lock.acquire()
            for sgid in set(cur_sgids) - set(ori_sgids):
                self.create_security_group_rule_to_vcfc_and_local(context,
                                                                  plugin,
                                                                  sgid)
        except Exception as e:
            LOG.error(_LE("Failed to security group sync, "
                          "update_port_postcommit, exception is %(excep)s"),
                      {'excep': str(e)})
        finally:
            self.sg_sync_mutex_lock.release()

        # process for adding/removing fixed ip
        if len(cur_fixed_ip) > len(ori_fixed_ip):
            self.create_security_group_rule_for_ip_add(context,
                                                       plugin,
                                                       current_port)
        elif len(cur_fixed_ip) < len(ori_fixed_ip):
            self.delete_security_group_rule_for_ip_remove(context,
                                                          plugin,
                                                          current_port)

    def delete_sg_for_update_port(self,
                                  plugin,
                                  context,
                                  current_port,
                                  original_port):
        cur_sgids = current_port[ext_sg.SECURITYGROUPS]
        ori_sgids = original_port[ext_sg.SECURITYGROUPS]

        try:
            self.sg_sync_mutex_lock.acquire()
            # trying delete unused securitygroup
            for sgid in set(ori_sgids) - set(cur_sgids):
                self.delete_security_group_rule_to_vcfc_and_local(context,
                                                                  plugin,
                                                                  sgid,
                                                                  current_port)
        except Exception as e:
            LOG.error(_LE("Failed to security group sync "
                          "update_port_postcommit ,exception is %(excep)s"),
                      {'excep': str(e)})
        finally:
            self.sg_sync_mutex_lock.release()

    def delete_port_postcommit(self, mech_context):
        LOG.debug("H3C ML2 plugin delete_port_postcommit called")

        current_port = copy.deepcopy(mech_context.current)
        plugin = mech_context._plugin
        context = mech_context._plugin_context

        LOG.debug("context is %s", context.__dict__)
        LOG.debug("port id from ml2 is %s", current_port['id'])

        device_owner = current_port.get('device_owner', None)
        filter_device_owner = ['network:floatingip',
                               'network:router_interface',
                               'network:router_gateway',
                               'network:vsm_router_interface']
        if device_owner is not None and device_owner in filter_device_owner:
            LOG.debug("H3C ML2 plugin return for "
                      "careless device_owner %s port %s",
                      device_owner, current_port)
            return

        if device_owner == 'network:dhcp' and current_port['fixed_ips']:
            subnet_id = current_port['fixed_ips'][0]['subnet_id']
            subnet = plugin.get_subnet(context, subnet_id)
            subnet_mech_context = FakeSubnetContext(plugin,
                                                    context,
                                                    subnet)
            self.update_subnet_postcommit(subnet_mech_context)

        # delete port
        resource_path = "vds/1.0/ports/%s" % (current_port['id'])
        if (device_owner != 'network:dhcp' or
                (device_owner == 'network:dhcp' and
                    current_port['fixed_ips'])):
            response_status = self.client.rest_call(resource_path, "DELETE")
        LOG.debug("after delete port the resp_status from vcfc is %s",
                  response_status)
        LOG.debug("H3C ML2 plugin port %s deleted", current_port['id'])

        if self.enable_security_group:
            self.delete_security_group_rule_for_ip_remove(context,
                                                          plugin,
                                                          current_port)

        LOG.debug("H3C ML2 plugin delete_port_postcommit exited")

    def get_ip_prefixs_security_group(self, context, security_group_id):
        ip_prefixs = []
        with context.session.begin(subtransactions=True):
            query = context.session.query(sg_db.SecurityGroupPortBinding,
                                          models_v2.IPAllocation)
            query = query.filter(sg_db.SecurityGroupPortBinding.port_id ==
                                 models_v2.IPAllocation.port_id)
            query = query.filter(sg_db.SecurityGroupPortBinding.
                                 security_group_id == security_group_id)

        for element in query:
            sg_binding, port_info = element
            ip_prefix = port_info.ip_address + '/32'
            ip_prefixs.append(ip_prefix)

        return ip_prefixs

    def _is_exist_security_group_in_vcfc(self, security_group_id):
        """_is_exist_security_group_in_vcfc

        :param security_group_id: security_group_id
        """
        LOG.debug("H3C ML2 plugin _is_exist_security_group_in_vcfc called")
        LOG.debug("security_group_id=%s ", security_group_id)

        is_exist = False
        resource_path = "%s/%s" % (
            h_const.SECURITY_PORT_GROUPS_RESOURCE, security_group_id)
        resp_status, resp_body = self.client.rest_call(resource_path, "GET")
        if resp_status != 404 and 'port_security' in resp_body:
            is_exist = True

        LOG.debug("H3C ML2 plugin _is_exist_security_group_in_vcfc exited")
        return is_exist

    def _constructive_security_group_dict(self, security_group):
        res = {'id': security_group['id'],
               'name': security_group['name'],
               'ip_mac_binding': self.ip_mac_binding,
               'denyflow_age': self.denyflow_age,
               'empty_rule_action': self.empty_rule_action}
        return res

    def _constructive_security_rule_dict(self, security_group_rule):
        res = {"tenant_id": security_group_rule["tenant_id"],
               "direction": security_group_rule["direction"],
               "protocol": security_group_rule["protocol"],
               "portrange_max": security_group_rule["port_range_max"],
               "portrange_min": security_group_rule["port_range_min"],
               "name": "",
               "description": "",
               "id": security_group_rule["id"],
               "portsecurity_id": security_group_rule["security_group_id"],
               "ipprefix": security_group_rule["remote_ip_prefix"]
               }
        if security_group_rule["ethertype"] == "IPv4":
            res["ip_version"] = "4"
        elif security_group_rule["ethertype"] == "IPv6":
            res["ip_version"] = "6"
        return res

    def _constructive_remote_sg_rule(self, ip_prefixes, security_group_rule):
        remote_security_group_rules = []
        for ip_prefix in ip_prefixes:
            res = {'id': None,
                   'tenant_id': security_group_rule['tenant_id'],
                   'security_group_id':
                       security_group_rule['security_group_id'],
                   'ethertype': security_group_rule['ethertype'],
                   'direction': security_group_rule['direction'],
                   'protocol': security_group_rule['protocol'],
                   'port_range_min': security_group_rule['port_range_min'],
                   'port_range_max': security_group_rule['port_range_max'],
                   'remote_ip_prefix': ip_prefix,
                   'remote_group_id': None}
            remote_security_group_rules.append(res)
        return remote_security_group_rules

    def _constructive_set_security_group_rule_for_neutron(self,
                                                          security_group_rule):

        res = {'tenant_id': str(uuid.UUID(security_group_rule['tenant_id'])),
               'name': '',
               'description': '',
               'portsecurity_id': security_group_rule['security_group_id'],
               'ip_version': '4' if
               security_group_rule["ethertype"] == "IPv4" else '6',
               'direction': security_group_rule['direction'],
               'protocol': security_group_rule['protocol'],
               'portrange_min': security_group_rule['port_range_min'],
               'portrange_max': security_group_rule['port_range_max'],
               'ipprefix': security_group_rule['remote_ip_prefix']}

        return res

    def _constructive_set_security_group_rule_for_vcfc(self,
                                                       security_group_rule):

        res = {'tenant_id': security_group_rule['tenant_id'],
               'name': '',
               'description': '',
               'portsecurity_id': security_group_rule['portsecurity_id'],
               'ip_version': security_group_rule["ip_version"],
               'direction': security_group_rule['direction'],
               'protocol': security_group_rule['protocol'],
               'portrange_min': security_group_rule['portrange_min'],
               'portrange_max': security_group_rule['portrange_max'],
               'ipprefix': security_group_rule['ipprefix']}

        return res

    def _get_rule_id_from_vcfc_sg_rule_list(self, sg_rule, vcfc_dict_list):

        sg_rule_id = None
        for sg_rule_element in vcfc_dict_list:
            if sg_rule_element['sg_rule'] == sg_rule:
                sg_rule_id = sg_rule_element['sg_rule_id']
                break

        return sg_rule_id

    def sync_security_groups_use_sg_id(self,
                                       context,
                                       plugin,
                                       security_group_id):
        LOG.debug("H3C ML2 plugin sync_security_groups_use_sg_id called")
        LOG.debug("security_group_id %s", security_group_id)

        filters = {'remote_group_id': [security_group_id]}
        security_group_rules = self.get_security_group_rules(context, filters)
        sg_ids = [sg_rule['security_group_id']
                  for sg_rule in security_group_rules
                  if sg_rule['ethertype'] == 'IPv4']

        for sg_id in sg_ids:
            self._sync_security_group_rules(context, plugin, sg_id)

        LOG.debug("H3C ML2 plugin sync_security_groups_use_sg_id "
                  "exiting: sg is %s", security_group_id)
        return

    def create_security_group_to_vcfc_and_local(self,
                                                context,
                                                plugin,
                                                security_group_id):
        LOG.debug("H3C ML2 plugin create_security_group called")
        LOG.debug("security_group_id=%(security_group_id)s ",
                  {'security_group_id': security_group_id})

        try:
            security_group = plugin.get_security_group(context,
                                                       security_group_id)

            # create a security group to vcfc
            security_group_resource_path = \
                h_const.SECURITY_PORT_GROUPS_RESOURCE
            security_group_request_data = \
                self._constructive_security_group_dict(security_group)
            security_group_request_dict = \
                {'port_securities': [security_group_request_data]}
            self.client.rest_call(security_group_resource_path, "POST",
                                  security_group_request_dict)

            # create security_group_rules that all the
            # security_group owns to vcfc
            sg_rules = [sg_rule
                        for sg_rule in security_group["security_group_rules"]
                        if sg_rule['ethertype'] == 'IPv4']

            remote_group_rules = \
                copy.deepcopy([sg_rule for sg_rule in sg_rules
                               if sg_rule['remote_group_id'] is not None])

            for remote_group_rule in remote_group_rules:
                ip_prefixes = \
                    self.get_ip_prefixs_security_group(context,
                                                       remote_group_rule[
                                                           'remote_group_id'])

                sg_rules.remove(remote_group_rule)
                if len(ip_prefixes) > 0:
                    remote_sg_rules = \
                        self._constructive_remote_sg_rule(ip_prefixes,
                                                          remote_group_rule)
                    sg_rules.extend(remote_sg_rules)

            # generate set of sg_rules for neutron
            neutron_set = set([])
            # construct neutron_set of neutron security_group_rule
            # for processing
            for sg_rule in sg_rules:
                neutron_rule = self. \
                    _constructive_set_security_group_rule_for_neutron(sg_rule)
                neutron_set.add(jsonutils.dumps(neutron_rule))

            for sg_rule_str in neutron_set:
                sg_rule = jsonutils.loads(sg_rule_str)
                self.create_security_group_rule_to_vcfc(sg_rule)

        except Exception as e:
            LOG.error(_LE("Failed to create h3c resources for "
                          "sg %(sg)s, exception is %(exception)s"),
                      {'sg': security_group, 'exception': str(e)})

        LOG.debug("H3C ML2 plugin create_security_group exiting: sg %(sg)s",
                  {'sg': security_group})

    def create_security_group_rule_for_ip_add(self,
                                              context,
                                              plugin,
                                              port):
        """create_security_group

        :param context: context
        :param plugin: plugin
        :param port: current port
        """
        LOG.debug("H3C ML2 plugin create_security_group_rule_for_ip_add "
                  "called")

        sgids = port[ext_sg.SECURITYGROUPS]
        try:
            self.sg_sync_mutex_lock.acquire()
            for sgid in sgids:
                self.create_security_group_rule_to_vcfc_and_local(context,
                                                                  plugin,
                                                                  sgid)
        except Exception as e:
            LOG.error(_LE("Failed to create_security_group_rule_for_ip_add "
                          "create_security_group_rule_for_ip_add, "
                          "exception is %(exception)s"),
                      {'exception': str(e)})
        finally:
            self.sg_sync_mutex_lock.release()

    def create_security_group_rule_to_vcfc_and_local(self,
                                                     context,
                                                     plugin,
                                                     security_group_id):
        LOG.debug("H3C ML2 plugin create_security_group called")
        LOG.debug("security_group_id %s ", security_group_id)

        try:
            is_exist = self._is_exist_security_group_in_vcfc(security_group_id)
            if not is_exist:
                self.create_security_group_to_vcfc_and_local(context,
                                                             plugin,
                                                             security_group_id)
            else:
                self._sync_security_group_rules(context,
                                                plugin,
                                                security_group_id,
                                                is_exist=is_exist)

            self.sync_security_groups_use_sg_id(context,
                                                plugin,
                                                security_group_id)

        except Exception as e:
            LOG.error(_LE("Failed to create h3c resources for "
                          "sg %(sg)s, exception is %(exception)s"),
                      {'sg': security_group_id, 'exception': str(e)})

        LOG.debug("H3C ML2 plugin create_security_group exiting: sg %(sg)s",
                  {'sg': security_group_id})

    def delete_security_group_to_vcfc_and_local(self, security_group_id):
        """delete_security_group

        :param security_group_id: UUID of security_group which to delete
        """
        LOG.debug("VSM delete_security_group called: "
                  "security_group_id=%(sg_id)s",
                  {'sg_id': security_group_id})

        try:
            # get data from vcfc
            resource_path = "%s?portsecurity_id=%s" % (
                h_const.SECURITY_GROUP_RULES_RESOURCE, security_group_id)
            response_status, resp_dict = \
                self.client.rest_call(resource_path, "GET")

            vcfc_list = resp_dict["securityrules"]
            LOG.debug("Get %s's data from vcfc", "securityrules")
            LOG.debug("Data from vcfc: %s",
                      jsonutils.dumps(vcfc_list, indent=4))

            for rule in vcfc_list:
                self.delete_security_group_rule_to_vcfc(rule['id'])

            security_group_resource_path = "%s/%s" % (
                h_const.SECURITY_PORT_GROUPS_RESOURCE, security_group_id)
            self.client.rest_call(security_group_resource_path, "DELETE")

        except Exception as e:
            LOG.error(_LE("Failed to delete h3c security_group for "
                          "security_group_id %(id)s, "
                          "exception is %(exception)s"),
                      {'id': security_group_id, 'exception': str(e)})

    def delete_security_group_rule_for_ip_remove(self,
                                                 context,
                                                 plugin,
                                                 current_port):
        """delete_security_group_rule_to_vsm

        :param context: neutron api request context
        :param plugin: plugin
        :param current_port: current_port
        """
        LOG.debug("VCFC delete_security_group_rule_for_ip_remove called:")

        sgids = current_port[ext_sg.SECURITYGROUPS]
        try:
            self.sg_sync_mutex_lock.acquire()
            for sgid in sgids:
                self.delete_security_group_rule_to_vcfc_and_local(context,
                                                                  plugin,
                                                                  sgid,
                                                                  current_port)
        except Exception as e:
            LOG.error(_LE("Failed to delete_security_group_rule_for_ip_remove,"
                          "exception is %(exception)s"), {'exception': str(e)})
        finally:
            self.sg_sync_mutex_lock.release()

    def delete_security_group_rule_to_vcfc_and_local(self,
                                                     context,
                                                     plugin,
                                                     security_group_id,
                                                     current_port):
        LOG.debug("VCFC delete_security_group_rule_to_vcfc_and_local called: "
                  "security_group_id=%(sg_id)s",
                  {'sg_id': security_group_id})

        try:
            filters = {'security_group_id': [security_group_id]}
            ports = self.neutron_db._get_port_security_group_bindings(context,
                                                                      filters)

            if not ports:
                self.delete_security_group_to_vcfc_and_local(security_group_id)
            else:
                self._sync_security_group_rules(context,
                                                plugin,
                                                security_group_id)

            self.sync_security_groups_use_sg_id(context,
                                                plugin,
                                                security_group_id)

        except Exception as e:
            LOG.error(_LE("Failed to delete h3c security_group for "
                          "security_group_id %(id)s, "
                          "exception is %(exception)s"),
                      {'id': security_group_id, 'exception': str(e)})

    def get_sg_rule_resource_for_sync_neutron_to_vcfc(self,
                                                      context,
                                                      plugin,
                                                      security_group_id):

        """get data from neutron"""
        filters = {'security_group_id': [security_group_id]}
        neutron_list = plugin.get_security_group_rules(context, filters)
        neutron_list = [element for element in neutron_list
                        if element["ethertype"] == "IPv4"]
        LOG.debug("Get securityrules data from neutron: %s",
                  jsonutils.dumps(neutron_list, indent=4))

        remote_group_rules = \
            copy.deepcopy([sg_rule for sg_rule in neutron_list
                           if sg_rule['remote_group_id'] is not None])
        for remote_group_rule in remote_group_rules:
            ip_prefixes = \
                self.get_ip_prefixs_security_group(context,
                                                   remote_group_rule[
                                                       'remote_group_id'])
            if len(ip_prefixes) > 0:
                remote_sg_rules = \
                    self._constructive_remote_sg_rule(ip_prefixes,
                                                      remote_group_rule)
                neutron_list.extend(remote_sg_rules)

        neutron_list = [element for element in neutron_list
                        if element["remote_group_id"] is None]

        # get data from vcfc
        resource_path = "%s?portsecurity_id=%s" % (
            h_const.SECURITY_GROUP_RULES_RESOURCE, security_group_id)
        response_status, resp_dict = \
            self.client.rest_call(resource_path, "GET")

        vcfc_list = resp_dict["securityrules"]
        for sg_rule in vcfc_list:
            if sg_rule['protocol'] == 'icmp':
                sg_rule['portrange_min'] = sg_rule['icmp_type']
                sg_rule['portrange_max'] = sg_rule['icmp_code']
            else:
                if sg_rule['portrange_min'] is not None:
                    sg_rule['portrange_min'] = int(sg_rule['portrange_min'])
                if sg_rule['portrange_max'] is not None:
                    sg_rule['portrange_max'] = int(sg_rule['portrange_max'])
        LOG.debug("Get %s's data from vcfc", "securityrules")
        LOG.debug("Data from vcfc: %s",
                  jsonutils.dumps(vcfc_list, indent=4))

        return neutron_list, vcfc_list

    def remove_sg_rule_for_sync_neutron_to_vcfc_and_local(self,
                                                          neutron_set,
                                                          vcfc_set,
                                                          vcfc_dict_list):

        delete_list = []
        for sg_rule_str in vcfc_set - neutron_set:
            sg_rule = jsonutils.loads(sg_rule_str)

            sg_rule_id = \
                self._get_rule_id_from_vcfc_sg_rule_list(sg_rule,
                                                         vcfc_dict_list)
            delete_list.append(sg_rule_id)

        # delete dirty data in vcfc
        for element in delete_list:
            self.delete_security_group_rule_to_vcfc(element)

    def create_sg_rule_for_sync_neutron_to_vcfc_and_local(self,
                                                          neutron_set,
                                                          vcfc_set):

        create_list = []
        for sg_rule_str in neutron_set - vcfc_set:
            sg_rule = jsonutils.loads(sg_rule_str)
            create_list.append(sg_rule)

        for security_group_rule in create_list:
            self.create_security_group_rule_to_vcfc(security_group_rule)

    def _sync_security_group_rules(self, context, plugin, sg_id,
                                   is_exist=False):
        if is_exist is False:
            if self._is_exist_security_group_in_vcfc(sg_id) is False:
                return
        # get resource list from neutron and vcfc
        neutron_list, vcfc_list = \
            self.get_sg_rule_resource_for_sync_neutron_to_vcfc(context,
                                                               plugin,
                                                               sg_id)
        vcfc_dict_list = []
        for sg_rule in vcfc_list:
            sg_rule_data = \
                self._constructive_set_security_group_rule_for_vcfc(sg_rule)
            element = {'sg_rule_id': sg_rule['id'],
                       'sg_rule': sg_rule_data}
            vcfc_dict_list.append(element)

        # generate set of sg_rules for vcfc and neutron
        neutron_set = set([])
        vcfc_set = set([])
        # construct neutron_set of neutron security_group_rule
        # for processing
        for sg_rule in neutron_list:
            if sg_rule['remote_group_id'] is None:
                neutron_rule = self. \
                    _constructive_set_security_group_rule_for_neutron(sg_rule)
                neutron_set.add(jsonutils.dumps(neutron_rule))

        # construct vcfc_set of vcfc security_group_rule for processing
        for sg_rule in vcfc_list:
            vcfc_rule = \
                self._constructive_set_security_group_rule_for_vcfc(sg_rule)
            vcfc_set.add(jsonutils.dumps(vcfc_rule))

        # remove dirty data to vcfc
        self.remove_sg_rule_for_sync_neutron_to_vcfc_and_local(neutron_set,
                                                               vcfc_set,
                                                               vcfc_dict_list)

        # create new data to vcfc
        self.create_sg_rule_for_sync_neutron_to_vcfc_and_local(neutron_set,
                                                               vcfc_set)

    def _get_uuids(self, res_list):
        return [element['id'] for element in res_list]

    def create_security_group_rule_to_vcfc(self, sg_rule):
        LOG.debug("VSM create_security_group_rule called: "
                  "security_group_rule=%(security_group_rule)r",
                  {'security_group_rule': sg_rule})

        if sg_rule['protocol'] == 'icmp':
            sg_rule['icmp_type'] = sg_rule['portrange_min']
            sg_rule['icmp_code'] = sg_rule['portrange_max']
            del sg_rule['portrange_min']
            del sg_rule['portrange_max']

        try:
            security_rule_resource_path = h_const.SECURITY_GROUP_RULES_RESOURCE
            security_rule_request_dic = \
                {"securityrules": [sg_rule]}
            self.client.rest_call(security_rule_resource_path, "POST",
                                  security_rule_request_dic)

        except Exception as e:
            LOG.error(_LE("Failed to create h3c security_group_rule for "
                          "sg_rule %(sg_rule)s, exception is %(exception)s"),
                      {'sg_rule': security_rule_request_dic,
                       'exception': str(e)})

        LOG.debug("Plugin.create_security_group_rule exiting: rule %(sg)s",
                  {'sg': sg_rule})
        return

    def delete_security_group_rule_to_vcfc(self, sg_rule_id):
        """delete_security_group_rule

        :param sg_rule_id: UUID of delete_security_group_rule which to delete
        """
        LOG.debug("VSM delete_security_group_rule called: sg_rule_id=%s",
                  sg_rule_id)

        try:
            res_path = "%s/%s" % (h_const.SECURITY_GROUP_RULES_RESOURCE,
                                  sg_rule_id)
            self.client.rest_call(res_path, "DELETE")
        except Exception as e:
            LOG.error(_LE("Failed to delete h3c security_group_rule "
                          "for sg_rule_id %(sg_rule_id)r, exception is %s"),
                      {"sg_rule_id": sg_rule_id}, e)
