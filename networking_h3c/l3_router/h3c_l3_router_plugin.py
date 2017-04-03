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
import netaddr
import uuid
from networking_h3c import extensions  # noqa
from networking_h3c._i18n import _
from networking_h3c._i18n import _LE
from networking_h3c.common import config  # noqa
from networking_h3c.common import constants as h_const
from networking_h3c.common import exceptions
from networking_h3c.common import rest_client
from networking_h3c.db import h3c_l3_vxlan_db
from neutron import manager
from neutron.api.rpc.agentnotifiers import l3_rpc_agent_api
from neutron.api.rpc.handlers import l3_rpc
from neutron.common import constants as q_const
from neutron.common import exceptions as common_exceptions
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.db import common_db_mixin
from neutron.db import extraroute_db
from neutron.db import l3_db
from neutron.db import l3_dvrscheduler_db
from neutron.db import l3_gwmode_db
from neutron.db import l3_hamode_db
from neutron.db import l3_hascheduler_db
from neutron.db import models_v2
from neutron.extensions import extraroute
from neutron.extensions import l3
from neutron.plugins.common import constants
from neutron_lib.api import attributes
from oslo.config import cfg
from oslo.log import log as logging
from oslo.utils import excutils
from oslo.utils import importutils
from sqlalchemy.orm import exc

EXTERNAL_GW_INFO = l3.EXTERNAL_GW_INFO
VENDOR_RPC_TOPIC = ['DP_PLUGIN', 'H3C_PLUGIN']
LOG = logging.getLogger(__name__)


class H3CL3RouterPlugin(common_db_mixin.CommonDbMixin,
                        extraroute_db.ExtraRoute_db_mixin,
                        l3_gwmode_db.L3_NAT_db_mixin,
                        l3_hamode_db.L3_HA_NAT_db_mixin,
                        l3_dvrscheduler_db.L3_DVRsch_db_mixin,
                        l3_hascheduler_db.L3_HA_scheduler_db_mixin):

    """Implementation of the Neutron L3 Router Service Plugin.

    This class implements a L3 service plugin that provides
    router and floatingip resources and manages associated
    request/response.
    All DB related work is implemented in classes
    l3_db.L3_NAT_db_mixin and extraroute_db.ExtraRoute_db_mixin.
    """

    supported_extension_aliases = ["router", "ext-gw-mode",
                                   "extraroute", "l3_agent_scheduler"]

    def __init__(self):
        self.router_scheduler = importutils.import_object(
            cfg.CONF.router_scheduler_driver)
        self.start_periodic_l3_agent_status_check()

        super(H3CL3RouterPlugin, self).__init__()
        self.vds_id = None
        self.client = rest_client.RestClient()
        self.enable_metadata = cfg.CONF.VCFCONTROLLER.enable_metadata
        self.router_binding_public_vrf = \
            cfg.CONF.VCFCONTROLLER.router_binding_public_vrf
        self.disable_internal_l3flow_offload = \
            cfg.CONF.VCFCONTROLLER.disable_internal_l3flow_offload
        self.enable_l3_router_rpc_notify = \
            cfg.CONF.VCFCONTROLLER.enable_l3_router_rpc_notify
        self.vendor_rpc_topic = cfg.CONF.VCFCONTROLLER.vendor_rpc_topic
        self.setup_rpc()

        self.enable_l3_vxlan = cfg.CONF.VCFCONTROLLER.enable_l3_vxlan
        self.h3c_l3_vxlan = h3c_l3_vxlan_db.H3CL3VxlanDriver()
        if self.enable_l3_vxlan is True:
            self.h3c_l3_vxlan.initialize()

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
        LOG.debug("H3C driver get vds id %s by vdsname %s",
                  vds_uuid, vds_name)
        return vds_uuid

    def setup_rpc(self):
        if self.enable_l3_router_rpc_notify is False:
            return
        self.topic = topics.L3PLUGIN
        self.conn = n_rpc.create_connection(new=True)
        self.agent_notifiers.update(
            {q_const.AGENT_TYPE_L3: l3_rpc_agent_api.L3AgentNotifyAPI()})
        self.endpoints = [l3_rpc.L3RpcCallback()]
        self.conn.create_consumer(self.topic, self.endpoints, fanout=False)
        self.conn.consume_in_threads()

    @staticmethod
    def get_plugin_type():
        return constants.L3_ROUTER_NAT

    @staticmethod
    def get_plugin_description():
        """returns string description of the plugin."""
        return _("L3 Router Service Plugin for basic L3 forwarding"
                 "between (L2) Neutron networks and access to"
                 "external networks via a NAT gateway.")

    def process_create_router(self, router_in_db):
        router_tmp = {
            'id': router_in_db['id'],
            'name': router_in_db['name'],
            'tenant_id': router_in_db['tenant_id'],
        }
        if self.vds_id is None:
            self.vds_id = self.get_vds_id_from_vcfc(
                cfg.CONF.VCFCONTROLLER.vds_name)
        router_tmp['provider:domain'] = self.vds_id
        if self.router_binding_public_vrf is True:
            router_tmp['provider:vpninstance_name'] = ''
        if self.disable_internal_l3flow_offload is True:
            router_tmp['disable_internal_l3flow_offload'] = True
        if 'provider:segmentation_id' in router_in_db:
            router_tmp['provider:segmentation_id'] = \
                router_in_db['provider:segmentation_id']
        resource_path = h_const.ROUTERS_RESOURCE
        request_dic = {'routers': [router_tmp]}
        return self.client.rest_call(resource_path, "POST", request_dic)

    def process_update_router(self, router_in_db):
        router_tmp = {
            'name': router_in_db['name']
        }
        if EXTERNAL_GW_INFO in router_in_db:
            info = router_in_db[EXTERNAL_GW_INFO]
            ex_gw_info = [{
                'network_id': info['network_id'],
                'enable_snat': info.get('enable_snat'),
                'external_fixed_ips': [
                    {
                        'subnet_id': i.get('subnet_id'),
                        'ip': i.get('ip_address')
                    }
                    for i in info['external_fixed_ips']
                    ]
            }] if info is not None else None
            router_tmp[EXTERNAL_GW_INFO] = ex_gw_info
        resource_path = h_const.ROUTER_RESOURCE % router_in_db['id']
        return self.client.rest_call(resource_path, "PUT", router_tmp)

    def process_delete_router(self, router_in_db):
        resource_path = h_const.ROUTER_RESOURCE % router_in_db['id']
        return self.client.rest_call(resource_path, "DELETE")

    def create_router(self, context, router):
        LOG.debug("VCFC create_router called")
        LOG.debug("ctx = %s", context.__dict__)
        LOG.debug("router from north is %s", router)

        router_in_db = super(H3CL3RouterPlugin, self).create_router(
            context, router)
        router_for_creation = copy.deepcopy(router_in_db)

        if self.enable_l3_vxlan is True:
            try:
                segment_id = self.h3c_l3_vxlan.create_l3_segments(
                    context, router_in_db['id'])
            except Exception as e:
                with excutils.save_and_reraise_exception():
                    LOG.exception(_LE("H3C failed to create router with vni: "
                                      "%s"), e)
                    super(H3CL3RouterPlugin, self).delete_router(
                        context, router_in_db['id'])
            router_for_creation['provider:segmentation_id'] = segment_id
        try:
            response_status, response = self.process_create_router(
                router_for_creation)
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE("H3C l3 driver create router"
                                  "to vcfc exception: %s"), e)
                if self.enable_l3_vxlan is True:
                    self.h3c_l3_vxlan.release_segment(context.session,
                                                      router_in_db['id'])
                super(H3CL3RouterPlugin, self).delete_router(
                    context, router_in_db['id'])
        LOG.debug("after create router"
                  "the resp_body from vcfc is %s", response)
        LOG.debug("after create router"
                  "the resp_status from vcfc is %s", response_status)

        if (EXTERNAL_GW_INFO in router_in_db and
                router_in_db[EXTERNAL_GW_INFO]) is not None:
            try:
                resp_status, resp_body = self.process_update_router(
                    router_in_db)
            except Exception as e:
                with excutils.save_and_reraise_exception():
                    LOG.exception(_LE("starting rollback because "
                                      "H3C l3 driver failed to "
                                      "update router gateway info: %s"), e)
                    try:
                        response_status = self.process_delete_router(
                            router_in_db)
                    except Exception as e:
                        LOG.exception(_LE("H3C l3 driver delete router "
                                          "from vcfc exception: %s"),
                                      e)
                    LOG.debug("H3C l3 driver delete router "
                              "from vcfc response_status is %s",
                              response_status)
                    if self.enable_l3_vxlan is True:
                        self.h3c_l3_vxlan.release_segment(context.session,
                                                          router_in_db['id'])
                    super(H3CL3RouterPlugin, self).delete_router(
                        context, router_in_db['id'])

            LOG.debug("after update router gateway info "
                      "the resp_body from vcfc is %s",
                      resp_body)
            LOG.debug("after update router gateway info "
                      "the resp_status from vcfc is %s",
                      resp_status)

        # create route tables
        routetable_name = router_in_db['name']
        routetable_id = router_in_db['id']
        routetables = {"id": routetable_id,
                       "name": routetable_name,
                       "router_id": routetable_id}
        resource_path = h_const.ROUTETABLES_RESOURCE
        request_dic = {"routetables": [routetables]}
        response_status, response = self.client.rest_call(resource_path,
                                                          "POST", request_dic)
        LOG.debug("after create route tables the resp_body from vcfc is %s",
                  response)
        LOG.debug("after create route tables the resp_status from vcfc is %s",
                  response_status)

        # binding route table to router
        resource_path = h_const.ROUTER_RESOURCE % routetable_id
        request_dic = {"route_table_id": routetable_id}
        self.client.rest_call(resource_path, "PUT", request_dic)

        LOG.debug("VCFC create_router exited")
        return router_in_db

    def _update_router_without_check_rescheduling(self, context, rid, router):
        # TODO(Huang Cheng): _check_router_needs_rescheduling when h3c-agent support dvr
        r = router['router']
        with context.session.begin(subtransactions=True):
            # check if route exists and have permission to access
            router_db = self._get_router(context, rid)
            if 'routes' in r:
                self._update_extra_routes(context, router_db, r['routes'])
                try:
                    self.sync_vcfc_route_entries(context, rid, router)
                except Exception as e:
                    LOG.error(_LE("H3C driver route entries id exception: %s"),
                              e)
            routes = self._get_extra_routes_by_router_id(context, rid)
        gw_info = r.pop(EXTERNAL_GW_INFO, attributes.ATTR_NOT_SPECIFIED)
        if gw_info != attributes.ATTR_NOT_SPECIFIED:
            # Update the gateway outside of the DB update since it involves L2
            # calls that don't make sense to rollback and may cause deadlocks
            # in a transaction.
            self._update_router_gw_info(context, rid, gw_info)
        router_db = self._update_router_db(context, rid, r)
        router_updated = self._make_router_dict(router_db)
        router_updated['routes'] = routes
        return router_updated

    @staticmethod
    def get_create_route_entries_list(routes, route_entries):
        create_route_list = []
        vcfc_routes = [{'destination': route_entry['cidr'],
                        'nexthop': route_entry['next_hop']}
                       for route_entry in route_entries]
        for route in routes:
            if route not in vcfc_routes:
                create_route_list.append(route)
        return create_route_list

    @staticmethod
    def get_delete_route_entries_list(routes, route_entries):
        delete_route_list = []
        for route_entry in route_entries:
            temp_route_entry = {'destination': route_entry['cidr'],
                                'nexthop': route_entry['next_hop']}
            if temp_route_entry not in routes:
                delete_route_list.append(route_entry['id'])
        return delete_route_list

    def sync_vcfc_route_entries(self, context, rid, router):
        """route table"""
        get_path = h_const.ROUTETABLE_RESOURCE % rid
        response_status, resp_dict = self.client.rest_call(get_path, "GET")
        if response_status == 404:
            router_in_db = self.get_router(context, rid)
            routetables = {"id": rid,
                           "name": router_in_db['name'],
                           "router_id": router_in_db['id']}
            resource_path = h_const.ROUTETABLES_RESOURCE
            request_dic = {"routetables": [routetables]}
            resp_status, resp = self.client.rest_call(resource_path, "POST",
                                                      request_dic)
            # binding route tables to router
            resource_path = h_const.ROUTER_RESOURCE % rid
            request_dic = {"route_table_id": rid}
            self.client.rest_call(resource_path, "PUT", request_dic)
        # prepare route entry
        get_path = h_const.ROUTE_ENTRIES_IN_ROUTETABLE_RESOURCE % rid
        response_status, resp_dict = self.client.rest_call(get_path, "GET")

        delete_list = self.get_delete_route_entries_list(
            router['router']['routes'], resp_dict['route_entries'])

        create_list = self.get_create_route_entries_list(
            router['router']['routes'], resp_dict['route_entries'])
        # create route entries
        route_entries = []
        for route in create_list:
            route_entry = {'routetable_id': rid,
                           'cidr': route['destination'],
                           'next_hop_type': 'IPv4',
                           'next_hop': route['nexthop']
                           }
            route_entries.append(route_entry)
        if route_entries:
            resource_path = h_const.ROUTE_ENTRIES_RESOURCE
            request_dic = {'route_entries': route_entries}
            resp_status, resp = self.client.rest_call(resource_path, "POST",
                                                      request_dic)
        # delete route entries
        for route_entry_id in delete_list:
            resource_path = h_const.ROUTE_ENTRY_RESOURCE % route_entry_id
            self.client.rest_call(resource_path, "DELETE")

    @staticmethod
    def _validate_routes_nexthop(cidrs, ips, routes, nexthop):
        # Note(nati) nexthop should not be same as fixed_ips
        if nexthop in ips:
            raise extraroute.InvalidRoutes(
                routes=routes,
                reason=_('the nexthop is used by router'))

    def _create_router_gw_port(self, context, router, network_id, ext_ips):
        # Port has no 'tenant-id', as it is hidden from user
        gw_port = self._core_plugin.create_port(context.elevated(), {
            'port': {'tenant_id': '',  # intentionally not set
                     'network_id': network_id,
                     'mac_address': attributes.ATTR_NOT_SPECIFIED,
                     'fixed_ips': ext_ips or attributes.ATTR_NOT_SPECIFIED,
                     'device_id': router['id'],
                     'device_owner': l3_db.DEVICE_OWNER_ROUTER_GW,
                     'admin_state_up': True,
                     'status': q_const.PORT_STATUS_ACTIVE,
                     'name': ''}})
        if not gw_port['fixed_ips']:
            LOG.debug('No IPs available for external network %s',
                      network_id)

        with context.session.begin(subtransactions=True):
            router.gw_port = self._core_plugin._get_port(context.elevated(),
                                                         gw_port['id'])
            router_port = l3_db.RouterPort(
                router_id=router.id,
                port_id=gw_port['id'],
                port_type=l3_db.DEVICE_OWNER_ROUTER_GW
            )
            context.session.add(router)
            context.session.add(router_port)

    def update_router(self, context, rid, router):
        LOG.debug("VCFC update_router called")
        LOG.debug("router id from north is %s", rid)
        LOG.debug("router from north is %s", router)

        orig_router_dict = copy.deepcopy(router)

        original_router = super(H3CL3RouterPlugin, self).get_router(
            context, rid)
        router_in_db = self._update_router_without_check_rescheduling(
            context, rid, router)

        payload = {
            'gw_exists':
                router['router'].get(
                    EXTERNAL_GW_INFO, attributes.ATTR_NOT_SPECIFIED) !=
                attributes.ATTR_NOT_SPECIFIED
        }
        try:
            resp_status, resp_body = self.process_update_router(router_in_db)
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE("starting rollback because "
                                  "H3C l3 driver failed to update router: %s"),
                              e)
                rollback_router = {"router": {}}
                for i in orig_router_dict["router"]:
                    if i in original_router:
                        rollback_router["router"][i] = original_router[i]
                self._update_router_without_check_rescheduling(
                    context, rid, rollback_router)
        LOG.debug("after update router the resp_body from vcfc is %s",
                  resp_body)
        LOG.debug("after update router the resp_status from vcfc is %s",
                  resp_status)
        if self.enable_l3_router_rpc_notify:
            self.notify_router_updated(context, rid, payload)

        LOG.debug("VCFC update_router exited")
        return router_in_db

    def _ensure_router_not_attached_to_firewall(self, context, router):
        """Ensure that the router is not attached to one of the tenant firewalls.
        
        :param context: neutron api request context
        :param router: router in db
        """
        fw_plugin = manager.NeutronManager.get_service_plugins().get(
            constants.FIREWALL)
        if fw_plugin:
            tenant_firewalls = fw_plugin.get_firewalls(
                context, filters={'tenant_id': [router['tenant_id']]})
            for firewall in tenant_firewalls:
                if router['id'] in firewall['router_ids']:
                    raise exceptions.H3CRouterBindFirewall()
        return

    def delete_router(self, context, rid):
        LOG.debug("VCFC delete_router called")
        LOG.debug("ctx = %s", context.__dict__)
        self._ensure_router_not_in_use(context, rid)

        router_in_db = super(H3CL3RouterPlugin, self).get_router(context, rid)
        self._ensure_router_not_attached_to_firewall(context, router_in_db)

        if router_in_db.get(EXTERNAL_GW_INFO):
            delgateway_router = {'router': {EXTERNAL_GW_INFO: {}}}
            self.update_router(context, rid, delgateway_router)

        # unbinding route tables from router
        resource_path = h_const.ROUTER_RESOURCE % rid
        request_dic = {"route_table_id": None}
        self.client.rest_call(resource_path, "PUT", request_dic)

        # delete route tables
        resource_path = h_const.ROUTETABLE_RESOURCE % rid
        response_status = self.client.rest_call(resource_path, "DELETE")
        LOG.debug("after delete route tables the status from vcfc is %s",
                  response_status)
        response_status = self.process_delete_router(router_in_db)
        LOG.debug("after delete router the resp_status from vcfc is %s",
                  response_status)
        # release router vxlan
        if self.enable_l3_vxlan is True:
            self.h3c_l3_vxlan.release_segment(context.session, rid)

        super(H3CL3RouterPlugin, self).delete_router(context, rid)

        LOG.debug("VCFC router %s created", rid)
        LOG.debug("VCFC delete router exited")

    def add_router_port(self, context, port_id, router_id):
        with context.session.begin(subtransactions=True):
            router_port = l3_db.RouterPort(
                port_id=port_id,
                router_id=router_id,
                port_type=q_const.DEVICE_OWNER_ROUTER_INTF
            )
            context.session.add(router_port)

    def _validate_router_migration(self, context, router_db, router_res):
        pass

    def _check_for_dup_router_subnet(self, context, router,
                                     network_id, subnet_id, subnet_cidr):
        try:
            # It's possible these ports are on the same network, but
            # different subnets.
            new_ipnet = netaddr.IPNetwork(subnet_cidr)
            for p in (rp.port for rp in router.attached_ports):
                for ip in p['fixed_ips']:
                    if ip['subnet_id'] == subnet_id:
                        msg = (_("Router already has a port on subnet %s")
                               % subnet_id)
                        raise common_exceptions.BadRequest(
                            resource='router', msg=msg)
                    # Ignore temporary Prefix Delegation CIDRs
                    if subnet_cidr == q_const.PROVISIONAL_IPV6_PD_PREFIX:
                        continue
                    sub_id = ip['subnet_id']
                    cidr = self._core_plugin.get_subnet(context.elevated(),
                                                        sub_id)['cidr']
                    ipnet = netaddr.IPNetwork(cidr)
                    match1 = netaddr.all_matching_cidrs(new_ipnet, [cidr])
                    match2 = netaddr.all_matching_cidrs(ipnet, [subnet_cidr])
                    if match1 or match2:
                        data = {'subnet_cidr': subnet_cidr,
                                'subnet_id': subnet_id,
                                'cidr': cidr,
                                'sub_id': sub_id}
                        msg = (_("Cidr %(subnet_cidr)s of subnet "
                                 "%(subnet_id)s overlaps with cidr %(cidr)s "
                                 "of subnet %(sub_id)s") % data)
                        raise common_exceptions.BadRequest(
                            resource='router', msg=msg)
        except exc.NoResultFound:
            pass

    def _add_interface_by_subnet(self, context, router, subnet_id, owner):
        subnet = self._core_plugin._get_subnet(context, subnet_id)
        if not subnet['gateway_ip']:
            msg = _('Subnet for router interface must have a gateway IP')
            raise common_exceptions.BadRequest(resource='router', msg=msg)

        self._check_for_dup_router_subnet(context, router,
                                          subnet['network_id'],
                                          subnet_id,
                                          subnet['cidr'])

        return [subnet]

    def add_router_interface(self, context, router_id, interface_info):
        LOG.debug("VCFC add_router_interface called")
        LOG.debug("ctx = %s", context.__dict__)
        LOG.debug("router id from north is %s", router_id)

        add_by_port, add_by_sub = self._validate_interface_info(interface_info)
        if add_by_port:
            raise exceptions.IpNotSupportAssigned()
        else:
            router = self._get_router(context, router_id)
            device_owner = self._get_device_owner(context, router_id)
            subnets = self._add_interface_by_subnet(
                context, router, interface_info['subnet_id'], device_owner)

        resource_path = h_const.ROUTER_ADD_INTERFACE_RESOURCE % router_id
        request_dic = interface_info
        response_status, add_router_resp = self.client.rest_call(
            resource_path, "PUT", request_dic)
        LOG.debug("after add router interface "
                  "the resp_body from vcfc is %s", add_router_resp)
        LOG.debug("after add router interface "
                  "the resp_status from vcfc is %s", response_status)

        port_id = add_router_resp["port_id"]
        subnet_id = add_router_resp["subnet_id"]

        resource_path = h_const.PORT_RESOURCE % port_id
        response_status, get_port_resp = \
            self.client.rest_call(resource_path, "GET")
        port = get_port_resp["port"]

        if port["status"] == "UP":
            port["status"] = "ACTIVE"

        LOG.debug("after get port the resp_body from vcfc is %s", port)

        port["device_owner"] = "network:router_interface"
        port["admin_state_up"] = True
        port["device_id"] = router_id
        port["name"] = ''
        port["mac_address"] = self._core_plugin._generate_mac()
        port['tenant_id'] = uuid.UUID(port['tenant_id']).hex
        port = {"port": port}
        LOG.debug("port into db is %s", port)
        self._core_plugin.create_port(context, port)

        resp_body = {"subnet_id": subnet_id, "port_id": port_id}
        LOG.debug("resp_body is %s", resp_body)
        router_port_id = port_id

        self.add_router_port(context, router_port_id, router_id)
        router_interface_info = {
            'id': router_id,
            'tenant_id': subnets[0]['tenant_id'],
            'port_id': router_port_id,
            'subnet_id': port['port']['fixed_ips'][0]['subnet_id']}

        if self.enable_l3_router_rpc_notify:
            self.notify_router_interface_action(
                context, router_interface_info, 'add')

        if self.enable_metadata:
            # update gw port mac
            request_dic = {
                'port': {'id': get_port_resp["port"]['id'],
                         'mac_address': port['port']['mac_address']}}
            resource_path = \
                h_const.PORT_RESOURCE % (get_port_resp["port"]['id'])
            LOG.debug("update gw port to vcfc is %s", request_dic)
            response_status, resp_body = \
                self.client.rest_call(resource_path, "PUT", request_dic)
            LOG.debug("after update gw port "
                      "the resp_body from vcfc is %s", resp_body)
            LOG.debug("after update gw port "
                      "the resp_status from vcfc is %s", response_status)

            LOG.debug("VCFC router interface %s added", router_id)
            LOG.debug("VCFC add_router_interface exited")

        return router_interface_info

    def remove_interface_by_subnet(self, context,
                                   router_id, subnet_id, owner):
        self._confirm_router_interface_not_in_use(
            context, router_id, subnet_id)
        subnet = self._core_plugin._get_subnet(context, subnet_id)

        try:
            rport_qry = context.session.query(models_v2.Port).join(
                l3_db.RouterPort)
            ports = rport_qry.filter(
                l3_db.RouterPort.router_id == router_id,
                l3_db.RouterPort.port_type == owner,
                models_v2.Port.network_id == subnet['network_id']
            )

            for p in ports:
                port_subnets = [fip['subnet_id'] for fip in p['fixed_ips']]

                if subnet_id in port_subnets:
                    port_neutron = p
                    return port_neutron, [subnet]
        except exc.NoResultFound:
            pass
        raise l3.RouterInterfaceNotFoundForSubnet(router_id=router_id,
                                                  subnet_id=subnet_id)

    def remove_interface_by_port(self, context, router_id,
                                 port_id, subnet_id, owner):
        qry = context.session.query(l3_db.RouterPort)
        qry = qry.filter_by(
            port_id=port_id,
            router_id=router_id,
            port_type=owner
        )
        try:
            port_db = qry.one().port
        except exc.NoResultFound:
            raise l3.RouterInterfaceNotFound(router_id=router_id,
                                             port_id=port_id)
        port_subnet_ids = [fixed_ip['subnet_id']
                           for fixed_ip in port_db['fixed_ips']]
        if subnet_id and subnet_id not in port_subnet_ids:
            raise common_exceptions.SubnetMismatchForPort(
                port_id=port_id, subnet_id=subnet_id)
        subnets = [self._core_plugin._get_subnet(context, port_subnet_id)
                   for port_subnet_id in port_subnet_ids]
        for port_subnet_id in port_subnet_ids:
            self._confirm_router_interface_not_in_use(
                context, router_id, port_subnet_id)

        port_neutron = port_db
        return port_neutron, subnets

    def remove_router_interface(self, context, router_id, interface_info):

        LOG.debug("VCFC remove_router_interface called")
        LOG.debug("ctx = %s", context.__dict__)
        LOG.debug("remove router interface called and interface info is %s",
                  interface_info)

        remove_by_port, remove_by_subnet = (
            self._validate_interface_info(interface_info, for_removal=True))
        port_id = interface_info.get('port_id')
        subnet_id = interface_info.get('subnet_id')
        device_owner = self._get_device_owner(context, router_id)
        if remove_by_port:
            port_neutron, subnets = \
                self.remove_interface_by_port(context, router_id,
                                              port_id, subnet_id,
                                              device_owner)
        else:
            port_neutron, subnets = self.remove_interface_by_subnet(
                context, router_id, subnet_id, device_owner)

        delmsg = {'subnet_id': subnets[0]['id']}

        resource_path = \
            h_const.ROUTER_REMOVE_INTERFACE_RESOURCE % router_id
        request_dic = delmsg
        response_status, response = \
            self.client.rest_call(resource_path, "PUT", request_dic)
        LOG.debug("after remove_router_interface "
                  "the resp_body from vcfc is %s", response)
        LOG.debug("after remove_router_interface "
                  "the resp_status from vcfc is %s", response_status)

        self._core_plugin.delete_port(
            context, port_neutron["id"], l3_port_check=False)

        router_interface_info = {'id': router_id,
                                 'tenant_id': port_neutron["tenant_id"],
                                 'port_id': port_neutron["id"],
                                 'subnet_id': subnets[0]['id']}

        if self.enable_l3_router_rpc_notify:
            self.notify_router_interface_action(
                context, router_interface_info, 'remove')

        LOG.debug("VCFC router interface %s removed", router_id)
        LOG.debug("VCFC remove_router_interface exited")

        return router_interface_info

    def create_floatingip(self, context, floatingip, **kwargs):
        LOG.debug("VCFC create_floatingip called")
        LOG.debug("ctx = %s", context.__dict__)
        LOG.debug("floating ip from north is %s", floatingip)

        floatingip_neutron = super(H3CL3RouterPlugin, self). \
            create_floatingip(context, floatingip)
        floatingip_vcfc = copy.deepcopy(floatingip_neutron)
        LOG.debug(" floatingip content from db is %s", floatingip_neutron)

        if 'fixed_ip_address' in floatingip_vcfc:
            del floatingip_vcfc['fixed_ip_address']

        resource_path = h_const.FLOATINGIPS_RESOURCE
        request_dic = {"floatingips": [floatingip_vcfc]}
        LOG.debug("create floating ip into vcfc is %s", request_dic)
        try:
            response_status, resp_body = self.client.rest_call(
                resource_path, "POST", request_dic)
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE("H3C failed to create floating ip: %s"), e)
                super(H3CL3RouterPlugin, self).delete_floatingip(
                    context, floatingip_neutron['id'])
        LOG.debug("after create floating ip "
                  "the resp_body from vcfc is %s", resp_body)
        LOG.debug("after create floating ip "
                  "the resp_status from vcfc is %s", response_status)

        LOG.debug("floatingip resp_body content from vcfc is %s", resp_body)
        LOG.debug("VCFC create_floatingip exited")
        return floatingip_neutron

    def update_floatingip(self, context, fid, floatingip):
        LOG.debug("VCFC update_floatingip called")
        LOG.debug("ctx = %s", context.__dict__)
        LOG.debug("floating ip from north is %s", floatingip)

        resource_path = h_const.FLOATINGIP_RESOURCE % fid

        floatingip_tmp = super(H3CL3RouterPlugin, self).\
            get_floatingip(context, fid)
        update_floatingip_port = floatingip['floatingip'].get('port_id', None)
        if floatingip_tmp['port_id'] and update_floatingip_port:
            if floatingip_tmp['port_id'] != update_floatingip_port:
                request_dic = {'floatingip': {'port_id': None}}
                response_status, resp_body = \
                    self.client.rest_call(resource_path, "PUT", request_dic)
                LOG.debug("after update floatingips "
                          "the resp_body from vcfc is %s", resp_body)
                LOG.debug("after update floatingips "
                          "the resp_status from vcfc is %s", response_status)

        floatingip_neutron = super(H3CL3RouterPlugin, self).\
            update_floatingip(context, fid, floatingip)
        LOG.debug(" floatingip content from db is %s", floatingip_neutron)

        request_dic = {
            'floatingip':
                {'port_id': floatingip_neutron['port_id']}
        }
        response_status, resp_body = \
            self.client.rest_call(resource_path, "PUT", request_dic)
        LOG.debug("after update floatingips "
                  "the resp_body from vcfc is %s", resp_body)
        LOG.debug("after update floatingips "
                  "the resp_status from vcfc is %s", response_status)

        LOG.debug("VCFC update_floatingip exited")
        return floatingip_neutron

    def delete_floatingip(self, context, fid):
        LOG.debug("VCFC delete_floatingip called")
        LOG.debug("ctx = %s", context.__dict__)

        super(H3CL3RouterPlugin, self).delete_floatingip(context, fid)

        resource_path = h_const.FLOATINGIP_RESOURCE % fid
        response_status = self.client.rest_call(resource_path, "DELETE")
        LOG.debug("after delete floatingips "
                  "the resp_status from vcfc is %s", response_status)

        LOG.debug("VCFC floatingip %s deleted", fid)
        LOG.debug("VCFC delete floatingip exited")
