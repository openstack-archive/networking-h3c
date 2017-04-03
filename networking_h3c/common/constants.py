# Copyright 2016 Hangzhou H3C Technologies Co. Ltd. All rights reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

TENANTS_RESOURCE = "tenant/v1.0/tenants"
NET_RESOURCES_RESOURCE = "nem/v1.0/net_resources"
FLOATINGIP_STATUS_ACTIVE = "ACTIVE"

ROUTERS_RESOURCE = "vds/1.0/routers"
ROUTER_RESOURCE = "vds/1.0/routers/%s"
ROUTER_ADD_INTERFACE_RESOURCE = "vds/1.0/routers/%s/add_router_interface"
ROUTER_REMOVE_INTERFACE_RESOURCE = \
    "vds/1.0/routers/%s/remove_router_interface"
ROUTER_BINDING_RESOURCE = "nem/v1.0/gateway_network/router_bind"
ROUTETABLES_RESOURCE = "vds/1.0/routetables"
ROUTETABLE_RESOURCE = "vds/1.0/routetables/%s"
ROUTE_ENTRIES_RESOURCE = "vds/1.0/route_entries"
ROUTE_ENTRY_RESOURCE = "vds/1.0/route_entries/%s"
ROUTE_ENTRIES_IN_ROUTETABLE_RESOURCE = "vds/1.0/route_entries?routetable_id=%s"

PORTS_RESOURCE = "vds/1.0/ports"
PORT_RESOURCE = "vds/1.0/ports/%s"

FLOATINGIPS_RESOURCE = "vds/1.0/floatingips"
FLOATINGIP_RESOURCE = "vds/1.0/floatingips/%s"

DEFAULT_ROUTER_NAME = "defaultRouter"
DEFAULT_TENANT_ID = "ffffffff-0000-0000-0000-000000000001"
VDS_RESOURCE = "vds/1.0/h3c_vdsconf"

AGENTS_RESOURCE = "vds/1.0/host"

GATEWAY_NETWORK_RESOURCE = "nem/v1.0/gateway_network"

NET_RESOURCE_RESOURCE = "nem/v1.0/net_resources"
GROUP_RESOURCE_RESOURCE = "nem/v1.0/groups"
RESOURCE_POOL_RESOURCE = "ngfwm/v1.0/resource_pool"

SECURITY_GROUP_RULES_RESOURCE = "vds/1.0/securityrules"

SECURITY_PORT_GROUPS_RESOURCE = "vds/1.0/portsecurities"

PORT_GROUPS_RESOURCE = "vds/1.0/portgroups"
