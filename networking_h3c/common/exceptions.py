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
from neutron_lib import exceptions as qexception
from neutron_lib.exceptions import NeutronException
from neutron_lib.exceptions import ServiceUnavailable


class RequestTimeoutError(ServiceUnavailable):
    message = _("%(resource)s request:  VCFC timeout!  URL = %(url)s")


class PoolCountExceeded(qexception.Conflict):
    message = _("Exceeded allowed count of Pool for tenant "
                "%(tenant_id)s. Only one Pool is supported per tenant.")


class JsonDecodingError(NeutronException):
    message = _("%(resource)s request:  Decoding json error! ")


class HttpNotAuthError(NeutronException):
    message = _("VCFC Authorization failed")


class HttpNotFoundError(NeutronException):
    message = _("The requested content not found.")


class ConflictError(NeutronException):
    message = _("This operation leaded to conflict.")


class ForbiddenError(NeutronException):
    message = _("This operation is forbidden.")


class BadRequests(NeutronException):
    message = _("Bad Request")


class InternalError(NeutronException):
    message = _("VCFC internal server error.")


class UnknownError(NeutronException):
    message = _("A unknown error occurred during request.")


class OperationNotSupported(NeutronException):
    message = _("OperationNotSupported")


class HttpServiceUnavailable(NeutronException):
    message = _("HttpServiceUnavailable")


class LoadbalancerNotFound(qexception.NotFound):
    message = _("The Loadbalancer %(loadbalancer_id)s could not be found")


class ServiceContextNotFound(qexception.NotFound):
    message = _("ServiceContext %(service_context_id)s could not be found")


class ServiceInsertionNotFound(qexception.NotFound):
    message = _("ServiceInsertion %(service_insertion_id)s not found")


class ServiceNodeNotFound(qexception.NotFound):
    message = _("ServiceNode %(service_node_id)s not found")


class BindSecurityGroupOverLimit(NeutronException):
    message = _("Only bind one security group per instance")


class ResourceNotFound(qexception.NotFound):
    message = _("Resource of Tenant %(Tenant_id)s should create first")


class H3CSecurityGroupRuleDbNotFound(qexception.NotFound):
    message = _("H3CSecurityGroupRule %(h3c_security_group_rule_id)s "
                "could not be found")


class PortIpInused(qexception.Conflict):
    message = _("The port ip %(port_ip)s is being used by "
                "floating ip %(floating_ip)s.")


class IpNotSupportAssigned(NeutronException):
    message = _("The ip address couldn't be assigned.")


class PoolSubnetNotBound(NeutronException):
    message = _("VCFC create pool failed, the subnet of vlan "
                "pool has not bound to a router.")


class RouterBindResource(NeutronException):
    message = _("Failed to delete the vRouter because it has "
                "been bound to service resources.")


class H3CRouterBindFirewall(NeutronException):
    message = _("The router is bound to one of the tenant's firewalls.")


class NoTunnelIdAvailable(NeutronException):
    message = _("Unable to allocate tunnel id "
                "for %(tunnel_type)s type tunnel.")
