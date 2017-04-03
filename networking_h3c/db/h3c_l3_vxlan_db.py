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

import sqlalchemy as sa
import sys
from networking_h3c._i18n import _
from networking_h3c._i18n import _LE
from networking_h3c.common import config  # noqa
from networking_h3c.common import exceptions as h_exc
from neutron.common import exceptions as exc
from neutron.db import api as db_api
from neutron.db import model_base
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers import helpers
from oslo.config import cfg
from oslo.log import log
from six import moves
from sqlalchemy import sql

LOG = log.getLogger(__name__)


class H3CL3VxlanAllocation(model_base.BASEV2):
    """Represent allocation state of a vlan_id on a physical network.

    If allocated is False, the vlan_id on the physical_network is
    available for allocation to a tenant network. If allocated is
    True, the vlan_id on the physical_network is in use, either as a
    tenant or provider network.

    When an allocation is released, if the vlan_id for the
    physical_network is inside the pool described by
    VlanTypeDriver.network_vlan_ranges, then allocated is set to
    False. If it is outside the pool, the record is deleted.
    """

    __tablename__ = 'h3c_l3_vxlan_allocations'

    router_id = sa.Column(sa.String(255))
    vxlan_vni = sa.Column(sa.Integer, nullable=False, primary_key=True,
                          autoincrement=False)
    allocated = sa.Column(sa.Boolean, nullable=False, default=False,
                          server_default=sql.false(), index=True)


class H3CL3VxlanDriver(helpers.SegmentTypeDriver):
    """Manage state for VLAN networks with ML2.

    The VlanTypeDriver implements the 'vlan' network_type. VLAN
    network segments provide connectivity between VMs and other
    devices using any connected IEEE 802.1Q conformant
    physical_network segmented into virtual networks via IEEE 802.1Q
    headers. Up to 4094 VLAN network segments can exist on each
    available physical_network.
    """

    def __init__(self):
        super(H3CL3VxlanDriver, self).__init__(H3CL3VxlanAllocation)
        self._parse_l3_vni_ranges()

    def _parse_l3_vni_ranges(self):
        try:
            self.l3_vni_ranges = self.parse_l3_vni_ranges(
                cfg.CONF.VCFCONTROLLER.l3_vni_ranges)
        except Exception as e:
            LOG.exception(_LE("Failed to parse l3_vni_ranges. "
                              "Service terminated!: %s"), e)
            sys.exit(1)
        LOG.info(_("L3 vni ranges: %s"), self.l3_vni_ranges)

    def create_l3_segments(self, context, router_id):
        """Call type drivers to create network segments."""
        session = context.session
        mtu = []
        with session.begin(subtransactions=True):
            segment = self.allocate_tenant_segment(session)
            if segment.get(api.MTU) > 0:
                mtu.append(segment[api.MTU])

            segment_id = segment['segmentation_id']
            query = (session.query(self.model).filter_by(vxlan_vni=segment_id))
            query.update({"router_id": router_id})

        return segment_id

    def parse_l3_vni_ranges(self, l3_vxlan_ranges_cfg_entries):
        """Interpret a list of strings as vxlan_begin:vxlan_end entries."""
        l3_vxlan_ranges = []
        for entry in l3_vxlan_ranges_cfg_entries:
            entry = entry.strip()
            try:
                vni_min, vni_max = entry.split(':')
                vni_min = vni_min.strip()
                vni_max = vni_max.strip()
                vni_range = int(vni_min), int(vni_max)
            except ValueError as ex:
                raise exc.NetworkTunnelRangeError(tunnel_range=entry, error=ex)
            l3_vxlan_ranges.append(vni_range)
        return l3_vxlan_ranges

    def _sync_l3_vxlan_allocations(self):

        # determine current configured allocatable vnis
        l3_vxlan_vnis = set()
        for vni_min, vni_max in self.l3_vni_ranges:
                l3_vxlan_vnis |= set(moves.xrange(vni_min, vni_max + 1))

        session = db_api.get_session()
        with session.begin(subtransactions=True):
            # remove from table unallocated tunnels not currently allocatable
            # fetch results as list via all() because we'll be iterating
            # through them twice
            allocs = (session.query(H3CL3VxlanAllocation).
                      with_lockmode("update").all())
            # collect all vnis present in db
            existing_vnis = set(alloc.vxlan_vni for alloc in allocs)
            # collect those vnis that needs to be deleted from db
            vnis_to_remove = [alloc.vxlan_vni for alloc in allocs
                              if (alloc.vxlan_vni not in l3_vxlan_vnis and
                                  not alloc.allocated)]
            # Immediately delete vnis in chunks. This leaves no work for
            # flush at the end of transaction
            bulk_size = 100
            chunked_vnis = (vnis_to_remove[i:i + bulk_size] for i in
                            range(0, len(vnis_to_remove), bulk_size))
            for vni_list in chunked_vnis:
                if vni_list:
                    session.query(H3CL3VxlanAllocation).filter(
                        H3CL3VxlanAllocation.vxlan_vni.in_(vni_list)).delete(
                            synchronize_session=False)
            # collect vnis that need to be added
            vnis = list(l3_vxlan_vnis - existing_vnis)
            chunked_vnis = (vnis[i:i + bulk_size] for i in
                            range(0, len(vnis), bulk_size))
            for vni_list in chunked_vnis:
                bulk = [{'vxlan_vni': vni, 'allocated': False}
                        for vni in vni_list]
                session.execute(H3CL3VxlanAllocation.__table__.insert(), bulk)

    def initialize(self):
        self._sync_l3_vxlan_allocations()
        LOG.info(_("L3VxlanDriver initialization complete"))

    def get_type(self):
        return 'l3_vxlan'

    def allocate_tenant_segment(self, session):
        alloc = self.allocate_partially_specified_segment(session)
        if not alloc:
            raise h_exc.NoTunnelIdAvailable(tunnel_type=self.get_type())
        return {api.NETWORK_TYPE: self.get_type(),
                api.PHYSICAL_NETWORK: None,
                api.SEGMENTATION_ID: alloc.vxlan_vni,
                api.MTU: self.get_mtu()}

    def release_segment(self, session, router_id):
        query = (session.query(self.model).filter_by(router_id=router_id))
        if query.first() is None:
            return
        vxlan_id = query.first().vxlan_vni

        inside = any(lo <= vxlan_id <= hi for lo, hi in self.l3_vni_ranges)

        info = {'type': self.get_type(), 'id': vxlan_id}
        with session.begin(subtransactions=True):
            query = (session.query(self.model).filter_by(vxlan_vni=vxlan_id))
            if inside:
                count = query.update({"allocated": False, 'router_id': None})
                if count:
                    LOG.debug("Releasing %(type)s tunnel %(id)s to pool",
                              info)
            else:
                count = query.delete()
                if count:
                    LOG.debug("Releasing %(type)s tunnel %(id)s outside pool",
                              info)

        if not count:
            LOG.warning(_("%(type)s tunnel %(id)s not found"), info)

    def get_allocation(self, session, vxlan_id):
        return (session.query(self.model).
                filter_by(vxlan_vni=vxlan_id).first())

    def is_partial_segment(self, segment):
        return segment.get(api.SEGMENTATION_ID) is None

    def reserve_provider_segment(self, session, segment):
        pass

    def validate_provider_segment(self, segment):
        pass
