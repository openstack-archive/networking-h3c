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
import uuid
from six import moves
from testtools import matchers

from networking_h3c.db import h3c_l3_vxlan_db as l3_vxlan
from networking_h3c.common import exceptions as h_exc
from neutron.common import exceptions as exc
import neutron.db.api as db
from neutron.plugins.common import constants as p_const
from neutron.plugins.common import utils as plugin_utils
from neutron.plugins.ml2 import config
from neutron.plugins.ml2 import driver_api as api
from neutron.tests.unit import testlib_api

VXLAN_MIN = 10000
VXLAN_MAX = 10100
VXLAN_RANGES = ['%s:%s' % (VXLAN_MIN, VXLAN_MAX)]
L3_VXLAN_RANGES = [(VXLAN_MIN, VXLAN_MAX)]
UPDATED_L3_VXLAN_RANGES = [(VXLAN_MIN + 5, VXLAN_MAX + 5)]


class TestH3CL3VxlanDriver(testlib_api.SqlTestCase):
    TYPE = 'l3_vxlan'

    def setUp(self):
        super(TestH3CL3VxlanDriver, self).setUp()
        config.cfg.CONF.set_override('l3_vni_ranges', VXLAN_RANGES,
                                     'VCFCONTROLLER')
        self.driver = l3_vxlan.H3CL3VxlanDriver()
        self.driver._sync_l3_vxlan_allocations()
        self.context = mock.Mock(session=db.get_session())

    def _get_allocation(self, session, router_id):
        return session.query(l3_vxlan.H3CL3VxlanAllocation).filter_by(
            router_id=router_id).first()

    def test_parse_vni_exception_handling(self):
        with mock.patch.object(self.driver,
                               'parse_l3_vni_ranges') as parse_ranges:
            parse_ranges.side_effect = Exception('any exception')
            self.assertRaises(SystemExit,
                              self.driver._parse_l3_vni_ranges)

    def test_parse_l3_vni_ranges(self):
        l3_vxlan_ranges = self.driver.parse_l3_vni_ranges(VXLAN_RANGES)
        self.assertEqual(l3_vxlan_ranges, L3_VXLAN_RANGES)

    def test_parse_l3_vni_ranges_invalid_value(self):
        vxlan_ranges = 'a:b'
        self.assertRaises(exc.NetworkTunnelRangeError,
                          self.driver.parse_l3_vni_ranges, vxlan_ranges)

    def test_create_l3_segments(self):
        rids = set()
        for x in moves.range(VXLAN_MIN, VXLAN_MAX + 1):
            rid = str(uuid.uuid1())
            segment = self.driver.create_l3_segments(self.context, rid)
            self.assertThat(segment, matchers.GreaterThan(VXLAN_MIN - 1))
            self.assertThat(segment, matchers.LessThan(VXLAN_MAX + 1))
            rids.add(rid)
        self.assertRaises(h_exc.NoTunnelIdAvailable,
                          self.driver.create_l3_segments,
                          self.context,
                          str(uuid.uuid1()))

        rid = rids.pop()
        self.driver.release_segment(self.context.session, rid)
        segment = self.driver.create_l3_segments(self.context, rid)
        self.assertThat(segment, matchers.GreaterThan(VXLAN_MIN - 1))
        self.assertThat(segment, matchers.LessThan(VXLAN_MAX + 1))
        rids.add(rid)
        for rid in rids:
            self.driver.release_segment(self.context.session, rid)

    def test_release_segment(self):
        rids = []
        segments = set()
        for i in range(4):
            rid = str(uuid.uuid1())
            segment = self.driver.create_l3_segments(self.context, rid)
            rids.append(rid)
            segments.add(segment)

        # Release them in random order. No special meaning.
        for i in (0, 2, 1, 3):
            self.driver.release_segment(self.context.session, rids[i])

        for segment in segments:
            alloc = self.driver.get_allocation(self.context.session, segment)
            self.assertFalse(alloc.allocated)

    def test_partial_segment_is_partial_segment(self):
        segment = {api.NETWORK_TYPE: self.TYPE,
                   api.PHYSICAL_NETWORK: None,
                   api.SEGMENTATION_ID: None}
        self.assertTrue(self.driver.is_partial_segment(segment))

    def test_specific_segment_is_not_partial_segment(self):
        segment = {api.NETWORK_TYPE: self.TYPE,
                   api.PHYSICAL_NETWORK: None,
                   api.SEGMENTATION_ID: 101}
        self.assertFalse(self.driver.is_partial_segment(segment))

    def test_sync_l3_vxlan_allocations(self):
        self.assertIsNone(
            self.driver.get_allocation(self.context.session, (VXLAN_MIN - 1)))
        self.assertFalse(
            self.driver.get_allocation(self.context.session,
                                       VXLAN_MIN).allocated)
        self.assertFalse(
            self.driver.get_allocation(self.context.session,
                                       (VXLAN_MIN + 1)).allocated)
        self.assertFalse(
            self.driver.get_allocation(self.context.session,
                                       (VXLAN_MAX - 1)).allocated)
        self.assertFalse(
            self.driver.get_allocation(self.context.session,
                                       VXLAN_MAX).allocated)
        self.assertIsNone(
            self.driver.get_allocation(self.context.session, (VXLAN_MAX + 1)))

        self.driver.l3_vni_ranges = UPDATED_L3_VXLAN_RANGES
        self.driver._sync_l3_vxlan_allocations()

        self.assertIsNone(
            self.driver.get_allocation(self.context.session,
                                       (VXLAN_MIN + 5 - 1)))
        self.assertFalse(
            self.driver.get_allocation(self.context.session,
                                       (VXLAN_MIN + 5)).allocated)
        self.assertFalse(
            self.driver.get_allocation(self.context.session,
                                       (VXLAN_MIN + 5 + 1)).allocated)
        self.assertFalse(
            self.driver.get_allocation(self.context.session,
                                       (VXLAN_MAX + 5 - 1)).allocated)
        self.assertFalse(
            self.driver.get_allocation(self.context.session,
                                       (VXLAN_MAX + 5)).allocated)
        self.assertIsNone(
            self.driver.get_allocation(self.context.session,
                                       (VXLAN_MAX + 5 + 1)))

        self.driver.l3_vni_ranges = L3_VXLAN_RANGES
        self.driver._sync_l3_vxlan_allocations()
