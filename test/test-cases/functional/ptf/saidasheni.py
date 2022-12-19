# Copyright 2022-present Intel Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Thrift SAI interface ENI tests
"""

from unittest import skipIf

from ptf.testutils import test_param_get
from sai_dash_utils import *
from sai_thrift.sai_headers import *


class CreateDeleteEniTest(VnetAPI):
    """
    Verifies ENI creation/deletion and association with MAC and VNI

    Configuration:
    Empty configuration
    """

    def setUp(self):
        super(CreateDeleteEniTest, self).setUp()

        self.cps = 10000         # ENI connections per second
        self.pps = 100000        # ENI packets per seconds
        self.flows = 100000      # ENI flows
        self.admin_state = True  # ENI admin state
        self.vm_vni = 10         # ENI VM VNI
        self.eni_mac = '00:11:22:33:44:55'  # ENI MAC address
        self.vm_underlay_dip = sai_ipaddress('192.168.1.5')  # ENI VM underlay DIP

        self.sip = '10.0.1.2'  # PA validation entry SIP address

        self.in_acl_group_id = 0
        self.out_acl_group_id = 0

    def runTest(self):

        print("Starting CreateDeleteEniTest")

        # Note: tests MUST be run in the following sequence:

        # Create verification
        self.createVnetTest()
        self.createDirectionLookupTest()
        self.createEniTest()
        self.createEniEtherAddressMapTest()
        if not test_param_get('bmv2'):
            # Issue #233
            self.createInboundRoutingEntryTest()
            self.createPaValidationTest()
        self.createOutboundRoutingEntryTest()
        self.createCa2PaEntryTest()

        # Remove verification
        if not test_param_get('bmv2'):
            # TODO: add issue
            self.deleteEniWhenMapExistTest()

        print("Destroying CreateDeleteEniTest configuration")
        # verify all entries can be removed with status success
        self.destroy_teardown_obj()
        # clear teardown_objects not to remove all entries again in tearDown
        self.teardown_objects.clear()

        print("CreateDeleteEniTest PASS")

    def tearDown(self):
        super(CreateDeleteEniTest, self).tearDown()

    def createVnetTest(self):
        """
        Verifies VNET creation

        Note: test should be run before createEniTest
        """

        # vnet for ENI creation
        self.vm_vnet = self.vnet_create(vni=self.vm_vni)

        # src_vnet for Inbound routing entry
        self.outbound_vnet = self.vnet_create(vni=10000)

    def createDirectionLookupTest(self):
        """
        Verifies Direction Lookup creation
        """
        self.dir_lookup = self.direction_lookup_create(vni=self.vm_vni)

    def createEniTest(self):
        """
        Verifies ENI entry creation

        Note: ENI entry deletion is in deleteEniTest
        """

        self.eni = self.eni_create(cps=self.cps,
                                   pps=self.pps,
                                   flows=self.flows,
                                   admin_state=self.admin_state,
                                   vm_underlay_dip=self.vm_underlay_dip,
                                   vm_vni=self.vm_vni,
                                   vnet_id=self.vm_vnet)

    def createEniEtherAddressMapTest(self):
        """
        Verifies Eni Ether Address Map entry creation

        Note: test should be run after createEniTest
        """

        self.eni_mac_map_entry = self.eni_mac_map_create(eni_id=self.eni,
                                                         mac=self.eni_mac)

    def createInboundRoutingEntryTest(self):
        """
        Verifies Inbound routing entry creation

        Note: test should be run after createEniTest
        """

        self.inbound_routing_entry = self.inbound_routing_decap_validate_create(
            eni_id=self.eni, vni=self.vm_vni,
            sip=self.sip, sip_mask="255.255.255.0",
            src_vnet_id=self.outbound_vnet)

    def createPaValidationTest(self):
        """
        Verifies PA validation entry creation

        Note: test should be run after createEniTest
        """

        self.pa_valid_entry = self.pa_validation_create(sip=self.sip,
                                                        vnet_id=self.outbound_vnet)

    def createOutboundRoutingEntryTest(self):
        """
        Verifies Outbound routing entry creation

        Note: test should be run after createEniTest
        """
        self.overlay_ip = "192.168.2.22"

        self.outbound_routing_entry = self.outbound_routing_vnet_direct_create(
            eni_id=self.eni,
            lpm="192.168.2.0/24",
            dst_vnet_id=self.outbound_vnet,
            overlay_ip=self.overlay_ip)
        # TODO: add counter

    def createCa2PaEntryTest(self):
        """
        Verifies Outbound CA to PA entry creation

        Note: test should be run after createOutboundRoutingEntryTest
        """

        self.underlay_dip = '192.168.10.10'
        self.overlay_dmac = '55:44:33:22:11:00'

        self.ca_to_pa_entry = self.outbound_ca_to_pa_create(
            dst_vnet_id=self.outbound_vnet,
            dip=self.overlay_ip,
            underlay_dip=self.underlay_dip,
            overlay_dmac=self.overlay_dmac,
            use_dst_vnet_vni=True)
        # TODO: add counter

    def deleteEniWhenMapExistTest(self):
        """
        Verifies ENI entry deletion when mappings exist
        (e.g. vnet, eni_ether_address_map, inbound/outbound routing entries)
        Expect that ENI entry and other entries will be deleted successfully

        # TODO: clarify how to verify that other objects also has been deleted

        Note: createEniTest should be run first to create ENI
        """
        sai_thrift_remove_eni(self.client, eni_oid=self.eni)
        self.assertEqual(self.status(), SAI_STATUS_SUCCESS)


@skipIf(test_param_get('bmv2'), "Blocked by Issue #233. Inbound Routing is not supported in BMv2.")
class CreateTwoSameEnisNegativeTest(VnetAPI):
    """
    Verifies failure in case of creation the same ENIs in one VNET
    """

    def runTest(self):

        vip = "10.1.1.1"
        vm_vni = 1
        vm_underlay_dip = "10.10.1.10"
        eni_mac = "00:01:00:00:03:14"

        self.vip_create(vip=vip)

        self.direction_lookup_create(vni=vm_vni)

        vnet = self.vnet_create(vni=vm_vni)

        # first eni and eni mac mapping
        eni_id_0 = self.eni_create(admin_state=True,
                                   vm_underlay_dip=sai_ipaddress(vm_underlay_dip),
                                   vm_vni=vm_vni,
                                   vnet_id=vnet)

        self.eni_mac_map_create(eni_id_0, eni_mac)

        # second eni and eni mac mapping
        eni_id_1 = self.eni_create(admin_state=True,
                                   vm_underlay_dip=sai_ipaddress(vm_underlay_dip),
                                   vm_vni=vm_vni,
                                   vnet_id=vnet)

        # create ENI 1 mac mapping and expect failure
        eni_ether_address_map_entry = sai_thrift_eni_ether_address_map_entry_t(
            switch_id=self.switch_id,
            address=eni_mac)
        sai_thrift_create_eni_ether_address_map_entry(self.client,
                                                      eni_ether_address_map_entry,
                                                      eni_id=eni_id_1)

        self.assertEqual(self.status(), SAI_STATUS_FAILURE)
