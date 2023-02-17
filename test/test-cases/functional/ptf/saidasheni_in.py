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

    def runTest(self):
        # Not all tests are interdependent,
        # so they must be run in the following sequence:

        # Create verification
        self.createInOutAclGroupsTest()
        self.createVnetTest()
        self.createDirectionLookupTest()
        self.createEniTest()
        self.createEniEtherAddressMapTest()
        self.createInboundRoutingEntryTest()
        self.createPaValidationTest()
        self.createOutboundRoutingEntryTest()
        self.createCa2PaEntryTest()

        # Remove verification
        # if not test_param_get('target') == 'bmv2':
        #     # TODO: add issue
        #     self.deleteVnetWhenMapExistTest()
        #     self.deleteEniWhenMapExistTest()
        # verify all entries can be removed with status success
        self.destroy_teardown_obj()
        # clear teardown_objects not to remove all entries again in tearDown
        self.teardown_objects.clear()

    def tearDown(self):
        super(CreateDeleteEniTest, self).tearDown()

    def createInOutAclGroupsTest(self):
        """
        Verifies ACL groups creation needed for ENI creation

        Note: test should be run before createEniTest
        """

        self.in_acl_group_id = self.dash_acl_group_create()
        self.out_acl_group_id = self.dash_acl_group_create()

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
        self.dir_lookup = self.direction_lookup_create(vni=self.outbound_vnet)

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
                                   vnet_id=self.vm_vnet,
                                   inbound_v4_stage1_dash_acl_group_id=self.in_acl_group_id,
                                   inbound_v4_stage2_dash_acl_group_id=self.in_acl_group_id,
                                   inbound_v4_stage3_dash_acl_group_id=self.in_acl_group_id,
                                   inbound_v4_stage4_dash_acl_group_id=self.in_acl_group_id,
                                   inbound_v4_stage5_dash_acl_group_id=self.in_acl_group_id,
                                   outbound_v4_stage1_dash_acl_group_id=self.out_acl_group_id,
                                   outbound_v4_stage2_dash_acl_group_id=self.out_acl_group_id,
                                   outbound_v4_stage3_dash_acl_group_id=self.out_acl_group_id,
                                   outbound_v4_stage4_dash_acl_group_id=self.out_acl_group_id,
                                   outbound_v4_stage5_dash_acl_group_id=self.out_acl_group_id,
                                   inbound_v6_stage1_dash_acl_group_id=0,
                                   inbound_v6_stage2_dash_acl_group_id=0,
                                   inbound_v6_stage3_dash_acl_group_id=0,
                                   inbound_v6_stage4_dash_acl_group_id=0,
                                   inbound_v6_stage5_dash_acl_group_id=0,
                                   outbound_v6_stage1_dash_acl_group_id=0,
                                   outbound_v6_stage2_dash_acl_group_id=0,
                                   outbound_v6_stage3_dash_acl_group_id=0,
                                   outbound_v6_stage4_dash_acl_group_id=0,
                                   outbound_v6_stage5_dash_acl_group_id=0)

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
            src_vnet_id=self.outbound_vnet
        )

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
            use_dst_vnet_vni=True
        )
        # TODO: add counter

    def deleteVnetWhenMapExistTest(self):
        """
        Verifies Vnet entry deletion attempt when mapping with ENI exists
        Expect that Vnet entry cannot be deleted

        Note: createVnetTest and createEniTest should be run first
        """
        sai_thrift_remove_vnet(self.client, self.vm_vnet)
        self.assertEqual(self.status(), SAI_STATUS_OBJECT_IN_USE)

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
