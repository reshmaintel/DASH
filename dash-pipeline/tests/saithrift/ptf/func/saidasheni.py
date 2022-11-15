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

from sai_thrift.sai_headers import *
from sai_dash_utils import *


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
        # All tests are interdependent,
        # so they must be run in the following sequence:
        self.createInOutAclGroupsTest()
        self.createVnetTest()
        self.createEniTest()
        self.createEniEtherAddressMapTest()
        print("\nWARNING: sai_thrift_create_inbound_routing_entry failed with type error.\n")
        # self.createInboundRoutingEntryTest()
        # self.createPaValidationTest()
        self.createOutboundRoutingEntryTest()

        print("\nWARNING: get attribute tests all fail.\n")
        #self.eniAttributesTest()
        #self.eniEtherAddressMapAttributesTest()
        # self.inboundRoutingEntryAttributesTest()
        # self.paValidationEntryAttributesTest()
        #self.outboundRoutingEntryAttributesTest()

        print("\nWARNING: ENI delete when mappings exist pass despite requirement #13 (which conflicts with #11) and then teardown fail despite requirement #11...\n")
        # self.deleteEniWhenMapExistTest()
        # verify all entries can be removed with status success
        self.destroy_teardown_obj()
        # clear teardown_objects not to remove all entries again in tearDown
        self.teardown_objects.clear()
        # self.duplicatedEniDeletionTest()

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

    def eniAttributesTest(self):
        """
        Verifies getting and setting ENI entry attributes

        Note: createEniTest should be run first to create ENI entry
        """
        # verify attributes initially created ENI
        attr = sai_thrift_get_eni_attribute(self.client,
                                            self.eni,
                                            cps=True,
                                            pps=True,
                                            flows=True,
                                            admin_state=True,
                                            vm_underlay_dip=True,
                                            vm_vni=True,
                                            vnet_id=True,
                                            inbound_v4_stage1_dash_acl_group_id=True,
                                            inbound_v4_stage2_dash_acl_group_id=True,
                                            inbound_v4_stage3_dash_acl_group_id=True,
                                            inbound_v4_stage4_dash_acl_group_id=True,
                                            inbound_v4_stage5_dash_acl_group_id=True,
                                            inbound_v6_stage1_dash_acl_group_id=True,
                                            inbound_v6_stage2_dash_acl_group_id=True,
                                            inbound_v6_stage3_dash_acl_group_id=True,
                                            inbound_v6_stage4_dash_acl_group_id=True,
                                            inbound_v6_stage5_dash_acl_group_id=True,
                                            outbound_v4_stage1_dash_acl_group_id=True,
                                            outbound_v4_stage2_dash_acl_group_id=True,
                                            outbound_v4_stage3_dash_acl_group_id=True,
                                            outbound_v4_stage4_dash_acl_group_id=True,
                                            outbound_v4_stage5_dash_acl_group_id=True,
                                            outbound_v6_stage1_dash_acl_group_id=True,
                                            outbound_v6_stage2_dash_acl_group_id=True,
                                            outbound_v6_stage3_dash_acl_group_id=True,
                                            outbound_v6_stage4_dash_acl_group_id=True,
                                            outbound_v6_stage5_dash_acl_group_id=True)

        self.assertEqual(attr['cps'], self.cps)
        self.assertEqual(attr['pps'], self.pps)
        self.assertEqual(attr['flows'], self.flows)
        self.assertEqual(attr['admin_state'], self.admin_state)
        self.assertEqual(attr['vm_underlay_dip'], self.vm_underlay_dip)
        self.assertEqual(attr['vm_vni'], self.vm_vni)
        self.assertEqual(attr['vnet_id'], self.vm_vnet)
        self.assertEqual(attr['inbound_v4_stage1_dash_acl_group_id'], self.in_acl_group_id)
        self.assertEqual(attr['inbound_v4_stage2_dash_acl_group_id'], self.in_acl_group_id)
        self.assertEqual(attr['inbound_v4_stage3_dash_acl_group_id'], self.in_acl_group_id)
        self.assertEqual(attr['inbound_v4_stage4_dash_acl_group_id'], self.in_acl_group_id)
        self.assertEqual(attr['inbound_v4_stage5_dash_acl_group_id'], self.in_acl_group_id)
        self.assertEqual(attr['inbound_v6_stage1_dash_acl_group_id'], 0)
        self.assertEqual(attr['inbound_v6_stage2_dash_acl_group_id'], 0)
        self.assertEqual(attr['inbound_v6_stage3_dash_acl_group_id'], 0)
        self.assertEqual(attr['inbound_v6_stage4_dash_acl_group_id'], 0)
        self.assertEqual(attr['inbound_v6_stage5_dash_acl_group_id'], 0)
        self.assertEqual(attr['outbound_v4_stage1_dash_acl_group_id'], self.out_acl_group_id)
        self.assertEqual(attr['outbound_v4_stage2_dash_acl_group_id'], self.out_acl_group_id)
        self.assertEqual(attr['outbound_v4_stage3_dash_acl_group_id'], self.out_acl_group_id)
        self.assertEqual(attr['outbound_v4_stage4_dash_acl_group_id'], self.out_acl_group_id)
        self.assertEqual(attr['outbound_v4_stage5_dash_acl_group_id'], self.out_acl_group_id)
        self.assertEqual(attr['outbound_v6_stage1_dash_acl_group_id'], 0)
        self.assertEqual(attr['outbound_v6_stage2_dash_acl_group_id'], 0)
        self.assertEqual(attr['outbound_v6_stage3_dash_acl_group_id'], 0)
        self.assertEqual(attr['outbound_v6_stage4_dash_acl_group_id'], 0)
        self.assertEqual(attr['outbound_v6_stage5_dash_acl_group_id'], 0)


    def eniAttributes2Test(self):
        try:
            test_cps = self.cps * 2
            test_pps = self.pps * 2
            test_flows = self.flows * 2
            test_admin_state = False
            test_vm_vni = 5

            test_vm_underlay_dip = sai_ipaddress('172.2.1.5')

            test_vnet = self.vnet_create(vni=test_vm_vni)

            test_ipv6_in_acl_group_id = self.dash_acl_group_create(ipv6=True)
            test_ipv6_out_acl_group_id = self.dash_acl_group_create(ipv6=True)

            # set and verify new cps value
            sai_thrift_set_eni_attribute(self.client, self.eni, cps=test_cps)
            self.assertEqual(self.status(), SAI_STATUS_SUCCESS)

            attr = sai_thrift_get_eni_attribute(self.client, self.eni, cps=True)
            self.assertEqual(attr['cps'], test_cps)

            # set and verify new pps value
            sai_thrift_set_eni_attribute(self.client, self.eni, pps=test_pps)
            self.assertEqual(self.status(), SAI_STATUS_SUCCESS)

            attr = sai_thrift_get_eni_attribute(self.client, self.eni, pps=True)
            self.assertEqual(attr['pps'], test_pps)

            # set and verify new flow value
            sai_thrift_set_eni_attribute(self.client, self.eni, flows=test_flows)
            self.assertEqual(self.status(), SAI_STATUS_SUCCESS)

            attr = sai_thrift_get_eni_attribute(self.client, self.eni, flows=True)
            self.assertEqual(attr['flows'], test_flows)

            # set and verify new admin_state value
            sai_thrift_set_eni_attribute(self.client, self.eni, admin_state=test_admin_state)
            self.assertEqual(self.status(), SAI_STATUS_SUCCESS)

            attr = sai_thrift_get_eni_attribute(self.client, self.eni, admin_state=True)
            self.assertEqual(attr['admin_state'], test_admin_state)

            # set and verify new vm_underlay_dip value
            sai_thrift_set_eni_attribute(self.client, self.eni, vm_underlay_dip=test_vm_underlay_dip)
            self.assertEqual(self.status(), SAI_STATUS_SUCCESS)

            attr = sai_thrift_get_eni_attribute(self.client, self.eni, vm_underlay_dip=True)
            self.assertEqual(attr['vm_underlay_dip'], test_vm_underlay_dip)

            # set and verify new vm_vni value
            sai_thrift_set_eni_attribute(self.client, self.eni, vm_vni=test_vm_vni)
            self.assertEqual(self.status(), SAI_STATUS_SUCCESS)

            attr = sai_thrift_get_eni_attribute(self.client, self.eni, vm_vni=True)
            self.assertEqual(attr['vm_vni'], test_vm_vni)

            # set and verify new vnet_id value
            sai_thrift_set_eni_attribute(self.client, self.eni, vnet_id=test_vnet)
            self.assertEqual(self.status(), SAI_STATUS_SUCCESS)

            attr = sai_thrift_get_eni_attribute(self.client, self.eni, vnet_id=True)
            self.assertEqual(attr['vnet_id'], test_vnet)

            # set and verify new inbound_v4_stage1_dash_acl_group_id value
            sai_thrift_set_eni_attribute(self.client, self.eni, inbound_v4_stage1_dash_acl_group_id=0)
            self.assertEqual(self.status(), SAI_STATUS_SUCCESS)

            attr = sai_thrift_get_eni_attribute(self.client, self.eni, inbound_v4_stage1_dash_acl_group_id=True)
            self.assertEqual(attr['inbound_v4_stage1_dash_acl_group_id'], 0)

            # set and verify new inbound_v4_stage2_dash_acl_group_id value
            sai_thrift_set_eni_attribute(self.client, self.eni, inbound_v4_stage2_dash_acl_group_id=0)
            self.assertEqual(self.status(), SAI_STATUS_SUCCESS)

            attr = sai_thrift_get_eni_attribute(self.client, self.eni, inbound_v4_stage2_dash_acl_group_id=True)
            self.assertEqual(attr['inbound_v4_stage2_dash_acl_group_id'], 0)

            # set and verify new inbound_v4_stage3_dash_acl_group_id value
            sai_thrift_set_eni_attribute(self.client, self.eni, inbound_v4_stage3_dash_acl_group_id=0)
            self.assertEqual(self.status(), SAI_STATUS_SUCCESS)

            attr = sai_thrift_get_eni_attribute(self.client, self.eni, inbound_v4_stage3_dash_acl_group_id=True)
            self.assertEqual(attr['inbound_v4_stage3_dash_acl_group_id'], 0)

            # set and verify new inbound_v4_stage4_dash_acl_group_id value
            sai_thrift_set_eni_attribute(self.client, self.eni, inbound_v4_stage4_dash_acl_group_id=0)
            self.assertEqual(self.status(), SAI_STATUS_SUCCESS)

            attr = sai_thrift_get_eni_attribute(self.client, self.eni, inbound_v4_stage4_dash_acl_group_id=True)
            self.assertEqual(attr['inbound_v4_stage4_dash_acl_group_id'], 0)

            # set and verify new inbound_v4_stage5_dash_acl_group_id value
            sai_thrift_set_eni_attribute(self.client, self.eni, inbound_v4_stage5_dash_acl_group_id=0)
            self.assertEqual(self.status(), SAI_STATUS_SUCCESS)

            attr = sai_thrift_get_eni_attribute(self.client, self.eni, inbound_v4_stage5_dash_acl_group_id=True)
            self.assertEqual(attr['inbound_v4_stage5_dash_acl_group_id'], 0)

            # set and verify new inbound_v6_stage1_dash_acl_group_id value
            sai_thrift_set_eni_attribute(self.client, self.eni,
                                         inbound_v6_stage1_dash_acl_group_id=test_ipv6_in_acl_group_id)
            self.assertEqual(self.status(), SAI_STATUS_SUCCESS)

            attr = sai_thrift_get_eni_attribute(self.client, self.eni, inbound_v6_stage1_dash_acl_group_id=True)
            self.assertEqual(attr['inbound_v6_stage1_dash_acl_group_id'], test_ipv6_in_acl_group_id)

            # set and verify new inbound_v6_stage2_dash_acl_group_id value
            sai_thrift_set_eni_attribute(self.client, self.eni,
                                         inbound_v6_stage2_dash_acl_group_id=test_ipv6_in_acl_group_id)
            self.assertEqual(self.status(), SAI_STATUS_SUCCESS)

            attr = sai_thrift_get_eni_attribute(self.client, self.eni, inbound_v6_stage2_dash_acl_group_id=True)
            self.assertEqual(attr['inbound_v6_stage2_dash_acl_group_id'], test_ipv6_in_acl_group_id)

            # set and verify new inbound_v6_stage3_dash_acl_group_id value
            sai_thrift_set_eni_attribute(self.client, self.eni,
                                         inbound_v6_stage3_dash_acl_group_id=test_ipv6_in_acl_group_id)
            self.assertEqual(self.status(), SAI_STATUS_SUCCESS)

            attr = sai_thrift_get_eni_attribute(self.client, self.eni, inbound_v6_stage3_dash_acl_group_id=True)
            self.assertEqual(attr['inbound_v6_stage3_dash_acl_group_id'], test_ipv6_in_acl_group_id)

            # set and verify new inbound_v6_stage4_dash_acl_group_id value
            sai_thrift_set_eni_attribute(self.client, self.eni,
                                         inbound_v6_stage4_dash_acl_group_id=test_ipv6_in_acl_group_id)
            self.assertEqual(self.status(), SAI_STATUS_SUCCESS)

            attr = sai_thrift_get_eni_attribute(self.client, self.eni, inbound_v6_stage4_dash_acl_group_id=True)
            self.assertEqual(attr['inbound_v6_stage4_dash_acl_group_id'], test_ipv6_in_acl_group_id)

            # set and verify new inbound_v6_stage5_dash_acl_group_id value
            sai_thrift_set_eni_attribute(self.client, self.eni,
                                         inbound_v6_stage5_dash_acl_group_id=test_ipv6_in_acl_group_id)
            self.assertEqual(self.status(), SAI_STATUS_SUCCESS)

            attr = sai_thrift_get_eni_attribute(self.client, self.eni, inbound_v6_stage5_dash_acl_group_id=True)
            self.assertEqual(attr['inbound_v6_stage5_dash_acl_group_id'], test_ipv6_in_acl_group_id)

            # set and verify new outbound_v4_stage1_dash_acl_group_id value
            sai_thrift_set_eni_attribute(self.client, self.eni, outbound_v4_stage1_dash_acl_group_id=0)
            self.assertEqual(self.status(), SAI_STATUS_SUCCESS)

            attr = sai_thrift_get_eni_attribute(self.client, self.eni, outbound_v4_stage1_dash_acl_group_id=True)
            self.assertEqual(attr['outbound_v4_stage1_dash_acl_group_id'], 0)

            # set and verify new outbound_v4_stage2_dash_acl_group_id value
            sai_thrift_set_eni_attribute(self.client, self.eni, outbound_v4_stage2_dash_acl_group_id=0)
            self.assertEqual(self.status(), SAI_STATUS_SUCCESS)

            attr = sai_thrift_get_eni_attribute(self.client, self.eni, outbound_v4_stage2_dash_acl_group_id=True)
            self.assertEqual(attr['outbound_v4_stage2_dash_acl_group_id'], 0)

            # set and verify new outbound_v4_stage3_dash_acl_group_id value
            sai_thrift_set_eni_attribute(self.client, self.eni, outbound_v4_stage3_dash_acl_group_id=0)
            self.assertEqual(self.status(), SAI_STATUS_SUCCESS)

            attr = sai_thrift_get_eni_attribute(self.client, self.eni, outbound_v4_stage3_dash_acl_group_id=True)
            self.assertEqual(attr['outbound_v4_stage3_dash_acl_group_id'], 0)

            # set and verify new outbound_v4_stage4_dash_acl_group_id value
            sai_thrift_set_eni_attribute(self.client, self.eni, outbound_v4_stage4_dash_acl_group_id=0)
            self.assertEqual(self.status(), SAI_STATUS_SUCCESS)

            attr = sai_thrift_get_eni_attribute(self.client, self.eni, outbound_v4_stage4_dash_acl_group_id=True)
            self.assertEqual(attr['outbound_v4_stage4_dash_acl_group_id'], 0)

            # set and verify new outbound_v4_stage5_dash_acl_group_id value
            sai_thrift_set_eni_attribute(self.client, self.eni, outbound_v4_stage5_dash_acl_group_id=0)
            self.assertEqual(self.status(), SAI_STATUS_SUCCESS)

            attr = sai_thrift_get_eni_attribute(self.client, self.eni, outbound_v4_stage5_dash_acl_group_id=True)
            self.assertEqual(attr['outbound_v4_stage5_dash_acl_group_id'], 0)

            # set and verify new outbound_v6_stage1_dash_acl_group_id value
            sai_thrift_set_eni_attribute(self.client, self.eni,
                                         outbound_v6_stage1_dash_acl_group_id=test_ipv6_out_acl_group_id)
            self.assertEqual(self.status(), SAI_STATUS_SUCCESS)

            attr = sai_thrift_get_eni_attribute(self.client, self.eni, outbound_v6_stage1_dash_acl_group_id=True)
            self.assertEqual(attr['outbound_v6_stage1_dash_acl_group_id'], test_ipv6_out_acl_group_id)

            # set and verify new outbound_v6_stage2_dash_acl_group_id value
            sai_thrift_set_eni_attribute(self.client, self.eni,
                                         outbound_v6_stage2_dash_acl_group_id=test_ipv6_out_acl_group_id)
            self.assertEqual(self.status(), SAI_STATUS_SUCCESS)

            attr = sai_thrift_get_eni_attribute(self.client, self.eni, outbound_v6_stage2_dash_acl_group_id=True)
            self.assertEqual(attr['outbound_v6_stage2_dash_acl_group_id'], test_ipv6_out_acl_group_id)

            # set and verify new outbound_v6_stage3_dash_acl_group_id value
            sai_thrift_set_eni_attribute(self.client, self.eni,
                                         outbound_v6_stage3_dash_acl_group_id=test_ipv6_out_acl_group_id)
            self.assertEqual(self.status(), SAI_STATUS_SUCCESS)

            attr = sai_thrift_get_eni_attribute(self.client, self.eni, outbound_v6_stage3_dash_acl_group_id=True)
            self.assertEqual(attr['outbound_v6_stage3_dash_acl_group_id'], test_ipv6_out_acl_group_id)

            # set and verify new outbound_v6_stage4_dash_acl_group_id value
            sai_thrift_set_eni_attribute(self.client, self.eni,
                                         outbound_v6_stage4_dash_acl_group_id=test_ipv6_out_acl_group_id)
            self.assertEqual(self.status(), SAI_STATUS_SUCCESS)

            attr = sai_thrift_get_eni_attribute(self.client, self.eni, outbound_v6_stage4_dash_acl_group_id=True)
            self.assertEqual(attr['outbound_v6_stage4_dash_acl_group_id'], test_ipv6_out_acl_group_id)

            # set and verify new outbound_v6_stage5_dash_acl_group_id value
            sai_thrift_set_eni_attribute(self.client, self.eni,
                                         outbound_v6_stage5_dash_acl_group_id=test_ipv6_out_acl_group_id)
            self.assertEqual(self.status(), SAI_STATUS_SUCCESS)

            attr = sai_thrift_get_eni_attribute(self.client, self.eni, outbound_v6_stage5_dash_acl_group_id=True)
            self.assertEqual(attr['outbound_v6_stage5_dash_acl_group_id'], test_ipv6_out_acl_group_id)

        finally:
            # set ENI attributes to the original values
            sai_thrift_set_eni_attribute(self.client, self.eni, cps=self.cps)
            sai_thrift_set_eni_attribute(self.client, self.eni, pps=self.pps)
            sai_thrift_set_eni_attribute(self.client, self.eni, flows=self.flows)
            sai_thrift_set_eni_attribute(self.client, self.eni, admin_state=self.admin_state)
            sai_thrift_set_eni_attribute(self.client, self.eni, vm_underlay_dip=self.vm_underlay_dip)
            sai_thrift_set_eni_attribute(self.client, self.eni, vm_vni=self.vm_vni)
            sai_thrift_set_eni_attribute(self.client, self.eni, vnet_id=self.vm_vnet)
            sai_thrift_set_eni_attribute(self.client, self.eni,
                                         inbound_v4_stage1_dash_acl_group_id=self.in_acl_group_id)
            sai_thrift_set_eni_attribute(self.client, self.eni,
                                         inbound_v4_stage2_dash_acl_group_id=self.in_acl_group_id)
            sai_thrift_set_eni_attribute(self.client, self.eni,
                                         inbound_v4_stage3_dash_acl_group_id=self.in_acl_group_id)
            sai_thrift_set_eni_attribute(self.client, self.eni,
                                         inbound_v4_stage4_dash_acl_group_id=self.in_acl_group_id)
            sai_thrift_set_eni_attribute(self.client, self.eni,
                                         inbound_v4_stage5_dash_acl_group_id=self.in_acl_group_id)
            sai_thrift_set_eni_attribute(self.client, self.eni, inbound_v6_stage1_dash_acl_group_id=0)
            sai_thrift_set_eni_attribute(self.client, self.eni, inbound_v6_stage2_dash_acl_group_id=0)
            sai_thrift_set_eni_attribute(self.client, self.eni, inbound_v6_stage3_dash_acl_group_id=0)
            sai_thrift_set_eni_attribute(self.client, self.eni, inbound_v6_stage4_dash_acl_group_id=0)
            sai_thrift_set_eni_attribute(self.client, self.eni, inbound_v6_stage5_dash_acl_group_id=0)
            sai_thrift_set_eni_attribute(self.client, self.eni,
                                         outbound_v4_stage1_dash_acl_group_id=self.out_acl_group_id)
            sai_thrift_set_eni_attribute(self.client, self.eni,
                                         outbound_v4_stage2_dash_acl_group_id=self.out_acl_group_id)
            sai_thrift_set_eni_attribute(self.client, self.eni,
                                         outbound_v4_stage3_dash_acl_group_id=self.out_acl_group_id)
            sai_thrift_set_eni_attribute(self.client, self.eni,
                                         outbound_v4_stage4_dash_acl_group_id=self.out_acl_group_id)
            sai_thrift_set_eni_attribute(self.client, self.eni,
                                         outbound_v4_stage5_dash_acl_group_id=self.out_acl_group_id)
            sai_thrift_set_eni_attribute(self.client, self.eni, outbound_v6_stage1_dash_acl_group_id=0)
            sai_thrift_set_eni_attribute(self.client, self.eni, outbound_v6_stage2_dash_acl_group_id=0)
            sai_thrift_set_eni_attribute(self.client, self.eni, outbound_v6_stage3_dash_acl_group_id=0)
            sai_thrift_set_eni_attribute(self.client, self.eni, outbound_v6_stage4_dash_acl_group_id=0)
            sai_thrift_set_eni_attribute(self.client, self.eni, outbound_v6_stage5_dash_acl_group_id=0)

            attr = sai_thrift_get_eni_attribute(self.client,
                                                self.eni,
                                                cps=True,
                                                pps=True,
                                                flows=True,
                                                admin_state=True,
                                                vm_underlay_dip=True,
                                                vm_vni=True,
                                                vnet_id=True,
                                                inbound_v4_stage1_dash_acl_group_id=True,
                                                inbound_v4_stage2_dash_acl_group_id=True,
                                                inbound_v4_stage3_dash_acl_group_id=True,
                                                inbound_v4_stage4_dash_acl_group_id=True,
                                                inbound_v4_stage5_dash_acl_group_id=True,
                                                inbound_v6_stage1_dash_acl_group_id=True,
                                                inbound_v6_stage2_dash_acl_group_id=True,
                                                inbound_v6_stage3_dash_acl_group_id=True,
                                                inbound_v6_stage4_dash_acl_group_id=True,
                                                inbound_v6_stage5_dash_acl_group_id=True,
                                                outbound_v4_stage1_dash_acl_group_id=True,
                                                outbound_v4_stage2_dash_acl_group_id=True,
                                                outbound_v4_stage3_dash_acl_group_id=True,
                                                outbound_v4_stage4_dash_acl_group_id=True,
                                                outbound_v4_stage5_dash_acl_group_id=True,
                                                outbound_v6_stage1_dash_acl_group_id=True,
                                                outbound_v6_stage2_dash_acl_group_id=True,
                                                outbound_v6_stage3_dash_acl_group_id=True,
                                                outbound_v6_stage4_dash_acl_group_id=True,
                                                outbound_v6_stage5_dash_acl_group_id=True)

            self.assertEqual(attr['cps'], self.cps)
            self.assertEqual(attr['pps'], self.pps)
            self.assertEqual(attr['flows'], self.flows)
            self.assertEqual(attr['admin_state'], self.admin_state)
            self.assertEqual(attr['vm_underlay_dip'], self.vm_underlay_dip)
            self.assertEqual(attr['vm_vni'], self.vm_vni)
            self.assertEqual(attr['vnet_id'], self.vm_vnet)
            self.assertEqual(attr['inbound_v4_stage1_dash_acl_group_id'], self.in_acl_group_id)
            self.assertEqual(attr['inbound_v4_stage2_dash_acl_group_id'], self.in_acl_group_id)
            self.assertEqual(attr['inbound_v4_stage3_dash_acl_group_id'], self.in_acl_group_id)
            self.assertEqual(attr['inbound_v4_stage4_dash_acl_group_id'], self.in_acl_group_id)
            self.assertEqual(attr['inbound_v4_stage5_dash_acl_group_id'], self.in_acl_group_id)
            self.assertEqual(attr['inbound_v6_stage1_dash_acl_group_id'], 0)
            self.assertEqual(attr['inbound_v6_stage2_dash_acl_group_id'], 0)
            self.assertEqual(attr['inbound_v6_stage3_dash_acl_group_id'], 0)
            self.assertEqual(attr['inbound_v6_stage4_dash_acl_group_id'], 0)
            self.assertEqual(attr['inbound_v6_stage5_dash_acl_group_id'], 0)
            self.assertEqual(attr['outbound_v4_stage1_dash_acl_group_id'], self.out_acl_group_id)
            self.assertEqual(attr['outbound_v4_stage2_dash_acl_group_id'], self.out_acl_group_id)
            self.assertEqual(attr['outbound_v4_stage3_dash_acl_group_id'], self.out_acl_group_id)
            self.assertEqual(attr['outbound_v4_stage4_dash_acl_group_id'], self.out_acl_group_id)
            self.assertEqual(attr['outbound_v4_stage5_dash_acl_group_id'], self.out_acl_group_id)
            self.assertEqual(attr['outbound_v6_stage1_dash_acl_group_id'], 0)
            self.assertEqual(attr['outbound_v6_stage2_dash_acl_group_id'], 0)
            self.assertEqual(attr['outbound_v6_stage3_dash_acl_group_id'], 0)
            self.assertEqual(attr['outbound_v6_stage4_dash_acl_group_id'], 0)
            self.assertEqual(attr['outbound_v6_stage5_dash_acl_group_id'], 0)

    def eniEtherAddressMapAttributesTest(self):
        """
        Verifies getting and setting ENI MAC map entry attributes

        Note: createEniTest should be run first to create eni_ether_address_map_entry entry
        """
        # verify attributes initially created eni_ether_address_map_entry
        attr = sai_thrift_get_eni_ether_address_map_entry_attribute(self.client,
                                                                    eni_ether_address_map_entry=self.eni_mac_map_entry,
                                                                    eni_id=True)
        self.assertEqual(attr['eni_id'], self.eni)

    def eniEtherAddressMapAttributes2Test(self):
        try:
            # create test eni to verify set method
            test_cps = 500
            test_pps = 500
            test_flows = 500
            test_vm_underlay_ip = sai_ipaddress('172.0.15.15')

            test_eni = self.eni(cps=test_cps,
                                pps=test_pps,
                                flows=test_flows,
                                admin_state=True,
                                vm_underlay_dip=test_vm_underlay_ip,
                                vm_vni=self.vm_vni,
                                vnet_id=self.vm_vnet,
                                inbound_v4_stage1_dash_acl_group_id=0,
                                inbound_v4_stage2_dash_acl_group_id=0,
                                inbound_v4_stage3_dash_acl_group_id=0,
                                inbound_v4_stage4_dash_acl_group_id=0,
                                inbound_v4_stage5_dash_acl_group_id=0,
                                outbound_v4_stage1_dash_acl_group_id=0,
                                outbound_v4_stage2_dash_acl_group_id=0,
                                outbound_v4_stage3_dash_acl_group_id=0,
                                outbound_v4_stage4_dash_acl_group_id=0,
                                outbound_v4_stage5_dash_acl_group_id=0,
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

            sai_thrift_set_eni_ether_address_map_entry_attribute(
                self.client, eni_ether_address_map_entry=self.eni_mac_map_entry, eni_id=test_eni)
            self.assertEqual(self.status(), SAI_STATUS_SUCCESS)

            attr = sai_thrift_get_eni_ether_address_map_entry_attribute(
                self.client, eni_ether_address_map_entry=self.eni_mac_map_entry, eni_id=True)
            self.assertEqual(attr['eni_id'], test_eni)

        finally:
            # set map back to original ENI
            sai_thrift_set_eni_ether_address_map_entry_attribute(
                self.client, eni_ether_address_map_entry=self.eni_mac_map_entry, eni_id=self.eni)
            self.assertEqual(self.status(), SAI_STATUS_SUCCESS)

            attr = sai_thrift_get_eni_ether_address_map_entry_attribute(
                self.client, eni_ether_address_map_entry=self.eni_mac_map_entry, eni_id=True)
            self.assertEqual(attr['eni_id'], self.eni)

    def paValidationEntryAttributesTest(self):
        """
        Verifies getting PA validation entry attribute

        Note: setting new attribute value cannot be verified
              because PA Validation entry has only 1 attribute value

        Note: createPaValidationTest should be run first to create PA validation entry
        """

        # verify original attributes
        attr = sai_thrift_get_pa_validation_entry_attribute(self.client,
                                                            pa_validation_entry=self.pa_valid_entry,
                                                            action=True)
        self.assertEqual(attr['action'], SAI_PA_VALIDATION_ENTRY_ACTION_PERMIT)

    def inboundRoutingEntryAttributesTest(self):
        """
        Verifies getting and setting Inbound routing entry attributes

        Note: createInboundRoutingEntryTest should be run first to create Inbound routing entry
        """

        # verify original attributes
        attr = sai_thrift_get_inbound_routing_entry_attribute(self.client,
                                                              inbound_routing_entry=self.inbound_routing_entry,
                                                              action=True,
                                                              src_vnet_id=True)
        self.assertEqual(attr['action'], SAI_INBOUND_ROUTING_ENTRY_ACTION_VXLAN_DECAP_PA_VALIDATE)
        self.assertEqual(attr['src_vnet_id'], self.outbound_vnet)

        try:
            # set and verify new action
            sai_thrift_set_inbound_routing_entry_attribute(self.client,
                                                           inbound_routing_entry=self.inbound_routing_entry,
                                                           action=SAI_INBOUND_ROUTING_ENTRY_ACTION_VXLAN_DECAP)
            self.assertEqual(self.status(), SAI_STATUS_SUCCESS)

            attr = sai_thrift_get_inbound_routing_entry_attribute(self.client,
                                                                  inbound_routing_entry=self.inbound_routing_entry,
                                                                  action=True)
            self.assertEqual(attr['action'], SAI_INBOUND_ROUTING_ENTRY_ACTION_VXLAN_DECAP)

            # set and verify new src_vnet_id value
            test_vnet = self.vnet_create(vni=500)

            sai_thrift_set_inbound_routing_entry_attribute(self.client,
                                                           inbound_routing_entry=self.inbound_routing_entry,
                                                           src_vnet_id=test_vnet)
            self.assertEqual(self.status(), SAI_STATUS_SUCCESS)

            attr = sai_thrift_get_inbound_routing_entry_attribute(self.client,
                                                                  inbound_routing_entry=self.inbound_routing_entry,
                                                                  src_vnet_id=True)
            self.assertEqual(attr['src_vnet_id'], test_vnet)
        finally:
            # set back original attribute value
            sai_thrift_set_inbound_routing_entry_attribute(
                self.client,
                inbound_routing_entry=self.inbound_routing_entry,
                action=SAI_INBOUND_ROUTING_ENTRY_ACTION_VXLAN_DECAP_PA_VALIDATE)
            sai_thrift_set_inbound_routing_entry_attribute(self.client,
                                                           inbound_routing_entry=self.inbound_routing_entry,
                                                           src_vnet_id=self.outbound_vnet)

            attr = sai_thrift_get_inbound_routing_entry_attribute(self.client,
                                                                  inbound_routing_entry=self.inbound_routing_entry,
                                                                  action=True,
                                                                  src_vnet_id=True)
            self.assertEqual(attr['action'], SAI_INBOUND_ROUTING_ENTRY_ACTION_VXLAN_DECAP_PA_VALIDATE)
            self.assertEqual(attr['src_vnet_id'], self.outbound_vnet)

    def outboundRoutingEntryAttributesTest(self):
        """
        Verifies getting and setting Outbound routing entry attributes

        Note: createOutboundRoutingEntryTest should be run first to create Outbound routing entry
        """

        # verify original attributes
        attr = sai_thrift_get_outbound_routing_entry_attribute(self.client,
                                                               self.outbound_routing_entry,
                                                               action=True,
                                                               dst_vnet_id=True,
                                                               overlay_ip=True)
        self.assertEqual(attr['action'], SAI_OUTBOUND_ROUTING_ENTRY_ACTION_ROUTE_VNET_DIRECT)
        self.assertEqual(attr['dst_vnet_id'], self.outbound_vnet)
        self.assertEqual(attr['overlay_ip'], self.overlay_ip)

        try:
            test_action = SAI_OUTBOUND_ROUTING_ENTRY_ACTION_ROUTE_VNET
            test_dst_vnet = self.vnet_create(vni=9999)
            test_overlay_ip = "9.9.9.9"

            # set and verify new action
            sai_thrift_set_outbound_routing_entry_attribute(self.client,
                                                            self.outbound_routing_entry,
                                                            action=test_action)
            self.assertEqual(self.status(), SAI_STATUS_SUCCESS)

            sai_thrift_set_outbound_routing_entry_attribute(self.client,
                                                            self.outbound_routing_entry,
                                                            dst_vnet_id=test_dst_vnet)
            self.assertEqual(self.status(), SAI_STATUS_SUCCESS)

            sai_thrift_set_outbound_routing_entry_attribute(self.client,
                                                            self.outbound_routing_entry,
                                                            overlay_ip=test_overlay_ip)
            self.assertEqual(self.status(), SAI_STATUS_SUCCESS)

            # verify that all set correct
            attr = sai_thrift_get_outbound_routing_entry_attribute(self.client,
                                                                   self.outbound_routing_entry,
                                                                   action=True,
                                                                   dst_vnet_id=True,
                                                                   overlay_ip=True)
            self.assertEqual(attr['action'], test_action)
            self.assertEqual(attr['dst_vnet_id'], test_dst_vnet)
            self.assertEqual(attr['overlay_ip'], test_overlay_ip)

        finally:
            # verify that original values can be set back
            sai_thrift_set_outbound_routing_entry_attribute(self.client,
                                                            self.outbound_routing_entry,
                                                            action=SAI_OUTBOUND_ROUTING_ENTRY_ACTION_ROUTE_VNET_DIRECT)
            sai_thrift_set_outbound_routing_entry_attribute(self.client,
                                                            self.outbound_routing_entry,
                                                            dst_vnet_id=self.outbound_vnet)
            sai_thrift_set_outbound_routing_entry_attribute(self.client,
                                                            self.outbound_routing_entry,
                                                            overlay_ip=self.overlay_ip)

            # verify original attributes
            attr = sai_thrift_get_outbound_routing_entry_attribute(self.client,
                                                                   self.outbound_routing_entry,
                                                                   action=True,
                                                                   dst_vnet_id=True,
                                                                   overlay_ip=True)
            self.assertEqual(attr['action'], SAI_OUTBOUND_ROUTING_ENTRY_ACTION_ROUTE_VNET_DIRECT)
            self.assertEqual(attr['dst_vnet_id'], self.outbound_vnet)
            self.assertEqual(attr['overlay_ip'], self.overlay_ip)

    def deleteEniWhenMapExistTest(self):
        """
        Verifies ENI entry deletion attempt when eni_ether_address_map_entry exist

        Note: createEniTest should be run first to create ENI and eni_ether_address_map_entry entry
        """
        sai_thrift_remove_eni(self.client, eni_oid=self.eni)
        self.assertEqual(self.status(), SAI_STATUS_OBJECT_IN_USE)

    def duplicatedEniDeletionTest(self):
        """
        Verifies deletion of previously deleted ENI entry

        Note: createEniTest and deleteEniTest should be run first
              to create and delete ENI entry
        """
        sai_thrift_remove_eni(self.client, self.eni)
        # TODO: clarify status SAI_STATUS_ITEM_NOT_FOUND?
        self.assertEqual(self.status(), SAI_STATUS_SUCCESS)


class EniScaleTest(VnetAPI):
    """
    Verifies ENI scaling:
     - creation/deletion a max number of ENI entries
     - recreation (repeated creation/deletion a max number of ENI entries)

    Configuration:
    Empty configuration
    """
    def setUp(self):
        super(EniScaleTest, self).setUp()

        self.MAX_ENI = 64  # Expected max number of ENI entries per card

        self.cps = 10000         # ENI connections per second
        self.pps = 100000        # ENI packets per second
        self.flows = 100000      # ENI flows
        self.admin_state = True  # ENI admin state
        self.vm_vni = 0          # ENI VM VNI (increments during ENIs creation)
        self.vm_underlay_dip = sai_ipaddress("10.10.0.1")

        # Create list with MAX_ENI + 1 number of unique MAC addresses for ENI creation
        self.eni_mac_list = []
        i = 0
        for last_octet in range(0, 256):
            self.eni_mac_list.append('01:01:01:00:00:' +
                                     ('%02x' % last_octet))
            i += 1
            if i == self.MAX_ENI + 1:
                break

    def runTest(self):
        self.eniScaleTest()
        self.destroy_teardown_obj()  # remove all created entries
        # clear teardown_objects not to remove all entries again in tearDown
        self.teardown_objects.clear()
        self.eniScaleTest()  # verify that max number on ENI entries can be created again

    def eniScaleTest(self):
        """
        Verifies creating and deleting a max number of ENI entries.
        Also creates: vnet, inbound and outbound dash acl groups, eni ether address map entries,
                      pa validation and inbound routing entries.

        Max number of ENI entries hardcoded in MAX_ENI value.
        """

        for indx in range(self.MAX_ENI + 1):
            # create ACL groups for ENI
            in_acl_group_id = self.dash_acl_group_create()
            out_acl_group_id = self.dash_acl_group_create()

            # create VNET
            self.vm_vni += 1
            vm_vnet = self.vnet_create(vni=self.vm_vni)

            # create ENI
            try:
                eni = self.eni_create(cps=self.cps,
                                      pps=self.pps,
                                      flows=self.flows,
                                      admin_state=self.admin_state,
                                      vm_underlay_dip=self.vm_underlay_dip,
                                      vm_vni=self.vm_vni,
                                      vnet_id=vm_vnet,
                                      inbound_v4_stage1_dash_acl_group_id=in_acl_group_id,
                                      inbound_v4_stage2_dash_acl_group_id=in_acl_group_id,
                                      inbound_v4_stage3_dash_acl_group_id=in_acl_group_id,
                                      inbound_v4_stage4_dash_acl_group_id=in_acl_group_id,
                                      inbound_v4_stage5_dash_acl_group_id=in_acl_group_id,
                                      outbound_v4_stage1_dash_acl_group_id=out_acl_group_id,
                                      outbound_v4_stage2_dash_acl_group_id=out_acl_group_id,
                                      outbound_v4_stage3_dash_acl_group_id=out_acl_group_id,
                                      outbound_v4_stage4_dash_acl_group_id=out_acl_group_id,
                                      outbound_v4_stage5_dash_acl_group_id=out_acl_group_id,
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
            except AssertionError as ae:
                if self.status() == SAI_STATUS_INSUFFICIENT_RESOURCES:
                    print(f'ENI entries created: {indx}')
                    error_msg = f'Not expected number of ENI entries are created.' \
                                f'Created: {indx}, Expected: {self.MAX_ENI}'
                    self.assertEqual(indx, self.MAX_ENI, error_msg)
                    break
                else:
                    raise ae

            # create eni_ether_address_map_entry
            self.eni_mac_map_create(eni_id=eni, mac=self.eni_mac_list[indx])

            # create inbound_routing_entry
            if indx == 0:
                print("\nWARNING: Enable inbound_routing_decap_create once issue #233 is fixed\n")
            # self.inbound_routing_decap_create(eni_id=eni,
            #                                   vni=self.vm_vni,
            #                                   sip="10.10.2.0",
            #                                   sip_mask="255.255.255.0")

            # create outbound_routing_entry
            self.outbound_routing_direct_create(eni_id=eni,
                                                lpm="192.168.1.0/24")


@group("draft")
class CreateTwoSameEnisNegativeTest(VnetApiEndpoints):
    """
    Verifies failure in case of creation the same ENIs in one VNET
    """

    def runTest(self):

        self.preconfigureTest()
        self.enisCreationTest()

    def preconfigureTest(self):
        """
        Setup DUT in accordance with test purpose
        """

        # Define two the same hosts
        self.host_0 = self.tx_host

        self.host_1 = self.define_neighbor_network(port=self.host_0.port,
                                                   mac=self.host_0.mac,
                                                   ip=self.host_0.ip,
                                                   ip_prefix=self.host_0.ip_prefix,
                                                   peer_port=self.host_0.peer.port,
                                                   peer_mac=self.host_0.peer.mac,
                                                   peer_ip=self.host_0.peer.ip,
                                                   client_mac=self.host_0.client.mac,
                                                   client_ip=self.host_0.client.ip,
                                                   client_vni=self.host_0.client.vni)

        self.vip_create(self.host_0.peer.ip)

        # direction lookup VNI, reserved VNI assigned to the VM->Appliance
        self.direction_lookup_create(self.host_0.client.vni)

    def enisCreationTest(self):

        vnet = self.vnet_create(vni=self.host_0.client.vni)

        eni_id_0 = self.eni_create(admin_state=True,
                                   vm_underlay_dip=sai_ipaddress(self.host_0.ip),
                                   vm_vni=self.host_0.client.vni,
                                   vnet_id=vnet)

        eni_id_1 = self.eni_create(admin_state=True,
                                   vm_underlay_dip=sai_ipaddress(self.host_1.ip),
                                   vm_vni=self.host_1.client.vni,
                                   vnet_id=vnet)

        self.eni_mac_map_create(eni_id_0, self.host_0.client.mac)

        # create ENI 1 mac mapping and expect failure
        eni_ether_address_map_entry = sai_thrift_eni_ether_address_map_entry_t(switch_id=self.switch_id,
                                                                               address=self.host_1.client.mac)
        sai_thrift_create_eni_ether_address_map_entry(self.client,
                                                      eni_ether_address_map_entry,
                                                      eni_id=eni_id_1)

        self.assertEqual(self.status(), SAI_STATUS_FAILURE)
