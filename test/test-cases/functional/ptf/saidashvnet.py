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
Thrift SAI interface VNet tests
"""

from unittest import skipIf

from ptf.testutils import test_param_get
from sai_base_test import *
from sai_thrift.sai_headers import *
from sai_dash_utils import *


@group("draft")
@skipIf(test_param_get('bmv2'), "Blocked by Issue #233. Inbound Routing is not supported in BMv2.")
class Vnet2VnetInboundDecapPaValidateTwoPortsTest(VnetApiEndpoints, VnetTrafficMixin):
    """
    Inbound Vnet to Vnet scenario test case with
    VXLAN_DECAP_PA_VALIDATE inbound routing entry action
    """

    def runTest(self):
        self.configureTest()

        self.configure_underlay(self.rx_host)
        self.vnet2VnetInboundRoutingTest(tx_equal_to_rx=False)
        self.vnet2VnetInboundNegativeTest()

    def configureTest(self):
        """
        Setup DUT in accordance with test purpose
        """

        self.router_interface_create(port=self.tx_host.peer.port,
                                     src_mac=self.tx_host.peer.mac)

        self.vip_create(self.tx_host.peer.ip)

        # direction lookup VNI, reserved VNI assigned to the VM->Appliance
        self.direction_lookup_create(self.rx_host.client.vni)

        src_vnet = self.vnet_create(vni=self.tx_host.client.vni)
        dst_vnet = self.vnet_create(vni=self.rx_host.client.vni)

        eni_id = self.eni_create(admin_state=True,
                                 vm_underlay_dip=sai_ipaddress(self.rx_host.ip),
                                 vm_vni=self.rx_host.client.vni,
                                 vnet_id=dst_vnet)
        self.eni_mac_map_create(eni_id, self.rx_host.client.mac)  # ENI MAC

        # Inbound routing PA Validate
        self.inbound_routing_decap_validate_create(eni_id, vni=self.tx_host.client.vni,
                                                   sip=self.tx_host.ip, sip_mask="255.255.255.0",
                                                   src_vnet_id=src_vnet)
        # PA validation entry with Permit action
        self.pa_validation_create(self.tx_host.ip, src_vnet)

    def vnet2VnetInboundRoutingTest(self, tx_equal_to_rx):
        """
        Inbound VNET to VNET test
        Verifies correct packet routing
        """

        self.verify_oneway_connection(client=self.tx_host, server=self.rx_host,
                                      connection='tcp', fake_mac=False)

        print('\n', self.vnet2VnetInboundRoutingTest.__name__, ' OK\n')

    def vnet2VnetInboundNegativeTest(self):
        """
        Verifies negative scenarios (packet drop):
        - wrong CA Dst MAC
        - wrong PA Validation IP: pa validation missmatch
        - wrong Physical SIP: routing missmatch
        - wrong VIP
        - wrong VNI
        """

        invalid_vni = 1000
        invalid_ca_dst_mac = "9e:ba:ce:98:d9:e2"
        invalid_pa_sip = "10.10.5.1"  # routing missmatch
        invalid_vip = "10.10.10.10"

        self.verify_negative_traffic_scenario(client=self.tx_host, server=self.rx_host,
                                              invalid_vni=invalid_vni,
                                              invalid_outer_src_ip=invalid_pa_sip,
                                              invalid_inner_dst_mac=invalid_ca_dst_mac,
                                              invalid_vip=invalid_vip)

        invalid_pa_valid_ip = "10.10.1.25"  # pa validation missmatch
        self.verify_negative_traffic_scenario(client=self.tx_host, server=self.rx_host,
                                              invalid_outer_src_ip=invalid_pa_valid_ip)

        print('\n', self.vnet2VnetInboundNegativeTest.__name__, ' OK\n')


@group("draft")
@skipIf(test_param_get('bmv2'), "Blocked by Issue #233. Inbound Routing is not supported in BMv2.")
class Vnet2VnetInboundDecapTwoPortsTest(Vnet2VnetInboundDecapPaValidateTwoPortsTest):
    """
    Inbound Vnet to Vnet scenario test case with
    VXLAN_DECAP inbound routing entry action
    """

    def runTest(self):
        self.configureTest()
        self.configure_underlay(self.rx_host)

        self.vnet2VnetInboundRoutingTest(tx_equal_to_rx=False)
        self.vnet2VnetInboundNegativeTest()

    def configureTest(self):
        """
        Setup DUT overlay in accordance with test purpose
        """

        self.router_interface_create(port=self.tx_host.peer.port,
                                     src_mac=self.tx_host.peer.mac)

        self.vip_create(self.tx_host.peer.ip)

        # direction lookup VNI, reserved VNI assigned to the VM->Appliance
        self.direction_lookup_create(self.rx_host.client.vni)

        dst_vnet = self.vnet_create(vni=self.rx_host.client.vni)

        eni_id = self.eni_create(admin_state=True,
                                 vm_underlay_dip=sai_ipaddress(self.rx_host.ip),
                                 vm_vni=self.rx_host.client.vni,
                                 vnet_id=dst_vnet)
        self.eni_mac_map_create(eni_id, self.rx_host.client.mac)  # ENI MAC

        # Inbound routing PA Validate
        self.inbound_routing_decap_create(eni_id, vni=self.tx_host.client.vni,
                                          sip=self.tx_host.ip, sip_mask="255.255.255.0")

    def vnet2VnetInboundNegativeTest(self):
        """
        Verifies negative scenarios (packet drop):
        - wrong CA Dst MAC
        - wrong VIP
        - wrong VNI
        - wrong Physical SIP: routing missmatch
        """

        invalid_vni = 1000
        invalid_ca_dst_mac = "9e:ba:ce:98:d9:e2"
        invalid_vip = "10.10.10.10"
        invalid_pa_sip = "10.10.3.22"

        self.verify_negative_traffic_scenario(client=self.tx_host, server=self.rx_host,
                                              invalid_vni=invalid_vni,
                                              invalid_inner_dst_mac=invalid_ca_dst_mac,
                                              invalid_vip=invalid_vip,
                                              invalid_outer_src_ip=invalid_pa_sip)

        print('\n', self.vnet2VnetInboundNegativeTest.__name__, ' OK\n')


@group("draft")
@skipIf(test_param_get('bmv2'), "Blocked on BMv2 by Issue #236")
class Vnet2VnetOutboundRouteVnetDirectTwoPortsTest(VnetApiEndpoints, VnetTrafficMixin):
    """
    Outbound Vnet to Vnet test scenario with Outbound routing entry
    SAI_OUTBOUND_ROUTING_ENTRY_ACTION_ROUTE_VNET_DIRECT action
    """

    def runTest(self):
        self.configureTest()
        self.configure_underlay(self.rx_host)

        self.vnet2VnetOutboundRoutingTest(tx_equal_to_rx=False)
        self.vnet2VnetOutboundNegativeTest()

    def configureTest(self):
        """
        Setup DUT in accordance with test purpose
        """
        self.router_interface_create(port=self.tx_host.peer.port,
                                     src_mac=self.tx_host.peer.mac)

        self.vip_create(self.tx_host.peer.ip)

        # direction lookup VNI, reserved VNI assigned to the VM->Appliance
        self.direction_lookup_create(self.tx_host.client.vni)

        src_vnet = self.vnet_create(vni=self.tx_host.client.vni)
        dst_vnet = self.vnet_create(vni=self.rx_host.client.vni)

        eni_id = self.eni_create(admin_state=True,
                                 vm_underlay_dip=sai_ipaddress(self.tx_host.ip),
                                 vm_vni=self.tx_host.client.vni,
                                 vnet_id=src_vnet)
        self.eni_mac_map_create(eni_id, self.tx_host.client.mac)  # ENI MAC
        # outbound routing
        self.outbound_routing_vnet_direct_create(eni_id, "192.168.1.0/24", dst_vnet,
                                                 overlay_ip="192.168.1.10")
        self.outbound_ca_to_pa_create(dst_vnet,  # DST vnet id
                                      "192.168.1.10",  # DST IP addr
                                      self.rx_host.ip,
                                      overlay_dmac=self.rx_host.client.mac)  # Underlay DIP

    def vnet2VnetOutboundRoutingTest(self, tx_equal_to_rx):
        """
        Outbound VNET to VNET test
        Verifies correct packet routing
        """

        self.verify_oneway_connection(client=self.tx_host, server=self.rx_host,
                                      connection='tcp', fake_mac=True)

        print('\n', self.vnet2VnetOutboundRoutingTest.__name__, ' OK')

    def vnet2VnetOutboundNegativeTest(self):
        """
        Verifies negative scenarios (packet drop):
        - wrong VIP
        - routing drop (CA Dst IP does not match any routing entry)
        - wrong CA Src MAC (does not match any ENI)
        """

        invalid_vip = "10.10.10.10"
        wrong_inner_dst_ip = "192.168.200.200"
        wrong_inner_src_ca_mac = "00:aa:00:aa:00:aa"

        self.verify_negative_traffic_scenario(client=self.tx_host, server=self.rx_host,
                                              invalid_vip=invalid_vip,
                                              invalid_inner_dst_ip=wrong_inner_dst_ip,
                                              invalid_inner_src_mac=wrong_inner_src_ca_mac)

        print('\n', self.vnet2VnetOutboundNegativeTest.__name__, ' OK')


@group("draft")
@skipIf(test_param_get('bmv2'), "Blocked on BMv2 by Issue #236")
class Vnet2VnetOutboundRouteVnetTwoPortsTest(VnetApiEndpoints, VnetTrafficMixin):
    """
    Outbound Vnet to Vnet test scenario with outbound routing entry
    SAI_OUTBOUND_ROUTING_ENTRY_ACTION_ROUTE_VNET action
    """

    def runTest(self):
        self.configureTest()
        self.configure_underlay(self.rx_host)

        self.vnet2VnetOutboundRoutingTest(tx_equal_to_rx=False)
        self.vnet2VnetOutboundNegativeTest()

    def configureTest(self):
        """
        Setup DUT in accordance with test purpose
        """

        self.router_interface_create(port=self.tx_host.peer.port,
                                     src_mac=self.tx_host.peer.mac)

        self.vip_create(self.tx_host.peer.ip)

        # direction lookup VNI, reserved VNI assigned to the VM->Appliance
        self.direction_lookup_create(self.tx_host.client.vni)

        src_vnet = self.vnet_create(vni=self.tx_host.client.vni)
        dst_vnet = self.vnet_create(vni=self.rx_host.client.vni)

        eni_id = self.eni_create(admin_state=True,
                                 vm_underlay_dip=sai_ipaddress(self.tx_host.ip),
                                 vm_vni=self.tx_host.client.vni,
                                 vnet_id=src_vnet)
        self.eni_mac_map_create(eni_id, self.tx_host.client.mac)  # ENI MAC

        self.outbound_routing_vnet_create(eni_id=eni_id, lpm="192.168.1.0/24",
                                          dst_vnet_id=dst_vnet)
        self.outbound_ca_to_pa_create(dst_vnet_id=dst_vnet,
                                      dip=self.rx_host.client.ip,
                                      underlay_dip=self.rx_host.ip,
                                      overlay_dmac=self.rx_host.client.mac,
                                      use_dst_vnet_vni=True)

    def vnet2VnetOutboundRoutingTest(self, tx_equal_to_rx):
        """
        Outbound VNET to VNET test
        Verifies correct packet routing
        """

        self.verify_oneway_connection(client=self.tx_host, server=self.rx_host,
                                      connection='tcp', fake_mac=True)

        print('\n', self.vnet2VnetOutboundRoutingTest.__name__, ' OK')

    def vnet2VnetOutboundNegativeTest(self):
        """
        Verifies negative scenarios (packet drop):
        - wrong VIP
        - routing drop (CA Dst IP does not match any routing entry)
        - wrong CA Src MAC (does not match any ENI)
        - mapping drop (CA Dst IP matches routing entry prefix but drops by ca_to_pa)
        """

        invalid_vip = "10.10.10.10"
        wrong_inner_dst_ip = "192.168.200.200"
        wrong_inner_src_ca_mac = "00:aa:00:aa:00:aa"

        self.verify_negative_traffic_scenario(client=self.tx_host, server=self.rx_host,
                                              invalid_vip=invalid_vip,
                                              invalid_inner_dst_ip=wrong_inner_dst_ip,
                                              invalid_inner_src_mac=wrong_inner_src_ca_mac)

        wrong_inner_dst_ip = "192.168.1.200"
        self.verify_negative_traffic_scenario(client=self.tx_host, server=self.rx_host,
                                              invalid_inner_dst_ip=wrong_inner_dst_ip)

        print('\n', self.vnet2VnetOutboundNegativeTest.__name__, ' OK')


@group("draft")
@skipIf(test_param_get('bmv2'), "Blocked on BMv2 by Issue #236")
class Vnet2VnetOutboundSameCaPaIpPrefixesTwoPortsTest(VnetApiEndpoints, VnetTrafficMixin):
    """
    Outbound Vnet to Vnet test scenario
    with the same CA and PA IP prefixes
    """

    def runTest(self):
        self.configureTest()
        self.configure_underlay(self.rx_host)

        self.vnet2VnetOutboundRouteVnetTest()

    def configureTest(self):
        """
        Setup DUT in accordance with test purpose
        """

        self.router_interface_create(port=self.tx_host.peer.port,
                                     src_mac=self.tx_host.peer.mac)

        # Update network parameters with the same provider and client ip addresses
        self.tx_host.ip = self.tx_host.client.ip  # 192.168.0.1
        self.tx_host.ip_prefix = "192.168.0.0/24"

        self.rx_host.ip = self.rx_host.client.ip  # 192.168.1.1
        self.rx_host.ip_prefix = "192.168.1.0/24"

        # Configure overlay routing
        self.vip_create(self.tx_host.peer.ip)

        # direction lookup VNI, reserved VNI assigned to the VM->Appliance
        self.direction_lookup_create(self.tx_host.client.vni)

        src_vnet = self.vnet_create(vni=self.tx_host.client.vni)
        dst_vnet = self.vnet_create(vni=self.rx_host.client.vni)

        eni_id = self.eni_create(admin_state=True,
                                 vm_underlay_dip=sai_ipaddress(self.tx_host.ip),
                                 vm_vni=self.tx_host.client.vni,
                                 vnet_id=src_vnet)
        self.eni_mac_map_create(eni_id, self.tx_host.client.mac)  # ENI MAC

        self.outbound_routing_vnet_create(eni_id=eni_id, lpm="192.168.1.0/24",
                                          dst_vnet_id=dst_vnet)
        self.outbound_ca_to_pa_create(dst_vnet_id=dst_vnet,
                                      dip=self.rx_host.client.ip,
                                      underlay_dip=self.rx_host.ip,
                                      overlay_dmac=self.rx_host.client.mac,
                                      use_dst_vnet_vni=True)

    def vnet2VnetOutboundRouteVnetTest(self):
        """
        Packet sending:
            CA IP: 192.168.0.1/24  -> 192.168.1.1/24
            PA IP: 192.168.0.1/24  -> VIP -> 192.168.1.1/24
            VNET: 1 -> 2
        """

        self.verify_oneway_connection(client=self.tx_host, server=self.rx_host,
                                      connection="tcp", fake_mac=True)
