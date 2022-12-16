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

from copy import copy
from unittest import skipIf

from ptf.testutils import test_param_get
from sai_base_test import *
from sai_thrift.sai_headers import *
from sai_dash_utils import *


@group("draft")
@disabled  # This is a Demo test. It should not be executed on CI
class Vnet2VnetCTTest(VnetAPI):
    """
    Vnet to Vnet scenario test case Inbound
    """

    def runTest(self):
        self.configureTest()
        import pdb
        pdb.set_trace()

    def configureTest(self):
        """
        Setup DUT in accordance with test purpose
        """
        self.VIP_ADDRESS = "192.168.1.112"  # Appliance IP address
        self.ENI_MAC = "88:ba:ce:98:d9:e2"
        self.SRC_VM_VNI = 3
        self.DST_VM_VNI = 10

        self.vip_create(self.VIP_ADDRESS)  # Appliance VIP

        # direction lookup VNI, reserved VNI assigned to the VM->Appliance
        self.direction_lookup_create(self.SRC_VM_VNI)
        vnet_id_1 = self.vnet_create(self.SRC_VM_VNI)

        eni_id = self.eni_create(vm_vni=self.SRC_VM_VNI,
                                 vm_underlay_dip=sai_ipaddress("10.10.20.20"),
                                 vnet_id=vnet_id_1)
        self.eni_mac_map_create(eni_id, self.ENI_MAC)  # ENI MAC address

        vnet_id_2 = self.vnet_create(self.DST_VM_VNI)  # VNET VNI = 10
        # outbound routing
        self.outbound_routing_vnet_direct_create(eni_id, "10.10.2.3/24", vnet_id_2,
                                                 overlay_ip="10.10.2.10")
        self.outbound_ca_to_pa_create(vnet_id_2,  # DST vnet id
                                      "192.168.1.10",  # DST IP addr not used
                                      "10.10.20.20",  # Underlay DIP
                                      overlay_dmac="aa:bb:cc:dd:ee:ff")

        # Inbound routing PA Validate
        self.inbound_routing_decap_validate_create(eni_id, vni=self.DST_VM_VNI,  # routing VNI lookup = 10
                                                   sip="192.168.2.10", sip_mask="255.255.255.255",
                                                   src_vnet_id=vnet_id_2)
        # underlay routing
        self.router_interface_create(self.port1)
        rif0 = self.router_interface_create(self.port0, src_mac="44:33:33:22:55:66")
        nhop = self.nexthop_create(rif0, "10.10.2.10")  # ip not used
        self.neighbor_create(rif0, "10.10.2.10", "aa:bb:cc:11:22:33")  # ip not used
        self.route_create("10.10.20.20/24", nhop)


@group("draft")
@skipIf(test_param_get('bmv2'), "Blocked by Issue #233. Inbound Routing is not supported in BMv2.")
class Vnet2VnetInboundTest(VnetAPI):
    """
    Inbound Vnet to Vnet scenario test case
    """

    def setUp(self):
        super(Vnet2VnetInboundTest, self).setUp()
        """
        Configuration
        +----------+-----------+
        | port0    | port0_rif |
        +----------+-----------+
        | port1    | port1_rif |
        +----------+-----------+
        """
        self.PA_VALIDATION_SIP = "192.168.2.10"  # PA validation PERMIT
        self.ENI_MAC = "88:ba:ce:98:d9:e2"  # ENI MAC address
        self.VM_VNI = 3  # DST VM VNI (Inbound VNI)
        self.ROUTE_VNI = 10  # Inbound route VNI

        self.VIP_ADDRESS = "192.168.1.112"  # Appliance IP address

        self.OUTER_DMAC = "aa:bb:cc:11:22:33"  # DST MAC for outer VxLAN pkt and Neighbor MAC
        self.OUTER_DIP = "10.10.20.20"  # DST IP for outer IP pkt and Next-hop/Neighbor IP

        # SDN Appliance rif`s MAC addresses
        self.RIF0_RIF_MAC = "44:00:00:00:88:99"
        self.RIF1_RIF_MAC = "44:33:33:22:55:66"

    def runTest(self):
        self.configureTest()
        self.vnet2VnetInboundPaValidatePermitTest()
        self.vnet2VnetInboundRouteInvalidVniTest()
        self.vnet2VnetInboundInvalidEniMacTest()
        self.vnet2VnetInboundInvalidPaSrcIpTest()

    def configureTest(self):
        """
        Setup DUT in accordance with test purpose
        """
        # Underlay routing
        self.router_interface_create(self.port0, src_mac=self.RIF0_RIF_MAC)
        rif1 = self.router_interface_create(self.port1, src_mac=self.RIF1_RIF_MAC)

        nhop = self.nexthop_create(rif1, self.OUTER_DIP)  # ip not used
        self.neighbor_create(rif1, self.OUTER_DIP, self.OUTER_DMAC)  # ip not used
        self.route_create("10.10.20.20/24", nhop)

        # Overlay routing
        self.vip_create(self.VIP_ADDRESS)  # Appliance VIP

        # direction lookup VNI, reserved VNI assigned to the VM->Appliance
        self.direction_lookup_create(self.VM_VNI)

        vnet1 = self.vnet_create(self.VM_VNI)
        eni_id = self.eni_create(admin_state=True,
                                 vm_underlay_dip=sai_ipaddress(self.OUTER_DIP),
                                 vm_vni=self.VM_VNI,
                                 vnet_id=vnet1)
        self.eni_mac_map_create(eni_id, self.ENI_MAC)

        vnet2 = self.vnet_create(self.ROUTE_VNI)

        # Inbound routing PA Validate
        self.inbound_routing_decap_validate_create(eni_id, vni=self.ROUTE_VNI,  # routing VNI lookup = 2
                                                   sip="192.168.2.10", sip_mask="255.255.255.255", src_vnet_id=vnet2)
        # PA validation entry with Permit action
        self.pa_validation_create(self.PA_VALIDATION_SIP, vnet2)

        # Create VxLAN packets
        self.inner_pkt = simple_tcp_packet(eth_dst=self.ENI_MAC,
                                           eth_src="4a:7f:01:3b:a2:71",
                                           ip_dst="10.10.3.2",
                                           ip_src="10.10.2.3",
                                           ip_id=108,
                                           ip_ttl=64)

        self.vxlan_pkt = simple_vxlan_packet(eth_dst=self.RIF0_RIF_MAC,
                                             eth_src="9e:ba:ce:98:d9:e2",
                                             ip_dst=self.VIP_ADDRESS,
                                             ip_src=self.PA_VALIDATION_SIP,
                                             ip_id=0,
                                             ip_ttl=64,
                                             ip_flags=0x2,
                                             with_udp_chksum=True,
                                             vxlan_vni=self.ROUTE_VNI,
                                             inner_frame=self.inner_pkt)

        self.exp_vxlan_pkt = simple_vxlan_packet(eth_dst=self.OUTER_DMAC,
                                                 eth_src=self.RIF1_RIF_MAC,
                                                 ip_dst=self.OUTER_DIP,
                                                 ip_src=self.VIP_ADDRESS,
                                                 ip_id=0,
                                                 ip_ttl=64,
                                                 ip_flags=0x2,
                                                 with_udp_chksum=True,
                                                 vxlan_vni=self.VM_VNI,
                                                 inner_frame=self.inner_pkt)

        # Create Eth packets for verify_no_packet method
        self.inner_eth_packet = simple_eth_packet(eth_dst=self.inner_pkt.getlayer('Ether').dst,
                                                  eth_src=self.inner_pkt.getlayer('Ether').src, eth_type=0x800)
        self.outer_eth_packet = simple_eth_packet(eth_dst=self.exp_vxlan_pkt.getlayer('Ether').dst,
                                                  eth_src=self.exp_vxlan_pkt.getlayer('Ether').src, eth_type=0x800)

    def vnet2VnetInboundPaValidatePermitTest(self):
        """
        Inbound VNET to VNET test with PA validation entry Permit action
        Verifies correct packet routing
        """

        print("Sending VxLAN IPv4 packet, expect VxLAN packet routed")

        send_packet(self, self.dev_port0, self.vxlan_pkt)
        verify_packet(self, self.exp_vxlan_pkt, self.dev_port1, timeout=1)

        print('\n', self.vnet2VnetInboundPaValidatePermitTest.__name__, ' OK')

    def vnet2VnetInboundInvalidEniMacTest(self):
        """
        Inbound VNET to VNET test
        Verifies packet drop in case of invalid ENI MAC address
        """

        # Invalid CA (ENI) DST MAC
        vxlan_pkt_invalid_dmac = copy(self.vxlan_pkt)
        vxlan_pkt_invalid_dmac.getlayer('VXLAN').getlayer('Ether').dst = "9e:ba:ce:98:d9:e2"

        print("Sending VxLAN IPv4 packet with invalid destination mac, expect drop")

        send_packet(self, self.dev_port0, vxlan_pkt_invalid_dmac)
        verify_no_packet(self, self.inner_eth_packet, self.dev_port1, timeout=1)
        verify_no_packet(self, self.outer_eth_packet, self.dev_port1, timeout=1)

        print('\n', self.vnet2VnetInboundInvalidEniMacTest.__name__, ' OK')

    def vnet2VnetInboundInvalidPaSrcIpTest(self):
        """
        Inbound VNET to VNET test
        Verifies packet drop in case of invalid Physical source IP address
        """

        # Invalid PA IP
        vxlan_pkt_invalid_pa_ip = copy(self.vxlan_pkt)
        vxlan_pkt_invalid_pa_ip.getlayer('IP').src = "192.168.56.12"

        print("Sending VxLAN IPv4 packet with invalid pa validation ip, expect drop")

        send_packet(self, self.dev_port0, vxlan_pkt_invalid_pa_ip)
        verify_no_packet(self, self.inner_eth_packet, self.dev_port1, timeout=1)
        verify_no_packet(self, self.outer_eth_packet, self.dev_port1, timeout=1)

        print('\n', self.vnet2VnetInboundInvalidPaSrcIpTest.__name__, ' OK')

    def vnet2VnetInboundRouteInvalidVniTest(self):
        """
        Inbound VNET to VNET test scenario
        Verifies packet drop in case of invalid routing VNI lookup
        """

        vxlan_pkt_invalid_vni = copy(self.vxlan_pkt)
        vxlan_pkt_invalid_vni.getlayer('VXLAN').vni = 1000

        print("Sending VxLAN IPv4 packet with invalid routing VNI lookup, expect drop")

        send_packet(self, self.dev_port0, vxlan_pkt_invalid_vni)
        verify_no_packet(self, self.inner_eth_packet, self.dev_port1, timeout=1)
        verify_no_packet(self, self.outer_eth_packet, self.dev_port1, timeout=1)

        print('\n', self.vnet2VnetInboundRouteInvalidVniTest.__name__, ' OK')


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
class Vnet2VnetOutboundMultipleEniSameIpPrefixTwoPortsTest(VnetApiEndpoints, VnetTrafficMixin):
    """
    Outbound Vnet to Vnet test scenario when multiple ENI and
    Outbound routing entries exist with the same CA IP prefixes
    """

    def runTest(self):
        self.configureTest()
        self.configure_underlay(self.rx_host_0)

        self.outboundEni0Test(tx_equal_to_rx=False)
        self.outboundEni1Test(tx_equal_to_rx=False)
        self.outboundEni2Test(tx_equal_to_rx=False)

    def configureTest(self):
        """
        Setup DUT in accordance with test purpose

        192.168.0.1         -> 192.168.1.1
        tx_host_0 (vni 1)   -> rx_host_0 (vni 2)
        tx_host_1 (vni 10)  -> rx_host_1 (vni 20)
        tx_host_2 (vni 100) -> rx_host_2 (vni 200)
        """

        self.router_interface_create(port=self.tx_host.peer.port,
                                     src_mac=self.tx_host.peer.mac)

        self.tx_host_0 = self.tx_host

        self.tx_host_1 = self.define_neighbor_network(port=self.tx_host_0.port,
                                                      mac=self.tx_host_0.mac,
                                                      ip=self.tx_host_0.ip,
                                                      ip_prefix=self.tx_host_0.ip_prefix,
                                                      peer_port=self.tx_host_0.peer.port,
                                                      peer_mac=self.tx_host_0.peer.mac,
                                                      peer_ip=self.tx_host_0.peer.ip,
                                                      client_mac="00:03:00:00:05:16",
                                                      client_ip=self.tx_host_0.client.ip,
                                                      client_vni=10)

        self.tx_host_2 = self.define_neighbor_network(port=self.tx_host_0.port,
                                                      mac=self.tx_host_0.mac,
                                                      ip=self.tx_host_0.ip,
                                                      ip_prefix=self.tx_host_0.ip_prefix,
                                                      peer_port=self.tx_host_0.peer.port,
                                                      peer_mac=self.tx_host_0.peer.mac,
                                                      peer_ip=self.tx_host_0.peer.ip,
                                                      client_mac="00:04:00:00:06:17",
                                                      client_ip=self.tx_host_0.client.ip,
                                                      client_vni=100)

        self.rx_host_0 = self.rx_host

        self.rx_host_1 = self.define_neighbor_network(port=self.rx_host_0.port,
                                                      mac=self.rx_host_0.mac,
                                                      ip=self.rx_host_0.ip,
                                                      ip_prefix=self.rx_host_0.ip_prefix,
                                                      peer_port=self.rx_host_0.peer.port,
                                                      peer_mac=self.rx_host_0.peer.mac,
                                                      peer_ip=self.rx_host_0.peer.ip,
                                                      client_mac="00:05:00:00:06:17",
                                                      client_ip=self.rx_host.client.ip,
                                                      client_vni=20)

        self.rx_host_2 = self.define_neighbor_network(port=self.rx_host_0.port,
                                                      mac=self.rx_host_0.mac,
                                                      ip=self.rx_host_0.ip,
                                                      ip_prefix=self.rx_host_0.ip_prefix,
                                                      peer_port=self.rx_host_0.peer.port,
                                                      peer_mac=self.rx_host_0.peer.mac,
                                                      peer_ip=self.rx_host_0.peer.ip,
                                                      client_mac="00:06:00:00:07:18",
                                                      client_ip=self.rx_host.client.ip,
                                                      client_vni=200)

        # Overlay routing
        self.vip_create(self.tx_host_0.peer.ip)  # Appliance VIP

        # direction lookup VNI, reserved VNI assigned to the VM->Appliance
        self.direction_lookup_create(self.tx_host_0.client.vni)
        self.direction_lookup_create(self.tx_host_1.client.vni)
        self.direction_lookup_create(self.tx_host_2.client.vni)

        src_vnet_0 = self.vnet_create(vni=self.tx_host_0.client.vni)
        src_vnet_1 = self.vnet_create(vni=self.tx_host_1.client.vni)
        src_vnet_2 = self.vnet_create(vni=self.tx_host_2.client.vni)

        dst_vnet_0 = self.vnet_create(vni=self.rx_host_0.client.vni)
        dst_vnet_1 = self.vnet_create(vni=self.rx_host_1.client.vni)
        dst_vnet_2 = self.vnet_create(vni=self.rx_host_2.client.vni)

        eni_id_0 = self.eni_create(admin_state=True,
                                   vm_underlay_dip=sai_ipaddress(self.tx_host_0.ip),
                                   vm_vni=self.tx_host_0.client.vni,
                                   vnet_id=src_vnet_0)
        self.eni_mac_map_create(eni_id=eni_id_0, mac=self.tx_host_0.client.mac)

        eni_id_1 = self.eni_create(admin_state=True,
                                   vm_underlay_dip=sai_ipaddress(self.tx_host_1.ip),
                                   vm_vni=self.tx_host_1.client.vni,
                                   vnet_id=src_vnet_1)
        self.eni_mac_map_create(eni_id=eni_id_1, mac=self.tx_host_1.client.mac)

        eni_id_2 = self.eni_create(admin_state=True,
                                   vm_underlay_dip=sai_ipaddress(self.tx_host_2.ip),
                                   vm_vni=self.tx_host_2.client.vni,
                                   vnet_id=src_vnet_2)
        self.eni_mac_map_create(eni_id=eni_id_2, mac=self.tx_host_2.client.mac)

        # Outbound routing and CA to PA entries creation
        #  for use_dst_vnet_vni=True
        self.outbound_routing_vnet_create(eni_id=eni_id_0, lpm="192.168.1.0/24",
                                          dst_vnet_id=dst_vnet_0)
        self.outbound_ca_to_pa_create(dst_vnet_id=dst_vnet_0,
                                      dip=self.rx_host_0.client.ip,
                                      underlay_dip=self.rx_host_0.ip,
                                      overlay_dmac=self.rx_host_0.client.mac,
                                      use_dst_vnet_vni=True)

        # for use_dst_vnet_vni=False
        self.outbound_routing_vnet_create(eni_id=eni_id_1, lpm="192.168.1.0/24",
                                          dst_vnet_id=dst_vnet_1)
        self.outbound_ca_to_pa_create(dst_vnet_id=dst_vnet_1,
                                      dip=self.rx_host_1.client.ip,
                                      underlay_dip=self.rx_host_1.ip,
                                      overlay_dmac=self.rx_host_1.client.mac,
                                      use_dst_vnet_vni=True)

        self.outbound_routing_vnet_direct_create(eni_id=eni_id_2, lpm="192.168.1.0/24",
                                                 dst_vnet_id=dst_vnet_2,
                                                 overlay_ip="192.168.1.111")
        self.outbound_ca_to_pa_create(dst_vnet_id=dst_vnet_2,
                                      dip="192.168.1.111",
                                      underlay_dip=self.rx_host_2.ip,
                                      overlay_dmac=self.rx_host_2.client.mac,
                                      use_dst_vnet_vni=True)

    def outboundEni0Test(self, tx_equal_to_rx):
        self.verify_oneway_connection(client=self.tx_host_0,
                                      server=self.rx_host_0,
                                      connection='tcp',
                                      fake_mac=True)

        print('\n', self.outboundEni0Test(tx_equal_to_rx).__name__, ' OK')

    def outboundEni1Test(self, tx_equal_to_rx):
        self.verify_oneway_connection(client=self.tx_host_1,
                                      server=self.rx_host_1,
                                      connection='tcp',
                                      fake_mac=True)

        print('\n', self.outboundEni1Test(tx_equal_to_rx).__name__, ' OK')

    def outboundEni2Test(self, tx_equal_to_rx):
        self.verify_oneway_connection(client=self.tx_host_2,
                                      server=self.rx_host_2,
                                      connection='tcp',
                                      fake_mac=True)

        print('\n', self.outboundEni2Test(tx_equal_to_rx).__name__, ' OK')


@group("draft")
@skipIf(test_param_get('bmv2'), "Blocked by Issue #233. Inbound Routing is not supported in BMv2.")
class Vnet2VnetInboundOutboundMultipleConfigsTwoPortsTest(VnetApiEndpoints, VnetTrafficMixin):
    """
    Inbound and Outbound Vnet to Vnet test scenario
    Verifies overlay routing with multiple inbound/outbound configurations
    """

    def runTest(self):
        self.configureTest()
        self.configure_underlay(self.host_0, self.host_2,
                                add_routes=True)

        self.outboundHost0toHost2Test(tx_equal_to_rx=False)
        self.inboundHost2toHost0Test(tx_equal_to_rx=False)

        self.outboundHost3toHost1Test(tx_equal_to_rx=False)
        self.inboundHost1toHost3Test(tx_equal_to_rx=False)

    def configureTest(self):
        """
        Setup DUT in accordance with test purpose

        host_0.client (vni 1) ca ip: 192.168.0.1 (eni_0) <---> host_2.client (vni 2) ca ip: 192.168.1.1
        host_1.client (vni 10) ca ip: 192.168.2.1 <---> (eni_3) host_3.client (vni 20) ca ip: 192.168.3.1
        """

        self.host_0 = self.tx_host

        self.host_1 = self.define_neighbor_network(port=self.host_0.port,
                                                   mac=self.host_0.mac,
                                                   ip=self.host_0.ip,
                                                   ip_prefix=self.host_0.ip_prefix,
                                                   peer_port=self.host_0.peer.port,
                                                   peer_mac=self.host_0.peer.mac,
                                                   peer_ip=self.host_0.peer.ip,
                                                   client_mac="00:03:00:00:05:16",
                                                   client_ip="192.168.2.1",
                                                   client_vni=10)
        self.host_2 = self.rx_host

        self.host_3 = self.define_neighbor_network(port=self.host_2.port,
                                                   mac=self.host_2.mac,
                                                   ip=self.host_2.ip,
                                                   ip_prefix=self.host_2.ip_prefix,
                                                   peer_port=self.host_2.peer.port,
                                                   peer_mac=self.host_2.peer.mac,
                                                   peer_ip=self.host_2.peer.ip,
                                                   client_mac="00:04:00:00:06:17",
                                                   client_ip="192.168.3.1",
                                                   client_vni=20)
        # Overlay routing
        self.vip_create(self.host_0.peer.ip)  # Appliance VIP

        # direction lookup VNI, reserved VNI assigned to the VM->Appliance
        self.direction_lookup_create(self.host_0.client.vni)
        self.direction_lookup_create(self.host_3.client.vni)

        host_0_vnet = self.vnet_create(vni=self.host_0.client.vni)
        host_1_vnet = self.vnet_create(vni=self.host_1.client.vni)

        host_2_vnet = self.vnet_create(vni=self.host_2.client.vni)
        host_3_vnet = self.vnet_create(vni=self.host_3.client.vni)

        eni_id_0 = self.eni_create(admin_state=True,
                                   vm_underlay_dip=sai_ipaddress(self.host_0.ip),
                                   vm_vni=self.host_0.client.vni,
                                   vnet_id=host_0_vnet)
        self.eni_mac_map_create(eni_id_0, self.host_0.client.mac)

        eni_id_3 = self.eni_create(admin_state=True,
                                   vm_underlay_dip=sai_ipaddress(self.host_3.ip),
                                   vm_vni=self.host_3.client.vni,
                                   vnet_id=host_3_vnet)
        self.eni_mac_map_create(eni_id_3, self.host_3.client.mac)

        # ENI 0 inbound/outbound routing
        self.inbound_routing_decap_validate_create(eni_id=eni_id_0, vni=self.host_0.client.vni,
                                                   sip="10.10.2.0", sip_mask="255.255.255.0",
                                                   src_vnet_id=host_2_vnet)
        self.pa_validation_create(sip=self.host_2.ip,
                                  vnet_id=host_2_vnet)

        self.outbound_routing_vnet_create(eni_id_0, lpm="192.168.1.0/24",
                                          dst_vnet_id=host_2_vnet)
        self.outbound_ca_to_pa_create(dst_vnet_id=host_2_vnet,
                                      dip=self.host_2.client.ip,
                                      underlay_dip=self.host_2.ip,
                                      overlay_dmac=self.host_2.client.mac)

        # ENI 3 inbound/outbound routing
        self.inbound_routing_decap_validate_create(eni_id=eni_id_3, vni=self.host_3.client.vni,
                                                   sip="10.10.1.0", sip_mask="255.255.255.0",
                                                   src_vnet_id=host_1_vnet)
        self.pa_validation_create(sip=self.host_1.ip,
                                  vnet_id=host_1_vnet)

        self.outbound_routing_vnet_create(eni_id_3, lpm="192.168.2.0/24",
                                          dst_vnet_id=host_1_vnet)
        self.outbound_ca_to_pa_create(dst_vnet_id=host_1_vnet,
                                      dip=self.host_1.client.ip,
                                      underlay_dip=self.host_1.ip,
                                      overlay_dmac=self.host_1.client.mac)

    def outboundHost0toHost2Test(self, tx_equal_to_rx):
        self.verify_oneway_connection(client=self.host_0,
                                      server=self.host_2,
                                      connection='tcp',
                                      fake_mac=True)

        print('\n', self.outboundHost0toHost2Test(tx_equal_to_rx).__name__, ' OK')

    def inboundHost2toHost0Test(self, tx_equal_to_rx):
        self.verify_oneway_connection(client=self.host_2,
                                      server=self.host_0,
                                      connection='tcp',
                                      fake_mac=False)

        print('\n', self.inboundHost2toHost0Test(tx_equal_to_rx).__name__, ' OK')

    def outboundHost3toHost1Test(self, tx_equal_to_rx):
        self.verify_oneway_connection(client=self.host_3,
                                      server=self.host_1,
                                      connection='tcp',
                                      fake_mac=True)

        print('\n', self.outboundHost3toHost1Test(tx_equal_to_rx).__name__, ' OK')

    def inboundHost1toHost3Test(self, tx_equal_to_rx):
        self.verify_oneway_connection(client=self.host_1,
                                      server=self.host_3,
                                      connection='tcp',
                                      fake_mac=False)

        print('\n', self.inboundHost1toHost3Test(tx_equal_to_rx).__name__, ' OK')


@group("draft")
@skipIf(test_param_get('bmv2'), "Blocked on BMv2 by Issue #236")
class Vnet2VnetOutboundRouteDirectTest(VnetAPI):
    """
    Outbound VNet to VNet test scenario with Outbound routing entry
    SAI_OUTBOUND_ROUTING_ENTRY_ACTION_ROUTE_DIRECT action
    """

    def setUp(self):
        super(Vnet2VnetOutboundRouteDirectTest, self).setUp()
        """
        Configuration
        +----------+-----------+
        | port0    | port0_rif |
        +----------+-----------+
        | port1    | port1_rif |
        +----------+-----------+
        """

        self.VIP_ADDRESS = "10.1.1.1"  # Appliance VIP address
        self.ENI_MAC = "00:01:00:00:03:14"
        self.SRC_VM_VNI = 1

    def configureTest(self):
        """
        Setup DUT in accordance with test purpose
        """

        self.vip_create(self.VIP_ADDRESS)  # Appliance VIP

        # direction lookup VNI, reserved VNI assigned to the VM->Appliance
        self.direction_lookup_create(self.SRC_VM_VNI)

        vnet_id_1 = self.vnet_create(self.SRC_VM_VNI)

        eni_id = self.eni_create(vm_vni=self.SRC_VM_VNI,
                                 vm_underlay_dip=sai_ipaddress("10.10.1.10"),
                                 vnet_id=vnet_id_1)
        self.eni_mac_map_create(eni_id, self.ENI_MAC)  # ENI MAC address

        # outbound routing
        self.outbound_routing_direct_create(eni_id, "192.168.1.0/24")

        # underlay routing
        self.router_interface_create(self.port1)
        rif0 = self.router_interface_create(self.port0, src_mac="00:77:66:55:44:00")
        nhop = self.nexthop_create(rif0, "10.10.2.10")
        self.neighbor_create(rif0, "10.10.2.10", "aa:bb:cc:11:22:33")
        self.route_create("10.10.2.0/24", nhop)

    def runTest(self):
        self.configureTest()

        # send packet and check
        inner_pkt = simple_udp_packet(eth_src=self.ENI_MAC,
                                      eth_dst="20:30:40:50:60:70",
                                      ip_dst="192.168.1.1",
                                      ip_src="192.168.0.1",
                                      ip_ttl=64,
                                      ip_ihl=5,
                                      with_udp_chksum=True)

        vxlan_pkt = simple_vxlan_packet(eth_dst="00:00:cc:11:22:33",
                                        eth_src="00:00:66:00:44:00",
                                        ip_dst=self.VIP_ADDRESS,
                                        ip_src="10.10.1.10",
                                        with_udp_chksum=True,
                                        vxlan_vni=self.SRC_VM_VNI,
                                        ip_ttl=0,
                                        ip_ihl=5,
                                        ip_id=0,
                                        udp_sport=5000,
                                        vxlan_flags=0x8,
                                        vxlan_reserved0=None,
                                        vxlan_reserved1=0,
                                        vxlan_reserved2=0,
                                        ip_flags=0x2,
                                        inner_frame=inner_pkt)

        direct_pkt = simple_udp_packet(eth_src="00:77:66:55:44:00",
                                       eth_dst="aa:bb:cc:11:22:33",
                                       ip_dst="192.168.1.1",
                                       ip_src="192.168.0.1",
                                       ip_ttl=63,
                                       ip_ihl=5,
                                       with_udp_chksum=True)

        print("Sending VxLAN IPv4 packet, expected UDP packet forwarded")
        send_packet(self, self.dev_port1, vxlan_pkt)
        verify_packet(self, direct_pkt, self.dev_port0)


@group("draft")
@skipIf(test_param_get('bmv2'), "Blocked on BMv2 by Issue #236")
class VnetRouteTest(VnetAPI):
    """
    Vnet to Vnet scenario test case Outbound
    """

    def setUp(self):
        super(VnetRouteTest, self).setUp()
        """
        Configuration
        +----------+-----------+
        | port0    | port0_rif |
        +----------+-----------+
        | port1    | port1_rif |
        +----------+-----------+
        """
        self.RIF_SRC_MAC = "44:33:33:22:55:66"
        self.NEIGH_DMAC = "aa:bb:cc:11:22:33"

    def configureTest(self):
        """
        Setup DUT in accordance with test purpose
        """

        # underlay routing
        self.router_interface_create(self.port1)
        rif0 = self.router_interface_create(self.port0, src_mac=self.RIF_SRC_MAC)
        nhop = self.nexthop_create(rif0, "10.10.2.10")
        self.neighbor_create(rif0, "10.10.2.10", self.NEIGH_DMAC)
        self.route_create("10.10.2.2/24", nhop)

    def runTest(self):
        self.configureTest()

        out_pkt = simple_udp_packet(eth_src="00:00:00:01:03:14",
                                    eth_dst="20:30:40:50:60:70",
                                    ip_dst="10.10.2.2",
                                    ip_src="10.10.20.20",
                                    ip_ttl=64)
        exp_pkt = simple_udp_packet(eth_src=self.RIF_SRC_MAC,
                                    eth_dst=self.NEIGH_DMAC,
                                    ip_dst="10.10.2.2",
                                    ip_src="10.10.20.20",
                                    ip_ttl=64)

        print("Sending simple UDP packet, expecting routed packet")
        send_packet(self, self.dev_port1, out_pkt)
        verify_packet(self, exp_pkt, self.dev_port0)
