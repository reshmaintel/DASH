# Table of content

1. [Objectives](#objectives)
2. [Requirements](#requirements)
    - [Scaling](#scaling)
    - [Performance](#performance)
    - [Other](#other)
3. [Test Suites](#test-suites)

---

# Objectives

The test plan designed to cover **overlay** related features for the **DASH SmartAppliances** use case.

The test suites should validate that the DASH devices satisfy the standard SONiC functional requirements. This is a black-box testing concerned with validating whether the device works as intended with SONiC.

Two test frameworks are suggested for automation:
- **SAI PTF** - Functional verification
- **sonic-mgmt** - System/Integration verification

---

# Requirements

### Scaling
| Item |	Expected value
|---|---
| VNETs | 1024
| ENI per card | 64
| Routes per ENI | 100k (**to clarify** in some md docs it is 200k)
| NSGs per ENI | 6
| ACLs per ENI | 6x100K prefixes
| ACLs per ENI | 6x10K SRC/DST ports
| CA-PA Mappings | 10M
| Active Connections/ENI | 1M (Bidirectional)

### Performance
| Item |	Expected value
|---|---
| CPS per card | 4M+
| Flows per ENI | 1M
| Flows per card | 16M per 200G

### Other

More requirements may be found in [DASH SONiC HLD](https://github.com/Azure/DASH/blob/main/documentation/general/design/dash-sonic-hld.md#15-design-considerations).

---

# Test suites

1. [ENI config](./eni.md)<br>
Verifies base CRUD operations and scaling for Elastic Network Interface (ENI),
1. Connection tracking
1. ACL
1. [VNET-to-VNET](./vnet.md)<br>
Verifies VM to VM communication in VNET, using an Appliance for rules and routing offload.
1. VNET Peering<br>
Virtual network peering connects two virtual networks seamlessly. Once peered, for connectivity purposes, the virtual networks appear as one. For background information, see Virtual network peering.
1. High Availability (HA)<br>
Useful for failure and failover events.
flow efficiently replicates to secondary card; Active/Passive (depending upon ENI policy) or can even have Active/Active; OR provision the same ENI over multiple devices w/o multiple SDN appliances – Primaries for a certain set of VMS can be on both
1. Load Balancer<br>
The feature that switches traffic from using VIP-to-VIP connectivity (which involves transiting SLB MUXes), into using a direct path between VMs (direct PA to PA path).
1. Service Tunnel & Private Link<br>
Service Tunnel prevents Internet access to specific services. Access is permitted only from a specific virtual network (VNET). The Service Tunnel feature provides this capability by encoding certain id's via packet transformation. Private Link feature is an extension to the Service Tunnel feature and enables customers to access public facing shared services via their private IP addresses within their VNET.
1. Encryption Gateway<br>
Express Route Gateway.
1. gNMI
1. Multiple DPUs device
