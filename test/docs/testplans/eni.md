# Table of content

1. [Objectives](#objectives)
2. [Requirements](#requirements)
3. [Automation](#automation)
4. [Test Suites](#test-suites)
    - [ENI creation](#eni-creation)
    - [ENI removal](#eni-removal)
    - [ENI scale](#eni-scale)

---

# Objectives

Verify proper CRUD API operations and scaling for Elastic Network Interface (ENI).

# Requirements

| Item |	Expected value
|---|---
| ENI per card | 64
| Bulk operations | Yes
| Admin state | When the ENI is admin-state down, the packets destined to this ENI shall be dropped.
| Remove | - During ENI delete, implementation must support ability to delete all mappings or routes in a single API call.<br>- Deleting an object that doesn't exists shall not return an error and shall not perform any force-deletions or delete dependencies implicitly. Sonic implementation shall validate the entire API as pre-checks before applying and return accordingly
| Memory | Flexible memory allocation for ENI and not reserve max scale during initial create. (To allow oversubscription)
| Error handling | Implementation must not have silent failures for APIs.

# Automation

Test cases are automated using SAI PTF test framework.

# Test suites

## ENI creation

Verifies create operations, an association with VNI, MAC.

| Test case | Test Class.Method
| --- | ---
| create inbound/outbound DASH ACL groups | CreateDeleteEniTest.createInOutAclGroupsTest
| create VNET | CreateDeleteEniTest.createVnetTest
| create ENI | CreateDeleteEniTest.createEniTest
| create ENI Ether address map entry | CreateDeleteEniTest.createEniEtherAddressMapTest
| create PA validation entry | CreateDeleteEniTest.createPaValidationTest
| create Outbound routing entry | CreateDeleteEniTest.createOutboundRoutingEntryTest
| verify ENI attributes getting/setting | CreateDeleteEniTest.eniAttributesTest
| verify ENI Ether address map entry attributes getting/setting | CreateDeleteEniTest.eniEtherAddressMapAttributesTest
| verify PA validation entry attributes getting/setting | CreateDeleteEniTest.paValidationEntryAttributesTest
| verify Outbound routing entry attributes getting/setting | CreateDeleteEniTest.outboundRoutingEntryAttributesTest
    
## ENI removal

Verifies remove operations.

| Test case | Test Class.Method
| --- | ---
| normal delete:<br>verify deletion of: inbound/outbound DASH ACL groups, VNET, ENI, ENI Ether address map entry, PA validation entry, Outbound routing entry | CreateDeleteEniTest.deleteEniTest
| error id mapped rules exist:<br>verify ENI cannot be deleted when map exist | CreateDeleteEniTest.deleteEniWhenMapExistTest
| duplicated deletion<br>no errors | CreateDeleteEniTest.duplicatedEniDeletionTest 
| normal bulk delete | -
| bulk delete does not remove any if there is a mapping for some ENI | -

## ENI scale. 

Verifies basic ENI scale, create/remove/recreate maximum number of ENIs.

| Test case | Test Class.Method
| --- | ---
| Create/remove a max number of ENI entries | EniScaleTest.eniScaleTest
| Recreate (repeated creation/removal a max number of ENI entries) | EniScaleTest.eniScaleTest
