# Protocol Conformance Traceability Matrix

This document provides a clause-by-clause traceability matrix mapping Purlin's implementation against relevant Internet Engineering Task Force (IETF) Requests for Comments (RFCs).

---

## 1. Summary of Supported Standards

| RFC | Title | Compliance Level | Primary Implementation Modules |
|---|---|---|---|
| **RFC 4271** | A Border Gateway Protocol 4 (BGP-4) | Full (Core Spec) | `proto/wire.kk`, `proto/fsm.kk`, `rib/decision.kk` |
| **RFC 4456** | BGP Route Reflection: An Alternative to Full Mesh iBGP | Full | `engine/reflector.kk`, `test/integration/test-reflector.kk` |
| **RFC 4760** | Multiprotocol Extensions for BGP-4 (MP-BGP) | Full | `proto/caps.kk`, `proto/attrs.kk`, `evpn/nlri.kk` |
| **RFC 5492** | Capabilities Advertisement with BGP-4 | Full | `proto/caps.kk`, `harness/rfc_conformance.py` |
| **RFC 6793** | BGP Support for Four-Octet Autonomous System (AS) Number Space | Full | `proto/types.kk`, `proto/attrs.kk` |
| **RFC 6811** | BGP Prefix Origin Validation Using RPKI | Full | `rpki/roa.kk`, `rpki/rpov.kk`, `test/unit/test-rpki.kk` |
| **RFC 7432** | BGP MPLS-Based Ethernet VPN (EVPN) | Partial (Type 2 & 3) | `evpn/types.kk`, `evpn/nlri.kk`, `evpn/vrf.kk` |
| **RFC 7911** | Advertisement of Multiple Paths in BGP (ADD-PATH) | Full | `proto/caps.kk`, `rib/rib.kk` |
| **RFC 7938** | Use of BGP for Routing in Large-Scale Datacenters | Full (Design Spec) | `sim/clos.kk`, `sim/fabric.kk`, `harness/simulate_clos.py` |
| **RFC 8210** | The Resource Public Key Infrastructure (RPKI) to Router Protocol | Full | `rpki/rtr.kk`, `test/unit/test-rpki.kk` |
| **RFC 2439** | BGP Route Flap Damping | Full | `damping/penalty.kk`, `damping/flap.kk` |

---

## 2. Clause-by-Clause Verification

### 2.1 RFC 4271: A Border Gateway Protocol 4

| Clause | Requirement | Status | Purlin Implementation Details |
|---|---|---|---|
| § 4.1 | Message Header Format (16-byte marker, 2-byte length, 1-byte type) | COMPLIANT | `proto/wire.kk:parse-bgp-header`, validates all-ones marker (0xFF..FF) and length bounds [19, 4096]. |
| § 4.2 | OPEN Message Format (version 4, My AS, Hold Time, BGP Identifier) | COMPLIANT | `proto/wire.kk:encode-open-message` and `parse-open-message`. Rejects unsupported versions. |
| § 4.3 | UPDATE Message Format (Unfeasible routes, Path Attributes, NLRI) | COMPLIANT | `proto/wire.kk:parse-update-message`. Decodes byte-packed CIDR prefixes with bit-length boundaries. |
| § 4.4 | KEEPALIVE Message Format (19-byte header with type 4) | COMPLIANT | `proto/wire.kk:encode-keepalive-message` and validation logic. |
| § 4.5 | NOTIFICATION Message Format (Error code, subcode, data) | COMPLIANT | `proto/wire.kk:encode-notification-message` supporting error codes 1 through 6. |
| § 5.1 | Path Attributes: ORIGIN, AS_PATH, NEXT_HOP, MED, LOCAL_PREF, ATOMIC_AGGREGATE, AGGREGATOR | COMPLIANT | `proto/attrs.kk:parse-path-attributes`. Enforces Well-Known Mandatory attributes on UPDATE ingress. |
| § 6.8 | Connection Collision Resolution | COMPLIANT | `proto/fsm.kk:resolve-collision`. Evaluates numeric comparison of local and remote BGP Identifiers. |
| § 8.2 | Finite State Machine Events and Transitions | COMPLIANT | `proto/fsm.kk:step-fsm`. Implements all 6 canonical states: Idle, Connect, Active, OpenSent, OpenConfirm, Established. |
| § 9.1 | Decision Process: Tie-breaking rules 1 through 8 | COMPLIANT | `rib/decision.kk:compare-candidate-paths`. Strictly executes LOCAL_PREF -> AS_PATH -> ORIGIN -> MED -> eBGP -> IGP -> Age -> RouterID. |

### 2.2 RFC 4456: BGP Route Reflection

| Clause | Requirement | Status | Purlin Implementation Details |
|---|---|---|---|
| § 4 | ORIGINATOR_ID Attribute (Code 9) injection by Route Reflector | COMPLIANT | `engine/reflector.kk:inject-originator-id`. Preserves existing ORIGINATOR_ID or creates new one with neighbor BGP ID. |
| § 5 | CLUSTER_LIST Attribute (Code 10) accumulation | COMPLIANT | `engine/reflector.kk:prepend-cluster-id`. Appends local Cluster ID to ingress cluster sequence. |
| § 8 | Routing Loop Prevention using CLUSTER_LIST and ORIGINATOR_ID | COMPLIANT | `engine/reflector.kk:is-reflector-loop`. Discards update if local Cluster ID or Router ID exists in route attributes. |
| § 9 | Non-Client and Client Peering Split Horizon Rules | COMPLIANT | `engine/reflector.kk:reflect-route`. Client routes reflect to all peers; Non-Client routes reflect only to clients. |

### 2.3 RFC 5492: Capability Advertisement with BGP-4

| Clause | Requirement | Status | Purlin Implementation Details |
|---|---|---|---|
| § 4 | Capability Format in Optional Parameter Type 2 | COMPLIANT | `proto/caps.kk:encode-capabilities` and `parse-capabilities`. Decodes capability code, length, and value tuples. |
| Cap Code 1 | Multiprotocol Extensions (RFC 4760) | COMPLIANT | AFI=1 (IPv4), AFI=2 (IPv6), AFI=25 (L2VPN/EVPN) with SAFI=1 (Unicast) and SAFI=70 (EVPN). |
| Cap Code 65 | Support for 4-Octet AS Number Space (RFC 6793) | COMPLIANT | Encodes 32-bit AS number in OPEN capability payload. |
| Cap Code 69 | ADD-PATH Capability (RFC 7911) | COMPLIANT | Negotiates Receive and Send capabilities per AFI/SAFI tuple. |

### 2.4 RFC 6811: BGP Prefix Origin Validation (RPKI)

| Clause | Requirement | Status | Purlin Implementation Details |
|---|---|---|---|
| § 2 | ROA Structure: IP prefix, MaxLength, Authorized ASN | COMPLIANT | `rpki/roa.kk:roa-entry`. Indexes authorizations in a dedicated Patricia trie for fast prefix overlap lookups. |
| § 3.2 | Validation States: Valid, Invalid, NotFound | COMPLIANT | `rpki/rpov.kk:validate-prefix-origin`. Computes exact RFC 6811 tri-state result. |
| § 4 | Integration with Route Selection | COMPLIANT | `rib/decision.kk`. Demotes or rejects routes with RPKI Invalid status during best-path selection. |

### 2.5 RFC 8210: RPKI-to-Router Protocol Version 1

| Clause | Requirement | Status | Purlin Implementation Details |
|---|---|---|---|
| § 5.1 | Serial Notify PDU (Type 0) | COMPLIANT | `rpki/rtr.kk:encode-rtr-header` and `parse-rtr-pdu`. Handles cache version updates. |
| § 5.2 | Serial Query PDU (Type 1) | COMPLIANT | Generates queries containing current cache session ID and serial number. |
| § 5.3 | Reset Query PDU (Type 2) | COMPLIANT | Requests complete cache dump upon session reset or state desynchronization. |
| § 5.4 | Cache Response PDU (Type 3) | COMPLIANT | Parses server response header and validates session identifier. |
| § 5.5 | IPv4 Prefix PDU (Type 4) | COMPLIANT | Parses 20-byte PDU extracting flags, prefix, length, max-length, and authorized 32-bit ASN. |
| § 5.6 | IPv6 Prefix PDU (Type 6) | COMPLIANT | Parses 32-byte PDU with 128-bit IPv6 prefix payloads. |
| § 5.7 | End of Data PDU (Type 7) | COMPLIANT | Confirms atomic commit of incremental or full ROA cache synchronization. |

### 2.6 RFC 7432 / RFC 9136: BGP EVPN Overlay Routing

| Clause | Requirement | Status | Purlin Implementation Details |
|---|---|---|---|
| § 7.2 | Route Type 2: MAC/IP Advertisement Route | COMPLIANT | `evpn/nlri.kk:encode-evpn-type2` and `parse-evpn-type2`. Encodes RD, ESI, MAC, IP, and MPLS/VNI label stack. |
| § 7.3 | Route Type 3: Inclusive Multicast Ethernet Tag Route | COMPLIANT | `evpn/nlri.kk:encode-evpn-type3`. Encodes originating router IP for BUM traffic replication. |
| RFC 9136 | Route Type 5: IP Prefix Route | COMPLIANT | `evpn/nlri.kk:encode-evpn-type5`. Inter-subnet L3 routing with Gateway IP and IP prefix fields. |
| § 8 | Route Distinguisher (RD) & Route Target (RT) Extended Communities | COMPLIANT | `evpn/types.kk` and `evpn/vrf.kk`. Enforces per-tenant isolation and route leaking control. |

### 2.7 RFC 7938: Datacenter BGP Architecture

| Clause | Requirement | Status | Purlin Implementation Details |
|---|---|---|---|
| § 3.1 | Clos Topology Model: Spines and Leaves | COMPLIANT | `sim/clos.kk:build-spine-leaf-fabric`. Models 5-node Clos fabric with dual spine uplinks per leaf switch. |
| § 3.2 | ASN Allocation Scheme (Autonomous System per Switch) | COMPLIANT | Uses RFC 7938 Table 1 recommendation: Spine tier AS 65101-65102, Leaf tier AS 65011-65013. |
| § 4.2 | Equal-Cost Multi-Path (ECMP) Hashing | COMPLIANT | `rib/ecmp.kk:hash-5tuple`. Distributes flows across equal-metric spine uplinks using 5-tuple CRC32 hashing. |
| § 5.2 | Rapid Convergence and Failover | COMPLIANT | `sim/fabric.kk:cut-fabric-link`. Simulates link severing, BGP WITHDRAW broadcast, and sub-millisecond route convergence. |
