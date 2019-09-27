// Module: evpn/vrf
// Virtual Routing and Forwarding (VRF) table and EVPN tenant isolation.
//
// In multi-tenant cloud fabrics, each tenant occupies an isolated VRF routing
// namespace. Route Targets (RTs) govern cross-tenant export and import, while
// Route Distinguishers (RDs) keep overlapping IP spaces unique in BGP.
//
// This module provides:
//   1. Tenant VRF instance with dedicated RIB and L2 Forwarding Database (FDB)
//   2. Route Target matching and policy-driven import filtering
//   3. EVPN Type-2 (MAC/IP) and Type-5 (IP Prefix) route ingestion
//   4. Cross-tenant route leak prevention and isolation enforcement

module evpn/vrf

import std/core/list
import std/core/maybe
import std/core/string
import proto/types
import proto/attr
import rib/table
import evpn/types
import evpn/routes

// Host entry in L2 MAC Forwarding Database (FDB)
pub struct mac-entry(
  mac-addr  : mac-address,
  host-ip   : maybe<ipv4>,
  vni-id    : vni,
  next-hop  : ipv4
)

// Virtual Routing and Forwarding (VRF) tenant instance
pub struct vrf-instance(
  vrf-name        : string,
  rd              : route-distinguisher,
  vni-val         : vni,
  import-targets  : list<route-target>,
  export-targets  : list<route-target>,
  mac-table       : list<mac-entry>,
  rib             : rib-table
)

// Construct a new empty VRF instance
pub fun vrf-create(
  name           : string,
  rd-val         : route-distinguisher,
  vni-id         : vni,
  import-rts     : list<route-target>,
  export-rts     : list<route-target>
) : vrf-instance
  Vrf-instance(name, rd-val, vni-id, import-rts, export-rts, [], rib-empty())

// Check if a set of candidate Route Targets matches any import RT of the VRF
pub fun vrf-matches-import(vrf : vrf-instance, candidate-rts : list<route-target>) : bool
  candidate-rts.any(fn(c-rt) {
    vrf.import-targets.any(fn(i-rt) i-rt == c-rt)
  })

// Ingest EVPN Type-2 MAC/IP route into the VRF FDB if Route Targets match
pub fun vrf-ingest-type2(
  vrf           : vrf-instance,
  nlri          : evpn-nlri,
  route-rts     : list<route-target>,
  tunnel-ip     : ipv4
) : vrf-instance
  if !vrf-matches-import(vrf, route-rts) then vrf
  else
    match nlri
      EvpnTypeTwo(_, _, _, mac, ip-opt, v) ->
        val new-entry = Mac-entry(mac, ip-opt, v, tunnel-ip)
        // Deduplicate existing entry for same MAC
        val filtered = vrf.mac-table.filter(fn(e) !(e.mac-addr == mac))
        vrf(mac-table = Cons(new-entry, filtered))
      _ -> vrf

// Ingest EVPN Type-5 IP Prefix route into the tenant RIB if Route Targets match
pub fun vrf-ingest-type5(
  vrf           : vrf-instance,
  nlri          : evpn-nlri,
  route-rts     : list<route-target>,
  peer-as       : asn,
  peer-router   : ipv4
) : div vrf-instance
  if !vrf-matches-import(vrf, route-rts) then vrf
  else
    match nlri
      EvpnTypeFive(_, _, _, target-pfx, gw, _) ->
        val route = route-from-attributes(
          target-pfx,
          peer-as,
          peer-router,
          Router-id(peer-router),
          [
            AttrOrigin(OriginIgp),
            AttrAsPath(As-path([As-segment(as-segment-sequence, [peer-as])])),
            AttrNextHop(gw),
            AttrMed(0),
            AttrLocalPref(100)
          ],
          1000
        )
        val updated-rib = rib-insert(vrf.rib, route)
        vrf(rib = updated-rib)
      _ -> vrf

// Lookup MAC address in VRF Forwarding Database
pub fun vrf-lookup-mac(vrf : vrf-instance, mac : mac-address) : maybe<mac-entry>
  vrf.mac-table.filter(fn(e) e.mac-addr == mac).head

// Tenant route isolation check: verifies whether a route originated in vrf-src
// is permitted to leak into vrf-dst based on explicit mutual Route Target overlap
pub fun can-leak-route(vrf-src : vrf-instance, vrf-dst : vrf-instance) : bool
  vrf-src.export-targets.any(fn(exp-rt) {
    vrf-dst.import-targets.any(fn(imp-rt) imp-rt == exp-rt)
  })
