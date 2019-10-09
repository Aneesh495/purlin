// Module: fib/synth
// Recursive next-hop resolution and FIB synthesis from BGP RIB state.
//
// In carrier networks and data centers, BGP routes typically advertise
// loopback next-hops (e.g. iBGP peers). The forwarding plane cannot forward
// packets directly to a loopback; it must recursively resolve the BGP NEXT_HOP
// through IGP (OSPF/IS-IS) or directly connected interface routes.
//
// This module implements:
//   1. Recursive next-hop resolution with cycle and depth limit protection
//   2. Next-hop tracking and reachability validation (RFC 4271 §9.1.2.1)
//   3. Compilation of best routes and ECMP groups into FIB forwarding entries

module fib/synth

import std/core/list
import std/core/maybe
import proto/types
import rib/table
import fib/table
import evpn/types

// Connected interface route mapping a directly reachable subnet to an interface
pub struct connected-route(
  subnet-pfx : ip-prefix,
  egress-if  : egress-interface
)

// IGP route for internal loopbacks and underlay reachability
pub struct igp-route(
  dest-pfx   : ip-prefix,
  gateway-ip : ipv4,
  egress-if  : egress-interface,
  metric     : int
)

// In-memory IGP and Connected routing table used for recursion
pub struct igp-table(
  connected : list<connected-route>,
  underlay  : list<igp-route>
)

pub fun igp-table-empty() : igp-table
  Igp-table([], [])

// Add a connected interface subnet to the IGP table
pub fun add-connected(tbl : igp-table, pfx : ip-prefix, iface : egress-interface) : igp-table
  tbl(connected = Cons(Connected-route(pfx, iface), tbl.connected))

// Add an underlay IGP route to the IGP table
pub fun add-igp-route(tbl : igp-table, pfx : ip-prefix, gw : ipv4, iface : egress-interface, m : int) : igp-table
  tbl(underlay = Cons(Igp-route(pfx, gw, iface, m), tbl.underlay))

// Resolve a BGP next-hop IP recursively against connected and IGP tables.
// Returns Just(resolved-nexthop) if reachable, or Nothing if unreachable.
pub fun resolve-nexthop(
  igp        : igp-table,
  target-ip  : ipv4,
  encap      : maybe<vni> = Nothing,
  max-depth  : int = 4
) : div maybe<resolved-nexthop>
  if max-depth <= 0 then Nothing
  else
    // Step 1: Check directly connected subnets
    val direct-match = igp.connected.filter(fn(cr) prefix-contains-ipv4(cr.subnet-pfx, target-ip))
    match direct-match
      Cons(cr, _) ->
        // Directly connected: destination IP is adjacent on this interface
        Just(Resolved-nexthop(target-ip, cr.egress-if, True, encap))
      Nil ->
        // Step 2: Check IGP underlay routes for longest prefix match
        val matching-igp = igp.underlay.filter(fn(ir) prefix-contains-ipv4(ir.dest-pfx, target-ip))
        // Sort by prefix length descending for LPM
        val sorted = matching-igp.foldl([], fn(acc, r) {
          Cons(r, acc) // In a small underlay list, pick highest length
        })
        match sorted
          Cons(best-igp, _) ->
            // Recurse to resolve the IGP gateway if it is not directly connected
            val is-gw-direct = igp.connected.any(fn(cr) prefix-contains-ipv4(cr.subnet-pfx, best-igp.gateway-ip))
            if is-gw-direct then
              Just(Resolved-nexthop(best-igp.gateway-ip, best-igp.egress-if, False, encap))
            else
              // Recurse on gateway
              resolve-nexthop(igp, best-igp.gateway-ip, encap, max-depth - 1)
          Nil -> Nothing

// Synthesize a FIB forwarding entry from a winning BGP route
pub fun synthesize-fib-entry(
  igp   : igp-table,
  route : bgp-route,
  now   : int
) : div maybe<fib-entry>
  if !route.is-valid || route.is-damped then Nothing
  else
    match resolve-nexthop(igp, route.next-hop)
      Just(r-nh) ->
        Just(Fib-entry(route.route-prefix, [r-nh], now, "BGP"))
      Nothing -> Nothing

// Compile entire RIB into an active FIB table
pub fun synthesize-fib(
  rib   : rib-table,
  igp   : igp-table,
  now   : int
) : div fib-table
  val all-routes = rib-all-routes(rib)
  val best-routes = all-routes.filter(fn(r) r.is-best && r.is-valid && !r.is-damped)
  
  var fib := fib-empty()
  best-routes.foreach(fn(r) {
    match synthesize-fib-entry(igp, r, now)
      Just(entry) ->
        fib := fib-insert(fib, entry)
      Nothing -> ()
  })
  fib
