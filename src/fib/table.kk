// Module: fib/table
// Forwarding Information Base (FIB) data structures and hardware forwarding abstractions.
//
// While the RIB (Routing Information Base) stores control-plane routing state,
// the FIB stores compiled forwarding entries optimized for line-rate packet
// forwarding and hardware Longest Prefix Match (LPM) ASIC pipelines.
//
// This module provides:
//   1. Physical/virtual egress interface definitions
//   2. Resolved next-hop descriptors with optional VXLAN encapsulation
//   3. Multipath (ECMP) forwarding entries
//   4. High-speed Patricia-trie indexed FIB with LPM lookup

module fib/table

import std/core/list
import std/core/maybe
import std/core/string
import proto/types
import rib/patricia
import evpn/types

// Network Interface descriptor
pub struct egress-interface(
  if-index : int,
  if-name  : string
)

pub fun egress-interface/show(i : egress-interface) : string
  i.if-name ++ " (idx " ++ i.if-index.show ++ ")"

pub fun egress-interface/(==)(a : egress-interface, b : egress-interface) : bool
  (a.if-index == b.if-index) && (a.if-name == b.if-name)

// Resolved Next-Hop specifying direct egress interface and gateway IP
pub struct resolved-nexthop(
  gateway-ip : ipv4,
  egress-if  : egress-interface,
  is-direct  : bool,
  encap-vni  : maybe<vni>
)

pub fun resolved-nexthop/show(nh : resolved-nexthop) : string
  val vni-str = match nh.encap-vni
    Just(v) -> " " ++ v.show
    Nothing -> ""
  nh.gateway-ip.show ++ " via " ++ nh.egress-if.show ++ vni-str

pub fun resolved-nexthop/(==)(a : resolved-nexthop, b : resolved-nexthop) : bool
  (a.gateway-ip == b.gateway-ip) && (a.egress-if == b.egress-if) &&
  (a.is-direct == b.is-direct) && (a.encap-vni == b.encap-vni)

// Compiled Forwarding Entry installed in kernel or forwarding ASIC
pub struct fib-entry(
  dest-prefix    : ip-prefix,
  nexthops       : list<resolved-nexthop>, // Single or multipath (ECMP) set
  installed-time : int,                    // Monotonic seconds
  route-source   : string                  // "BGP", "CONNECTED", "STATIC"
)

pub fun fib-entry/show(e : fib-entry) : string
  val nh-str = e.nexthops.map(show).join(", ")
  e.dest-prefix.show ++ " [" ++ e.route-source ++ "] -> " ++ nh-str

// In-memory Forwarding Information Base indexed by Patricia Trie
pub struct fib-table(
  trie        : patricia-trie<fib-entry>,
  entry-count : int
)

// Construct an empty FIB table
pub fun fib-empty() : fib-table
  Fib-table(patricia-empty(), 0)

// Install a compiled forwarding entry into the FIB
pub fun fib-insert(fib : fib-table, entry : fib-entry) : div fib-table
  val updated-trie = patricia-insert(fib.trie, entry.dest-prefix, entry)
  Fib-table(updated-trie, fib.entry-count + 1)

// Delete a forwarding entry from the FIB
pub fun fib-delete(fib : fib-table, pfx : ip-prefix) : div fib-table
  val updated-trie = patricia-delete(fib.trie, pfx)
  Fib-table(updated-trie, max(0, fib.entry-count - 1))

// Exact match lookup in FIB
pub fun fib-lookup-exact(fib : fib-table, pfx : ip-prefix) : div maybe<fib-entry>
  patricia-lookup-exact(fib.trie, pfx)

// Longest Prefix Match (LPM) on FIB for packet forwarding
pub fun fib-lpm(fib : fib-table, dst-ip : ipv4) : div maybe<(ip-prefix, fib-entry)>
  patricia-lpm(fib.trie, dst-ip)

// Enumerate all active FIB forwarding entries
pub fun fib-all-entries(fib : fib-table) : div list<fib-entry>
  val pairs = patricia-to-list(fib.trie)
  pairs.map(fn(pair) pair.snd)
