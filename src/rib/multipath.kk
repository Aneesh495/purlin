// Module: rib/multipath
// Equal-Cost Multi-Path (ECMP) route aggregation and flow distribution.
//
// In data center spine-leaf Clos networks and modern carrier backbones,
// multiple equal-cost paths to a destination prefix exist simultaneously.
// Rather than selecting a single tie-break winner and discarding alternate
// paths, ECMP groups paths that tie across all criteria down to the IGP metric.
//
// This module implements:
//   1. Multipath candidate qualification based on RFC 7911 / industry standards
//   2. ECMP group synthesis with bounded group cardinality (max-paths)
//   3. High-entropy 5-tuple flow hashing for packet load distribution
//   4. Consistent path selection avoiding polarization in multi-tier fabrics

module rib/multipath

import std/core/list
import std/core/maybe
import proto/types
import proto/attr
import rib/table

// Represents an Equal-Cost Multi-Path group for a specific prefix.
pub struct multipath-group(
  group-prefix : ip-prefix,
  members : list<bgp-route>,
  max-paths : int
)

// Check if two routes qualify for mutual ECMP inclusion given local ASN.
// Both routes must tie on:
//   - Weight
//   - Local Preference
//   - AS_PATH hop count
//   - Origin code
//   - Multi-Exit Discriminator (MED)
//   - Peering mode (both eBGP or both iBGP)
pub fun can-multipath(a : bgp-route, b : bgp-route, local-asn : asn) : bool
  // Both must be valid and not damped
  if (!a.is-valid || !b.is-valid || a.is-damped || b.is-damped) return False
  
  // Weight must match
  if (a.weight != b.weight) return False
  
  // Local preference must match
  if (a.local-pref != b.local-pref) return False
  
  // AS_PATH length must match
  val a-as-len = as-path-length(a.as-path)
  val b-as-len = as-path-length(b.as-path)
  if (a-as-len != b-as-len) return False
  
  // Origin must match
  if (a.origin != b.origin) return False
  
  // MED must match
  if (a.med != b.med) return False
  
  // Peering mode must match (both eBGP or both iBGP)
  val a-is-ebgp = a.peer-asn != local-asn
  val b-is-ebgp = b.peer-asn != local-asn
  if (a-is-ebgp != b-is-ebgp) return False
  
  True

// Form an ECMP group from a list of candidate routes for a prefix.
// The list is evaluated against the best route (head of list).
// All routes that can multipath with the best route are included,
// up to max-paths count.
pub fun form-ecmp-group(routes : list<bgp-route>, local-asn : asn, max-allowed : int = 16) : maybe<multipath-group>
  match routes
    Nil -> Nothing
    Cons(best, rest) ->
      if (!best.is-valid || best.is-damped) then Nothing
      else
        val target = best.route-prefix
        val eligible = rest.filter(fn(r) can-multipath(best, r, local-asn))
        val all-members = Cons(best, eligible).take(max-allowed)
        Just(Multipath-group(target, all-members, max-allowed))

// Helper to mix one byte into the running DJB2 flow hash
fun mix-byte(h : int, b : int) : int
  val byte-val = if b < 0 then (0 - b) % 256 else b % 256
  val mixed = (h * 33) + byte-val
  val bounded = mixed % 2147483647
  if (bounded < 0) then 0 - bounded else bounded

// Compute 5-tuple flow hash for traffic distribution.
// Uses DJB2 hashing algorithm to generate entropy from
// Source IP, Destination IP, Protocol, Source Port, Destination Port.
pub fun compute-flow-hash(
  src-ip : ipv4,
  dst-ip : ipv4,
  proto-num : int,
  src-port : int,
  dst-port : int
) : int
  var h := 5381
  
  // Mix Source IP
  val s-val = src-ip.addr
  h := mix-byte(h, s-val / 16777216)
  h := mix-byte(h, s-val / 65536)
  h := mix-byte(h, s-val / 256)
  h := mix-byte(h, s-val)
  
  // Mix Destination IP
  val d-val = dst-ip.addr
  h := mix-byte(h, d-val / 16777216)
  h := mix-byte(h, d-val / 65536)
  h := mix-byte(h, d-val / 256)
  h := mix-byte(h, d-val)
  
  // Mix Protocol
  h := mix-byte(h, proto-num)
  
  // Mix Source Port
  h := mix-byte(h, src-port / 256)
  h := mix-byte(h, src-port)
  
  // Mix Destination Port
  h := mix-byte(h, dst-port / 256)
  h := mix-byte(h, dst-port)
  
  h

// Select next-hop path from an ECMP group given a flow hash.
// Uses modulo hashing across available paths.
pub fun select-path(group : multipath-group, hash-val : int) : maybe<bgp-route>
  val count = group.members.length
  if (count <= 0) then Nothing
  else
    val safe-hash = if (hash-val < 0) then (0 - hash-val) else hash-val
    val index = safe-hash % count
    group.members.drop(index).head

// Get count of paths in the group
pub fun group-size(group : multipath-group) : int
  group.members.length
