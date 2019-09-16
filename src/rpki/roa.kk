// Module: rpki/roa
// Route Origin Authorization (ROA) cache and prefix trie indexing.
//
// In RPKI (Resource Public Key Infrastructure), a ROA is a digitally signed
// object certifying that an Autonomous System is authorized to originate
// announcements for a specified IP address prefix and optional maximum length
// (RFC 6482).
//
// This module provides:
//   1. ROA payload representation (prefix, max-length, ASN)
//   2. High-performance Patricia-trie indexed ROA cache
//   3. Covering prefix retrieval for RFC 6811 validation queries

module rpki/roa

import std/core/list
import std/core/maybe
import std/core/string
import proto/types
import rib/patricia

// Validated ROA Payload (VRP) according to RFC 6482 / RFC 6811
pub struct roa-payload(
  roa-prefix : ip-prefix,
  max-length : int,
  origin-asn : asn
)

pub fun roa-payload/(==)(a : roa-payload, b : roa-payload) : bool
  (a.roa-prefix == b.roa-prefix) && (a.max-length == b.max-length) && (a.origin-asn == b.origin-asn)

pub fun roa-payload/show(r : roa-payload) : string
  r.roa-prefix.show ++ " max-len " ++ r.max-length.show ++ " AS" ++ r.origin-asn.show

// ROA Cache storing VRPs indexed by prefix in a Patricia Trie
pub struct roa-cache(
  trie        : patricia-trie<list<roa-payload>>,
  total-count : int
)

// Construct an empty ROA cache
pub fun roa-cache-empty() : roa-cache
  Roa-cache(patricia-empty(), 0)

// Insert a VRP into the ROA cache
pub fun roa-cache-insert(cache : roa-cache, roa : roa-payload) : div roa-cache
  val existing = patricia-lookup-exact(cache.trie, roa.roa-prefix).default([])
  if existing.any(fn(x) x == roa) then cache
  else
    val updated-list = Cons(roa, existing)
    val updated-trie = patricia-insert(cache.trie, roa.roa-prefix, updated-list)
    Roa-cache(updated-trie, cache.total-count + 1)

// Delete a VRP from the ROA cache
pub fun roa-cache-delete(cache : roa-cache, roa : roa-payload) : div roa-cache
  val existing = patricia-lookup-exact(cache.trie, roa.roa-prefix).default([])
  val filtered = existing.filter(fn(x) !(x == roa))
  if existing.length == filtered.length then cache
  else
    val updated-trie = if filtered.is-empty then
      patricia-delete(cache.trie, roa.roa-prefix)
    else
      patricia-insert(cache.trie, roa.roa-prefix, filtered)
    Roa-cache(updated-trie, cache.total-count - 1)

// Retrieve all ROAs whose prefix covers (is a supernet of or equals) the target route prefix
pub fun roa-cache-lookup-covering(cache : roa-cache, route-pfx : ip-prefix) : div list<roa-payload>
  val covering-nodes = patricia-covering(cache.trie, route-pfx)
  covering-nodes.flatmap(fn(pair) pair.snd)

// Count of VRPs in cache
pub fun roa-cache-size(cache : roa-cache) : int
  cache.total-count
