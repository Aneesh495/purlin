// Module: policy/ast
// Abstract Syntax Tree for BGP route policy language and filtering rules.
//
// Modern carrier and cloud data center routing engines rely on declarative
// route policies to filter invalid routes, manipulate traffic engineering
// metrics (Local-Preference, Multi-Exit Discriminator), tag routing intent
// with BGP Communities, and protect Autonomous Systems from route leaks.
//
// This module defines the AST for:
//   1. Prefix lists with ge/le prefix length range constraints
//   2. AS_PATH regex filters (origin, neighbor, transit, prepend)
//   3. Standard, extended, and large community filters
//   4. Route-map clauses with match criteria and set actions

module policy/ast

import std/core/list
import std/core/maybe
import std/core/string
import proto/types
import proto/attr

// Policy rule action: permit or deny
pub type policy-disposition
  PolicyPermit
  PolicyDeny

pub fun policy-disposition/(==)(a : policy-disposition, b : policy-disposition) : bool
  match (a, b)
    (PolicyPermit, PolicyPermit) -> True
    (PolicyDeny, PolicyDeny) -> True
    _ -> False

pub fun policy-disposition/show(d : policy-disposition) : string
  match d
    PolicyPermit -> "permit"
    PolicyDeny -> "deny"

// Prefix list rule with optional prefix length bounds (ge, le)
// Example: ip prefix-list CUST-IN permit 10.0.0.0/8 ge 16 le 24
pub struct prefix-rule(
  seq-num        : int,
  rule-action    : policy-disposition,
  match-prefix   : ip-prefix,
  ge-len         : maybe<int>,
  le-len         : maybe<int>
)

// Check if a target prefix matches a prefix-rule with ge/le bounds
pub fun match-prefix-rule(rule : prefix-rule, target : ip-prefix) : bool
  // Both prefixes must have the same IP version
  match (rule.match-prefix, target)
    (Ipv4-prefix(r-ip, r-len), Ipv4-prefix(t-ip, t-len)) ->
      if t-len < r-len then False
      else
        // Target must fall within rule prefix network mask
        val r-net = ipv4-network(r-ip, r-len)
        val t-net = ipv4-network(t-ip, r-len)
        if r-net != t-net then False
        else
          val min-len = rule.ge-len.default(r-len)
          val max-len = rule.le-len.default(32)
          (t-len >= min-len) && (t-len <= max-len)
    (Ipv6-prefix(r-hi, r-lo, r-len), Ipv6-prefix(t-hi, t-lo, t-len)) ->
      if t-len < r-len then False
      else
        val min-len = rule.ge-len.default(r-len)
        val max-len = rule.le-len.default(128)
        (t-len >= min-len) && (t-len <= max-len)
    _ -> False

// Prefix list containing ordered prefix rules
pub struct prefix-list(
  list-name : string,
  rules     : list<prefix-rule>
)

// Evaluate a prefix against an ordered prefix-list.
// Returns PolicyPermit or PolicyDeny. Default implicit deny.
pub fun eval-prefix-list(plist : prefix-list, target : ip-prefix) : policy-disposition
  fun loop(rem : list<prefix-rule>) : policy-disposition
    match rem
      Nil -> PolicyDeny // Implicit deny at end of list
      Cons(rule, tail) ->
        if match-prefix-rule(rule, target) then rule.rule-action
        else loop(tail)
  loop(plist.rules)

// AS_PATH filter pattern
pub type as-path-pattern
  AsPatternAny
  AsPatternOrigin(origin-asn : asn)       // Route originated by ASN
  AsPatternNeighbor(neighbor-asn : asn)   // Directly received from neighbor ASN
  AsPatternTransit(transit-asn : asn)     // ASN appears anywhere in path
  AsPatternLengthExact(expected-len : int)
  AsPatternLengthMax(max-len : int)

// Match an AS_PATH against an as-path-pattern
pub fun match-as-path(pattern : as-path-pattern, path : as-path) : bool
  val as-list = as-path-flatten(path)
  match pattern
    AsPatternAny -> True
    AsPatternOrigin(target) ->
      match as-list.reverse
        Cons(orig, _) -> orig == target
        Nil -> False
    AsPatternNeighbor(target) ->
      match as-list
        Cons(neigh, _) -> neigh == target
        Nil -> False
    AsPatternTransit(target) ->
      as-list.any(fn(a) a == target)
    AsPatternLengthExact(expected) ->
      as-path-length(path) == expected
    AsPatternLengthMax(max-allowed) ->
      as-path-length(path) <= max-allowed

// Community filter matching criterion
pub type community-filter
  CommunityExact(comm : community)
  CommunityWellKnown(tag : int)
  CommunityListAny(comms : list<community>)

// Match communities against filter
pub fun match-community-filter(filter : community-filter, comms : list<community>) : bool
  match filter
    CommunityExact(target) ->
      comms.any(fn(c) c == target)
    CommunityWellKnown(tag) ->
      comms.any(fn(c) c.comm-val == tag)
    CommunityListAny(targets) ->
      targets.any(fn(t) comms.any(fn(c) c == t))

// Route-map match criteria
pub type route-match
  MatchPrefixList(p-list : prefix-list)
  MatchAsPath(pattern : as-path-pattern)
  MatchCommunity(c-filter : community-filter)
  MatchMed(expected-med : int)
  MatchLocalPref(expected-pref : int)
  MatchNextHop(expected-nh : ipv4)

// Route-map set operations to mutate route attributes
pub type route-set
  SetLocalPref(new-pref : int)
  SetMed(new-med : int)
  SetWeight(new-weight : int)
  SetNextHop(new-nh : ipv4)
  SetAsPathPrepend(prepend-asns : list<asn>)
  SetCommunityAdd(comm : community)
  SetCommunityDelete(comm : community)

// A single route-map clause with sequence number, disposition, matches, and sets
pub struct route-map-clause(
  seq-num        : int,
  clause-action  : policy-disposition,
  matches        : list<route-match>,
  sets           : list<route-set>
)

// Named route-map consisting of ordered clauses
pub struct route-map(
  map-name : string,
  clauses  : list<route-map-clause>
)
