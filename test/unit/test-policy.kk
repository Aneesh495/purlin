// Unit tests for Policy AST, Algebraic Effects, and Route-Map Evaluation Pipeline
module unit/test-policy

import std/core/list
import std/core/maybe
import proto/types
import proto/attr
import rib/table
import policy/ast
import policy/effects
import policy/eval

fun make-test-route(
  pfx-oct1 : int,
  pfx-oct2 : int,
  pfx-len  : int,
  peer-oct : int,
  as-hops  : list<int>,
  lp       : int,
  med-val  : int
) : bgp-route
  val segs = [As-segment(as-segment-sequence, as-hops.map(asn))]
  route-from-attributes(
    prefix4(pfx-oct1, pfx-oct2, 0, 0, pfx-len),
    asn(65001),
    ipv4-create(10, 0, peer-oct, 1),
    router-id(10, 0, peer-oct, 1),
    [
      AttrOrigin(OriginIgp),
      AttrAsPath(As-path(segs)),
      AttrNextHop(ipv4-create(192, 168, peer-oct, 1)),
      AttrMed(med-val),
      AttrLocalPref(lp)
    ],
    1000
  )

fun test-prefix-list-matching() : bool
  // Rule: permit 10.0.0.0/8 ge 16 le 24
  val rule1 = Prefix-rule(
    10,
    PolicyPermit,
    prefix4(10, 0, 0, 0, 8),
    Just(16),
    Just(24)
  )
  val plist = Prefix-list("CUSTOMER-IN", [rule1])
  
  // 10.1.0.0/16 should match (in /8, len 16 within [16, 24])
  val p1 = prefix4(10, 1, 0, 0, 16)
  val t1 = eval-prefix-list(plist, p1) == PolicyPermit
  
  // 10.2.3.0/24 should match (in /8, len 24 within [16, 24])
  val p2 = prefix4(10, 2, 3, 0, 24)
  val t2 = eval-prefix-list(plist, p2) == PolicyPermit
  
  // 10.0.0.0/8 should fail (len 8 < ge 16)
  val p3 = prefix4(10, 0, 0, 0, 8)
  val t3 = eval-prefix-list(plist, p3) == PolicyDeny
  
  // 10.4.5.6/32 should fail (len 32 > le 24)
  val p4 = prefix4(10, 4, 5, 6, 32)
  val t4 = eval-prefix-list(plist, p4) == PolicyDeny
  
  // 192.168.1.0/24 should fail (not in 10.0.0.0/8)
  val p5 = prefix4(192, 168, 1, 0, 24)
  val t5 = eval-prefix-list(plist, p5) == PolicyDeny
  
  t1 && t2 && t3 && t4 && t5

fun test-as-path-matching() : bool
  // Path: 65001 65002 65003
  val path = As-path([As-segment(as-segment-sequence, [asn(65001), asn(65002), asn(65003)])])
  
  // Origin ASN (last ASN = 65003)
  val t1 = match-as-path(AsPatternOrigin(asn(65003)), path)
  val t2 = !match-as-path(AsPatternOrigin(asn(65001)), path)
  
  // Neighbor ASN (first ASN = 65001)
  val t3 = match-as-path(AsPatternNeighbor(asn(65001)), path)
  val t4 = !match-as-path(AsPatternNeighbor(asn(65003)), path)
  
  // Transit ASN (65002)
  val t5 = match-as-path(AsPatternTransit(asn(65002)), path)
  val t6 = !match-as-path(AsPatternTransit(asn(65999)), path)
  
  // Length match
  val t7 = match-as-path(AsPatternLengthExact(3), path)
  val t8 = match-as-path(AsPatternLengthMax(4), path)
  val t9 = !match-as-path(AsPatternLengthMax(2), path)
  
  t1 && t2 && t3 && t4 && t5 && t6 && t7 && t8 && t9

fun test-community-filtering() : bool
  val c1 = community-create(65000, 100)
  val c2 = community-create(65535, 65281) // NO_EXPORT
  val comms = [c1, c2]
  
  val t1 = match-community-filter(CommunityExact(c1), comms)
  val t2 = !match-community-filter(CommunityExact(community-create(65000, 200)), comms)
  
  // Well known NO_EXPORT = (65535 * 65536) + 65281 = 4294901761
  val no-export-val = (65535 * 65536) + 65281
  val t3 = match-community-filter(CommunityWellKnown(no-export-val), comms)
  
  t1 && t2 && t3

fun test-route-map-permit-and-mutate() : bool
  val route = make-test-route(10, 1, 24, 1, [65001, 65002], 100, 0)
  
  // Clause 10: Match prefix 10.0.0.0/8 ge 16 le 24
  // Sets: Local-Pref = 250, MED = 20, Prepend ASN 65000
  val p-rule = Prefix-rule(10, PolicyPermit, prefix4(10, 0, 0, 0, 8), Just(16), Just(24))
  val plist = Prefix-list("PL-IN", [p-rule])
  val clause10 = Route-map-clause(
    10,
    PolicyPermit,
    [MatchPrefixList(plist)],
    [
      SetLocalPref(250),
      SetMed(20),
      SetAsPathPrepend([asn(65000)]),
      SetCommunityAdd(community-create(65000, 500))
    ]
  )
  val rmap = Route-map("RM-IMPORT", [clause10])
  
  val (res-opt, audit-logs) = eval-route-map-with-audit(rmap, route)
  match res-opt
    Just(mutated) ->
      val t1 = mutated.local-pref == 250
      val t2 = mutated.med == 20
      val t3 = as-path-length(mutated.as-path) == 3 // 65000 + 65001 + 65002
      val t4 = mutated.communities.length == 1
      val t5 = audit-logs.length == 1
      t1 && t2 && t3 && t4 && t5
    Nothing -> False

fun test-route-map-deny() : bool
  val route = make-test-route(192, 168, 24, 1, [65999], 100, 0)
  
  // Clause 10: Deny routes matching AS 65999
  val clause10 = Route-map-clause(
    10,
    PolicyDeny,
    [MatchAsPath(AsPatternTransit(asn(65999)))],
    []
  )
  val clause20 = Route-map-clause(
    20,
    PolicyPermit,
    [],
    [SetLocalPref(200)]
  )
  val rmap = Route-map("RM-FILTER", [clause10, clause20])
  
  val (res-opt, audit-logs) = eval-route-map-with-audit(rmap, route)
  val t1 = res-opt.is-nothing
  val t2 = match audit-logs
    Cons(ev, _) -> ev.disposition == PolicyDeny
    Nil -> False
  
  t1 && t2

pub fun main()
  val t1 = test-prefix-list-matching()
  val t2 = test-as-path-matching()
  val t3 = test-community-filtering()
  val t4 = test-route-map-permit-and-mutate()
  val t5 = test-route-map-deny()
  
  if t1 && t2 && t3 && t4 && t5 then
    println("PASS: policy subsystem unit tests passed successfully")
  else
    println("FAIL: policy subsystem unit tests failed")
