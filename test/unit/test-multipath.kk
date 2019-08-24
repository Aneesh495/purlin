// Unit tests for Equal-Cost Multi-Path (ECMP) route grouping and flow hashing
module unit/test-multipath

import std/core/list
import std/core/maybe
import proto/types
import proto/attr
import rib/table
import rib/multipath

fun make-test-route(
  peer-oct : int,
  as-num : int,
  as-hops : list<int>,
  local-pref-val : int,
  med-val : int,
  w : int
) : bgp-route
  val segs = [As-segment(as-segment-sequence, as-hops.map(asn))]
  val r = route-from-attributes(
    prefix4(10, 0, 0, 0, 24),
    asn(as-num),
    ipv4-create(10, 0, peer-oct, 1),
    router-id(10, 0, peer-oct, 1),
    [
      AttrOrigin(OriginIgp),
      AttrAsPath(As-path(segs)),
      AttrNextHop(ipv4-create(192, 168, peer-oct, 1)),
      AttrMed(med-val),
      AttrLocalPref(local-pref-val)
    ],
    1000
  )
  r(weight = w)

fun test-can-multipath() : bool
  val local = asn(65000)
  val r1 = make-test-route(1, 65001, [65001, 65002], 100, 0, 0)
  val r2 = make-test-route(2, 65001, [65001, 65003], 100, 0, 0)
  
  // Both routes have same weight (0), local-pref (100), as-path len (2), origin (IGP), med (0), eBGP (65001 != 65000)
  val t1 = can-multipath(r1, r2, local)
  
  // Different weight
  val r-diff-weight = r2(weight = 50)
  val t2 = !can-multipath(r1, r-diff-weight, local)
  
  // Different local-pref
  val r-diff-pref = r2(local-pref = 200)
  val t3 = !can-multipath(r1, r-diff-pref, local)
  
  // Different AS-path length
  val r-diff-as = make-test-route(2, 65001, [65001, 65002, 65003], 100, 0, 0)
  val t4 = !can-multipath(r1, r-diff-as, local)
  
  // Different MED
  val r-diff-med = r2(med = 50)
  val t5 = !can-multipath(r1, r-diff-med, local)
  
  // Different peering mode (eBGP vs iBGP)
  val r-diff-peer = r2(peer-asn = local)
  val t6 = !can-multipath(r1, r-diff-peer, local)
  
  // Invalid route
  val r-invalid = r2(is-valid = False)
  val t7 = !can-multipath(r1, r-invalid, local)
  
  t1 && t2 && t3 && t4 && t5 && t6 && t7

fun test-form-ecmp-group() : bool
  val local = asn(65000)
  val best = make-test-route(1, 65100, [65100], 100, 0, 0)(is-best = True)
  val alt1 = make-test-route(2, 65200, [65200], 100, 0, 0)
  val alt2 = make-test-route(3, 65300, [65300], 100, 0, 0)
  val alt-bad = make-test-route(4, 65400, [65400, 65401], 100, 0, 0) // Longer path
  
  val grp-opt = form-ecmp-group([best, alt1, alt2, alt-bad], local, 4)
  val t1 = match grp-opt
    Just(grp) -> grp.group-size == 3
    Nothing -> False
  
  // Test max-allowed constraint
  val grp-capped = form-ecmp-group([best, alt1, alt2], local, 2)
  val t2 = match grp-capped
    Just(grp) -> grp.group-size == 2
    Nothing -> False
  
  t1 && t2

fun test-flow-hashing() : bool
  val src = ipv4-create(192, 168, 1, 100)
  val dst = ipv4-create(10, 0, 0, 1)
  val h1 = compute-flow-hash(src, dst, 6, 45123, 80)
  val h2 = compute-flow-hash(src, dst, 6, 45123, 80)
  val t1 = (h1 == h2)
  
  // Different port produces different hash
  val h3 = compute-flow-hash(src, dst, 6, 45124, 80)
  val t2 = (h1 != h3)
  
  // Hash is within positive 31-bit bounds
  val t3 = (h1 >= 0)
  
  t1 && t2 && t3

fun test-path-selection() : bool
  val local = asn(65000)
  val p1 = make-test-route(1, 65001, [65001], 100, 0, 0)
  val p2 = make-test-route(2, 65002, [65002], 100, 0, 0)
  match form-ecmp-group([p1, p2], local, 4)
    Just(grp) ->
      val sel0 = select-path(grp, 0)
      val sel1 = select-path(grp, 1)
      val sel2 = select-path(grp, 2)
      val t1 = match sel0
        Just(r) -> r.peer-ip.addr == p1.peer-ip.addr
        Nothing -> False
      val t2 = match sel1
        Just(r) -> r.peer-ip.addr == p2.peer-ip.addr
        Nothing -> False
      val t3 = match sel2
        Just(r) -> r.peer-ip.addr == p1.peer-ip.addr
        Nothing -> False
      t1 && t2 && t3
    Nothing -> False

pub fun main()
  val t1 = test-can-multipath()
  val t2 = test-form-ecmp-group()
  val t3 = test-flow-hashing()
  val t4 = test-path-selection()
  if t1 && t2 && t3 && t4 then
    println("PASS: rib/multipath unit tests passed successfully")
  else
    println("FAIL: rib/multipath unit tests failed")
