module unit/test-table

import proto/types
import proto/attr
import rib/patricia
import rib/table

fun test-route-from-attributes() : bool {
  val p = prefix4(192, 168, 1, 0, 24)
  val p-asn = asn(65001)
  val p-ip = ipv4-create(10, 0, 0, 1)
  val p-id = router-id(10, 0, 0, 1)
  
  val attrs = [
    AttrOrigin(OriginIgp),
    AttrAsPath(As-path([As-segment(as-segment-sequence, [asn(65001)])])),
    AttrNextHop(ipv4-create(10, 0, 0, 1)),
    AttrMed(25),
    AttrLocalPref(200),
    AttrCommunity([community-create(65001, 100)])
  ]
  
  val r = route-from-attributes(p, p-asn, p-ip, p-id, attrs, 1000)
  val orig-ok = (r.origin == OriginIgp)
  val nh-ok = (r.next-hop == ipv4-create(10, 0, 0, 1))
  val med-ok = (r.med == 25)
  val lp-ok = (r.local-pref == 200)
  val comm-ok = (r.communities == [community-create(65001, 100)])
  
  orig-ok && nh-ok && med-ok && lp-ok && comm-ok
}

fun test-multi-peer-routes() : div bool {
  var rib := rib-empty()
  val p = prefix4(192, 168, 1, 0, 24)
  
  val r1 = route-from-attributes(p, asn(65001), ipv4-create(10, 0, 0, 1), router-id(10, 0, 0, 1),
                                 [AttrOrigin(OriginIgp), AttrMed(10)], 100)
  val r2 = route-from-attributes(p, asn(65002), ipv4-create(10, 0, 0, 2), router-id(10, 0, 0, 2),
                                 [AttrOrigin(OriginIgp), AttrMed(20)], 105)
                                 
  rib := rib-insert(rib, r1)
  rib := rib-insert(rib, r2)
  
  val paths = rib-lookup(rib, p)
  val paths-len-ok = (paths.length == 2)
  val p-count-ok = (rib-prefix-count(rib) == 1)
  val r-count-ok = (rib-route-count(rib) == 2)
  
  paths-len-ok && p-count-ok && r-count-ok
}

fun test-route-replacement-same-peer() : div bool {
  var rib := rib-empty()
  val p = prefix4(192, 168, 1, 0, 24)
  val peer-ip = ipv4-create(10, 0, 0, 1)
  
  val r-initial = route-from-attributes(p, asn(65001), peer-ip, router-id(10, 0, 0, 1),
                                        [AttrMed(10)], 100)
  val r-updated = route-from-attributes(p, asn(65001), peer-ip, router-id(10, 0, 0, 1),
                                        [AttrMed(50)], 200)
                                        
  rib := rib-insert(rib, r-initial)
  rib := rib-insert(rib, r-updated)
  
  val paths = rib-lookup(rib, p)
  val single-path = (paths.length == 1)
  val updated-med = match paths.head
    Just(r) -> r.med == 50
    Nothing -> False
    
  single-path && updated-med
}

fun test-route-withdrawal() : div bool {
  var rib := rib-empty()
  val p = prefix4(192, 168, 1, 0, 24)
  val p1-ip = ipv4-create(10, 0, 0, 1)
  val p2-ip = ipv4-create(10, 0, 0, 2)
  
  val r1 = route-from-attributes(p, asn(65001), p1-ip, router-id(10, 0, 0, 1), [], 100)
  val r2 = route-from-attributes(p, asn(65002), p2-ip, router-id(10, 0, 0, 2), [], 105)
  
  rib := rib-insert(rib, r1)
  rib := rib-insert(rib, r2)
  
  // Withdraw r1
  rib := rib-withdraw(rib, p, p1-ip)
  val after-w1 = rib-lookup(rib, p)
  val w1-ok = (after-w1.length == 1) && (rib-prefix-count(rib) == 1)
  
  // Withdraw r2: prefix should be pruned entirely
  rib := rib-withdraw(rib, p, p2-ip)
  val after-w2 = rib-lookup(rib, p)
  val w2-ok = (after-w2.length == 0) && (rib-prefix-count(rib) == 0)
  
  w1-ok && w2-ok
}

fun main() {
  val t1 = test-route-from-attributes()
  val t2 = test-multi-peer-routes()
  val t3 = test-route-replacement-same-peer()
  val t4 = test-route-withdrawal()
  
  if t1 && t2 && t3 && t4 then {
    println("PASS: rib/table unit tests passed successfully")
  } else {
    println("FAIL: rib/table unit tests failed")
  }
}
