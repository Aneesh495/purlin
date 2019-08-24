module unit/test-decision

import proto/types
import proto/attr
import rib/table
import rib/decision

fun make-base-route(peer-ip-oct : int, rid-oct : int) : bgp-route {
  route-from-attributes(
    prefix4(192, 168, 1, 0, 24),
    asn(65002),
    ipv4-create(10, 0, 0, peer-ip-oct),
    router-id(10, 0, 0, rid-oct),
    [
      AttrOrigin(OriginIgp),
      AttrAsPath(As-path([As-segment(as-segment-sequence, [asn(65002)])])),
      AttrNextHop(ipv4-create(10, 0, 0, peer-ip-oct)),
      AttrMed(0),
      AttrLocalPref(100)
    ],
    1000
  )
}

fun test-weight-tie-breaker() : bool {
  val cfg = decision-config-default(asn(65001))
  val r1 = make-base-route(1, 1)
  val r2 = make-base-route(2, 2)(weight = 100)
  
  match select-best-path([r1, r2], cfg)
    Just((winner, reason)) -> {
      val ip-match = winner.peer-ip == r2.peer-ip
      val reason-match = match reason
        ReasonWeight(w, l) -> (w == 100) && (l == 0)
        _ -> False
      ip-match && reason-match
    }
    Nothing -> False
}

fun test-local-pref-tie-breaker() : bool {
  val cfg = decision-config-default(asn(65001))
  val r1 = make-base-route(1, 1) // LP 100
  val r2 = make-base-route(2, 2)(local-pref = 250)
  
  match select-best-path([r1, r2], cfg)
    Just((winner, reason)) -> {
      val ip-match = winner.peer-ip == r2.peer-ip
      val reason-match = match reason
        ReasonLocalPref(w, l) -> (w == 250) && (l == 100)
        _ -> False
      ip-match && reason-match
    }
    Nothing -> False
}

fun test-as-path-len-tie-breaker() : bool {
  val cfg = decision-config-default(asn(65001))
  val r-short = make-base-route(1, 1) // AS_PATH len 1
  val r-long = make-base-route(2, 2)(
    as-path = As-path([As-segment(as-segment-sequence, [asn(65002), asn(65003), asn(65004)])])
  )
  
  match select-best-path([r-long, r-short], cfg)
    Just((winner, reason)) -> {
      val ip-match = winner.peer-ip == r-short.peer-ip
      val reason-match = match reason
        ReasonAsPathLength(w, l) -> (w == 1) && (l == 3)
        _ -> False
      ip-match && reason-match
    }
    Nothing -> False
}

fun test-med-tie-breaker() : bool {
  val cfg = decision-config-default(asn(65001))
  val r-med50 = make-base-route(1, 1)(med = 50)
  val r-med10 = make-base-route(2, 2)(med = 10)
  
  match select-best-path([r-med50, r-med10], cfg)
    Just((winner, reason)) -> {
      val ip-match = winner.peer-ip == r-med10.peer-ip
      val reason-match = match reason
        ReasonMed(w, l) -> (w == 10) && (l == 50)
        _ -> False
      ip-match && reason-match
    }
    Nothing -> False
}

fun test-router-id-tie-breaker() : bool {
  val cfg = decision-config-default(asn(65001))
  // Identical except Router ID 10.0.0.1 vs 10.0.0.5
  val r-low-id = make-base-route(1, 1)
  val r-high-id = make-base-route(2, 5)
  
  match select-best-path([r-high-id, r-low-id], cfg)
    Just((winner, reason)) -> {
      val id-match = winner.peer-id == router-id(10, 0, 0, 1)
      val reason-match = match reason
        ReasonRouterId(w, l) -> (w == router-id(10, 0, 0, 1)) && (l == router-id(10, 0, 0, 5))
        _ -> False
      id-match && reason-match
    }
    Nothing -> False
}

fun main() {
  val t1 = test-weight-tie-breaker()
  val t2 = test-local-pref-tie-breaker()
  val t3 = test-as-path-len-tie-breaker()
  val t4 = test-med-tie-breaker()
  val t5 = test-router-id-tie-breaker()
  
  if t1 && t2 && t3 && t4 && t5 then {
    println("PASS: rib/decision unit tests passed successfully")
  } else {
    println("FAIL: rib/decision unit tests failed")
  }
}
