// Module: rib/decision
// RFC 4271 §9.1 BGP Best-Path Decision Algorithm with structured tie-break explanations.
//
// In BGP, when multiple routes to the same IP prefix are received from different
// peers or routes are locally originated, the Decision Process evaluates them
// sequentially through a strict hierarchy of tie-breaking rules.
//
// Tie-breaking sequence:
//   1. Highest Weight (local vendor extension)
//   2. Highest Local Preference (RFC 4271 §9.1.2.1)
//   3. Locally originated routes preferred over external
//   4. Shortest AS_PATH length (RFC 4271 §9.1.2.2.a)
//   5. Lowest Origin code (IGP < EGP < INCOMPLETE) (RFC 4271 §9.1.2.2.b)
//   6. Lowest Multi-Exit Discriminator (MED) (RFC 4271 §9.1.2.2.c)
//   7. eBGP preferred over iBGP (RFC 4271 §9.1.2.2.d)
//   8. Lowest IGP metric to next hop (RFC 4271 §9.1.2.2.e)
//   9. Oldest eBGP route (route flap stability tie-breaker)
//  10. Lowest BGP Router ID (RFC 4271 §9.1.2.2.f)
//  11. Shortest Cluster List length (RFC 4456 route reflection)
//  12. Lowest neighbor IP address (RFC 4271 §9.1.2.2.g)

module rib/decision

import std/core/list
import std/core/maybe
import std/core/string
import proto/types
import proto/attr
import rib/table

// Decision Reason explaining why a winning route beat a candidate route
pub type decision-reason
  ReasonWeight(win-val : int, lose-val : int)
  ReasonLocalPref(win-val : int, lose-val : int)
  ReasonLocalOrigin
  ReasonAsPathLength(win-len : int, lose-len : int)
  ReasonOriginCode(win-orig : origin-type, lose-orig : origin-type)
  ReasonMed(win-med : int, lose-med : int)
  ReasonEbgpOverIbgp
  ReasonIgpMetric(win-metric : int, lose-metric : int)
  ReasonOldestRoute(win-time : int, lose-time : int)
  ReasonRouterId(win-id : router-id, lose-id : router-id)
  ReasonClusterList(win-len : int, lose-len : int)
  ReasonPeerIp(win-ip : ipv4, lose-ip : ipv4)
  ReasonInitialCandidate

pub fun reason-tag(r : decision-reason) : int
  match r
    ReasonWeight -> 1
    ReasonLocalPref -> 2
    ReasonLocalOrigin -> 3
    ReasonAsPathLength -> 4
    ReasonOriginCode -> 5
    ReasonMed -> 6
    ReasonEbgpOverIbgp -> 7
    ReasonIgpMetric -> 8
    ReasonOldestRoute -> 9
    ReasonRouterId -> 10
    ReasonClusterList -> 11
    ReasonPeerIp -> 12
    ReasonInitialCandidate -> 13

pub fun (==)(a : decision-reason, b : decision-reason) : bool
  a.reason-tag == b.reason-tag

pub fun show(r : decision-reason) : string
  match r
    ReasonWeight(w, l) -> "Highest Weight (" ++ w.show ++ " vs " ++ l.show ++ ")"
    ReasonLocalPref(w, l) -> "Highest Local-Pref (" ++ w.show ++ " vs " ++ l.show ++ ")"
    ReasonLocalOrigin -> "Locally originated route preferred"
    ReasonAsPathLength(w, l) -> "Shortest AS_PATH length (" ++ w.show ++ " vs " ++ l.show ++ ")"
    ReasonOriginCode(w, l) -> "Lowest Origin code (" ++ w.show ++ " vs " ++ l.show ++ ")"
    ReasonMed(w, l) -> "Lowest MED (" ++ w.show ++ " vs " ++ l.show ++ ")"
    ReasonEbgpOverIbgp -> "eBGP path preferred over iBGP"
    ReasonIgpMetric(w, l) -> "Lowest IGP metric to next-hop (" ++ w.show ++ " vs " ++ l.show ++ ")"
    ReasonOldestRoute(w, l) -> "Oldest received eBGP route (" ++ w.show ++ "s vs " ++ l.show ++ "s)"
    ReasonRouterId(w, l) -> "Lowest BGP Router ID (" ++ w.show ++ " vs " ++ l.show ++ ")"
    ReasonClusterList(w, l) -> "Shortest Cluster List (" ++ w.show ++ " vs " ++ l.show ++ ")"
    ReasonPeerIp(w, l) -> "Lowest Neighbor IP (" ++ w.show ++ " vs " ++ l.show ++ ")"
    ReasonInitialCandidate -> "Sole candidate route"

// Decision Engine Configuration Options
pub struct decision-config(
  local-asn           : asn,
  always-compare-med  : bool,
  deterministic-med   : bool,
  prefer-oldest-ebgp  : bool
)

pub fun decision-config-default(my-asn : asn) : decision-config
  Decision-config(my-asn, False, True, True)

// Scalar comparison helpers to eliminate duplicate record teardowns in C generation

fun check-weight(w1 : int, w2 : int) : maybe<(order, decision-reason)>
  if w1 != w2 then
    if w1 > w2 then Just((Gt, ReasonWeight(w1, w2)))
    else Just((Lt, ReasonWeight(w2, w1)))
  else Nothing

fun check-local-pref(p1 : int, p2 : int) : maybe<(order, decision-reason)>
  if p1 != p2 then
    if p1 > p2 then Just((Gt, ReasonLocalPref(p1, p2)))
    else Just((Lt, ReasonLocalPref(p2, p1)))
  else Nothing

fun check-local-origin(loc1 : bool, loc2 : bool) : maybe<(order, decision-reason)>
  if loc1 != loc2 then
    if loc1 then Just((Gt, ReasonLocalOrigin))
    else Just((Lt, ReasonLocalOrigin))
  else Nothing

fun check-as-path(len1 : int, len2 : int) : maybe<(order, decision-reason)>
  if len1 != len2 then
    if len1 < len2 then Just((Gt, ReasonAsPathLength(len1, len2)))
    else Just((Lt, ReasonAsPathLength(len2, len1)))
  else Nothing

fun check-origin(o1 : origin-type, o2 : origin-type) : maybe<(order, decision-reason)>
  if o1 != o2 then
    if origin-type/cmp(o1, o2) == Lt then Just((Gt, ReasonOriginCode(o1, o2)))
    else Just((Lt, ReasonOriginCode(o2, o1)))
  else Nothing

fun check-med(m1 : int, m2 : int, should-compare : bool) : maybe<(order, decision-reason)>
  if should-compare && (m1 != m2) then
    if m1 < m2 then Just((Gt, ReasonMed(m1, m2)))
    else Just((Lt, ReasonMed(m2, m1)))
  else Nothing

fun check-peer-type(ebgp1 : bool, ebgp2 : bool) : maybe<(order, decision-reason)>
  if ebgp1 != ebgp2 then
    if ebgp1 then Just((Gt, ReasonEbgpOverIbgp))
    else Just((Lt, ReasonEbgpOverIbgp))
  else Nothing

fun check-oldest(t1 : int, t2 : int, both-ebgp : bool, prefer-oldest : bool) : maybe<(order, decision-reason)>
  if prefer-oldest && both-ebgp && (t1 != t2) then
    if t1 < t2 then Just((Gt, ReasonOldestRoute(t1, t2)))
    else Just((Lt, ReasonOldestRoute(t2, t1)))
  else Nothing

fun check-router-id(id1 : router-id, id2 : router-id) : maybe<(order, decision-reason)>
  if id1 != id2 then
    if id1 < id2 then Just((Gt, ReasonRouterId(id1, id2)))
    else Just((Lt, ReasonRouterId(id2, id1)))
  else Nothing

fun check-cluster-list(cl1 : int, cl2 : int) : maybe<(order, decision-reason)>
  if cl1 != cl2 then
    if cl1 < cl2 then Just((Gt, ReasonClusterList(cl1, cl2)))
    else Just((Lt, ReasonClusterList(cl2, cl1)))
  else Nothing

fun check-peer-ip(ip1 : ipv4, ip2 : ipv4) : (order, decision-reason)
  if ip1 < ip2 then (Gt, ReasonPeerIp(ip1, ip2))
  else (Lt, ReasonPeerIp(ip2, ip1))

// Compare two candidate routes according to RFC 4271 §9.1 tie-breaking rules.
pub fun compare-routes(r1 : bgp-route, r2 : bgp-route, cfg : decision-config) : (order, decision-reason)
  // Step 1: Weight
  match check-weight(r1.weight, r2.weight)
    Just(res) -> res
    Nothing ->
      // Step 2: Local Preference
      match check-local-pref(r1.local-pref, r2.local-pref)
        Just(res) -> res
        Nothing ->
          // Step 3: Local Origin
          match check-local-origin(r1.is-local, r2.is-local)
            Just(res) -> res
            Nothing ->
              // Step 4: AS_PATH length
              val len1 = as-path-length(r1.as-path)
              val len2 = as-path-length(r2.as-path)
              match check-as-path(len1, len2)
                Just(res) -> res
                Nothing ->
                  // Step 5: Origin Code
                  match check-origin(r1.origin, r2.origin)
                    Just(res) -> res
                    Nothing ->
                      // Step 6: MED
                      val same-asn = r1.peer-asn == r2.peer-asn
                      val cmp-med = cfg.always-compare-med || same-asn
                      match check-med(r1.med, r2.med, cmp-med)
                        Just(res) -> res
                        Nothing ->
                          // Step 7: eBGP over iBGP
                          val ebgp1 = r1.peer-asn != cfg.local-asn
                          val ebgp2 = r2.peer-asn != cfg.local-asn
                          match check-peer-type(ebgp1, ebgp2)
                            Just(res) -> res
                            Nothing ->
                              // Step 8: Oldest eBGP route
                              val both-ebgp = ebgp1 && ebgp2
                              match check-oldest(r1.received-time, r2.received-time, both-ebgp, cfg.prefer-oldest-ebgp)
                                Just(res) -> res
                                Nothing ->
                                  // Step 9: Lowest Router ID
                                  val id1 = r1.originator-id.default(r1.peer-id)
                                  val id2 = r2.originator-id.default(r2.peer-id)
                                  match check-router-id(id1, id2)
                                    Just(res) -> res
                                    Nothing ->
                                      // Step 10: Cluster list
                                      match check-cluster-list(r1.cluster-list.length, r2.cluster-list.length)
                                        Just(res) -> res
                                        Nothing ->
                                          // Step 11: Peer IP
                                          check-peer-ip(r1.peer-ip, r2.peer-ip)

// Select the single best path among candidate routes for a prefix
pub fun select-best-path(routes : list<bgp-route>, cfg : decision-config) : maybe<(bgp-route, decision-reason)>
  val eligible = routes.filter(fn(r) { r.is-valid && !r.is-damped })
  match eligible
    Nil -> Nothing
    Cons(first-route, rest) ->
      fun tournament(candidates : list<bgp-route>, current-best : bgp-route, last-reason : decision-reason) : (bgp-route, decision-reason)
        match candidates
          Nil -> (current-best, last-reason)
          Cons(cand, tail) ->
            val (ord, reason) = compare-routes(current-best, cand, cfg)
            if ord == Lt then tournament(tail, cand, reason)
            else tournament(tail, current-best, reason)
      val (winner, reason) = tournament(rest, first-route, ReasonInitialCandidate)
      val marked-winner = winner(is-best = True)
      Just((marked-winner, reason))
