module rib/table

import std/core/list
import std/core/maybe
import std/core/string
import proto/types
import proto/attr
import rib/patricia

// RPKI Origin Validation Status (RFC 6811)
pub type rpki-status
  RpkiValid
  RpkiNotFound
  RpkiInvalid

pub fun rpki-status/show(s : rpki-status) : string {
  match s
    RpkiValid -> "Valid"
    RpkiNotFound -> "NotFound"
    RpkiInvalid -> "Invalid"
}

pub fun rpki-status/(==)(a : rpki-status, b : rpki-status) : bool {
  match (a, b)
    (RpkiValid, RpkiValid) -> True
    (RpkiNotFound, RpkiNotFound) -> True
    (RpkiInvalid, RpkiInvalid) -> True
    _ -> False
}

// BGP Route entry stored in Routing Information Bases
pub struct bgp-route
  route-prefix    : ip-prefix
  peer-asn        : asn
  peer-ip         : ipv4
  peer-id         : router-id
  origin          : origin-type
  as-path         : as-path
  next-hop        : ipv4
  med             : int
  local-pref      : int
  weight          : int
  communities     : list<community>
  ext-communities : list<ext-community>
  cluster-list    : list<router-id>
  originator-id   : maybe<router-id>
  is-local        : bool
  is-valid        : bool
  is-best         : bool
  is-damped       : bool
  rpki            : rpki-status
  received-time   : int // Monotonic seconds

pub fun bgp-route/show(r : bgp-route) : string {
  val best-tag = if r.is-best then "*>" else "*"
  val damped-tag = if r.is-damped then "d" else " "
  val valid-tag = if r.is-valid then "v" else "i"
  val status = best-tag ++ damped-tag ++ valid-tag
  status ++ " " ++ r.route-prefix.show ++ " next-hop " ++ r.next-hop.show ++
  " aspath " ++ r.as-path.show ++ " med " ++ r.med.show ++ " lp " ++ r.local-pref.show
}

pub fun bgp-route/(==)(a : bgp-route, b : bgp-route) : bool {
  a.route-prefix == b.route-prefix && a.peer-asn == b.peer-asn && a.peer-ip == b.peer-ip &&
  a.peer-id == b.peer-id && a.origin == b.origin && a.as-path == b.as-path &&
  a.next-hop == b.next-hop && a.med == b.med && a.local-pref == b.local-pref &&
  a.weight == b.weight && a.communities == b.communities &&
  a.ext-communities == b.ext-communities && a.is-local == b.is-local &&
  a.is-valid == b.is-valid && a.is-best == b.is-best && a.is-damped == b.is-damped &&
  a.rpki == b.rpki
}

// Construct a bgp-route by parsing a list of path attributes
pub fun route-from-attributes(
  p             : ip-prefix,
  p-asn         : asn,
  p-ip          : ipv4,
  p-id          : router-id,
  attrs         : list<path-attribute>,
  rx-time       : int
) : bgp-route {
  var orig := OriginIncomplete
  var path := As-path([])
  var nh := ipv4-create(0, 0, 0, 0)
  var med-val := 0
  var lp-val := 100
  var comms := []
  var e-comms := []
  var cls := []
  var orig-id := Nothing

  attrs.foreach(fn(attr) {
    match attr
      AttrOrigin(o) -> { orig := o }
      AttrAsPath(ap) -> { path := ap }
      AttrNextHop(nip) -> { nh := nip }
      AttrMed(m) -> { med-val := m }
      AttrLocalPref(lp) -> { lp-val := lp }
      AttrCommunity(cs) -> { comms := cs }
      AttrExtCommunity(ecs) -> { e-comms := ecs }
      AttrClusterList(cl) -> { cls := cl }
      AttrOriginatorId(rid) -> { orig-id := Just(rid) }
      _ -> ()
  })

  Bgp-route(
    route-prefix = p,
    peer-asn = p-asn,
    peer-ip = p-ip,
    peer-id = p-id,
    origin = orig,
    as-path = path,
    next-hop = nh,
    med = med-val,
    local-pref = lp-val,
    weight = 0,
    communities = comms,
    ext-communities = e-comms,
    cluster-list = cls,
    originator-id = orig-id,
    is-local = False,
    is-valid = True,
    is-best = False,
    is-damped = False,
    rpki = RpkiNotFound,
    received-time = rx-time
  )
}

// Routing Information Base (RIB) backed by Patricia Trie
pub struct rib-table
  routes : patricia-trie<list<bgp-route>>

pub fun rib-empty() : rib-table {
  Rib-table(patricia-empty())
}

// Insert or update a route in the RIB table
pub fun rib-insert(rib : rib-table, route : bgp-route) : div rib-table {
  val existing-routes = patricia-lookup-exact(rib.routes, route.route-prefix).default([])
  // Replace route from same peer, or append
  val filtered = existing-routes.filter(fn(r) { r.peer-ip != route.peer-ip })
  val updated-list = Cons(route, filtered)
  Rib-table(patricia-insert(rib.routes, route.route-prefix, updated-list))
}

// Withdraw a route for a given prefix received from a peer
pub fun rib-withdraw(rib : rib-table, p : ip-prefix, p-ip : ipv4) : div rib-table {
  val existing-routes = patricia-lookup-exact(rib.routes, p).default([])
  val filtered = existing-routes.filter(fn(r) { r.peer-ip != p-ip })
  if filtered.is-empty then {
    Rib-table(patricia-delete(rib.routes, p))
  } else {
    Rib-table(patricia-insert(rib.routes, p, filtered))
  }
}

// Lookup all candidate routes for an IP prefix
pub fun rib-lookup(rib : rib-table, p : ip-prefix) : div list<bgp-route> {
  patricia-lookup-exact(rib.routes, p).default([])
}

// Longest Prefix Match in RIB
pub fun rib-lpm(rib : rib-table, dst-ip : ipv4) : div maybe<(ip-prefix, list<bgp-route>)> {
  patricia-lpm(rib.routes, dst-ip)
}

// Flatten all stored routes in the RIB table
pub fun rib-all-routes(rib : rib-table) : div list<bgp-route> {
  val entries = patricia-to-list(rib.routes)
  entries.flatmap(fn(pair) { pair.snd })
}

// Total number of unique IP prefixes in the RIB
pub fun rib-prefix-count(rib : rib-table) : div int {
  patricia-count(rib.routes)
}

// Total number of route paths across all prefixes
pub fun rib-route-count(rib : rib-table) : div int {
  rib-all-routes(rib).length
}
