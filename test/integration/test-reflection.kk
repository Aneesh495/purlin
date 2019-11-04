// Integration test: RFC 4456 BGP Route Reflection & Loop Prevention
module integration/test-reflection

import std/core/list
import std/core/maybe
import proto/types
import proto/attr
import proto/message
import proto/capabilities
import rib/table
import engine/peer
import engine/reflector

fun make-dummy-route(
  pfx       : ip-prefix,
  sender-ip : ipv4,
  orig-id   : maybe<router-id> = Nothing,
  clusters  : list<router-id> = []
) : bgp-route
  Bgp-route(
    route-prefix = pfx,
    peer-asn = asn(65000),
    peer-ip = sender-ip,
    peer-id = Router-id(sender-ip),
    origin = OriginIgp,
    as-path = As-path([]),
    next-hop = sender-ip,
    med = 0,
    local-pref = 100,
    weight = 0,
    communities = [],
    ext-communities = [],
    cluster-list = clusters,
    originator-id = orig-id,
    is-local = False,
    is-valid = True,
    is-best = True,
    is-damped = False,
    rpki = RpkiValid,
    received-time = 1000
  )

fun test-route-reflection() : exn bool
  val local-as = asn(65000)
  val rr-rid = router-id(192, 168, 0, 1)
  val cluster-id = rr-rid
  val rr-cfg = Rr-config(cluster-id, rr-rid, local-as, True)
  
  val client-a-ip = ipv4-create(192, 168, 0, 10)
  val client-b-ip = ipv4-create(192, 168, 0, 20)
  val non-client-ip = ipv4-create(192, 168, 0, 30)
  
  val peer-client-a = peer-create(default-peer-config(client-a-ip, local-as, ipv4-create(192, 168, 0, 1), local-as), rr-rid)
  val peer-client-b = peer-create(default-peer-config(client-b-ip, local-as, ipv4-create(192, 168, 0, 1), local-as), rr-rid)
  val peer-non-client = peer-create(default-peer-config(non-client-ip, local-as, ipv4-create(192, 168, 0, 1), local-as), rr-rid)
  
  val all-peers = [
    (peer-client-a, RoleClient),
    (peer-client-b, RoleClient),
    (peer-non-client, RoleNonClient)
  ]
  
  // Test Case 1: Route advertised by Client A
  val pfx-a = prefix4(10, 1, 0, 0, 16)
  val route-from-client-a = make-dummy-route(pfx-a, client-a-ip)
  
  val reflection-plan-a = rr-plan-reflection(
    route-from-client-a,
    peer-client-a,
    RoleClient,
    all-peers,
    rr-cfg
  )
  
  // Client A's route must be reflected to both Client B and Non-Client
  val t1 = reflection-plan-a.length == 2
  val targets-a = reflection-plan-a.map(fn((p, _)) p.config.peer-ip)
  val t2 = targets-a.any(fn(ip) ip == client-b-ip) && targets-a.any(fn(ip) ip == non-client-ip)
  
  // Reflected route must have ORIGINATOR_ID set to Client A
  val reflected-route-sample = reflection-plan-a.head.unjust.snd
  val t3 = match reflected-route-sample.originator-id
    Just(orig) -> orig == Router-id(client-a-ip)
    Nothing -> False
    
  // Reflected route must have local cluster ID prepended to CLUSTER_LIST
  val t4 = match reflected-route-sample.cluster-list
    Cons(cid, _) -> cid == cluster-id
    Nil -> False
    
  // Test Case 2: Route advertised by Non-Client
  val pfx-nc = prefix4(10, 3, 0, 0, 16)
  val route-from-nc = make-dummy-route(pfx-nc, non-client-ip)
  
  val reflection-plan-nc = rr-plan-reflection(
    route-from-nc,
    peer-non-client,
    RoleNonClient,
    all-peers,
    rr-cfg
  )
  
  // Non-Client route must be reflected ONLY to Clients (Client A and Client B), NOT to Non-Clients
  val t5 = reflection-plan-nc.length == 2
  val targets-nc = reflection-plan-nc.map(fn((p, _)) p.config.peer-ip)
  val t6 = targets-nc.any(fn(ip) ip == client-a-ip) && targets-nc.any(fn(ip) ip == client-b-ip)
  val t7 = !targets-nc.any(fn(ip) ip == non-client-ip)
  
  // Test Case 3: Loop Prevention via ORIGINATOR_ID
  val looped-orig-route = make-dummy-route(prefix4(10, 99, 0, 0, 16), client-a-ip, Just(rr-rid))
  val t8 = rr-detect-loop(looped-orig-route, cluster-id, rr-rid)
  val dropped-by-orig = rr-plan-reflection(looped-orig-route, peer-client-a, RoleClient, all-peers, rr-cfg)
  val t9 = dropped-by-orig.is-empty
  
  // Test Case 4: Loop Prevention via CLUSTER_LIST
  val looped-cluster-route = make-dummy-route(
    prefix4(10, 99, 0, 0, 16),
    client-a-ip,
    Just(router-id(10, 0, 0, 1)),
    [router-id(192, 168, 9, 9), cluster-id]
  )
  val t10 = rr-detect-loop(looped-cluster-route, cluster-id, rr-rid)
  val dropped-by-cluster = rr-plan-reflection(looped-cluster-route, peer-client-a, RoleClient, all-peers, rr-cfg)
  val t11 = dropped-by-cluster.is-empty
  
  t1 && t2 && t3 && t4 && t5 && t6 && t7 && t8 && t9 && t10 && t11

pub fun main() : <exn,console> ()
  val ok = test-route-reflection()
  if ok then
    println("PASS: RFC 4456 BGP route reflection and loop prevention test passed")
  else
    println("FAIL: RFC 4456 BGP route reflection test failed")
