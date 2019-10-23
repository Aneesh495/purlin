// Integration test: Two-router live BGP peering, FSM handshake, and route exchange
module integration/test-peering

import std/core/list
import std/core/maybe
import proto/types
import proto/wire
import proto/message
import proto/attr
import proto/fsm
import rib/table
import fib/table
import fib/synth
import engine/peer
import engine/daemon

fun test-two-peer-handshake-and-routing() : <div,exn,console> bool
  val as-a = asn(65001)
  val as-b = asn(65002)
  val ip-a = ipv4-create(192, 168, 1, 1)
  val ip-b = ipv4-create(192, 168, 1, 2)
  val rid-a = router-id(192, 168, 1, 1)
  val rid-b = router-id(192, 168, 1, 2)
  
  // Egress interfaces on connected subnet 192.168.1.0/24
  val if-a = Egress-interface(1, "eth0")
  val if-b = Egress-interface(1, "eth0")
  val igp-a = igp-table-empty().add-connected(prefix4(192, 168, 1, 0, 24), if-a)
  val igp-b = igp-table-empty().add-connected(prefix4(192, 168, 1, 0, 24), if-b)
  
  var router-a := daemon-create(as-a, rid-a, igp-a)
  var router-b := daemon-create(as-b, rid-b, igp-b)
  
  // Register peer sessions
  val cfg-a-to-b = default-peer-config(ip-b, as-b, ip-a, as-a)
  val cfg-b-to-a = default-peer-config(ip-a, as-a, ip-b, as-b)
  router-a := daemon-add-peer(router-a, cfg-a-to-b)
  router-b := daemon-add-peer(router-b, cfg-b-to-a)
  
  // Step 1: Simulate TCP connection establishment
  val peer-a-init = daemon-find-peer(router-a, ip-b).unjust
  val peer-b-init = daemon-find-peer(router-b, ip-a).unjust
  
  // Transition Router A FSM: Idle -> Connect -> OpenSent
  val (peer-a-conn, _) = peer-step-fsm(peer-a-init, EvManualStart)
  val (peer-a-opensent, _) = peer-step-fsm(peer-a-conn, EvTcpConnectionConfirmed)
  
  // Transition Router B FSM: Idle -> Connect -> OpenSent
  val (peer-b-conn, _) = peer-step-fsm(peer-b-init, EvManualStart)
  val (peer-b-opensent, _) = peer-step-fsm(peer-b-conn, EvTcpConnectionConfirmed)
  
  // Step 2: Exchange OPEN messages: OpenSent -> OpenConfirm
  val open-from-b = MsgOpen(4, as-b, 90, rid-b, [])
  val open-from-a = MsgOpen(4, as-a, 90, rid-a, [])
  val (peer-a-openconf, _) = peer-step-fsm(peer-a-opensent, EvRecvOpen(open-from-b))
  val (peer-b-openconf, _) = peer-step-fsm(peer-b-opensent, EvRecvOpen(open-from-a))
  
  // Step 3: Exchange KEEPALIVE messages -> Both reach Established!
  val (peer-a-est, _) = peer-step-fsm(peer-a-openconf, EvRecvKeepalive)
  val (peer-b-est, _) = peer-step-fsm(peer-b-openconf, EvRecvKeepalive)
  
  val t1 = peer-a-est.fsm-state == StateEstablished
  val t2 = peer-b-est.fsm-state == StateEstablished
  
  // Step 4: Router A advertises route 10.100.0.0/16 to Router B
  val test-pfx = prefix4(10, 100, 0, 0, 16)
  val update-attrs = [
    AttrOrigin(OriginIgp),
    AttrAsPath(As-path([As-segment(as-segment-sequence, [as-a])])),
    AttrNextHop(ip-a),
    AttrMed(0),
    AttrLocalPref(100)
  ]
  val update-msg = MsgUpdate([], update-attrs, [test-pfx])
  
  // Deliver update to Router B
  router-b := daemon-handle-update(router-b, ip-a, update-msg)
  
  // Verify Router B RIB contains the route
  val rib-matches = rib-lookup(router-b.rib, test-pfx)
  val t3 = rib-matches.length == 1
  val t4 = match rib-matches
    Cons(r, _) -> (r.next-hop == ip-a) && (r.peer-asn == as-a)
    Nil -> False
  
  // Verify Router B synthesized the route into its FIB!
  val fib-match = router-b.fib.fib-lookup-exact(test-pfx)
  val t5 = fib-match.is-just
  val t6 = match fib-match
    Just(entry) ->
      match entry.nexthops
        Cons(nh, _) -> (nh.gateway-ip == ip-a) && (nh.egress-if == if-b)
        Nil -> False
    Nothing -> False
  
  // Verify Router B line-rate packet LPM lookup on destination IP 10.100.42.1
  val lpm-res = router-b.fib.fib-lpm(ipv4-create(10, 100, 42, 1))
  val t7 = match lpm-res
    Just((pfx, _)) -> pfx == test-pfx
    Nothing -> False
  
  // Step 5: Router A withdraws route 10.100.0.0/16
  val withdraw-msg = MsgUpdate([test-pfx], [], [])
  router-b := daemon-handle-update(router-b, ip-a, withdraw-msg)
  
  // Verify route is withdrawn from RIB and pruned from FIB
  val rib-after = rib-lookup(router-b.rib, test-pfx)
  val t8 = rib-after.is-empty
  val fib-after = router-b.fib.fib-lookup-exact(test-pfx)
  val t9 = fib-after.is-nothing
  val lpm-after = router-b.fib.fib-lpm(ipv4-create(10, 100, 42, 1))
  val t10 = lpm-after.is-nothing
  
  t1 && t2 && t3 && t4 && t5 && t6 && t7 && t8 && t9 && t10

pub fun main() : <div,exn,console> ()
  val ok = test-two-peer-handshake-and-routing()
  if ok then
    println("PASS: two-router peering integration test passed successfully")
  else
    println("FAIL: two-router peering integration test failed")
