// Unit tests for FIB data structures, recursive next-hop resolution, and Netlink export
module unit/test-fib

import std/core/list
import std/core/maybe
import proto/types
import proto/attr
import rib/table
import fib/table
import fib/synth
import fib/export

fun test-direct-nexthop() : div bool
  val if0 = Egress-interface(1, "eth0")
  val igp = igp-table-empty().add-connected(prefix4(192, 168, 1, 0, 24), if0)
  
  val nh-ip = ipv4-create(192, 168, 1, 100)
  val res-opt = resolve-nexthop(igp, nh-ip)
  match res-opt
    Just(nh) ->
      (nh.gateway-ip == nh-ip) && (nh.egress-if == if0) && (nh.is-direct == True)
    Nothing -> False

fun test-recursive-nexthop() : div bool
  val if1 = Egress-interface(2, "eth1")
  // Connected link to spine switch: 10.0.0.0/30 on eth1
  var igp := igp-table-empty().add-connected(prefix4(10, 0, 0, 0, 30), if1)
  
  // Spine loopback reached via 10.0.0.2: 10.255.0.1/32 via 10.0.0.2 eth1
  val spine-loopback = prefix4(10, 255, 0, 1, 32)
  val spine-phys-ip = ipv4-create(10, 0, 0, 2)
  igp := igp.add-igp-route(spine-loopback, spine-phys-ip, if1, 10)
  
  // BGP route specifies next-hop 10.255.0.1 (spine loopback)
  val bgp-nh = ipv4-create(10, 255, 0, 1)
  val res-opt = resolve-nexthop(igp, bgp-nh)
  match res-opt
    Just(nh) ->
      // Should recursively resolve to direct gateway 10.0.0.2 on eth1
      (nh.gateway-ip == spine-phys-ip) && (nh.egress-if == if1) && (nh.is-direct == False)
    Nothing -> False

fun test-unresolvable-nexthop() : div bool
  val if0 = Egress-interface(1, "eth0")
  val igp = igp-table-empty().add-connected(prefix4(192, 168, 1, 0, 24), if0)
  
  // Next-hop 8.8.8.8 has no matching connected or IGP route
  val unreachable-ip = ipv4-create(8, 8, 8, 8)
  val res-opt = resolve-nexthop(igp, unreachable-ip)
  res-opt.is-nothing

fun test-fib-lpm-and-synthesis() : div bool
  val if0 = Egress-interface(1, "eth0")
  val igp = igp-table-empty().add-connected(prefix4(10, 0, 0, 0, 8), if0)
  
  // Populate FIB with nested subnets
  val e-def          = Fib-entry(prefix4(0, 0, 0, 0, 0), [Resolved-nexthop(ipv4-create(10, 0, 0, 1), if0, True, Nothing)], 1000, "STATIC")
  val e-sixteen      = Fib-entry(prefix4(172, 16, 0, 0, 16), [Resolved-nexthop(ipv4-create(10, 0, 0, 1), if0, True, Nothing)], 1000, "BGP")
  val e-twenty-four  = Fib-entry(prefix4(172, 16, 1, 0, 24), [Resolved-nexthop(ipv4-create(10, 0, 0, 1), if0, True, Nothing)], 1000, "BGP")
  val e-thirty-two   = Fib-entry(prefix4(172, 16, 1, 100, 32), [Resolved-nexthop(ipv4-create(10, 0, 0, 1), if0, True, Nothing)], 1000, "CONNECTED")
  
  var fib := fib-empty()
  fib := fib.fib-insert(e-def)
  fib := fib.fib-insert(e-sixteen)
  fib := fib.fib-insert(e-twenty-four)
  fib := fib.fib-insert(e-thirty-two)
  
  // LPM Test 1: Exact host route /32
  val lpm1 = fib.fib-lpm(ipv4-create(172, 16, 1, 100))
  val t1 = match lpm1
    Just((pfx, _)) -> pfx.length == 32
    Nothing -> False
  
  // LPM Test 2: Subnet /24
  val lpm2 = fib.fib-lpm(ipv4-create(172, 16, 1, 50))
  val t2 = match lpm2
    Just((pfx, _)) -> pfx.length == 24
    Nothing -> False
  
  // LPM Test 3: Wider subnet /16
  val lpm3 = fib.fib-lpm(ipv4-create(172, 16, 2, 1))
  val t3 = match lpm3
    Just((pfx, _)) -> pfx.length == 16
    Nothing -> False
  
  // LPM Test 4: Default route 0.0.0.0/0
  val lpm4 = fib.fib-lpm(ipv4-create(8, 8, 8, 8))
  val t4 = match lpm4
    Just((pfx, _)) -> pfx.length == 0
    Nothing -> False
  
  t1 && t2 && t3 && t4

fun test-netlink-export() : bool
  val if0 = Egress-interface(5, "eth0")
  val nh = Resolved-nexthop(ipv4-create(192, 168, 1, 1), if0, True, Nothing)
  val entry = Fib-entry(prefix4(10, 50, 0, 0, 16), [nh], 1000, "BGP")
  
  val nl-opt = export-netlink-msg(entry, True)
  match nl-opt
    Just(msg) ->
      (msg.msg-type == nl-rtm-newroute) &&
      (msg.dst-len == 16) &&
      (msg.if-index == 5) &&
      (msg.gateway-ip == ipv4-create(192, 168, 1, 1))
    Nothing -> False

pub fun main() : <div,console> ()
  val t1 = test-direct-nexthop()
  val t2 = test-recursive-nexthop()
  val t3 = test-unresolvable-nexthop()
  val t4 = test-fib-lpm-and-synthesis()
  val t5 = test-netlink-export()
  
  if t1 && t2 && t3 && t4 && t5 then
    println("PASS: fib subsystem unit tests passed successfully")
  else
    println("FAIL: fib subsystem unit tests failed")
