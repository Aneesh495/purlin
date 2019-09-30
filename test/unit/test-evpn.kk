// Unit tests for BGP EVPN types, NLRI encoding/decoding, and multi-tenant VRF isolation
module unit/test-evpn

import std/core/list
import std/core/maybe
import proto/types
import proto/attr
import rib/table
import evpn/types
import evpn/routes
import evpn/vrf

fun test-evpn-types() : bool
  // MAC round-trip
  val mac = Mac-address(0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E)
  val mac-bytes = mac-to-bytes(mac)
  val mac-rec = mac-from-bytes(mac-bytes).default(Mac-address(0, 0, 0, 0, 0, 0))
  val t1 = mac == mac-rec
  
  // RD Type 0 round-trip (ASN 65001, Assigned 100)
  val rd0 = RdTypeZero(65001, 100)
  val rd0-bytes = encode-rd(rd0)
  val rd0-rec = decode-rd(rd0-bytes)
  val t2 = match rd0-rec
    Just(r) -> r == rd0
    Nothing -> False
  
  // RD Type 1 round-trip (IP 10.0.0.1, Assigned 10)
  val rd1 = RdTypeOne(ipv4-create(10, 0, 0, 1), 10)
  val rd1-bytes = encode-rd(rd1)
  val rd1-rec = decode-rd(rd1-bytes)
  val t3 = match rd1-rec
    Just(r) -> r == rd1
    Nothing -> False
  
  // ESI Single-homed check
  val esi0 = esi-all-zero()
  val t4 = is-single-homed(esi0)
  
  // ESI Multi-homed round-trip
  val esi-mh = Esi(1, [1, 2, 3, 4, 5, 6, 7, 8, 9])
  val esi-bytes = encode-esi(esi-mh)
  val esi-rec = decode-esi(esi-bytes).default(esi0)
  val t5 = esi-mh == esi-rec
  val t6 = !is-single-homed(esi-mh)
  
  // VNI round-trip (VNI 10050)
  val v = Vni(10050)
  val v-bytes = vni-to-bytes(v)
  val v-rec = vni-from-bytes(
    v-bytes.head.default(0),
    v-bytes.drop(1).head.default(0),
    v-bytes.drop(2).head.default(0)
  )
  val t7 = v == v-rec
  
  t1 && t2 && t3 && t4 && t5 && t6 && t7

fun test-evpn-route-encoding() : bool
  val rd = RdTypeZero(65001, 500)
  val esi-mh = Esi(0, [0, 0, 0, 0, 0, 0, 0, 0, 0])
  val tag = Eth-tag(0)
  val mac = Mac-address(0x52, 0x54, 0x00, 0x12, 0x34, 0x56)
  val ip = ipv4-create(10, 1, 1, 100)
  val v = Vni(20001)
  
  // 1. Type-2 MAC/IP Route round-trip
  val type2 = EvpnTypeTwo(rd, esi-mh, tag, mac, Just(ip), v)
  val type2-bytes = encode-evpn-nlri(type2)
  val type2-rec = decode-evpn-nlri(type2-bytes)
  val t1 = match type2-rec
    Just(EvpnTypeTwo(r-rd, _, _, r-mac, r-ip-opt, r-v)) ->
      (r-rd == rd) && (r-mac == mac) && (r-ip-opt == Just(ip)) && (r-v == v)
    _ -> False
  
  // 2. Type-3 IMET Route round-trip
  val type3 = EvpnTypeThree(rd, tag, ipv4-create(192, 168, 10, 1))
  val type3-bytes = encode-evpn-nlri(type3)
  val type3-rec = decode-evpn-nlri(type3-bytes)
  val t2 = match type3-rec
    Just(EvpnTypeThree(r-rd, r-tag, r-orig)) ->
      (r-rd == rd) && (r-tag == tag) && (r-orig == ipv4-create(192, 168, 10, 1))
    _ -> False
  
  // 3. Type-5 IP Prefix Route round-trip
  val pfx = Ip-prefix(V4(ipv4-create(10, 20, 0, 0)), 16)
  val gw = ipv4-create(192, 168, 10, 1)
  val type5 = EvpnTypeFive(rd, esi-mh, tag, pfx, gw, v)
  val type5-bytes = encode-evpn-nlri(type5)
  val type5-rec = decode-evpn-nlri(type5-bytes)
  val t3 = match type5-rec
    Just(EvpnTypeFive(r-rd, _, _, r-pfx, r-gw, r-v)) ->
      (r-rd == rd) && (r-pfx == pfx) && (r-gw == gw) && (r-v == v)
    _ -> False
  
  t1 && t2 && t3

fun test-vrf-and-tenant-isolation() : div bool
  val rt-red = RtAsnTwo(65001, 100)
  val rt-blue = RtAsnTwo(65001, 200)
  
  // VRF-Red (Tenant A)
  val vrf-red = vrf-create("VRF-RED", RdTypeZero(65001, 100), Vni(100100), [rt-red], [rt-red])
  
  // VRF-Blue (Tenant B)
  val vrf-blue = vrf-create("VRF-BLUE", RdTypeZero(65001, 200), Vni(100200), [rt-blue], [rt-blue])
  
  // Cross-tenant route leaking prevention
  val leak-prevented = !can-leak-route(vrf-red, vrf-blue)
  
  // Type-2 MAC ingestion into VRF-Red
  val mac-host = Mac-address(0xAA, 0xBB, 0xCC, 0x11, 0x22, 0x33)
  val expected-ip = ipv4-create(10, 100, 1, 5)
  val t2-nlri = EvpnTypeTwo(vrf-red.rd, esi-all-zero(), Eth-tag(0), mac-host, Just(expected-ip), vrf-red.vni-val)
  
  // Ingest with matching RT -> accepted
  val vrf-red-updated = vrf-ingest-type2(vrf-red, t2-nlri, [rt-red], ipv4-create(192, 168, 1, 1))
  val mac-entry-opt = vrf-lookup-mac(vrf-red-updated, mac-host)
  val t1 = match mac-entry-opt
    Just(e) ->
      val mac-matches = e.mac-addr == mac-host
      val ip-matches = match e.host-ip
        Just(hip) -> hip.addr == expected-ip.addr
        Nothing -> False
      mac-matches && ip-matches
    Nothing -> False
  
  // Ingest with non-matching RT into VRF-Blue -> rejected
  val vrf-blue-updated = vrf-ingest-type2(vrf-blue, t2-nlri, [rt-red], ipv4-create(192, 168, 1, 1))
  val t2 = vrf-lookup-mac(vrf-blue-updated, mac-host).is-nothing
  
  // Type-5 IP Prefix ingestion into VRF-Red
  val pfx = Ip-prefix(V4(ipv4-create(10, 100, 2, 0)), 24)
  val t5-nlri = EvpnTypeFive(vrf-red.rd, esi-all-zero(), Eth-tag(0), pfx, ipv4-create(192, 168, 1, 1), vrf-red.vni-val)
  val vrf-red-pfx = vrf-ingest-type5(vrf-red-updated, t5-nlri, [rt-red], asn(65002), ipv4-create(192, 168, 1, 1))
  val rib-match = !rib-lookup(vrf-red-pfx.rib, pfx).is-empty
  val t3 = rib-match
  
  leak-prevented && t1 && t2 && t3

pub fun main() : <div,console> ()
  val t1 = test-evpn-types()
  val t2 = test-evpn-route-encoding()
  val t3 = test-vrf-and-tenant-isolation()
  
  if t1 && t2 && t3 then
    println("PASS: evpn subsystem unit tests passed successfully")
  else
    println("FAIL: evpn subsystem unit tests failed")
