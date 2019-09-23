// Module: evpn/types
// Core data types for BGP EVPN (RFC 7432) and VXLAN data center fabrics (RFC 8365).
//
// Modern hyperscale data centers implement multi-tenant network virtualization
// using BGP EVPN as the control plane and VXLAN encapsulation for overlay data.
//
// This module provides:
//   1. IEEE 802.1Q MAC Address representation and formatting
//   2. RFC 4364 Route Distinguishers (Type 0, Type 1, Type 2)
//   3. RFC 4360 / RFC 7432 Route Target Extended Communities
//   4. RFC 7432 Ethernet Segment Identifiers (ESI) for multi-homing
//   5. 24-bit VXLAN Network Identifiers (VNI) and 32-bit Ethernet Tag IDs

module evpn/types

import std/core/list
import std/core/maybe
import std/core/string
import proto/types
import proto/wire

// IEEE 802.1Q 48-bit MAC Address
pub struct mac-address(
  b0 : int,
  b1 : int,
  b2 : int,
  b3 : int,
  b4 : int,
  b5 : int
)

fun hex-digit(d : int) : string
  if d < 10 then d.show
  elif d == 10 then "a"
  elif d == 11 then "b"
  elif d == 12 then "c"
  elif d == 13 then "d"
  elif d == 14 then "e"
  elif d == 15 then "f"
  else "0"

fun hex2(n : int) : string
  val b = if n < 0 then 0 else n % 256
  hex-digit(b / 16) ++ hex-digit(b % 16)

pub fun mac-address/show(mac : mac-address) : string
  hex2(mac.b0) ++ ":" ++ hex2(mac.b1) ++ ":" ++ hex2(mac.b2) ++ ":" ++
  hex2(mac.b3) ++ ":" ++ hex2(mac.b4) ++ ":" ++ hex2(mac.b5)

pub fun mac-address/(==)(a : mac-address, b : mac-address) : bool
  (a.b0 == b.b0) && (a.b1 == b.b1) && (a.b2 == b.b2) &&
  (a.b3 == b.b3) && (a.b4 == b.b4) && (a.b5 == b.b5)

pub fun mac-from-bytes(bytes : list<int>) : maybe<mac-address>
  if bytes.length < 6 then Nothing
  else
    val b0 = bytes.head.default(0)
    val b1 = bytes.drop(1).head.default(0)
    val b2 = bytes.drop(2).head.default(0)
    val b3 = bytes.drop(3).head.default(0)
    val b4 = bytes.drop(4).head.default(0)
    val b5 = bytes.drop(5).head.default(0)
    Just(Mac-address(b0, b1, b2, b3, b4, b5))

pub fun mac-to-bytes(mac : mac-address) : list<int>
  [mac.b0, mac.b1, mac.b2, mac.b3, mac.b4, mac.b5]

// RFC 4364 §4.2 Route Distinguisher (RD) (8 octets)
pub type route-distinguisher
  RdTypeZero(asn-val : int, assigned-num : int)    // 2-byte ASN, 4-byte number
  RdTypeOne(router-ip : ipv4, assigned-num : int) // 4-byte IPv4, 2-byte number
  RdTypeTwo(asn-val : int, assigned-num : int)    // 4-byte ASN, 2-byte number

pub fun route-distinguisher/show(rd : route-distinguisher) : string
  match rd
    RdTypeZero(a, n) -> a.show ++ ":" ++ n.show
    RdTypeOne(ip, n) -> ip.show ++ ":" ++ n.show
    RdTypeTwo(a, n) -> a.show ++ ":" ++ n.show

pub fun route-distinguisher/(==)(a : route-distinguisher, b : route-distinguisher) : bool
  match (a, b)
    (RdTypeZero(a1, n1), RdTypeZero(a2, n2)) -> (a1 == a2) && (n1 == n2)
    (RdTypeOne(ip1, n1), RdTypeOne(ip2, n2)) -> (ip1 == ip2) && (n1 == n2)
    (RdTypeTwo(a1, n1), RdTypeTwo(a2, n2)) -> (a1 == a2) && (n1 == n2)
    _ -> False

pub fun encode-rd(rd : route-distinguisher) : list<int>
  match rd
    RdTypeZero(a, n) ->
      [0, 0] ++ write-u16(a) ++ write-u32(n)
    RdTypeOne(ip, n) ->
      [0, 1] ++ write-ipv4(ip) ++ write-u16(n)
    RdTypeTwo(a, n) ->
      [0, 2] ++ write-u32(a) ++ write-u16(n)

pub fun decode-rd(bytes : list<int>) : maybe<route-distinguisher>
  if bytes.length < 8 then Nothing
  else
    val rd-type = (bytes.head.default(0) * 256) + bytes.drop(1).head.default(0)
    if rd-type == 0 then
      val a = decode-u16(bytes.drop(2).head.default(0), bytes.drop(3).head.default(0))
      val n = decode-u32(bytes.drop(4).head.default(0), bytes.drop(5).head.default(0),
                         bytes.drop(6).head.default(0), bytes.drop(7).head.default(0))
      Just(RdTypeZero(a, n))
    elif rd-type == 1 then
      val ip = ipv4-create(bytes.drop(2).head.default(0), bytes.drop(3).head.default(0),
                           bytes.drop(4).head.default(0), bytes.drop(5).head.default(0))
      val n = decode-u16(bytes.drop(6).head.default(0), bytes.drop(7).head.default(0))
      Just(RdTypeOne(ip, n))
    elif rd-type == 2 then
      val a = decode-u32(bytes.drop(2).head.default(0), bytes.drop(3).head.default(0),
                         bytes.drop(4).head.default(0), bytes.drop(5).head.default(0))
      val n = decode-u16(bytes.drop(6).head.default(0), bytes.drop(7).head.default(0))
      Just(RdTypeTwo(a, n))
    else Nothing

// Route Target (RT) Extended Community (RFC 4360 / RFC 7432)
pub type route-target
  RtAsnTwo(target-asn : int, target-num : int)
  RtIpvFour(target-ip : ipv4, target-num : int)
  RtAsnFour(target-asn : int, target-num : int)

pub fun route-target/show(rt : route-target) : string
  match rt
    RtAsnTwo(a, n) -> "target:" ++ a.show ++ ":" ++ n.show
    RtIpvFour(ip, n) -> "target:" ++ ip.show ++ ":" ++ n.show
    RtAsnFour(a, n) -> "target:" ++ a.show ++ ":" ++ n.show

pub fun route-target/(==)(a : route-target, b : route-target) : bool
  match (a, b)
    (RtAsnTwo(a1, n1), RtAsnTwo(a2, n2)) -> (a1 == a2) && (n1 == n2)
    (RtIpvFour(ip1, n1), RtIpvFour(ip2, n2)) -> (ip1 == ip2) && (n1 == n2)
    (RtAsnFour(a1, n1), RtAsnFour(a2, n2)) -> (a1 == a2) && (n1 == n2)
    _ -> False

// RFC 7432 §5 Ethernet Segment Identifier (ESI) (10 octets)
// Value of all zeroes indicates a single-homed CE device.
pub struct esi(
  esi-type : int,
  octets   : list<int> // 9 octets following type
)

pub fun esi-all-zero() : esi
  Esi(0, [0, 0, 0, 0, 0, 0, 0, 0, 0])

pub fun is-single-homed(e : esi) : bool
  (e.esi-type == 0) && e.octets.all(fn(b) b == 0)

pub fun esi/(==)(a : esi, b : esi) : bool
  (a.esi-type == b.esi-type) && (a.octets == b.octets)

pub fun esi/show(e : esi) : string
  if is-single-homed(e) then "ESI-SingleHomed(0)"
  else
    val oct-str = e.octets.map(hex2).join(":")
    "ESI(" ++ hex2(e.esi-type) ++ ":" ++ oct-str ++ ")"

pub fun encode-esi(e : esi) : list<int>
  val full-octets = Cons(e.esi-type, e.octets)
  full-octets.take(10)

pub fun decode-esi(bytes : list<int>) : maybe<esi>
  if bytes.length < 10 then Nothing
  else
    val t = bytes.head.default(0)
    val octs = bytes.drop(1).take(9)
    Just(Esi(t, octs))

// 24-bit VXLAN Network Identifier (VNI: 1 to 16,777,215)
pub struct vni(
  vni-num : int
)

pub fun vni/show(v : vni) : string
  "VNI-" ++ v.vni-num.show

pub fun vni/(==)(a : vni, b : vni) : bool
  a.vni-num == b.vni-num

pub fun vni-to-bytes(v : vni) : list<int>
  val n = v.vni-num % 16777216
  [(n / 65536) % 256, (n / 256) % 256, n % 256]

pub fun vni-from-bytes(b0 : int, b1 : int, b2 : int) : vni
  Vni((b0 * 65536) + (b1 * 256) + b2)

// 32-bit Ethernet Tag ID (VLAN ID or normalized tag)
pub struct eth-tag(
  tag-val : int
)

pub fun eth-tag/show(t : eth-tag) : string
  "EthTag(" ++ t.tag-val.show ++ ")"

pub fun eth-tag/(==)(a : eth-tag, b : eth-tag) : bool
  a.tag-val == b.tag-val
