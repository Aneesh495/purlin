module proto/types

import std/core/string
import std/core/list

// Power of 2 helper for 0 <= n <= 32
pub fun pow2(n : int) : int {
  if n <= 0 then 1
  elif n == 1 then 2
  elif n == 2 then 4
  elif n == 3 then 8
  elif n == 4 then 16
  elif n == 5 then 32
  elif n == 6 then 64
  elif n == 7 then 128
  elif n == 8 then 256
  elif n == 9 then 512
  elif n == 10 then 1024
  elif n == 11 then 2048
  elif n == 12 then 4096
  elif n == 13 then 8192
  elif n == 14 then 16384
  elif n == 15 then 32768
  elif n == 16 then 65536
  elif n == 17 then 131072
  elif n == 18 then 262144
  elif n == 19 then 524288
  elif n == 20 then 1048576
  elif n == 21 then 2097152
  elif n == 22 then 4194304
  elif n == 23 then 8388608
  elif n == 24 then 16777216
  elif n == 25 then 33554432
  elif n == 26 then 67108864
  elif n == 27 then 134217728
  elif n == 28 then 268435456
  elif n == 29 then 536870912
  elif n == 30 then 1073741824
  elif n == 31 then 2147483648
  elif n == 32 then 4294967296
  else 4294967296
}

// IPv4 Address stored as an unsigned 32-bit integer representation (0 to 4294967295)
pub struct ipv4
  addr : int

// Construct an IPv4 address from four octets (0-255)
pub fun ipv4-create(o1 : int, o2 : int, o3 : int, o4 : int) : ipv4 {
  val n = ((o1 % 256) * 16777216) + ((o2 % 256) * 65536) + ((o3 % 256) * 256) + (o4 % 256)
  Ipv4(n)
}

pub fun octet1(ip-val : ipv4) : int {
  ip-val.addr / 16777216
}

pub fun octet2(ip-val : ipv4) : int {
  (ip-val.addr / 65536) % 256
}

pub fun octet3(ip-val : ipv4) : int {
  (ip-val.addr / 256) % 256
}

pub fun octet4(ip-val : ipv4) : int {
  ip-val.addr % 256
}

// Comparison and equality of IPv4 addresses
pub fun ipv4/cmp(a : ipv4, b : ipv4) : order {
  a.addr.cmp(b.addr)
}

pub fun ipv4/(==)(a : ipv4, b : ipv4) : bool {
  a.addr == b.addr
}

pub fun ipv4/show(ip-val : ipv4) : string {
  ip-val.octet1.show ++ "." ++ ip-val.octet2.show ++ "." ++ ip-val.octet3.show ++ "." ++ ip-val.octet4.show
}

// IPv6 Address stored as eight 16-bit words
pub struct ipv6
  w0 : int
  w1 : int
  w2 : int
  w3 : int
  w4 : int
  w5 : int
  w6 : int
  w7 : int

pub fun ipv6/show(ip-val : ipv6) : string {
  ip-val.w0.show ++ ":" ++ ip-val.w1.show ++ ":" ++ ip-val.w2.show ++ ":" ++ ip-val.w3.show ++ ":" ++
  ip-val.w4.show ++ ":" ++ ip-val.w5.show ++ ":" ++ ip-val.w6.show ++ ":" ++ ip-val.w7.show
}

pub fun ipv6/(==)(a : ipv6, b : ipv6) : bool {
  a.w0 == b.w0 && a.w1 == b.w1 && a.w2 == b.w2 && a.w3 == b.w3 &&
  a.w4 == b.w4 && a.w5 == b.w5 && a.w6 == b.w6 && a.w7 == b.w7
}

// Unified IP address variant
pub type ip-addr
  V4(v4 : ipv4)
  V6(v6 : ipv6)

pub fun ip-addr/show(ip-val : ip-addr) : string {
  match ip-val
    V4(v) -> v.show
    V6(v) -> v.show
}

pub fun ip-addr/(==)(a : ip-addr, b : ip-addr) : bool {
  match (a, b)
    (V4(x), V4(y)) -> x == y
    (V6(x), V6(y)) -> x == y
    _ -> False
}

// Network address with host bits zeroed out
pub fun ipv4-network(ip-val : ipv4, len : int) : ipv4 {
  if len <= 0 then Ipv4(0)
  elif len >= 32 then ip-val
  else {
    val host-bits = 32 - len
    val host-span = pow2(host-bits)
    val base = ip-val.addr - (ip-val.addr % host-span)
    Ipv4(base)
  }
}

// IP Prefix with network address and prefix length
pub struct ip-prefix
  network : ip-addr
  length  : int

pub fun prefix4(o1 : int, o2 : int, o3 : int, o4 : int, len : int) : ip-prefix {
  val base-ip = ipv4-create(o1, o2, o3, o4)
  val net-ip = ipv4-network(base-ip, len)
  Ip-prefix(V4(net-ip), len)
}

pub fun ip-prefix/show(p : ip-prefix) : string {
  p.network.show ++ "/" ++ p.length.show
}

pub fun ip-prefix/(==)(a : ip-prefix, b : ip-prefix) : bool {
  a.network == b.network && a.length == b.length
}

// Check whether prefix a contains IP address b
pub fun prefix-contains-ipv4(p : ip-prefix, ip-val : ipv4) : bool {
  match p.network
    V4(net-v4) -> {
      val masked-ip = ipv4-network(ip-val, p.length)
      masked-ip == net-v4
    }
    V6(_) -> False
}

// Check whether child prefix is a subnet of parent prefix
pub fun prefix-is-subnet(child : ip-prefix, parent : ip-prefix) : bool {
  if child.length < parent.length then False
  else {
    match (child.network, parent.network)
      (V4(c-ip), V4(p-ip)) -> {
        val parent-network = ipv4-network(c-ip, parent.length)
        parent-network == p-ip
      }
      _ -> False
  }
}

// Autonomous System Number (RFC 6793 supporting 4-byte ASN)
pub struct asn
  value : int

pub fun asn(n : int) : asn {
  Asn(n)
}

pub fun asn/show(a : asn) : string {
  "AS" ++ a.value.show
}

pub fun asn/cmp(a : asn, b : asn) : order {
  a.value.cmp(b.value)
}

pub fun asn/(==)(a : asn, b : asn) : bool {
  a.value == b.value
}

// Well-known ASN constants
pub val asn-as-trans : asn = Asn(23456)

// Check if an ASN falls in standard RFC 6996 private ranges:
// 2-byte private: 64512 to 65534
// 4-byte private: 4200000000 to 4294967294
pub fun is-private(a : asn) : bool {
  val v = a.value
  (v >= 64512 && v <= 65534) || (v >= 4200000000 && v <= 4294967294)
}

// BGP Router Identifier (RFC 4271 32-bit identifier in dotted-decimal format)
pub struct router-id
  rid-addr : ipv4

pub fun router-id(o1 : int, o2 : int, o3 : int, o4 : int) : router-id {
  Router-id(ipv4-create(o1, o2, o3, o4))
}

pub fun router-id/show(r : router-id) : string {
  r.rid-addr.show
}

pub fun router-id/cmp(a : router-id, b : router-id) : order {
  a.rid-addr.cmp(b.rid-addr)
}

pub fun router-id/(==)(a : router-id, b : router-id) : bool {
  a.rid-addr == b.rid-addr
}

// AFI and SAFI definitions (RFC 4760, RFC 7432)
pub struct afi-safi
  afi  : int
  safi : int

pub fun afi-safi(a : int, s : int) : afi-safi {
  Afi-safi(a, s)
}

pub val afi-ipv4 : int = 1
pub val afi-ipv6 : int = 2
pub val afi-l2vpn : int = 25

pub val safi-unicast : int = 1
pub val safi-multicast : int = 2
pub val safi-evpn : int = 70
pub val safi-mpls-vpn : int = 128

pub fun afi-safi/show(as-pair : afi-safi) : string {
  val afi-str = match as-pair.afi
    1 -> "IPv4"
    2 -> "IPv6"
    25 -> "L2VPN"
    other -> "AFI(" ++ other.show ++ ")"
  val safi-str = match as-pair.safi
    1 -> "Unicast"
    2 -> "Multicast"
    70 -> "EVPN"
    128 -> "MPLS-VPN"
    other -> "SAFI(" ++ other.show ++ ")"
  afi-str ++ "/" ++ safi-str
}

pub fun afi-safi/(==)(a : afi-safi, b : afi-safi) : bool {
  a.afi == b.afi && a.safi == b.safi
}
