// Module: rpki/rtr
// RFC 8210 RPKI-to-Router (RTR) Protocol version 1 & 2 client framing.
//
// Routers connect to RPKI Relying Party cache validators (e.g. Routinator,
// StayRTR) via the RTR protocol over TCP. The RTR protocol delivers authenticated
// VRP prefix/ASN bindings to routers and maintains synchronization via serial
// numbers and delta queries.
//
// This module provides:
//   1. Wire framing and serialization for RTR client queries (Reset, Serial)
//   2. Deserialization of IPv4/IPv6 Prefix PDUs (Types 4 and 5)
//   3. Session tracking and serial synchronization (End of Data PDU)
//   4. Direct translation from RTR PDUs into roa-cache updates

module rpki/rtr

import std/core/list
import std/core/maybe
import proto/types
import proto/wire
import rpki/roa

// RTR Protocol Versions (RFC 6810 = 0, RFC 8210 = 1 or 2)
pub val rtr-version-zero  : int = 0
pub val rtr-version-one   : int = 1
pub val rtr-version-two   : int = 2

// RTR PDU Types (RFC 8210 §5)
pub val pdu-serial-notify    : int = 0
pub val pdu-serial-query     : int = 1
pub val pdu-reset-query      : int = 2
pub val pdu-cache-response   : int = 3
pub val pdu-ipv4-prefix      : int = 4
pub val pdu-ipv6-prefix      : int = 5
pub val pdu-end-of-data      : int = 6
pub val pdu-cache-reset      : int = 7
pub val pdu-router-key       : int = 8
pub val pdu-error-report     : int = 10

// Parsed RTR PDU variants
pub type rtr-pdu
  RtrSerialNotify(session-id : int, serial : int)
  RtrCacheResponse(session-id : int)
  RtrIpv4Prefix(is-announce : bool, pfx : ip-prefix, max-len : int, as-num : asn)
  RtrIpv6Prefix(is-announce : bool, pfx : ip-prefix, max-len : int, as-num : asn)
  RtrEndOfData(session-id : int, serial : int, refresh : int, retry : int, expire : int)
  RtrCacheReset
  RtrErrorReport(err-code : int, err-msg : string)
  RtrUnknown(pdu-type : int, len : int)

// Encode Reset Query PDU (Type 2, 8 octets)
pub fun encode-reset-query(version : int = 1) : list<int>
  [version, pdu-reset-query, 0, 0, 0, 0, 0, 8]

fun read-u32(bytes : list<int>) : int
  match bytes
    Cons(b0, Cons(b1, Cons(b2, Cons(b3, _)))) ->
      decode-u32(b0, b1, b2, b3)
    _ -> 0

// Encode Serial Query PDU (Type 1, 12 octets)
pub fun encode-serial-query(session-id : int, serial : int, version : int = 1) : list<int>
  val hdr = [
    version,
    pdu-serial-query,
    (session-id / 256) % 256,
    session-id % 256,
    0, 0, 0, 12
  ]
  hdr ++ write-u32(serial)

// Decode an IPv4 Prefix PDU payload (12 octets after 8-octet header)
// Wire format: Flags (1), Prefix Length (1), Max Length (1), Zero (1), IPv4 (4), ASN (4)
pub fun decode-ipv4-prefix-pdu(bytes : list<int>) : maybe<rtr-pdu>
  if bytes.length < 12 then Nothing
  else
    val flags = bytes.head.default(0)
    val is-announce = (flags % 2) == 1
    val p-len = bytes.drop(1).head.default(0)
    val max-len = bytes.drop(2).head.default(0)
    val ip-bytes = bytes.drop(4).take(4)
    val asn-bytes = bytes.drop(8).take(4)
    
    val ip-val = read-u32(ip-bytes)
    val asn-val = read-u32(asn-bytes)
    
    val pfx = Ip-prefix(V4(Ipv4(ip-val)), p-len)
    Just(RtrIpv4Prefix(is-announce, pfx, max-len, asn(asn-val)))

// Decode a complete RTR PDU from raw bytes
pub fun decode-rtr-pdu(bytes : list<int>) : maybe<(rtr-pdu, list<int>)>
  if bytes.length < 8 then Nothing
  else
    val _version = bytes.head.default(0)
    val pdu-type = bytes.drop(1).head.default(0)
    val sess-hi = bytes.drop(2).head.default(0)
    val sess-lo = bytes.drop(3).head.default(0)
    val session-id = (sess-hi * 256) + sess-lo
    val pdu-len = read-u32(bytes.drop(4).take(4))
    
    if bytes.length < pdu-len then Nothing // Incomplete frame
    else
      val payload = bytes.drop(8).take(pdu-len - 8)
      val remainder = bytes.drop(pdu-len)
      
      val parsed-pdu = if pdu-type == pdu-cache-response then
        RtrCacheResponse(session-id)
      elif pdu-type == pdu-ipv4-prefix then
        decode-ipv4-prefix-pdu(payload).default(RtrUnknown(pdu-type, pdu-len))
      elif pdu-type == pdu-end-of-data then
        val serial = read-u32(payload.take(4))
        val refresh = read-u32(payload.drop(4).take(4))
        val retry = read-u32(payload.drop(8).take(4))
        val expire = read-u32(payload.drop(12).take(4))
        RtrEndOfData(session-id, serial, refresh, retry, expire)
      elif pdu-type == pdu-cache-reset then
        RtrCacheReset
      elif pdu-type == pdu-serial-notify then
        val serial = read-u32(payload.take(4))
        RtrSerialNotify(session-id, serial)
      else
        RtrUnknown(pdu-type, pdu-len)
      
      Just((parsed-pdu, remainder))

// Apply an RTR Prefix PDU directly to a ROA cache
pub fun apply-rtr-pdu-to-cache(cache : roa-cache, pdu : rtr-pdu) : div roa-cache
  match pdu
    RtrIpv4Prefix(is-announce, pfx, max-len, as-num) ->
      val roa = Roa-payload(pfx, max-len, as-num)
      if is-announce then roa-cache-insert(cache, roa)
      else roa-cache-delete(cache, roa)
    RtrIpv6Prefix(is-announce, pfx, max-len, as-num) ->
      val roa = Roa-payload(pfx, max-len, as-num)
      if is-announce then roa-cache-insert(cache, roa)
      else roa-cache-delete(cache, roa)
    _ -> cache
