// Unit tests for RPKI ROA Cache, RFC 6811 Prefix Origin Validation, and RFC 8210 RTR Framing
module unit/test-rpki

import std/core/list
import std/core/maybe
import proto/types
import proto/wire
import proto/attr
import rib/table
import rpki/roa
import rpki/validator
import rpki/rtr

fun test-roa-cache-ops() : div bool
  val c0 = roa-cache-empty()
  val roa1 = Roa-payload(prefix4(10, 0, 0, 0, 16), 24, asn(65001))
  val roa2 = Roa-payload(prefix4(192, 168, 0, 0, 16), 24, asn(65002))
  
  val c1 = roa-cache-insert(c0, roa1)
  val c2 = roa-cache-insert(c1, roa2)
  val t1 = roa-cache-size(c2) == 2
  
  // Lookup covering for 10.0.1.0/24 should return roa1
  val cov1 = roa-cache-lookup-covering(c2, prefix4(10, 0, 1, 0, 24))
  val t2 = cov1.length == 1
  val t3 = match cov1
    Cons(r, _) -> r.origin-asn == asn(65001)
    Nil -> False
  
  // Delete roa1
  val c3 = roa-cache-delete(c2, roa1)
  val t4 = roa-cache-size(c3) == 1
  val cov1-after = roa-cache-lookup-covering(c3, prefix4(10, 0, 1, 0, 24))
  val t5 = cov1-after.is-empty
  
  t1 && t2 && t3 && t4 && t5

fun test-rfc6811-origin-validation() : div bool
  // VRP: 203.0.113.0/24 max-length 24 ASN 64496
  // VRP: 198.51.100.0/22 max-length 24 ASN 64497
  val v1 = Roa-payload(prefix4(203, 0, 113, 0, 24), 24, asn(64496))
  val v2 = Roa-payload(prefix4(198, 51, 100, 0, 22), 24, asn(64497))
  
  var cache := roa-cache-empty()
  cache := roa-cache-insert(cache, v1)
  cache := roa-cache-insert(cache, v2)
  
  // Test Case 1: Valid (exact match)
  val res1 = validate-prefix-origin(cache, prefix4(203, 0, 113, 0, 24), asn(64496))
  val t1 = res1.status == RpkiValid
  
  // Test Case 2: Valid (sub-prefix /24 within /22 max-length 24)
  val res2 = validate-prefix-origin(cache, prefix4(198, 51, 101, 0, 24), asn(64497))
  val t2 = res2.status == RpkiValid
  
  // Test Case 3: Invalid - Origin ASN Mismatch (Route Hijack)
  val res3 = validate-prefix-origin(cache, prefix4(203, 0, 113, 0, 24), asn(65534))
  val t3 = res3.status == RpkiInvalid
  val t4 = match res3.reason
    ReasonInvalidAsnMismatch(orig, _) -> orig == asn(65534)
    _ -> False
  
  // Test Case 4: Invalid - Max Length Exceeded (/25 when max-length 24)
  val res4 = validate-prefix-origin(cache, prefix4(198, 51, 100, 0, 25), asn(64497))
  val t5 = res4.status == RpkiInvalid
  val t6 = match res4.reason
    ReasonInvalidLengthExceeded(rlen, max-len, _) -> (rlen == 25) && (max-len == 24)
    _ -> False
  
  // Test Case 5: NotFound - No covering VRP in cache
  val res5 = validate-prefix-origin(cache, prefix4(192, 0, 2, 0, 24), asn(64496))
  val t7 = res5.status == RpkiNotFound
  
  t1 && t2 && t3 && t4 && t5 && t6 && t7

fun test-rtr-framing-and-sync() : div bool
  // Test Reset Query encoding
  val reset-bytes = encode-reset-query(1)
  val t1 = reset-bytes.length == 8
  val t2 = reset-bytes == [1, 2, 0, 0, 0, 0, 0, 8]
  
  // Test Serial Query encoding
  val serial-bytes = encode-serial-query(42, 1005, 1)
  val t3 = serial-bytes.length == 12
  
  // Test IPv4 Prefix PDU decoding (announcement: flags=1, /22, max-len 24, 198.51.100.0, ASN 64497)
  val pdu-bytes = [
    1, 4, 0, 0, 0, 0, 0, 20, // Header: ver 1, type 4, len 20
    1, 22, 24, 0,            // flags=1 (ann), pfx-len=22, max-len=24, zero=0
    198, 51, 100, 0,         // IPv4 address
    0, 0, 251, 241           // ASN 64497 (0x0000FBF1)
  ]
  
  match decode-rtr-pdu(pdu-bytes)
    Just((parsed, rem)) ->
      val t4 = rem.is-empty
      match parsed
        RtrIpv4Prefix(is-ann, pfx, max-len, as-num) ->
          val t5 = is-ann == True
          val t6 = pfx.length == 22
          val t7 = max-len == 24
          val t8 = as-num == asn(64497)
          
          // Test applying to cache
          var cache := roa-cache-empty()
          cache := apply-rtr-pdu-to-cache(cache, parsed)
          val t9 = roa-cache-size(cache) == 1
          
          // Validate using the RTR-synchronized cache
          val val-res = validate-prefix-origin(cache, prefix4(198, 51, 100, 0, 24), as-num)
          val t10 = val-res.status == RpkiValid
          
          t1 && t2 && t3 && t4 && t5 && t6 && t7 && t8 && t9 && t10
        _ -> False
    Nothing -> False

pub fun main() : <div,console> ()
  val t1 = test-roa-cache-ops()
  val t2 = test-rfc6811-origin-validation()
  val t3 = test-rtr-framing-and-sync()
  
  if t1 && t2 && t3 then
    println("PASS: rpki subsystem unit tests passed successfully")
  else
    println("FAIL: rpki subsystem unit tests failed")
