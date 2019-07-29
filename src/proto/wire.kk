module proto/wire

import std/core/list
import std/core/string
import proto/types

// RFC 4271 Message Types
pub val msg-type-open          : int = 1
pub val msg-type-update        : int = 2
pub val msg-type-notification  : int = 3
pub val msg-type-keepalive     : int = 4
pub val msg-type-route-refresh : int = 5

// RFC 4271 Frame Constraints
pub val bgp-header-length      : int = 19
pub val bgp-min-message-length : int = 19
pub val bgp-max-message-length : int = 4096
pub val bgp-extended-max-len   : int = 65535

// BGP Frame Header
pub struct bgp-header
  length   : int
  msg-type : int

pub fun bgp-header/show(h : bgp-header) : string {
  val type-str = match h.msg-type
    1 -> "OPEN"
    2 -> "UPDATE"
    3 -> "NOTIFICATION"
    4 -> "KEEPALIVE"
    5 -> "ROUTE-REFRESH"
    n -> "UNKNOWN(" ++ n.show ++ ")"
  "BgpHeader(type=" ++ type-str ++ ", len=" ++ h.length.show ++ ")"
}

pub fun bgp-header/(==)(a : bgp-header, b : bgp-header) : bool {
  a.length == b.length && a.msg-type == b.msg-type
}

// Wire Parsing Errors
pub type wire-error
  WireErrIncompleteHeader
  WireErrMarkerNotSynchronized
  WireErrBadMessageLength(len : int)
  WireErrBadMessageType(msg-type : int)
  WireErrPayloadTruncated(expected : int, actual : int)

pub fun show(err : wire-error) : string {
  match err
    WireErrIncompleteHeader -> "Incomplete BGP header (less than 19 bytes)"
    WireErrMarkerNotSynchronized -> "Marker field is not synchronized (all 0xFF)"
    WireErrBadMessageLength(l) -> "Bad message length: " ++ l.show
    WireErrBadMessageType(t) -> "Unknown or unsupported message type: " ++ t.show
    WireErrPayloadTruncated(exp, act) ->
      "Payload truncated: expected " ++ exp.show ++ " bytes, got " ++ act.show
}

// 16-byte BGP synchronization marker (all 0xFF)
pub fun bgp-marker-bytes() : list<int> {
  [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255]
}

// Big-endian binary serialization helpers
pub fun write-u8(n : int) : list<int> {
  [n % 256]
}

pub fun write-u16(n : int) : list<int> {
  [(n / 256) % 256, n % 256]
}

pub fun write-u32(n : int) : list<int> {
  [(n / 16777216) % 256, (n / 65536) % 256, (n / 256) % 256, n % 256]
}

pub fun write-ipv4(ip-val : ipv4) : list<int> {
  [ip-val.octet1, ip-val.octet2, ip-val.octet3, ip-val.octet4]
}

pub fun write-asn2(a : asn) : list<int> {
  write-u16(a.value)
}

pub fun write-asn4(a : asn) : list<int> {
  write-u32(a.value)
}

// Wrap a message payload with the RFC 4271 19-byte header
pub fun frame-message(msg-type : int, payload : list<int>) : list<int> {
  val total-len = bgp-header-length + payload.length
  val header-bytes = bgp-marker-bytes() ++ write-u16(total-len) ++ write-u8(msg-type)
  header-bytes ++ payload
}

// Validate the 16-byte marker
pub fun check-marker(bytes : list<int>) : bool {
  fun check-marker-loop(xs : list<int>, count : int) : bool {
    if count >= 16 then True
    else {
      match xs
        Cons(b, rest) -> if b == 255 then check-marker-loop(rest, count + 1) else False
        Nil -> False
    }
  }
  check-marker-loop(bytes, 0)
}

// Decode a big-endian uint16 from two bytes
pub fun decode-u16(b0 : int, b1 : int) : int {
  (b0 * 256) + b1
}

// Decode a big-endian uint32 from four bytes
pub fun decode-u32(b0 : int, b1 : int, b2 : int, b3 : int) : int {
  (b0 * 16777216) + (b1 * 65536) + (b2 * 256) + b3
}

// Parse and validate the BGP header from a raw byte stream
pub fun parse-bgp-header(bytes : list<int>) : either<wire-error, (bgp-header, list<int>)> {
  if bytes.length < bgp-header-length then Left(WireErrIncompleteHeader)
  elif !check-marker(bytes) then Left(WireErrMarkerNotSynchronized)
  else {
    // Drop 16 marker bytes
    val after-marker = bytes.drop(16)
    match after-marker
      Cons(l0, Cons(l1, Cons(msg-type, rest-payload))) -> {
        val total-len = decode-u16(l0, l1)
        if total-len < bgp-min-message-length || total-len > bgp-max-message-length then {
          Left(WireErrBadMessageLength(total-len))
        } elif msg-type < 1 || msg-type > 5 then {
          Left(WireErrBadMessageType(msg-type))
        } else {
          val expected-payload-len = total-len - bgp-header-length
          if rest-payload.length < expected-payload-len then {
            Left(WireErrPayloadTruncated(expected-payload-len, rest-payload.length))
          } else {
            val payload = rest-payload.take(expected-payload-len)
            val header = Bgp-header(total-len, msg-type)
            Right((header, payload))
          }
        }
      }
      _ -> Left(WireErrIncompleteHeader)
  }
}
