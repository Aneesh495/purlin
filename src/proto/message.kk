module proto/message

import std/core/list
import std/core/string
import proto/types
import proto/wire
import proto/capabilities
import proto/attr

// RFC 4271 Notification Error Codes
pub val err-code-message-header : int = 1
pub val err-code-open-message   : int = 2
pub val err-code-update-message : int = 3
pub val err-code-hold-timer-exp : int = 4
pub val err-code-fsm-error      : int = 5
pub val err-code-cease           : int = 6

// Notification Subcodes for Message Header (Error Code 1)
pub val subcode-conn-not-sync   : int = 1
pub val subcode-bad-length      : int = 2
pub val subcode-bad-type        : int = 3

// Notification Subcodes for OPEN Message (Error Code 2)
pub val subcode-bad-version     : int = 1
pub val subcode-bad-peer-as     : int = 2
pub val subcode-bad-bgp-id      : int = 3
pub val subcode-bad-opt-param   : int = 4
pub val subcode-unsupported-cap : int = 7

// Notification Subcodes for UPDATE Message (Error Code 3)
pub val subcode-malformed-attr  : int = 1
pub val subcode-unrecog-wellknown : int = 2
pub val subcode-missing-wellknown : int = 3
pub val subcode-attr-flags-err  : int = 4
pub val subcode-attr-len-err    : int = 5
pub val subcode-invalid-origin  : int = 6
pub val subcode-as-loop-err     : int = 11
pub val subcode-invalid-nexthop : int = 8

// Notification Subcodes for Cease (Error Code 6)
pub val subcode-max-prefixes    : int = 1
pub val subcode-admin-shutdown  : int = 2
pub val subcode-peer-deconfig   : int = 3
pub val subcode-admin-reset     : int = 4
pub val subcode-conn-rejected   : int = 5
pub val subcode-collision-res   : int = 7

// BGP Message ADT
pub type bgp-message
  MsgOpen(version : int, peer-asn : asn, hold-time : int, bgp-id : router-id, caps : list<bgp-capability>)
  MsgUpdate(withdrawn : list<ip-prefix>, attributes : list<path-attribute>, nlri : list<ip-prefix>)
  MsgNotification(error-code : int, error-subcode : int, data-bytes : list<int>)
  MsgKeepalive
  MsgRouteRefresh(afi : int, safi : int)

pub fun show(msg : bgp-message) : string {
  match msg
    MsgOpen(v, a, ht, rid, caps) ->
      "BGP-OPEN(v=" ++ v.show ++ ", " ++ a.show ++ ", hold=" ++ ht.show ++ "s, id=" ++ rid.show ++
      ", caps=" ++ caps.length.show ++ ")"
    MsgUpdate(w, attrs, n) ->
      "BGP-UPDATE(withdrawn=" ++ w.length.show ++ ", attrs=" ++ attrs.length.show ++
      ", nlri=" ++ n.length.show ++ ")"
    MsgNotification(code, subcode, d) ->
      "BGP-NOTIFICATION(code=" ++ code.show ++ ", subcode=" ++ subcode.show ++
      ", data_len=" ++ d.length.show ++ ")"
    MsgKeepalive -> "BGP-KEEPALIVE"
    MsgRouteRefresh(a, s) ->
      "BGP-ROUTE-REFRESH(" ++ Afi-safi(a, s).show ++ ")"
}

pub fun (==)(a : bgp-message, b : bgp-message) : bool {
  match (a, b)
    (MsgOpen(v1, a1, h1, r1, c1), MsgOpen(v2, a2, h2, r2, c2)) ->
      v1 == v2 && a1 == a2 && h1 == h2 && r1 == r2 && c1 == c2
    (MsgUpdate(w1, at1, n1), MsgUpdate(w2, at2, n2)) ->
      w1 == w2 && at1 == at2 && n1 == n2
    (MsgNotification(c1, s1, d1), MsgNotification(c2, s2, d2)) ->
      c1 == c2 && s1 == s2 && d1 == d2
    (MsgKeepalive, MsgKeepalive) -> True
    (MsgRouteRefresh(a1, s1), MsgRouteRefresh(a2, s2)) ->
      a1 == a2 && s1 == s2
    _ -> False
}

// Encode IPv4 Prefix into RFC 4271 wire format:
// 1 byte Prefix Length + ceiling(Length/8) bytes of network address
pub fun encode-prefix(p : ip-prefix) : list<int> {
  match p.network
    V4(ip-val) -> {
      val len = p.length
      val num-bytes = if len <= 0 then 0
                      elif len <= 8 then 1
                      elif len <= 16 then 2
                      elif len <= 24 then 3
                      else 4
      val o1 = ip-val.octet1
      val o2 = ip-val.octet2
      val o3 = ip-val.octet3
      val o4 = ip-val.octet4
      
      val octets = match num-bytes
        0 -> []
        1 -> [o1]
        2 -> [o1, o2]
        3 -> [o1, o2, o3]
        _ -> [o1, o2, o3, o4]
      [len] ++ octets
    }
    V6(_) -> [] // IPv6 is encoded via MP_REACH_NLRI (RFC 4760)
}

// Decode list of IPv4 prefixes from bytes
pub fun decode-prefixes(bytes : list<int>) : div list<ip-prefix> {
  fun loop(curr : list<int>, acc : list<ip-prefix>) : div list<ip-prefix> {
    match curr
      Cons(len, rest) -> {
        val num-bytes = if len <= 0 then 0
                        elif len <= 8 then 1
                        elif len <= 16 then 2
                        elif len <= 24 then 3
                        else 4
        if rest.length < num-bytes then acc.reverse
        else {
          val p-bytes = rest.take(num-bytes)
          val remaining = rest.drop(num-bytes)
          
          val o1 = p-bytes.head.default(0)
          val o2 = p-bytes.drop(1).head.default(0)
          val o3 = p-bytes.drop(2).head.default(0)
          val o4 = p-bytes.drop(3).head.default(0)
          
          val p = prefix4(o1, o2, o3, o4, len)
          loop(remaining, Cons(p, acc))
        }
      }
      _ -> acc.reverse
  }
  loop(bytes, [])
}

// Serialize BGP Message to raw framed wire bytes
pub fun serialize-message(msg : bgp-message, use-four-byte-asn : bool) : list<int> {
  match msg
    MsgOpen(v, a, ht, rid, caps) -> {
      // 2-byte ASN on wire: if ASN > 65535, send AS_TRANS (23456)
      val wire-asn = if a.value > 65535 then asn-as-trans.value else a.value
      val opt-params = encode-open-opt-params(caps)
      val payload = [v] ++ write-u16(wire-asn) ++ write-u16(ht) ++
                    write-ipv4(rid.rid-addr) ++ write-u8(opt-params.length) ++ opt-params
      frame-message(msg-type-open, payload)
    }
    MsgUpdate(withdrawn, attrs, nlri) -> {
      val withdrawn-bytes = withdrawn.flatmap(encode-prefix)
      val attr-bytes = attrs.flatmap(fn(a) { encode-attribute(a, use-four-byte-asn) })
      val nlri-bytes = nlri.flatmap(encode-prefix)
      val payload = write-u16(withdrawn-bytes.length) ++ withdrawn-bytes ++
                    write-u16(attr-bytes.length) ++ attr-bytes ++ nlri-bytes
      frame-message(msg-type-update, payload)
    }
    MsgNotification(code, subcode, d) -> {
      val payload = [code, subcode] ++ d
      frame-message(msg-type-notification, payload)
    }
    MsgKeepalive -> {
      frame-message(msg-type-keepalive, [])
    }
    MsgRouteRefresh(a, s) -> {
      val payload = write-u16(a) ++ [0] ++ write-u8(s)
      frame-message(msg-type-route-refresh, payload)
    }
}

// Parse framed BGP message from raw wire bytes
pub fun parse-message(bytes : list<int>, use-four-byte-asn : bool) : div either<wire-error, bgp-message> {
  match parse-bgp-header(bytes)
    Left(err) -> Left(err)
    Right((header, payload)) -> {
      val t = header.msg-type
      if t == msg-type-open then {
        if payload.length < 10 then Left(WireErrPayloadTruncated(10, payload.length))
        else {
          val v = payload.head.default(4)
          val a0 = payload.drop(1).head.default(0)
          val a1 = payload.drop(2).head.default(0)
          val wire-asn = decode-u16(a0, a1)
          val ht0 = payload.drop(3).head.default(0)
          val ht1 = payload.drop(4).head.default(0)
          val ht = decode-u16(ht0, ht1)
          val r0 = payload.drop(5).head.default(0)
          val r1 = payload.drop(6).head.default(0)
          val r2 = payload.drop(7).head.default(0)
          val r3 = payload.drop(8).head.default(0)
          val rid = router-id(r0, r1, r2, r3)
          val opt-len = payload.drop(9).head.default(0)
          val opt-bytes = payload.drop(10).take(opt-len)
          val caps = decode-open-opt-params(opt-bytes)
          
          // If 4-octet ASN capability is advertised, use the 4-byte ASN value
          val effective-asn = caps.foldl(Asn(wire-asn), fn(curr-asn, c) {
            match c
              CapFourOctetAsn(actual-asn) -> actual-asn
              _ -> curr-asn
          })
          Right(MsgOpen(v, effective-asn, ht, rid, caps))
        }
      } elif t == msg-type-update then {
        if payload.length < 4 then Left(WireErrPayloadTruncated(4, payload.length))
        else {
          val w-len0 = payload.head.default(0)
          val w-len1 = payload.drop(1).head.default(0)
          val withdrawn-len = decode-u16(w-len0, w-len1)
          val after-w-header = payload.drop(2)
          val withdrawn-bytes = after-w-header.take(withdrawn-len)
          val withdrawn = decode-prefixes(withdrawn-bytes)
          
          val after-withdrawn = after-w-header.drop(withdrawn-len)
          if after-withdrawn.length < 2 then Left(WireErrPayloadTruncated(2, after-withdrawn.length))
          else {
            val a-len0 = after-withdrawn.head.default(0)
            val a-len1 = after-withdrawn.drop(1).head.default(0)
            val attr-len = decode-u16(a-len0, a-len1)
            val after-attr-header = after-withdrawn.drop(2)
            val attr-bytes = after-attr-header.take(attr-len)
            val attrs = decode-attributes(attr-bytes, use-four-byte-asn)
            
            val nlri-bytes = after-attr-header.drop(attr-len)
            val nlri = decode-prefixes(nlri-bytes)
            
            Right(MsgUpdate(withdrawn, attrs, nlri))
          }
        }
      } elif t == msg-type-notification then {
        if payload.length < 2 then Left(WireErrPayloadTruncated(2, payload.length))
        else {
          val code = payload.head.default(0)
          val subcode = payload.drop(1).head.default(0)
          val d = payload.drop(2)
          Right(MsgNotification(code, subcode, d))
        }
      } elif t == msg-type-keepalive then {
        Right(MsgKeepalive)
      } elif t == msg-type-route-refresh then {
        if payload.length < 4 then Left(WireErrPayloadTruncated(4, payload.length))
        else {
          val a0 = payload.head.default(0)
          val a1 = payload.drop(1).head.default(0)
          val a = decode-u16(a0, a1)
          val s = payload.drop(3).head.default(0)
          Right(MsgRouteRefresh(a, s))
        }
      } else {
        Left(WireErrBadMessageType(t))
      }
    }
}
