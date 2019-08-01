module proto/capabilities

import std/core/list
import std/core/string
import proto/types
import proto/wire

// RFC 5492 Capability Codes
pub val cap-code-mp-extensions    : int = 1   // RFC 4760 Multiprotocol Extensions
pub val cap-code-route-refresh    : int = 2   // RFC 2918 Route Refresh
pub val cap-code-graceful-restart : int = 64  // RFC 4724 Graceful Restart
pub val cap-code-four-octet-asn   : int = 65  // RFC 6793 4-octet AS Number
pub val cap-code-add-path         : int = 69  // RFC 7911 ADD-PATH
pub val cap-code-extended-message : int = 6   // RFC 8654 Extended Message Support

// ADD-PATH send/receive flags (RFC 7911)
pub val add-path-receive : int = 1
pub val add-path-send    : int = 2
pub val add-path-both    : int = 3

// Capability variants
pub type bgp-capability
  CapMpBgp(afi : int, safi : int)
  CapRouteRefresh
  CapFourOctetAsn(asn-val : asn)
  CapAddPath(afi : int, safi : int, flags : int)
  CapGracefulRestart(restart-time : int, restarting : bool)
  CapExtendedMessage
  CapUnknown(code : int, raw-bytes : list<int>)

pub fun show(cap : bgp-capability) : string {
  match cap
    CapMpBgp(a, s) -> "CapMpBgp(" ++ Afi-safi(a, s).show ++ ")"
    CapRouteRefresh -> "CapRouteRefresh"
    CapFourOctetAsn(a) -> "CapFourOctetAsn(" ++ a.show ++ ")"
    CapAddPath(a, s, f) ->
      val f-str = if f == 1 then "Receive" elif f == 2 then "Send" elif f == 3 then "Both" else f.show
      "CapAddPath(" ++ Afi-safi(a, s).show ++ ", mode=" ++ f-str ++ ")"
    CapGracefulRestart(t, r) ->
      "CapGracefulRestart(time=" ++ t.show ++ "s, restarting=" ++ r.show ++ ")"
    CapExtendedMessage -> "CapExtendedMessage(64KB)"
    CapUnknown(c, bs) -> "CapUnknown(code=" ++ c.show ++ ", len=" ++ bs.length.show ++ ")"
}

pub fun (==)(a : bgp-capability, b : bgp-capability) : bool {
  match (a, b)
    (CapMpBgp(a1, s1), CapMpBgp(a2, s2)) -> a1 == a2 && s1 == s2
    (CapRouteRefresh, CapRouteRefresh) -> True
    (CapFourOctetAsn(n1), CapFourOctetAsn(n2)) -> n1 == n2
    (CapAddPath(a1, s1, f1), CapAddPath(a2, s2, f2)) -> a1 == a2 && s1 == s2 && f1 == f2
    (CapGracefulRestart(t1, r1), CapGracefulRestart(t2, r2)) -> t1 == t2 && r1 == r2
    (CapExtendedMessage, CapExtendedMessage) -> True
    (CapUnknown(c1, bs1), CapUnknown(c2, bs2)) -> c1 == c2 && bs1 == bs2
    _ -> False
}

// Encode a single capability TLV: Code (1B) + Length (1B) + Value
pub fun encode-capability(cap : bgp-capability) : list<int> {
  match cap
    CapMpBgp(a, s) -> {
      val val-bytes = write-u16(a) ++ [0] ++ write-u8(s)
      write-u8(cap-code-mp-extensions) ++ write-u8(val-bytes.length) ++ val-bytes
    }
    CapRouteRefresh -> {
      write-u8(cap-code-route-refresh) ++ write-u8(0)
    }
    CapFourOctetAsn(a) -> {
      val val-bytes = write-asn4(a)
      write-u8(cap-code-four-octet-asn) ++ write-u8(val-bytes.length) ++ val-bytes
    }
    CapAddPath(a, s, f) -> {
      val val-bytes = write-u16(a) ++ write-u8(s) ++ write-u8(f)
      write-u8(cap-code-add-path) ++ write-u8(val-bytes.length) ++ val-bytes
    }
    CapGracefulRestart(t, r) -> {
      val flag-bit = if r then 128 else 0
      val flags-and-time = (flag-bit * 256) + (t % 4096)
      val val-bytes = write-u16(flags-and-time)
      write-u8(cap-code-graceful-restart) ++ write-u8(val-bytes.length) ++ val-bytes
    }
    CapExtendedMessage -> {
      write-u8(cap-code-extended-message) ++ write-u8(0)
    }
    CapUnknown(c, bs) -> {
      write-u8(c) ++ write-u8(bs.length) ++ bs
    }
}

// Decode a single capability value by code
pub fun decode-cap-value(code : int, len : int, val-bytes : list<int>) : bgp-capability {
  if code == cap-code-mp-extensions && len >= 4 then {
    val a = decode-u16(val-bytes.head.default(0), val-bytes.drop(1).head.default(0))
    val s = val-bytes.drop(3).head.default(0)
    CapMpBgp(a, s)
  } elif code == cap-code-route-refresh then {
    CapRouteRefresh
  } elif code == cap-code-four-octet-asn && len >= 4 then {
    val b0 = val-bytes.head.default(0)
    val b1 = val-bytes.drop(1).head.default(0)
    val b2 = val-bytes.drop(2).head.default(0)
    val b3 = val-bytes.drop(3).head.default(0)
    CapFourOctetAsn(Asn(decode-u32(b0, b1, b2, b3)))
  } elif code == cap-code-add-path && len >= 4 then {
    val a = decode-u16(val-bytes.head.default(0), val-bytes.drop(1).head.default(0))
    val s = val-bytes.drop(2).head.default(0)
    val f = val-bytes.drop(3).head.default(0)
    CapAddPath(a, s, f)
  } elif code == cap-code-graceful-restart && len >= 2 then {
    val raw-val = decode-u16(val-bytes.head.default(0), val-bytes.drop(1).head.default(0))
    val is-restarting = (raw-val / 32768) == 1
    val restart-time = raw-val % 4096
    CapGracefulRestart(restart-time, is-restarting)
  } elif code == cap-code-extended-message then {
    CapExtendedMessage
  } else {
    CapUnknown(code, val-bytes.take(len))
  }
}

// Parse a list of capability TLVs from raw bytes
pub fun decode-capabilities(bytes : list<int>) : div list<bgp-capability> {
  fun loop(curr : list<int>, acc : list<bgp-capability>) : div list<bgp-capability> {
    match curr
      Cons(code, Cons(len, rest)) -> {
        if rest.length < len then acc.reverse
        else {
          val val-bytes = rest.take(len)
          val remaining = rest.drop(len)
          val cap = decode-cap-value(code, len, val-bytes)
          loop(remaining, Cons(cap, acc))
        }
      }
      _ -> acc.reverse
  }
  loop(bytes, [])
}

// Encode capabilities list into RFC 4271 Optional Parameter Type 2
pub fun encode-open-opt-params(caps : list<bgp-capability>) : list<int> {
  if caps.is-empty then []
  else {
    val all-cap-bytes = caps.flatmap(encode-capability)
    // Parameter Type 2: Capabilities (RFC 5492)
    val param-type = 2
    val param-len = all-cap-bytes.length
    write-u8(param-type) ++ write-u8(param-len) ++ all-cap-bytes
  }
}

// Decode OPEN Optional Parameters to extract all capabilities
pub fun decode-open-opt-params(bytes : list<int>) : div list<bgp-capability> {
  fun loop(curr : list<int>, acc : list<bgp-capability>) : div list<bgp-capability> {
    match curr
      Cons(param-type, Cons(param-len, rest)) -> {
        if rest.length < param-len then acc.reverse
        else {
          val param-bytes = rest.take(param-len)
          val remaining = rest.drop(param-len)
          if param-type == 2 then {
            val parsed-caps = decode-capabilities(param-bytes)
            loop(remaining, parsed-caps.reverse ++ acc)
          } else {
            loop(remaining, acc)
          }
        }
      }
      _ -> acc.reverse
  }
  loop(bytes, [])
}

// Negotiated Session Capabilities between two peering BGP speakers
pub struct negotiated-caps
  supports-four-octet-asn : bool
  supports-route-refresh  : bool
  supports-extended-msg   : bool
  mp-bgp-families         : list<afi-safi>
  add-path-send-families  : list<afi-safi>
  add-path-recv-families  : list<afi-safi>

pub fun negotiate-session(local-caps : list<bgp-capability>, remote-caps : list<bgp-capability>) : negotiated-caps {
  val local-has-four-byte = local-caps.any(fn(c) { match c { CapFourOctetAsn(_) -> True; _ -> False } })
  val remote-has-four-byte = remote-caps.any(fn(c) { match c { CapFourOctetAsn(_) -> True; _ -> False } })
  val four-octet = local-has-four-byte && remote-has-four-byte

  val local-has-rr = local-caps.any(fn(c) { match c { CapRouteRefresh -> True; _ -> False } })
  val remote-has-rr = remote-caps.any(fn(c) { match c { CapRouteRefresh -> True; _ -> False } })
  val route-refresh = local-has-rr && remote-has-rr

  val local-has-ext = local-caps.any(fn(c) { match c { CapExtendedMessage -> True; _ -> False } })
  val remote-has-ext = remote-caps.any(fn(c) { match c { CapExtendedMessage -> True; _ -> False } })
  val ext-msg = local-has-ext && remote-has-ext

  // Intersect MP-BGP AFI/SAFI families
  val local-mp = local-caps.flatmap(fn(c) { match c { CapMpBgp(a, s) -> [Afi-safi(a, s)]; _ -> [] } })
  val remote-mp = remote-caps.flatmap(fn(c) { match c { CapMpBgp(a, s) -> [Afi-safi(a, s)]; _ -> [] } })
  val common-mp = local-mp.filter(fn(fam) { remote-mp.any(fn(rfam) { fam == rfam }) })

  Negotiated-caps(four-octet, route-refresh, ext-msg, common-mp, [], [])
}
