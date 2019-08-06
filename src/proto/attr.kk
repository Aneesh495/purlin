module proto/attr

import std/core/list
import std/core/string
import proto/types
import proto/wire

// RFC 4271 Attribute Type Codes
pub val attr-code-origin             : int = 1
pub val attr-code-as-path            : int = 2
pub val attr-code-next-hop           : int = 3
pub val attr-code-med                : int = 4
pub val attr-code-local-pref         : int = 5
pub val attr-code-atomic-aggregate   : int = 6
pub val attr-code-aggregator         : int = 7
pub val attr-code-community          : int = 8
pub val attr-code-originator-id      : int = 9
pub val attr-code-cluster-list       : int = 10
pub val attr-code-mp-reach-nlri      : int = 14
pub val attr-code-mp-unreach-nlri    : int = 15
pub val attr-code-extended-community : int = 16
pub val attr-code-as4-path           : int = 17
pub val attr-code-as4-aggregator     : int = 18
pub val attr-code-large-community    : int = 32

// Origin codes (RFC 4271 §4.3)
pub type origin-type
  OriginIgp         // 0: IGP (Network statement or interior protocol)
  OriginEgp         // 1: EGP (Historic exterior gateway protocol)
  OriginIncomplete  // 2: INCOMPLETE (Redistributed route)

pub fun origin-type/show(o : origin-type) : string {
  match o
    OriginIgp -> "IGP"
    OriginEgp -> "EGP"
    OriginIncomplete -> "INCOMPLETE"
}

pub fun origin-type/(==)(a : origin-type, b : origin-type) : bool {
  match (a, b)
    (OriginIgp, OriginIgp) -> True
    (OriginEgp, OriginEgp) -> True
    (OriginIncomplete, OriginIncomplete) -> True
    _ -> False
}

pub fun origin-type/cmp(a : origin-type, b : origin-type) : order {
  val score-a = match a { OriginIgp -> 0; OriginEgp -> 1; OriginIncomplete -> 2 }
  val score-b = match b { OriginIgp -> 0; OriginEgp -> 1; OriginIncomplete -> 2 }
  score-a.cmp(score-b)
}

// AS Path Segment Type (RFC 4271 §4.3)
pub val as-segment-set      : int = 1 // Unordered set of ASes
pub val as-segment-sequence : int = 2 // Ordered sequence of ASes

pub struct as-segment
  seg-type : int
  asns     : list<asn>

pub fun as-segment/show(s : as-segment) : string {
  val asns-str = s.asns.map(show).join(" ")
  if s.seg-type == as-segment-set then "{" ++ asns-str ++ "}"
  else asns-str
}

pub fun as-segment/(==)(a : as-segment, b : as-segment) : bool {
  a.seg-type == b.seg-type && a.asns == b.asns
}

// AS Path
pub struct as-path
  segments : list<as-segment>

pub fun as-path/show(p : as-path) : string {
  if p.segments.is-empty then "(empty)"
  else p.segments.map(show).join(" ")
}

pub fun as-path/(==)(a : as-path, b : as-path) : bool {
  a.segments == b.segments
}

// Calculate AS_PATH length for best-path decision (RFC 4271 §9.1.2.2.a):
// AS_SEQUENCE adds length equal to number of ASNs in the sequence.
// AS_SET adds 1 to length regardless of the number of ASNs in the set.
pub fun as-path-length(p : as-path) : int {
  p.segments.foldl(0, fn(acc, seg) {
    if seg.seg-type == as-segment-sequence then acc + seg.asns.length
    else acc + 1
  })
}

// BGP Loop Detection Algorithm (RFC 4271 §9.1.2):
// Checks if the local ASN already appears anywhere in the AS_PATH.
pub fun has-as-loop(p : as-path, local-asn : asn) : bool {
  p.segments.any(fn(seg) {
    seg.asns.any(fn(a) { a == local-asn })
  })
}

// Prepend an ASN to the AS_PATH (prepends to first AS_SEQUENCE, or creates one)
pub fun as-path-prepend(p : as-path, a : asn) : as-path {
  match p.segments
    Cons(s, rest) ->
      if s.seg-type == as-segment-sequence then {
        As-path(Cons(As-segment(as-segment-sequence, Cons(a, s.asns)), rest))
      } else {
        As-path(Cons(As-segment(as-segment-sequence, [a]), p.segments))
      }
    Nil -> As-path([As-segment(as-segment-sequence, [a])])
}

// RFC 1997 Standard 32-bit BGP Community
pub struct community
  asn-high : int
  val-low  : int

pub fun community-create(h : int, l : int) : community {
  Community(h, l)
}

pub fun community/show(c : community) : string {
  if c.asn-high == 65535 && c.val-low == 65281 then "NO_EXPORT"
  elif c.asn-high == 65535 && c.val-low == 65282 then "NO_ADVERTISE"
  elif c.asn-high == 65535 && c.val-low == 65283 then "NO_EXPORT_SUBCONFED"
  else c.asn-high.show ++ ":" ++ c.val-low.show
}

pub fun community/(==)(a : community, b : community) : bool {
  a.asn-high == b.asn-high && a.val-low == b.val-low
}

// Well-known BGP Community constants
pub val comm-no-export            : community = Community(65535, 65281)
pub val comm-no-advertise         : community = Community(65535, 65282)
pub val comm-no-export-subconfed  : community = Community(65535, 65283)

// RFC 4360 Extended Community (8 bytes)
pub struct ext-community
  type-high : int
  type-low  : int
  val-bytes : list<int> // 6 bytes

pub fun ext-comm-route-target(asn-val : int, target-id : int) : ext-community {
  val b0 = (asn-val / 256) % 256
  val b1 = asn-val % 256
  val b2 = (target-id / 16777216) % 256
  val b3 = (target-id / 65536) % 256
  val b4 = (target-id / 256) % 256
  val b5 = target-id % 256
  Ext-community(0, 2, [b0, b1, b2, b3, b4, b5])
}

pub fun ext-community/show(ec : ext-community) : string {
  if ec.type-high == 0 && ec.type-low == 2 && ec.val-bytes.length == 6 then {
    val b0 = ec.val-bytes.head.default(0)
    val b1 = ec.val-bytes.drop(1).head.default(0)
    val target-asn = (b0 * 256) + b1
    val t0 = ec.val-bytes.drop(2).head.default(0)
    val t1 = ec.val-bytes.drop(3).head.default(0)
    val t2 = ec.val-bytes.drop(4).head.default(0)
    val t3 = ec.val-bytes.drop(5).head.default(0)
    val target-id = (t0 * 16777216) + (t1 * 65536) + (t2 * 256) + t3
    "target:" ++ target-asn.show ++ ":" ++ target-id.show
  } else {
    "ExtCommunity(type=" ++ ec.type-high.show ++ ":" ++ ec.type-low.show ++ ")"
  }
}

pub fun ext-community/(==)(a : ext-community, b : ext-community) : bool {
  a.type-high == b.type-high && a.type-low == b.type-low && a.val-bytes == b.val-bytes
}

// Complete BGP Path Attribute ADT
pub type path-attribute
  AttrOrigin(origin : origin-type)
  AttrAsPath(path : as-path)
  AttrNextHop(next-hop : ipv4)
  AttrMed(metric : int)
  AttrLocalPref(pref : int)
  AttrAtomicAggregate
  AttrAggregator(agg-asn : asn, agg-id : router-id)
  AttrCommunity(communities : list<community>)
  AttrOriginatorId(originator : router-id)
  AttrClusterList(clusters : list<router-id>)
  AttrExtCommunity(ext-communities : list<ext-community>)
  AttrUnknown(type-code : int, flags : int, raw-val : list<int>)

pub fun path-attribute/show(attr : path-attribute) : string {
  match attr
    AttrOrigin(o) -> "Origin(" ++ o.show ++ ")"
    AttrAsPath(p) -> "AsPath(" ++ p.show ++ ")"
    AttrNextHop(nh) -> "NextHop(" ++ nh.show ++ ")"
    AttrMed(m) -> "MED(" ++ m.show ++ ")"
    AttrLocalPref(lp) -> "LocalPref(" ++ lp.show ++ ")"
    AttrAtomicAggregate -> "AtomicAggregate"
    AttrAggregator(a, r) -> "Aggregator(" ++ a.show ++ ", " ++ r.show ++ ")"
    AttrCommunity(cs) -> "Community(" ++ cs.map(show).join(" ") ++ ")"
    AttrOriginatorId(r) -> "OriginatorId(" ++ r.show ++ ")"
    AttrClusterList(cls) -> "ClusterList(" ++ cls.map(show).join(" ") ++ ")"
    AttrExtCommunity(ecs) -> "ExtCommunity(" ++ ecs.map(show).join(" ") ++ ")"
    AttrUnknown(c, _flags, bs) -> "UnknownAttr(code=" ++ c.show ++ ", len=" ++ bs.length.show ++ ")"
}

pub fun path-attribute/(==)(a : path-attribute, b : path-attribute) : bool {
  match (a, b)
    (AttrOrigin(o1), AttrOrigin(o2)) -> o1 == o2
    (AttrAsPath(p1), AttrAsPath(p2)) -> p1 == p2
    (AttrNextHop(nh1), AttrNextHop(nh2)) -> nh1 == nh2
    (AttrMed(m1), AttrMed(m2)) -> m1 == m2
    (AttrLocalPref(lp1), AttrLocalPref(lp2)) -> lp1 == lp2
    (AttrAtomicAggregate, AttrAtomicAggregate) -> True
    (AttrAggregator(a1, r1), AttrAggregator(a2, r2)) -> a1 == a2 && r1 == r2
    (AttrCommunity(c1), AttrCommunity(c2)) -> c1 == c2
    (AttrOriginatorId(r1), AttrOriginatorId(r2)) -> r1 == r2
    (AttrClusterList(cl1), AttrClusterList(cl2)) -> cl1 == cl2
    (AttrExtCommunity(ec1), AttrExtCommunity(ec2)) -> ec1 == ec2
    (AttrUnknown(c1, f1, bs1), AttrUnknown(c2, f2, bs2)) -> c1 == c2 && f1 == f2 && bs1 == bs2
    _ -> False
}

// Encode Path Attribute with Flags (1B) + Type Code (1B) + Length (1B or 2B) + Value
pub fun encode-attribute(attr : path-attribute, use-four-byte-asn : bool) : list<int> {
  match attr
    AttrOrigin(o) -> {
      // Well-known mandatory, transitive (flags: 0x40 = 64)
      val code-val = match o { OriginIgp -> 0; OriginEgp -> 1; OriginIncomplete -> 2 }
      [64, attr-code-origin, 1, code-val]
    }
    AttrAsPath(p) -> {
      // Well-known mandatory, transitive (flags: 0x40 = 64)
      val seg-bytes = p.segments.flatmap(fn(seg) {
        val seg-type-byte = seg.seg-type
        val seg-len-byte = seg.asns.length
        val asn-bytes = if use-four-byte-asn then {
          seg.asns.flatmap(write-asn4)
        } else {
          seg.asns.flatmap(write-asn2)
        }
        [seg-type-byte, seg-len-byte] ++ asn-bytes
      })
      [64, attr-code-as-path, seg-bytes.length] ++ seg-bytes
    }
    AttrNextHop(nh) -> {
      // Well-known mandatory, transitive (flags: 0x40 = 64)
      [64, attr-code-next-hop, 4] ++ write-ipv4(nh)
    }
    AttrMed(m) -> {
      // Optional non-transitive (flags: 0x80 = 128)
      [128, attr-code-med, 4] ++ write-u32(m)
    }
    AttrLocalPref(lp) -> {
      // Well-known discretionary, transitive (flags: 0x40 = 64)
      [64, attr-code-local-pref, 4] ++ write-u32(lp)
    }
    AttrAtomicAggregate -> {
      // Well-known discretionary (flags: 0x40 = 64)
      [64, attr-code-atomic-aggregate, 0]
    }
    AttrAggregator(agg-a, agg-r) -> {
      // Optional transitive (flags: 0xC0 = 192)
      val a-bytes = if use-four-byte-asn then write-asn4(agg-a) else write-asn2(agg-a)
      val r-bytes = write-ipv4(agg-r.rid-addr)
      val val-bytes = a-bytes ++ r-bytes
      [192, attr-code-aggregator, val-bytes.length] ++ val-bytes
    }
    AttrCommunity(cs) -> {
      // Optional transitive (flags: 0xC0 = 192)
      val comm-bytes = cs.flatmap(fn(c) {
        write-u16(c.asn-high) ++ write-u16(c.val-low)
      })
      [192, attr-code-community, comm-bytes.length] ++ comm-bytes
    }
    AttrOriginatorId(orig-r) -> {
      // Optional non-transitive (flags: 0x80 = 128)
      [128, attr-code-originator-id, 4] ++ write-ipv4(orig-r.rid-addr)
    }
    AttrClusterList(cls) -> {
      // Optional non-transitive (flags: 0x80 = 128)
      val cl-bytes = cls.flatmap(fn(r) { write-ipv4(r.rid-addr) })
      [128, attr-code-cluster-list, cl-bytes.length] ++ cl-bytes
    }
    AttrExtCommunity(ecs) -> {
      // Optional transitive (flags: 0xC0 = 192)
      val ec-bytes = ecs.flatmap(fn(ec) {
        [ec.type-high, ec.type-low] ++ ec.val-bytes.take(6)
      })
      [192, attr-code-extended-community, ec-bytes.length] ++ ec-bytes
    }
    AttrUnknown(c, flags, bs) -> {
      [flags, c, bs.length] ++ bs
    }
}

// Decode AS Path segments
pub fun decode-as-path(bytes : list<int>, use-four-byte-asn : bool) : div as-path {
  val asn-size = if use-four-byte-asn then 4 else 2
  fun loop(curr : list<int>, seg-acc : list<as-segment>) : div list<as-segment> {
    match curr
      Cons(seg-type, Cons(seg-len, rest)) -> {
        val total-bytes = seg-len * asn-size
        if rest.length < total-bytes then seg-acc.reverse
        else {
          val seg-asn-bytes = rest.take(total-bytes)
          val remaining = rest.drop(total-bytes)
          
          fun parse-asns(b : list<int>, count : int, asn-acc : list<asn>) : div list<asn> {
            if count <= 0 then asn-acc.reverse
            else {
              if use-four-byte-asn then {
                match b
                  Cons(b0, Cons(b1, Cons(b2, Cons(b3, r)))) ->
                    parse-asns(r, count - 1, Cons(Asn(decode-u32(b0, b1, b2, b3)), asn-acc))
                  _ -> asn-acc.reverse
              } else {
                match b
                  Cons(b0, Cons(b1, r)) ->
                    parse-asns(r, count - 1, Cons(Asn(decode-u16(b0, b1)), asn-acc))
                  _ -> asn-acc.reverse
              }
            }
          }
          
          val asns = parse-asns(seg-asn-bytes, seg-len, [])
          val seg = As-segment(seg-type, asns)
          loop(remaining, Cons(seg, seg-acc))
        }
      }
      _ -> seg-acc.reverse
  }
  As-path(loop(bytes, []))
}

// Decode Communities list
pub fun decode-communities(bytes : list<int>) : div list<community> {
  fun loop(curr : list<int>, acc : list<community>) : div list<community> {
    match curr
      Cons(b0, Cons(b1, Cons(b2, Cons(b3, rest)))) -> {
        val h = decode-u16(b0, b1)
        val l = decode-u16(b2, b3)
        loop(rest, Cons(Community(h, l), acc))
      }
      _ -> acc.reverse
  }
  loop(bytes, [])
}

// Decode Extended Communities list (RFC 4360 8-byte chunks)
pub fun decode-ext-communities(bytes : list<int>) : div list<ext-community> {
  fun loop(curr : list<int>, acc : list<ext-community>) : div list<ext-community> {
    if curr.length < 8 then acc.reverse
    else {
      val th = curr.head.default(0)
      val tl = curr.drop(1).head.default(0)
      val vb = curr.drop(2).take(6)
      val rest = curr.drop(8)
      loop(rest, Cons(Ext-community(th, tl, vb), acc))
    }
  }
  loop(bytes, [])
}

// Decode Cluster List (RFC 4456 4-byte Router IDs)
pub fun decode-cluster-list(bytes : list<int>) : div list<router-id> {
  fun loop(curr : list<int>, acc : list<router-id>) : div list<router-id> {
    match curr
      Cons(b0, Cons(b1, Cons(b2, Cons(b3, rest)))) -> {
        val rid = router-id(b0, b1, b2, b3)
        loop(rest, Cons(rid, acc))
      }
      _ -> acc.reverse
  }
  loop(bytes, [])
}

// Decode a single path attribute from bytes
pub fun decode-single-attribute(code : int, flags : int, val-bytes : list<int>, use-four-byte-asn : bool) : div path-attribute {
  if code == attr-code-origin then {
    val o-code = val-bytes.head.default(2)
    val orig = match o-code
      0 -> OriginIgp
      1 -> OriginEgp
      _ -> OriginIncomplete
    AttrOrigin(orig)
  } elif code == attr-code-as-path then {
    AttrAsPath(decode-as-path(val-bytes, use-four-byte-asn))
  } elif code == attr-code-next-hop && val-bytes.length >= 4 then {
    val b0 = val-bytes.head.default(0)
    val b1 = val-bytes.drop(1).head.default(0)
    val b2 = val-bytes.drop(2).head.default(0)
    val b3 = val-bytes.drop(3).head.default(0)
    AttrNextHop(ipv4-create(b0, b1, b2, b3))
  } elif code == attr-code-med && val-bytes.length >= 4 then {
    val b0 = val-bytes.head.default(0)
    val b1 = val-bytes.drop(1).head.default(0)
    val b2 = val-bytes.drop(2).head.default(0)
    val b3 = val-bytes.drop(3).head.default(0)
    AttrMed(decode-u32(b0, b1, b2, b3))
  } elif code == attr-code-local-pref && val-bytes.length >= 4 then {
    val b0 = val-bytes.head.default(0)
    val b1 = val-bytes.drop(1).head.default(0)
    val b2 = val-bytes.drop(2).head.default(0)
    val b3 = val-bytes.drop(3).head.default(0)
    AttrLocalPref(decode-u32(b0, b1, b2, b3))
  } elif code == attr-code-atomic-aggregate then {
    AttrAtomicAggregate
  } elif code == attr-code-aggregator then {
    if use-four-byte-asn && val-bytes.length >= 8 then {
      val a = decode-u32(val-bytes.head.default(0), val-bytes.drop(1).head.default(0),
                         val-bytes.drop(2).head.default(0), val-bytes.drop(3).head.default(0))
      val r = router-id(val-bytes.drop(4).head.default(0), val-bytes.drop(5).head.default(0),
                        val-bytes.drop(6).head.default(0), val-bytes.drop(7).head.default(0))
      AttrAggregator(Asn(a), r)
    } elif !use-four-byte-asn && val-bytes.length >= 6 then {
      val a = decode-u16(val-bytes.head.default(0), val-bytes.drop(1).head.default(0))
      val r = router-id(val-bytes.drop(2).head.default(0), val-bytes.drop(3).head.default(0),
                        val-bytes.drop(4).head.default(0), val-bytes.drop(5).head.default(0))
      AttrAggregator(Asn(a), r)
    } else {
      AttrUnknown(code, flags, val-bytes)
    }
  } elif code == attr-code-community then {
    AttrCommunity(decode-communities(val-bytes))
  } elif code == attr-code-originator-id && val-bytes.length >= 4 then {
    val r = router-id(val-bytes.head.default(0), val-bytes.drop(1).head.default(0),
                      val-bytes.drop(2).head.default(0), val-bytes.drop(3).head.default(0))
    AttrOriginatorId(r)
  } elif code == attr-code-cluster-list then {
    AttrClusterList(decode-cluster-list(val-bytes))
  } elif code == attr-code-extended-community then {
    AttrExtCommunity(decode-ext-communities(val-bytes))
  } else {
    AttrUnknown(code, flags, val-bytes)
  }
}

// Decode complete list of Path Attributes from UPDATE message bytes
pub fun decode-attributes(bytes : list<int>, use-four-byte-asn : bool) : div list<path-attribute> {
  fun loop(curr : list<int>, acc : list<path-attribute>) : div list<path-attribute> {
    match curr
      Cons(flags, Cons(code, rest)) -> {
        val has-extended-len = (flags / 16) % 2 == 1
        if has-extended-len then {
          match rest
            Cons(l0, Cons(l1, payload-rest)) -> {
              val attr-len = decode-u16(l0, l1)
              if payload-rest.length < attr-len then acc.reverse
              else {
                val val-bytes = payload-rest.take(attr-len)
                val remaining = payload-rest.drop(attr-len)
                val attr = decode-single-attribute(code, flags, val-bytes, use-four-byte-asn)
                loop(remaining, Cons(attr, acc))
              }
            }
            _ -> acc.reverse
        } else {
          match rest
            Cons(attr-len, payload-rest) -> {
              if payload-rest.length < attr-len then acc.reverse
              else {
                val val-bytes = payload-rest.take(attr-len)
                val remaining = payload-rest.drop(attr-len)
                val attr = decode-single-attribute(code, flags, val-bytes, use-four-byte-asn)
                loop(remaining, Cons(attr, acc))
              }
            }
            _ -> acc.reverse
        }
      }
      _ -> acc.reverse
  }
  loop(bytes, [])
}
