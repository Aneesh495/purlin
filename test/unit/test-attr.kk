module unit/test-attr

import proto/types
import proto/wire
import proto/attr

fun test-origin-roundtrip() : div bool {
  val orig = AttrOrigin(OriginIgp)
  val encoded = encode-attribute(orig, True)
  val decoded = decode-attributes(encoded, True)
  decoded == [orig]
}

fun test-as-path-loop-detection() : bool {
  val seg1 = As-segment(as-segment-sequence, [asn(65001), asn(65002), asn(65003)])
  val path = As-path([seg1])
  
  val has-loop-ok = has-as-loop(path, asn(65002))
  val no-loop-ok = !has-as-loop(path, asn(65099))
  
  has-loop-ok && no-loop-ok
}

fun test-as-path-prepend-and-len() : bool {
  val seg1 = As-segment(as-segment-sequence, [asn(65002), asn(65003)])
  val seg-set = As-segment(as-segment-set, [asn(65010), asn(65011)])
  val path = As-path([seg1, seg-set])
  
  // Length before prepend: 2 (sequence) + 1 (set counts as 1) = 3
  val len-before = as-path-length(path) == 3
  
  val prepended = as-path-prepend(path, asn(65001))
  val len-after = as-path-length(prepended) == 4
  
  len-before && len-after
}

fun test-as-path-roundtrip-four-byte() : div bool {
  val seg1 = As-segment(as-segment-sequence, [asn(65001), asn(131072)])
  val path = AttrAsPath(As-path([seg1]))
  
  val encoded = encode-attribute(path, True)
  val decoded = decode-attributes(encoded, True)
  
  decoded == [path]
}

fun test-as-path-roundtrip-two-byte() : div bool {
  val seg1 = As-segment(as-segment-sequence, [asn(65001), asn(65002)])
  val path = AttrAsPath(As-path([seg1]))
  
  val encoded = encode-attribute(path, False)
  val decoded = decode-attributes(encoded, False)
  
  decoded == [path]
}

fun test-next-hop-and-metrics() : div bool {
  val nh = AttrNextHop(ipv4-create(10, 0, 0, 1))
  val med = AttrMed(50)
  val lp = AttrLocalPref(200)
  val attrs = [nh, med, lp]
  
  val encoded = attrs.flatmap(fn(a) { encode-attribute(a, True) })
  val decoded = decode-attributes(encoded, True)
  
  decoded == attrs
}

fun test-communities-roundtrip() : div bool {
  val c1 = community-create(65001, 100)
  val c2 = comm-no-export
  val comm-attr = AttrCommunity([c1, c2])
  
  val encoded = encode-attribute(comm-attr, True)
  val decoded = decode-attributes(encoded, True)
  
  decoded == [comm-attr]
}

fun test-ext-communities-roundtrip() : div bool {
  val rt = ext-comm-route-target(65001, 10)
  val ec-attr = AttrExtCommunity([rt])
  
  val encoded = encode-attribute(ec-attr, True)
  val decoded = decode-attributes(encoded, True)
  
  decoded == [ec-attr]
}

fun test-originator-and-cluster-list() : div bool {
  val orig = AttrOriginatorId(router-id(10, 1, 1, 1))
  val cl = AttrClusterList([router-id(10, 254, 0, 1), router-id(10, 254, 0, 2)])
  val attrs = [orig, cl]
  
  val encoded = attrs.flatmap(fn(a) { encode-attribute(a, True) })
  val decoded = decode-attributes(encoded, True)
  
  decoded == attrs
}

fun main() {
  val t1 = test-origin-roundtrip()
  val t2 = test-as-path-loop-detection()
  val t3 = test-as-path-prepend-and-len()
  val t4 = test-as-path-roundtrip-four-byte()
  val t5 = test-as-path-roundtrip-two-byte()
  val t6 = test-next-hop-and-metrics()
  val t7 = test-communities-roundtrip()
  val t8 = test-ext-communities-roundtrip()
  val t9 = test-originator-and-cluster-list()
  
  if t1 && t2 && t3 && t4 && t5 && t6 && t7 && t8 && t9 then {
    println("PASS: proto/attr unit tests passed successfully")
  } else {
    println("FAIL: proto/attr unit tests failed")
  }
}
