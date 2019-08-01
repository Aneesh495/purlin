module unit/test-capabilities

import proto/types
import proto/wire
import proto/capabilities

fun test-four-octet-roundtrip() : div bool {
  val original = CapFourOctetAsn(asn(65001))
  val encoded = encode-capability(original)
  val decoded = decode-capabilities(encoded)
  decoded == [original]
}

fun test-mp-bgp-roundtrip() : div bool {
  val cap-v4 = CapMpBgp(afi-ipv4, safi-unicast)
  val cap-v6 = CapMpBgp(afi-ipv6, safi-unicast)
  val cap-evpn = CapMpBgp(afi-l2vpn, safi-evpn)
  
  val caps = [cap-v4, cap-v6, cap-evpn]
  val encoded = caps.flatmap(encode-capability)
  val decoded = decode-capabilities(encoded)
  
  decoded == caps
}

fun test-route-refresh-roundtrip() : div bool {
  val cap = CapRouteRefresh
  val encoded = encode-capability(cap)
  val decoded = decode-capabilities(encoded)
  decoded == [cap]
}

fun test-add-path-roundtrip() : div bool {
  val cap = CapAddPath(afi-ipv4, safi-unicast, add-path-both)
  val encoded = encode-capability(cap)
  val decoded = decode-capabilities(encoded)
  decoded == [cap]
}

fun test-graceful-restart-roundtrip() : div bool {
  val cap = CapGracefulRestart(120, True)
  val encoded = encode-capability(cap)
  val decoded = decode-capabilities(encoded)
  decoded == [cap]
}

fun test-extended-message-roundtrip() : div bool {
  val cap = CapExtendedMessage
  val encoded = encode-capability(cap)
  val decoded = decode-capabilities(encoded)
  decoded == [cap]
}

fun test-open-opt-params-roundtrip() : div bool {
  val caps = [
    CapFourOctetAsn(asn(65540)),
    CapRouteRefresh,
    CapMpBgp(afi-ipv4, safi-unicast),
    CapMpBgp(afi-l2vpn, safi-evpn)
  ]
  val opt-params-bytes = encode-open-opt-params(caps)
  val decoded = decode-open-opt-params(opt-params-bytes)
  decoded == caps
}

fun test-negotiation() : div bool {
  val local-caps = [
    CapFourOctetAsn(asn(65001)),
    CapRouteRefresh,
    CapMpBgp(afi-ipv4, safi-unicast),
    CapMpBgp(afi-l2vpn, safi-evpn)
  ]
  val remote-caps = [
    CapFourOctetAsn(asn(65002)),
    CapMpBgp(afi-ipv4, safi-unicast)
  ]
  
  val session = negotiate-session(local-caps, remote-caps)
  val four-octet-ok = session.supports-four-octet-asn
  val rr-not-ok = !session.supports-route-refresh // Remote does not support RR
  val fams-ok = (session.mp-bgp-families == [Afi-safi(afi-ipv4, safi-unicast)])
  
  four-octet-ok && rr-not-ok && fams-ok
}

fun main() {
  val t1 = test-four-octet-roundtrip()
  val t2 = test-mp-bgp-roundtrip()
  val t3 = test-route-refresh-roundtrip()
  val t4 = test-add-path-roundtrip()
  val t5 = test-graceful-restart-roundtrip()
  val t6 = test-extended-message-roundtrip()
  val t7 = test-open-opt-params-roundtrip()
  val t8 = test-negotiation()
  
  if t1 && t2 && t3 && t4 && t5 && t6 && t7 && t8 then {
    println("PASS: proto/capabilities unit tests passed successfully")
  } else {
    println("FAIL: proto/capabilities unit tests failed")
  }
}
