module unit/test-message

import proto/types
import proto/wire
import proto/capabilities
import proto/attr
import proto/message

fun test-prefix-encoding-boundaries() : div bool {
  val p0 = prefix4(0, 0, 0, 0, 0)
  val p8 = prefix4(10, 0, 0, 0, 8)
  val p16 = prefix4(172, 16, 0, 0, 16)
  val p24 = prefix4(192, 168, 1, 0, 24)
  val p32 = prefix4(192, 168, 1, 100, 32)
  
  val prefixes = [p0, p8, p16, p24, p32]
  val encoded = prefixes.flatmap(encode-prefix)
  val decoded = decode-prefixes(encoded)
  
  decoded == prefixes
}

fun test-open-message-roundtrip() : div bool {
  val caps = [
    CapFourOctetAsn(asn(131072)),
    CapRouteRefresh,
    CapMpBgp(afi-ipv4, safi-unicast)
  ]
  val open-msg = MsgOpen(4, asn(131072), 90, router-id(10, 0, 0, 1), caps)
  val serialized = serialize-message(open-msg, True)
  
  match parse-message(serialized, True)
    Right(parsed) -> parsed == open-msg
    Left(_) -> False
}

fun test-update-message-roundtrip() : div bool {
  val withdrawn = [prefix4(10, 1, 0, 0, 16)]
  val attrs = [
    AttrOrigin(OriginIgp),
    AttrAsPath(As-path([As-segment(as-segment-sequence, [asn(65001), asn(65002)])])),
    AttrNextHop(ipv4-create(10, 0, 0, 1)),
    AttrMed(100),
    AttrLocalPref(150),
    AttrCommunity([community-create(65001, 200)])
  ]
  val nlri = [prefix4(192, 168, 1, 0, 24), prefix4(192, 168, 2, 0, 24)]
  val update-msg = MsgUpdate(withdrawn, attrs, nlri)
  
  val serialized = serialize-message(update-msg, True)
  match parse-message(serialized, True)
    Right(parsed) -> parsed == update-msg
    Left(_) -> False
}

fun test-notification-roundtrip() : div bool {
  val notif = MsgNotification(err-code-update-message, subcode-as-loop-err, [1, 2, 3])
  val serialized = serialize-message(notif, True)
  match parse-message(serialized, True)
    Right(parsed) -> parsed == notif
    Left(_) -> False
}

fun test-keepalive-roundtrip() : div bool {
  val ka = MsgKeepalive
  val serialized = serialize-message(ka, True)
  match parse-message(serialized, True)
    Right(parsed) -> parsed == ka
    Left(_) -> False
}

fun test-route-refresh-roundtrip() : div bool {
  val rr = MsgRouteRefresh(afi-ipv4, safi-unicast)
  val serialized = serialize-message(rr, True)
  match parse-message(serialized, True)
    Right(parsed) -> parsed == rr
    Left(_) -> False
}

fun main() {
  val t1 = test-prefix-encoding-boundaries()
  val t2 = test-open-message-roundtrip()
  val t3 = test-update-message-roundtrip()
  val t4 = test-notification-roundtrip()
  val t5 = test-keepalive-roundtrip()
  val t6 = test-route-refresh-roundtrip()
  
  if t1 && t2 && t3 && t4 && t5 && t6 then {
    println("PASS: proto/message unit tests passed successfully")
  } else {
    println("FAIL: proto/message unit tests failed")
  }
}
