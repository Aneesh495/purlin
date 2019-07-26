module unit/test-types

import proto/types

fun test-ipv4() : bool {
  val ip1 = ipv4-create(192, 168, 1, 10)
  val ip2 = ipv4-create(192, 168, 1, 10)
  val ip3 = ipv4-create(10, 0, 0, 1)
  
  val eq-ok = (ip1 == ip2)
  val neq-ok = (ip1.cmp(ip3) == Gt)
  val str-ok = (ip1.show == "192.168.1.10")
  
  eq-ok && neq-ok && str-ok
}

fun test-prefix() : bool {
  val p1 = prefix4(192, 168, 1, 0, 24)
  val ip-in = ipv4-create(192, 168, 1, 45)
  val ip-out = ipv4-create(192, 168, 2, 1)
  
  val contains-in = prefix-contains-ipv4(p1, ip-in)
  val contains-out = !prefix-contains-ipv4(p1, ip-out)
  
  val child = prefix4(192, 168, 1, 128, 25)
  val subnet-ok = prefix-is-subnet(child, p1)
  val not-subnet = !prefix-is-subnet(p1, child)
  
  contains-in && contains-out && subnet-ok && not-subnet
}

fun test-asn() : bool {
  val a1 = asn(65001)
  val a2 = asn(65002)
  val priv-ok = is-private(a1)
  val pub-asn = asn(15169) // Google ASN
  val not-priv = !is-private(pub-asn)
  val cmp-ok = (a1.cmp(a2) == Lt)
  
  priv-ok && not-priv && cmp-ok
}

fun test-router-id() : bool {
  val r1 = router-id(10, 0, 0, 1)
  val r2 = router-id(10, 0, 0, 2)
  val cmp-ok = (r1.cmp(r2) == Lt)
  val str-ok = (r1.show == "10.0.0.1")
  
  cmp-ok && str-ok
}

fun main() {
  val t1 = test-ipv4()
  val t2 = test-prefix()
  val t3 = test-asn()
  val t4 = test-router-id()
  
  if t1 && t2 && t3 && t4 then {
    println("PASS: proto/types unit tests passed successfully")
  } else {
    println("FAIL: proto/types unit tests failed")
  }
}
