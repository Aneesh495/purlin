module unit/test-patricia

import proto/types
import rib/patricia

fun test-empty-trie() : div bool {
  val t : patricia-trie<string> = patricia-empty()
  is-empty(t) && (patricia-count(t) == 0)
}

fun test-exact-lookup() : div bool {
  var t : patricia-trie<string> := patricia-empty()
  val p1 = prefix4(192, 168, 1, 0, 24)
  val p2 = prefix4(10, 0, 0, 0, 8)
  
  t := patricia-insert(t, p1, "lan")
  t := patricia-insert(t, p2, "corp")
  
  val l1 = patricia-lookup-exact(t, p1)
  val l2 = patricia-lookup-exact(t, p2)
  val l3 = patricia-lookup-exact(t, prefix4(172, 16, 0, 0, 16))
  
  (l1 == Just("lan")) && (l2 == Just("corp")) && (l3 == Nothing)
}

fun test-longest-prefix-match() : div bool {
  var t : patricia-trie<string> := patricia-empty()
  
  val p-default = prefix4(0, 0, 0, 0, 0)
  val p-class-a = prefix4(10, 0, 0, 0, 8)
  val p-office  = prefix4(10, 1, 0, 0, 16)
  val p-dc      = prefix4(10, 1, 5, 0, 24)
  
  t := patricia-insert(t, p-default, "default")
  t := patricia-insert(t, p-class-a, "class-a")
  t := patricia-insert(t, p-office, "office")
  t := patricia-insert(t, p-dc, "datacenter")
  
  // 10.1.5.42 should match the most specific /24 datacenter route
  val match-dc = patricia-lpm(t, ipv4-create(10, 1, 5, 42))
  val ok-dc = match match-dc
    Just((p, tag)) -> (p == p-dc) && (tag == "datacenter")
    Nothing -> False
    
  // 10.1.8.1 should match /16 office route
  val match-office = patricia-lpm(t, ipv4-create(10, 1, 8, 1))
  val ok-office = match match-office
    Just((p, tag)) -> (p == p-office) && (tag == "office")
    Nothing -> False
    
  // 10.99.1.1 should match /8 class-a route
  val match-class-a = patricia-lpm(t, ipv4-create(10, 99, 1, 1))
  val ok-class-a = match match-class-a
    Just((p, tag)) -> (p == p-class-a) && (tag == "class-a")
    Nothing -> False
    
  // 192.168.1.1 should match /0 default route
  val match-def = patricia-lpm(t, ipv4-create(192, 168, 1, 1))
  val ok-def = match match-def
    Just((p, tag)) -> (p == p-default) && (tag == "default")
    Nothing -> False
    
  ok-dc && ok-office && ok-class-a && ok-def
}

fun test-deletion-and-fallback() : div bool {
  var t : patricia-trie<string> := patricia-empty()
  
  val p-office = prefix4(10, 1, 0, 0, 16)
  val p-dc     = prefix4(10, 1, 5, 0, 24)
  
  t := patricia-insert(t, p-office, "office")
  t := patricia-insert(t, p-dc, "datacenter")
  
  val count-before = patricia-count(t) == 2
  
  // Delete /24 route
  t := patricia-delete(t, p-dc)
  val count-after = patricia-count(t) == 1
  
  // Query 10.1.5.42: should now fall back to /16 office!
  val match-fallback = patricia-lpm(t, ipv4-create(10, 1, 5, 42))
  val ok-fallback = match match-fallback
    Just((p, tag)) -> (p == p-office) && (tag == "office")
    Nothing -> False
    
  count-before && count-after && ok-fallback
}

fun main() {
  val t1 = test-empty-trie()
  val t2 = test-exact-lookup()
  val t3 = test-longest-prefix-match()
  val t4 = test-deletion-and-fallback()
  
  if t1 && t2 && t3 && t4 then {
    println("PASS: rib/patricia unit tests passed successfully")
  } else {
    println("FAIL: rib/patricia unit tests failed")
  }
}
