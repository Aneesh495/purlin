module unit/test-fsm

import proto/types
import proto/wire
import proto/capabilities
import proto/attr
import proto/message
import proto/fsm

fun get-test-config() : fsm-config {
  fsm-config-create(
    asn(65001),
    asn(65002),
    router-id(10, 0, 0, 1),
    router-id(10, 0, 0, 2)
  )
}

fun test-happy-path-peering() : bool {
  val cfg = get-test-config()
  
  // Step 1: Idle -> Connect
  val res1 = step-fsm(StateIdle, EvManualStart, cfg)
  val ok1 = (res1.next-state == StateConnect) &&
            res1.actions.any(fn(a) { a == ActInitTcpConnection })
  
  // Step 2: Connect -> OpenSent
  val res2 = step-fsm(StateConnect, EvTcpConnectionConfirmed, cfg)
  val ok2 = (res2.next-state == StateOpenSent) &&
            res2.actions.any(fn(a) { a == ActSendOpen })
  
  // Step 3: OpenSent -> OpenConfirm
  val valid-open = MsgOpen(4, asn(65002), 90, router-id(10, 0, 0, 2), [])
  val res3 = step-fsm(StateOpenSent, EvRecvOpen(valid-open), cfg)
  val ok3 = (res3.next-state == StateOpenConfirm) &&
            res3.actions.any(fn(a) { a == ActSendKeepalive })
  
  // Step 4: OpenConfirm -> Established
  val res4 = step-fsm(StateOpenConfirm, EvRecvKeepalive, cfg)
  val ok4 = (res4.next-state == StateEstablished) &&
            res4.actions.any(fn(a) { a == ActSessionEstablished })
  
  ok1 && ok2 && ok3 && ok4
}

fun test-tcp-retry-fsm() : bool {
  val cfg = get-test-config()
  // Connect -> Active on failure
  val res1 = step-fsm(StateConnect, EvTcpConnectionFails, cfg)
  val ok1 = (res1.next-state == StateActive)
  
  // Active -> Connect on retry timer
  val res2 = step-fsm(StateActive, EvConnectRetryTimerExpires, cfg)
  val ok2 = (res2.next-state == StateConnect) &&
            res2.actions.any(fn(a) { a == ActInitTcpConnection })
  
  ok1 && ok2
}

fun test-open-validation-errors() : bool {
  val cfg = get-test-config()
  
  // Version mismatch (version 3)
  val bad-ver-open = MsgOpen(3, asn(65002), 90, router-id(10, 0, 0, 2), [])
  val res-ver = step-fsm(StateOpenSent, EvRecvOpen(bad-ver-open), cfg)
  val ver-ok = (res-ver.next-state == StateIdle) &&
               res-ver.actions.any(fn(a) { a == ActSendNotification(err-code-open-message, subcode-bad-version, [4]) })
  
  // ASN mismatch (peer claims to be AS 65099 instead of 65002)
  val bad-asn-open = MsgOpen(4, asn(65099), 90, router-id(10, 0, 0, 2), [])
  val res-asn = step-fsm(StateOpenSent, EvRecvOpen(bad-asn-open), cfg)
  val asn-ok = (res-asn.next-state == StateIdle) &&
               res-asn.actions.any(fn(a) { a == ActSendNotification(err-code-open-message, subcode-bad-peer-as, []) })
  
  // Router ID collision (peer claims same router ID as local)
  val bad-id-open = MsgOpen(4, asn(65002), 90, router-id(10, 0, 0, 1), [])
  val res-id = step-fsm(StateOpenSent, EvRecvOpen(bad-id-open), cfg)
  val id-ok = (res-id.next-state == StateIdle) &&
              res-id.actions.any(fn(a) { a == ActSendNotification(err-code-open-message, subcode-bad-bgp-id, []) })
  
  ver-ok && asn-ok && id-ok
}

fun test-established-hold-timer-expiry() : bool {
  val cfg = get-test-config()
  val res = step-fsm(StateEstablished, EvHoldTimerExpires, cfg)
  (res.next-state == StateIdle) &&
  res.actions.any(fn(a) { a == ActSendNotification(err-code-hold-timer-exp, 0, []) })
}

fun test-manual-stop-teardown() : bool {
  val cfg = get-test-config()
  val res = step-fsm(StateEstablished, EvManualStop, cfg)
  (res.next-state == StateIdle) &&
  res.actions.any(fn(a) { a == ActSendNotification(err-code-cease, subcode-admin-shutdown, []) })
}

fun test-collision-resolution() : bool {
  val r1 = router-id(10, 0, 0, 2)
  val r2 = router-id(10, 0, 0, 1)
  // Higher router ID (10.0.0.2) wins over (10.0.0.1)
  val r1-wins = resolve-connection-collision(r1, r2)
  val r2-loses = !resolve-connection-collision(r2, r1)
  
  r1-wins && r2-loses
}

fun main() {
  val t1 = test-happy-path-peering()
  val t2 = test-tcp-retry-fsm()
  val t3 = test-open-validation-errors()
  val t4 = test-established-hold-timer-expiry()
  val t5 = test-manual-stop-teardown()
  val t6 = test-collision-resolution()
  
  if t1 && t2 && t3 && t4 && t5 && t6 then {
    println("PASS: proto/fsm unit tests passed successfully")
  } else {
    println("FAIL: proto/fsm unit tests failed")
  }
}
