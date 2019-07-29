module unit/test-wire

import proto/types
import proto/wire

fun test-keepalive-framing() : bool {
  val framed = frame-message(msg-type-keepalive, [])
  val len-ok = (framed.length == 19)
  match parse-bgp-header(framed)
    Right((h, payload)) ->
      (h.length == 19) && (h.msg-type == msg-type-keepalive) && (payload.length == 0) && len-ok
    Left(_) -> False
}

fun test-payload-framing() : bool {
  val dummy-payload = [1, 2, 3, 4, 5]
  val framed = frame-message(msg-type-update, dummy-payload)
  val len-ok = (framed.length == 24)
  match parse-bgp-header(framed)
    Right((h, payload)) ->
      (h.length == 24) && (h.msg-type == msg-type-update) && (payload == dummy-payload) && len-ok
    Left(_) -> False
}

fun test-marker-desync() : bool {
  val framed = frame-message(msg-type-keepalive, [])
  // Corrupt first byte of marker
  val corrupted = Cons(0, framed.drop(1))
  match parse-bgp-header(corrupted)
    Left(WireErrMarkerNotSynchronized) -> True
    _ -> False
}

fun test-incomplete-header() : bool {
  val short-bytes = [255, 255, 255]
  match parse-bgp-header(short-bytes)
    Left(WireErrIncompleteHeader) -> True
    _ -> False
}

fun test-bad-message-length() : bool {
  // Construct header claiming length 10 (< 19)
  val bad-bytes = bgp-marker-bytes() ++ write-u16(10) ++ write-u8(msg-type-keepalive)
  match parse-bgp-header(bad-bytes)
    Left(WireErrBadMessageLength(10)) -> True
    _ -> False
}

fun test-bad-message-type() : bool {
  // Construct header with message type 42
  val bad-type = bgp-marker-bytes() ++ write-u16(19) ++ write-u8(42)
  match parse-bgp-header(bad-type)
    Left(WireErrBadMessageType(42)) -> True
    _ -> False
}

fun test-truncated-payload() : bool {
  // Header claims 24 bytes (5 payload bytes), but only 2 payload bytes provided
  val trunc = bgp-marker-bytes() ++ write-u16(24) ++ write-u8(msg-type-update) ++ [1, 2]
  match parse-bgp-header(trunc)
    Left(WireErrPayloadTruncated(5, 2)) -> True
    _ -> False
}

fun main() {
  val t1 = test-keepalive-framing()
  val t2 = test-payload-framing()
  val t3 = test-marker-desync()
  val t4 = test-incomplete-header()
  val t5 = test-bad-message-length()
  val t6 = test-bad-message-type()
  val t7 = test-truncated-payload()
  
  if t1 && t2 && t3 && t4 && t5 && t6 && t7 then {
    println("PASS: proto/wire unit tests passed successfully")
  } else {
    println("FAIL: proto/wire unit tests failed")
  }
}
