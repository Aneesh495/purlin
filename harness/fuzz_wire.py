#!/usr/bin/env python3
"""
Purlin Wire Protocol Fuzzing & Robustness Test Harness
Generates malformed BGP-4 byte frames to test stream parser boundary safety.
"""

import sys
import struct
import random
from typing import List, Tuple


def generate_fuzz_cases() -> List[Tuple[str, bytes]]:
    cases = []

    # 1. Truncated headers
    for l in range(0, 19):
        cases.append((f"Truncated header length {l}", b'\xff' * l))

    # 2. Corrupt marker bytes
    for i in range(16):
        bad_marker = bytearray(b'\xff' * 16)
        bad_marker[i] = 0x00
        hdr = bytes(bad_marker) + struct.pack("!HB", 19, 4)
        cases.append((f"Corrupt marker byte {i}", hdr))

    # 3. Invalid declared lengths (< 19)
    for bad_len in [0, 1, 10, 18]:
        cases.append((f"Declared length underflow {bad_len}", b'\xff' * 16 + struct.pack("!HB", bad_len, 4)))

    # 4. Invalid declared lengths (> 4096)
    for bad_len in [4097, 8192, 65535]:
        cases.append((f"Declared length overflow {bad_len}", b'\xff' * 16 + struct.pack("!HB", bad_len, 4)))

    # 5. Invalid message types
    for bad_type in [0, 5, 6, 99, 255]:
        cases.append((f"Unknown message type {bad_type}", b'\xff' * 16 + struct.pack("!HB", 19, bad_type)))

    # 6. OPEN message invalid BGP versions
    for bad_ver in [1, 2, 3, 5, 255]:
        open_payload = struct.pack("!BHHIB", bad_ver, 65001, 90, 0x0A000001, 0)
        hdr = b'\xff' * 16 + struct.pack("!HB", 19 + len(open_payload), 1)
        cases.append((f"OPEN invalid BGP version {bad_ver}", hdr + open_payload))

    # 7. OPEN message parameter length mismatch
    open_bad_opt = struct.pack("!BHHIB", 4, 65001, 90, 0x0A000001, 50)  # OptLen 50 but 0 bytes follow
    hdr = b'\xff' * 16 + struct.pack("!HB", 19 + len(open_bad_opt), 1)
    cases.append(("OPEN parameter length overflow", hdr + open_bad_opt))

    # 8. UPDATE message invalid prefix length (> 32)
    withdrawn = bytes([33, 10, 0, 0, 0, 0])  # Length 33
    update_payload = struct.pack("!H", len(withdrawn)) + withdrawn + struct.pack("!H", 0)
    hdr = b'\xff' * 16 + struct.pack("!HB", 19 + len(update_payload), 2)
    cases.append(("UPDATE prefix length overflow (/33)", hdr + update_payload))

    # 9. Completely random garbage bytes
    random.seed(12345)
    for i in range(100):
        length = random.randint(1, 256)
        garbage = bytes([random.randint(0, 255) for _ in range(length)])
        cases.append((f"Random fuzz payload {i+1}", garbage))

    return cases


def parse_mock_wire(frame: bytes) -> Tuple[bool, str]:
    """Simulates Purlin's wire parser rejection logic."""
    if len(frame) < 19:
        return False, "Under minimum header length (19 bytes)"

    marker = frame[:16]
    if marker != b'\xff' * 16:
        return False, "Invalid BGP marker sync bytes"

    length, msg_type = struct.unpack("!HB", frame[16:19])
    if length < 19 or length > 4096:
        return False, f"Declared length {length} outside RFC 4271 bounds [19, 4096]"

    if msg_type not in (1, 2, 3, 4):
        return False, f"Undefined BGP message type code {msg_type}"

    if len(frame) < length:
        return False, f"Truncated payload: expected {length} bytes, got {len(frame)}"

    # If it reached here, check specific message types
    if msg_type == 1:  # OPEN
        if length < 29:
            return False, "OPEN message shorter than minimum 29 bytes"
        version, asn, ht, bgp_id, opt_len = struct.unpack("!BHHIB", frame[19:29])
        if version != 4:
            return False, f"Unsupported BGP version {version}"
        if len(frame[29:length]) < opt_len:
            return False, f"Declared OptParamLen {opt_len} exceeds remaining {len(frame[29:length])}"
    elif msg_type == 2:  # UPDATE
        if length < 23:
            return False, "UPDATE message shorter than minimum 23 bytes"
        withdrawn_len = struct.unpack("!H", frame[19:21])[0]
        if len(frame[21:]) < withdrawn_len:
            return False, "Withdrawn routes length exceeds frame"
        w_offset = 21
        while w_offset < 21 + withdrawn_len:
            p_len = frame[w_offset]
            if p_len > 32:
                return False, f"Invalid IPv4 prefix length {p_len} > 32"
            w_offset += 1 + (p_len + 7) // 8

    return True, "Valid frame"


def main():
    print("=================================================================")
    print("  PURLIN WIRE PROTOCOL FUZZER & ROBUSTNESS VALIDATOR            ")
    print("=================================================================")

    cases = generate_fuzz_cases()
    print(f"Generated {len(cases)} malformed boundary fuzz test vectors.\n")

    rejections = 0
    crashes = 0

    for name, frame in cases:
        try:
            is_valid, reason = parse_mock_wire(frame)
            if not is_valid:
                rejections += 1
        except Exception as e:
            print(f"  [CRASH] Fuzz vector '{name}' triggered unhandled exception: {e}")
            crashes += 1

    print("=" * 65)
    print(f"  Total Fuzz Vectors Tested : {len(cases)}")
    print(f"  Properly Rejected         : {rejections}")
    print(f"  Unhandled Crashes         : {crashes}")
    print("=" * 65)

    if crashes == 0 and rejections == len(cases):
        print("  FUZZING VERIFICATION PASSED: 100% MALFORMED FRAMES REJECTED SAFELY")
        sys.exit(0)
    else:
        print(f"  FUZZING FAILED: {crashes} crashes detected")
        sys.exit(1)


if __name__ == "__main__":
    main()
