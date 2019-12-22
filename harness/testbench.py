#!/usr/bin/env python3
"""
Purlin Universal Testbench & Conformance Test Orchestrator
Executes unit tests, integration tests, regression tests, and parses outcomes.
"""

import os
import sys
import time
import subprocess
from typing import List, Tuple, Dict

KOKA_BIN = "/opt/homebrew/Cellar/koka/3.2.9/bin/koka"

UNIT_TESTS = [
    ("proto/types", "test/unit/test-types.kk"),
    ("proto/wire", "test/unit/test-wire.kk"),
    ("proto/capabilities", "test/unit/test-capabilities.kk"),
    ("proto/attr", "test/unit/test-attr.kk"),
    ("proto/message", "test/unit/test-message.kk"),
    ("proto/fsm", "test/unit/test-fsm.kk"),
    ("rib/patricia", "test/unit/test-patricia.kk"),
    ("rib/decision", "test/unit/test-decision.kk"),
    ("rib/multipath", "test/unit/test-multipath.kk"),
    ("policy/eval", "test/unit/test-policy.kk"),
    ("rpki/validator", "test/unit/test-rpki.kk"),
    ("evpn/codec", "test/unit/test-evpn.kk"),
    ("damping/decay", "test/unit/test-damping.kk"),
    ("fib/synth", "test/unit/test-fib.kk"),
]

INTEGRATION_TESTS = [
    ("engine/peering", "test/integration/test-peering.kk"),
    ("engine/reflector", "test/integration/test-reflection.kk"),
    ("sim/fabric", "test/integration/test-fabric.kk"),
]

REGRESSION_TESTS = [
    ("regression/suite", "test/regression/test-regressions.kk"),
]


def run_koka_test(name: str, path: str) -> Tuple[bool, float, str]:
    if not os.path.exists(path):
        return False, 0.0, f"File not found: {path}"

    cmd = [KOKA_BIN, "-isrc", "-itest", "-e", path]
    t0 = time.time()
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=60
        )
        elapsed = time.time() - t0
        output = proc.stdout
        is_ok = proc.returncode == 0 and "FAIL" not in output
        return is_ok, elapsed, output
    except subprocess.TimeoutExpired:
        return False, 60.0, "Test timed out after 60 seconds"
    except Exception as e:
        return False, 0.0, f"Execution exception: {e}"


def run_suite(category: str, tests: List[Tuple[str, str]]) -> Dict[str, any]:
    print(f"\n[{category.upper()}] Running {len(tests)} test suites...")
    passed = 0
    failed = 0
    results = []

    for name, path in tests:
        ok, elapsed, output = run_koka_test(name, path)
        status_tag = "[PASS]" if ok else "[FAIL]"
        print(f"  {status_tag:8} {name:<26} ({elapsed*1000:6.1f} ms)")
        if not ok:
            print(f"         Output snippet:\n{output.strip()[-300:]}")
            failed += 1
        else:
            passed += 1
        results.append((name, ok, elapsed))

    return {
        "category": category,
        "total": len(tests),
        "passed": passed,
        "failed": failed,
        "results": results
    }


def main():
    print("=================================================================")
    print("  PURLIN TESTBENCH: AUTONOMOUS SYSTEM ROUTING ENGINE VERIFIER   ")
    print("=================================================================")

    start_time = time.time()
    unit_res = run_suite("Unit Tests", UNIT_TESTS)
    integ_res = run_suite("Integration Tests", INTEGRATION_TESTS)
    regr_res = run_suite("Regression Tests", REGRESSION_TESTS)

    total_time = time.time() - start_time
    total_tests = unit_res["total"] + integ_res["total"] + regr_res["total"]
    total_passed = unit_res["passed"] + integ_res["passed"] + regr_res["passed"]
    total_failed = unit_res["failed"] + integ_res["failed"] + regr_res["failed"]

    print("\n" + "=" * 65)
    print("  TESTBENCH EXECUTION SUMMARY")
    print("=" * 65)
    print(f"  Total Test Suites  : {total_tests}")
    print(f"  Passed             : {total_passed}")
    print(f"  Failed             : {total_failed}")
    print(f"  Total Wall Clock   : {total_time:.2f} s")
    print("=" * 65)

    if total_failed == 0:
        print("  ALL TEST SUITES PASSED CLEANLY (100% SUCCESS RATE)")
        sys.exit(0)
    else:
        print(f"  {total_failed} SUITE(S) FAILED")
        sys.exit(1)


if __name__ == "__main__":
    main()
