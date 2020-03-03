# Purlin: Autonomous System BGP-4 & MP-BGP Routing Engine
# Universal Makefile for Koka, C glue layer, benchmarks, and verification

KOKA := /opt/homebrew/Cellar/koka/3.2.9/bin/koka
CC := clang
CFLAGS := -Wall -Wextra -Werror -O3 -I./c
AR := ar
ARFLAGS := rcs
PYTHON := python3

BIN_DIR := bin
LIB_DIR := lib
C_DIR := c
SRC_DIR := src
TEST_DIR := test

C_SRCS := $(wildcard $(C_DIR)/*.c)
C_OBJS := $(patsubst $(C_DIR)/%.c, $(LIB_DIR)/%.o, $(C_SRCS))
C_LIB := $(LIB_DIR)/libpurlin_c.a

.PHONY: all clean koka-build c-glue test test-unit test-integration test-regression verify bench help

all: verify c-glue koka-build

help:
	@echo "Purlin Build System Targets:"
	@echo "  make all               - Build C glue library and compile native Purlin binary"
	@echo "  make c-glue            - Compile C non-blocking socket and Netlink FIB library"
	@echo "  make koka-build        - Compile native Koka executable (bin/purlin)"
	@echo "  make test              - Run all unit, integration, and regression test suites"
	@echo "  make test-unit         - Run unit tests (proto, rib, policy, rpki, evpn, damping, fib)"
	@echo "  make test-integration  - Run integration tests (peering, reflection, Clos fabric)"
	@echo "  make test-regression   - Run regression test suite"
	@echo "  make verify            - Run zero em-dash verification scanner"
	@echo "  make bench             - Run Patricia trie LPM and policy benchmarks"
	@echo "  make clean             - Remove build directories and cached compilation artifacts"

$(LIB_DIR):
	@mkdir -p $(LIB_DIR)

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

$(LIB_DIR)/%.o: $(C_DIR)/%.c | $(LIB_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(C_LIB): $(C_OBJS)
	$(AR) $(ARFLAGS) $@ $^

c-glue: $(C_LIB)
	@echo "[OK] C networking and Netlink FIB library compiled: $(C_LIB)"

koka-build: | $(BIN_DIR)
	@echo "Compiling native Purlin binary with Koka..."
	$(KOKA) -O2 -isrc -o $(BIN_DIR)/purlin src/purlin.kk
	@echo "[OK] Binary built: $(BIN_DIR)/purlin"

verify:
	@$(PYTHON) scripts/verify_no_em_dash.py

test-unit:
	@echo "=== Running Unit Tests ==="
	$(KOKA) -isrc -itest -e test/unit/test-types.kk
	$(KOKA) -isrc -itest -e test/unit/test-wire.kk
	$(KOKA) -isrc -itest -e test/unit/test-capabilities.kk
	$(KOKA) -isrc -itest -e test/unit/test-attr.kk
	$(KOKA) -isrc -itest -e test/unit/test-message.kk
	$(KOKA) -isrc -itest -e test/unit/test-fsm.kk
	$(KOKA) -isrc -itest -e test/unit/test-patricia.kk
	$(KOKA) -isrc -itest -e test/unit/test-decision.kk
	$(KOKA) -isrc -itest -e test/unit/test-multipath.kk
	$(KOKA) -isrc -itest -e test/unit/test-policy.kk
	$(KOKA) -isrc -itest -e test/unit/test-rpki.kk
	$(KOKA) -isrc -itest -e test/unit/test-evpn.kk
	$(KOKA) -isrc -itest -e test/unit/test-damping.kk
	$(KOKA) -isrc -itest -e test/unit/test-fib.kk
	@echo "[OK] All 14 Unit Test Suites Passed."

test-integration:
	@echo "=== Running Integration Tests ==="
	$(KOKA) -isrc -itest -e test/integration/test-peering.kk
	$(KOKA) -isrc -itest -e test/integration/test-reflection.kk
	$(KOKA) -isrc -itest -e test/integration/test-fabric.kk
	@echo "[OK] All 3 Integration Test Suites Passed."

test-regression:
	@echo "=== Running Regression Tests ==="
	$(KOKA) -isrc -itest -e test/regression/test-regressions.kk
	@echo "[OK] Regression Test Suite Passed."

test: verify test-unit test-integration test-regression
	@echo "=========================================================="
	@echo "  ALL PURLIN TEST SUITES PASSED CLEANLY (ZERO FAILURES)   "
	@echo "=========================================================="

bench:
	@echo "=== Running Purlin Performance Benchmarks ==="
	@if [ -f bench/bench-rib.kk ]; then $(KOKA) -O2 -isrc -e bench/bench-rib.kk; fi
	@if [ -f bench/bench-policy.kk ]; then $(KOKA) -O2 -isrc -e bench/bench-policy.kk; fi

clean:
	@rm -rf $(BIN_DIR) $(LIB_DIR) .koka
	@echo "[OK] Cleaned build artifacts."
