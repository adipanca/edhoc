# ============================================================================
# Root Makefile (delegator)
# Keeps `make`, `make clean`, and `make -j$(nproc)` working with current layout.
#
# `make`       → builds ALL: P2P + EAP + Unified (./build/responder, initiator)
# `make p2p`   → builds P2P only
# `make eap`   → builds EAP only
# `make unified` → builds unified only (P2P+EAP in one binary)
# ============================================================================

.DEFAULT_GOAL := all

.PHONY: all clean help p2p eap unified p2p-clean eap-clean unified-clean

all: p2p eap unified

# Build P2P benchmark binaries
p2p:
	$(MAKE) -f Makefile.p2p_bench all

# Build EAP benchmark binaries
eap:
	@if [ -f Makefile.eap_bench ]; then \
		$(MAKE) -f Makefile.eap_bench all; \
	else \
		echo 'Skip EAP build: Makefile.eap_bench not found.'; \
	fi

# Build Unified benchmark binaries (P2P + EAP in one binary)
unified:
	@if [ -f Makefile.unified_bench ]; then \
		$(MAKE) -f Makefile.unified_bench all; \
	else \
		echo 'Skip Unified build: Makefile.unified_bench not found.'; \
	fi

# Clean all benchmark outputs
clean: p2p-clean eap-clean unified-clean

p2p-clean:
	$(MAKE) -f Makefile.p2p_bench clean

eap-clean:
	@if [ -f Makefile.eap_bench ]; then \
		$(MAKE) -f Makefile.eap_bench clean; \
	else \
		echo 'Skip EAP clean: Makefile.eap_bench not found.'; \
	fi

unified-clean:
	@if [ -f Makefile.unified_bench ]; then \
		$(MAKE) -f Makefile.unified_bench clean; \
	else \
		echo 'Skip Unified clean: Makefile.unified_bench not found.'; \
	fi

help:
	@echo ''
	@echo '  Root Build Targets'
	@echo '  =================='
	@echo '  make              - Build ALL (P2P + EAP + Unified)'
	@echo '  make p2p          - Build P2P benchmark only'
	@echo '  make eap          - Build EAP benchmark only'
	@echo '  make unified      - Build Unified benchmark only'
	@echo '  make clean        - Clean all benchmark artifacts'
	@echo ''
	@echo '  Run separately:'
	@echo '    ./build/p2p_responder [port]          (P2P only)'
	@echo '    ./build/p2p_initiator <ip> [port]'
	@echo ''
	@echo '    ./build/eap_responder [port]          (EAP only)'
	@echo '    ./build/eap_initiator <ip> [port]'
	@echo ''
	@echo '  Run ALL at once (P2P + EAP → all CSV):'
	@echo '    ./build/responder [port]'
	@echo '    ./build/initiator <ip> [port]'
	@echo ''
