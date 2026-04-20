# ============================================================================
# Root Makefile (delegator)
# Keeps `make`, `make clean`, and `make -j$(nproc)` working with current layout.
# ============================================================================

.DEFAULT_GOAL := all

.PHONY: all clean help p2p eap p2p-clean eap-clean

all: p2p

# Build P2P benchmark binaries (default)
p2p:
	$(MAKE) -f Makefile.p2p_bench all

# Optional: build EAP benchmark binaries
eap:
	@if [ -f Makefile.eap_bench ]; then \
		$(MAKE) -f Makefile.eap_bench all; \
	else \
		echo 'Skip EAP build: Makefile.eap_bench not found.'; \
	fi

# Clean both benchmark outputs so `make clean` is always safe
clean: p2p-clean eap-clean

p2p-clean:
	$(MAKE) -f Makefile.p2p_bench clean

eap-clean:
	@if [ -f Makefile.eap_bench ]; then \
		$(MAKE) -f Makefile.eap_bench clean; \
	else \
		echo 'Skip EAP clean: Makefile.eap_bench not found.'; \
	fi

help:
	@echo ''
	@echo '  Root Build Targets'
	@echo '  =================='
	@echo '  make              - Build P2P benchmark (default)'
	@echo '  make p2p          - Build P2P benchmark'
	@echo '  make eap          - Build EAP benchmark'
	@echo '  make clean        - Clean both P2P and EAP benchmark artifacts'
	@echo ''
	@echo '  Run examples:'
	@echo '    ./build/p2p_responder [port]'
	@echo '    ./build/p2p_initiator <server_ip> [port]'
	@echo '    ./build/eap_responder [port]'
	@echo '    ./build/eap_initiator <server_ip> [port]'
	@echo ''
