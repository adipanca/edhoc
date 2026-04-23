ROOT := .
SRC_DIR := $(ROOT)/src
BUILD_DIR := $(ROOT)/build
OBJ_DIR := $(BUILD_DIR)/obj_p2p

CC ?= gcc

# ---- Bootstrap: pastikan submodule sudah ter-checkout SEBELUM Makefile
# meng-evaluasi $(wildcard ...) di bawah. Tanpa ini, `rm -rf lib && make`
# akan gagal dengan "No rule to make target ... fips202.o" karena pattern
# rule butuh source .c yang belum ada saat parse phase.
ifeq ($(wildcard $(ROOT)/lib/PQClean/common/fips202.c),)
  ifneq ($(MAKECMDGOALS),clean)
  ifneq ($(MAKECMDGOALS),distclean)
    $(info [setup] lib/PQClean atau lib/uoscore-uedhoc belum ada, init submodule...)
    $(shell git -C $(ROOT) submodule update --init --recursive lib/PQClean lib/uoscore-uedhoc >&2)
  endif
  endif
endif

CFLAGS_COMMON := -std=c11 -Wall -Wextra -I$(ROOT)/include -I$(SRC_DIR) \
	-I$(ROOT)/lib/PQClean \
	-I$(ROOT)/lib/PQClean/common \
	-I$(ROOT)/lib/uoscore-uedhoc/externals/mbedtls/include \
	-O2

LDFLAGS_COMMON := -lsodium -lmbedcrypto -lm

SRC_COMMON := \
	$(SRC_DIR)/benchmark.c \
	$(SRC_DIR)/eap_wrap.c \
	$(SRC_DIR)/edhoc_plaintext.c \
	$(SRC_DIR)/pqclean_adapter.c \
	$(SRC_DIR)/pqclean_randombytes.c \
	$(SRC_DIR)/aaa_radius.c

SRC_INITIATOR         := $(SRC_DIR)/p2p_initiator.c
SRC_RESPONDER         := $(SRC_DIR)/p2p_responder.c
SRC_EAP_INITIATOR     := $(SRC_DIR)/p2p_eap_initiator.c
SRC_EAP_RESPONDER     := $(SRC_DIR)/p2p_eap_responder.c
SRC_EAP_AAA_INITIATOR := $(SRC_DIR)/p2p_eap_aaa_initiator.c
SRC_EAP_AAA_RESPONDER := $(SRC_DIR)/p2p_eap_aaa_responder.c

PQCLEAN_KEM_SRC := $(wildcard $(ROOT)/lib/PQClean/crypto_kem/ml-kem-768/clean/*.c)
PQCLEAN_SIG_SRC := $(wildcard $(ROOT)/lib/PQClean/crypto_sign/ml-dsa-65/clean/*.c)
PQCLEAN_COMMON_SRC := \
	$(ROOT)/lib/PQClean/common/fips202.c \
	$(ROOT)/lib/PQClean/common/sha2.c \
	$(ROOT)/lib/PQClean/common/sp800-185.c

PQ_OBJS := $(patsubst %.c,$(OBJ_DIR)/%.o,$(PQCLEAN_KEM_SRC) $(PQCLEAN_SIG_SRC) $(PQCLEAN_COMMON_SRC))
COMMON_OBJS := $(patsubst %.c,$(OBJ_DIR)/%.o,$(SRC_COMMON))

INITIATOR_OBJS         := $(COMMON_OBJS) $(patsubst %.c,$(OBJ_DIR)/%.o,$(SRC_INITIATOR))         $(PQ_OBJS)
RESPONDER_OBJS         := $(COMMON_OBJS) $(patsubst %.c,$(OBJ_DIR)/%.o,$(SRC_RESPONDER))         $(PQ_OBJS)
EAP_INITIATOR_OBJS     := $(COMMON_OBJS) $(patsubst %.c,$(OBJ_DIR)/%.o,$(SRC_EAP_INITIATOR))     $(PQ_OBJS)
EAP_RESPONDER_OBJS     := $(COMMON_OBJS) $(patsubst %.c,$(OBJ_DIR)/%.o,$(SRC_EAP_RESPONDER))     $(PQ_OBJS)
EAP_AAA_INITIATOR_OBJS := $(COMMON_OBJS) $(patsubst %.c,$(OBJ_DIR)/%.o,$(SRC_EAP_AAA_INITIATOR)) $(PQ_OBJS)
EAP_AAA_RESPONDER_OBJS := $(COMMON_OBJS) $(patsubst %.c,$(OBJ_DIR)/%.o,$(SRC_EAP_AAA_RESPONDER)) $(PQ_OBJS)

TARGET_INITIATOR         := $(BUILD_DIR)/p2p_initiator
TARGET_RESPONDER         := $(BUILD_DIR)/p2p_responder
TARGET_EAP_INITIATOR     := $(BUILD_DIR)/p2p_eap_initiator
TARGET_EAP_RESPONDER     := $(BUILD_DIR)/p2p_eap_responder
TARGET_EAP_AAA_INITIATOR := $(BUILD_DIR)/p2p_eap_aaa_initiator
TARGET_EAP_AAA_RESPONDER := $(BUILD_DIR)/p2p_eap_aaa_responder

# All-in-one wrapper scripts (run all 3 modes + merge CSVs).
WRAPPER_INITIATOR := $(BUILD_DIR)/initiator
WRAPPER_RESPONDER := $(BUILD_DIR)/responder
WRAPPER_INITIATOR_SRC := $(ROOT)/scripts/run_all_initiator.sh
WRAPPER_RESPONDER_SRC := $(ROOT)/scripts/run_all_responder.sh

ALL_TARGETS := \
	$(TARGET_INITIATOR) $(TARGET_RESPONDER) \
	$(TARGET_EAP_INITIATOR) $(TARGET_EAP_RESPONDER) \
	$(TARGET_EAP_AAA_INITIATOR) $(TARGET_EAP_AAA_RESPONDER) \
	$(WRAPPER_INITIATOR) $(WRAPPER_RESPONDER)

SUBMODULE_STAMP := $(BUILD_DIR)/.submodules.stamp
FREERADIUS_STAMP := $(ROOT)/output/freeradius_aaa/raddb/radiusd.conf
SETUP_STAMPS := $(SUBMODULE_STAMP) $(FREERADIUS_STAMP)

# ---- Progress bar ----------------------------------------------------
# Counter file: each compile step appends one byte; we read its size to
# compute percentage against TOTAL_OBJS. Works under -j (append is small
# and POSIX-atomic for short writes).
ALL_OBJS := $(sort $(INITIATOR_OBJS) $(RESPONDER_OBJS) \
	$(EAP_INITIATOR_OBJS) $(EAP_RESPONDER_OBJS) \
	$(EAP_AAA_INITIATOR_OBJS) $(EAP_AAA_RESPONDER_OBJS))
TOTAL_OBJS := $(words $(ALL_OBJS))
PROGRESS_FILE := $(BUILD_DIR)/.progress

define progress
	@mkdir -p $(BUILD_DIR); printf '.' >> $(PROGRESS_FILE); \
	done=$$(stat -c%s $(PROGRESS_FILE) 2>/dev/null || wc -c < $(PROGRESS_FILE)); \
	total=$(TOTAL_OBJS); \
	pct=$$(( done * 100 / total )); \
	bar_w=30; filled=$$(( done * bar_w / total )); \
	bar=$$(printf '%*s' $$filled '' | tr ' ' '#'); \
	empty=$$(printf '%*s' $$(( bar_w - filled )) ''); \
	printf '\r[build %3d%%] [%s%s] (%d/%d) %s\033[K' "$$pct" "$$bar" "$$empty" "$$done" "$$total" "$(notdir $1)"
endef

all: setup $(ALL_TARGETS) build_success

build_success: $(ALL_TARGETS)
	@printf '\n[build 100%%] Build successfully \xe2\x9c\x94 (%d objects, %d binaries)\n' \
		$(TOTAL_OBJS) $(words $(ALL_TARGETS))
	@rm -f $(PROGRESS_FILE)

setup: $(SETUP_STAMPS)

# Auto-init git submodules (PQClean, uoscore-uedhoc) recursively the first
# time the build runs. lib/freeradius-server is intentionally NOT
# initialized: it carries nested SSH-only submodules (libbacktrace) and we
# use the system FreeRADIUS v3 package instead.
$(SUBMODULE_STAMP):
	@mkdir -p $(BUILD_DIR)
	@rm -f $(PROGRESS_FILE)
	@if [ -d $(ROOT)/.git ]; then \
		echo "[setup] git submodule update --init --recursive lib/PQClean lib/uoscore-uedhoc"; \
		git -C $(ROOT) submodule update --init --recursive lib/PQClean lib/uoscore-uedhoc; \
	else \
		echo "[setup] not a git checkout, skipping submodule init"; \
	fi
	@touch $@

# First-time FreeRADIUS raddb prep for AAA mode.
$(FREERADIUS_STAMP): $(SUBMODULE_STAMP)
	@echo "[setup] preparing FreeRADIUS raddb (output/freeradius_aaa/)"
	@$(ROOT)/scripts/freeradius_aaa/prepare.sh

$(TARGET_INITIATOR): $(INITIATOR_OBJS)
	@mkdir -p $(BUILD_DIR)
	@printf '\n[link] %s\n' $(notdir $@)
	@$(CC) $^ -o $@ $(LDFLAGS_COMMON)

$(TARGET_RESPONDER): $(RESPONDER_OBJS)
	@mkdir -p $(BUILD_DIR)
	@printf '[link] %s\n' $(notdir $@)
	@$(CC) $^ -o $@ $(LDFLAGS_COMMON)

$(TARGET_EAP_INITIATOR): $(EAP_INITIATOR_OBJS)
	@mkdir -p $(BUILD_DIR)
	@printf '[link] %s\n' $(notdir $@)
	@$(CC) $^ -o $@ $(LDFLAGS_COMMON)

$(TARGET_EAP_RESPONDER): $(EAP_RESPONDER_OBJS)
	@mkdir -p $(BUILD_DIR)
	@printf '[link] %s\n' $(notdir $@)
	@$(CC) $^ -o $@ $(LDFLAGS_COMMON)

$(TARGET_EAP_AAA_INITIATOR): $(EAP_AAA_INITIATOR_OBJS)
	@mkdir -p $(BUILD_DIR)
	@printf '[link] %s\n' $(notdir $@)
	@$(CC) $^ -o $@ $(LDFLAGS_COMMON)

$(TARGET_EAP_AAA_RESPONDER): $(EAP_AAA_RESPONDER_OBJS)
	@mkdir -p $(BUILD_DIR)
	@printf '[link] %s\n' $(notdir $@)
	@$(CC) $^ -o $@ $(LDFLAGS_COMMON)

$(WRAPPER_INITIATOR): $(WRAPPER_INITIATOR_SRC)
	@mkdir -p $(BUILD_DIR)
	@cp $< $@
	@chmod +x $@
	@printf '[wrap] %s\n' $(notdir $@)

$(WRAPPER_RESPONDER): $(WRAPPER_RESPONDER_SRC)
	@mkdir -p $(BUILD_DIR)
	@cp $< $@
	@chmod +x $@
	@printf '[wrap] %s\n' $(notdir $@)

$(OBJ_DIR)/$(SRC_DIR)/%.o: $(SRC_DIR)/%.c | $(SETUP_STAMPS)
	@mkdir -p $(dir $@)
	$(call progress,$@)
	@$(CC) $(CFLAGS_COMMON) -c $< -o $@

$(OBJ_DIR)/$(ROOT)/lib/PQClean/crypto_kem/ml-kem-768/clean/%.o: $(ROOT)/lib/PQClean/crypto_kem/ml-kem-768/clean/%.c | $(SUBMODULE_STAMP)
	@mkdir -p $(dir $@)
	$(call progress,$@)
	@$(CC) $(CFLAGS_COMMON) -O0 -c $< -o $@

$(OBJ_DIR)/$(ROOT)/lib/PQClean/crypto_sign/ml-dsa-65/clean/%.o: $(ROOT)/lib/PQClean/crypto_sign/ml-dsa-65/clean/%.c | $(SUBMODULE_STAMP)
	@mkdir -p $(dir $@)
	$(call progress,$@)
	@$(CC) $(CFLAGS_COMMON) -O0 -c $< -o $@

$(OBJ_DIR)/$(ROOT)/lib/PQClean/common/%.o: $(ROOT)/lib/PQClean/common/%.c | $(SUBMODULE_STAMP)
	@mkdir -p $(dir $@)
	$(call progress,$@)
	@$(CC) $(CFLAGS_COMMON) -O0 -c $< -o $@

clean:
	rm -rf $(OBJ_DIR) $(ALL_TARGETS) $(SUBMODULE_STAMP) $(PROGRESS_FILE)

distclean: clean
	rm -rf $(ROOT)/output/freeradius_aaa $(ROOT)/output/detail $(ROOT)/output/result

.PHONY: all setup build_success clean distclean
