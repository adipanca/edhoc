ROOT := .
SRC_DIR := $(ROOT)/src
BUILD_DIR := $(ROOT)/build
OBJ_DIR := $(BUILD_DIR)/obj_p2p

CC ?= gcc

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

all: $(ALL_TARGETS)

$(TARGET_INITIATOR): $(INITIATOR_OBJS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $^ -o $@ $(LDFLAGS_COMMON)

$(TARGET_RESPONDER): $(RESPONDER_OBJS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $^ -o $@ $(LDFLAGS_COMMON)

$(TARGET_EAP_INITIATOR): $(EAP_INITIATOR_OBJS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $^ -o $@ $(LDFLAGS_COMMON)

$(TARGET_EAP_RESPONDER): $(EAP_RESPONDER_OBJS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $^ -o $@ $(LDFLAGS_COMMON)

$(TARGET_EAP_AAA_INITIATOR): $(EAP_AAA_INITIATOR_OBJS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $^ -o $@ $(LDFLAGS_COMMON)

$(TARGET_EAP_AAA_RESPONDER): $(EAP_AAA_RESPONDER_OBJS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $^ -o $@ $(LDFLAGS_COMMON)

$(WRAPPER_INITIATOR): $(WRAPPER_INITIATOR_SRC)
	@mkdir -p $(BUILD_DIR)
	cp $< $@
	chmod +x $@

$(WRAPPER_RESPONDER): $(WRAPPER_RESPONDER_SRC)
	@mkdir -p $(BUILD_DIR)
	cp $< $@
	chmod +x $@

$(OBJ_DIR)/$(SRC_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS_COMMON) -c $< -o $@

$(OBJ_DIR)/$(ROOT)/lib/PQClean/crypto_kem/ml-kem-768/clean/%.o: $(ROOT)/lib/PQClean/crypto_kem/ml-kem-768/clean/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS_COMMON) -O0 -c $< -o $@

$(OBJ_DIR)/$(ROOT)/lib/PQClean/crypto_sign/ml-dsa-65/clean/%.o: $(ROOT)/lib/PQClean/crypto_sign/ml-dsa-65/clean/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS_COMMON) -O0 -c $< -o $@

$(OBJ_DIR)/$(ROOT)/lib/PQClean/common/%.o: $(ROOT)/lib/PQClean/common/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS_COMMON) -O0 -c $< -o $@

clean:
	rm -rf $(OBJ_DIR) $(ALL_TARGETS)

.PHONY: all clean
