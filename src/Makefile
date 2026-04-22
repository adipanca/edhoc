ROOT := ..
BUILD_DIR := $(ROOT)/build
OBJ_DIR := $(BUILD_DIR)/obj_p2p

CC ?= gcc

CFLAGS_COMMON := -std=c11 -Wall -Wextra -I. \
	-I$(ROOT)/lib/PQClean \
	-I$(ROOT)/lib/PQClean/common \
	-I$(ROOT)/lib/uoscore-uedhoc/externals/mbedtls/include \
	-O2

LDFLAGS_COMMON := -lsodium -lmbedcrypto -lm

SRC_COMMON := \
	benchmark.c \
	eap_wrap.c \
	edhoc_plaintext.c \
	pqclean_adapter.c \
	pqclean_randombytes.c \
	aaa_radius.c

SRC_INITIATOR := p2p_initiator.c
SRC_RESPONDER := p2p_responder.c
SRC_EAP_INITIATOR := p2p_eap_initiator.c
SRC_EAP_RESPONDER := p2p_eap_responder.c
SRC_EAP_AAA_INITIATOR := p2p_eap_aaa_initiator.c
SRC_EAP_AAA_RESPONDER := p2p_eap_aaa_responder.c

PQCLEAN_KEM_SRC := $(wildcard $(ROOT)/lib/PQClean/crypto_kem/ml-kem-768/clean/*.c)
PQCLEAN_SIG_SRC := $(wildcard $(ROOT)/lib/PQClean/crypto_sign/ml-dsa-65/clean/*.c)
PQCLEAN_COMMON_SRC := \
	$(ROOT)/lib/PQClean/common/fips202.c \
	$(ROOT)/lib/PQClean/common/sha2.c \
	$(ROOT)/lib/PQClean/common/sp800-185.c

PQ_OBJS := $(patsubst %.c,$(OBJ_DIR)/%.o,$(PQCLEAN_KEM_SRC) $(PQCLEAN_SIG_SRC) $(PQCLEAN_COMMON_SRC))
COMMON_OBJS := $(patsubst %.c,$(OBJ_DIR)/%.o,$(SRC_COMMON))

INITIATOR_OBJS         := $(COMMON_OBJS) $(OBJ_DIR)/$(SRC_INITIATOR:.c=.o)         $(PQ_OBJS)
RESPONDER_OBJS         := $(COMMON_OBJS) $(OBJ_DIR)/$(SRC_RESPONDER:.c=.o)         $(PQ_OBJS)
EAP_INITIATOR_OBJS     := $(COMMON_OBJS) $(OBJ_DIR)/$(SRC_EAP_INITIATOR:.c=.o)     $(PQ_OBJS)
EAP_RESPONDER_OBJS     := $(COMMON_OBJS) $(OBJ_DIR)/$(SRC_EAP_RESPONDER:.c=.o)     $(PQ_OBJS)
EAP_AAA_INITIATOR_OBJS := $(COMMON_OBJS) $(OBJ_DIR)/$(SRC_EAP_AAA_INITIATOR:.c=.o) $(PQ_OBJS)
EAP_AAA_RESPONDER_OBJS := $(COMMON_OBJS) $(OBJ_DIR)/$(SRC_EAP_AAA_RESPONDER:.c=.o) $(PQ_OBJS)

TARGET_INITIATOR         := $(BUILD_DIR)/p2p_initiator
TARGET_RESPONDER         := $(BUILD_DIR)/p2p_responder
TARGET_EAP_INITIATOR     := $(BUILD_DIR)/p2p_eap_initiator
TARGET_EAP_RESPONDER     := $(BUILD_DIR)/p2p_eap_responder
TARGET_EAP_AAA_INITIATOR := $(BUILD_DIR)/p2p_eap_aaa_initiator
TARGET_EAP_AAA_RESPONDER := $(BUILD_DIR)/p2p_eap_aaa_responder

ALL_TARGETS := \
	$(TARGET_INITIATOR) $(TARGET_RESPONDER) \
	$(TARGET_EAP_INITIATOR) $(TARGET_EAP_RESPONDER) \
	$(TARGET_EAP_AAA_INITIATOR) $(TARGET_EAP_AAA_RESPONDER)

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

$(OBJ_DIR)/%.o: %.c
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
