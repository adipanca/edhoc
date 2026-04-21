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
	edhoc_plaintext.c \
	pqclean_adapter.c \
	pqclean_randombytes.c

SRC_INITIATOR := p2p_initiator.c
SRC_RESPONDER := p2p_responder.c

PQCLEAN_KEM_SRC := $(wildcard $(ROOT)/lib/PQClean/crypto_kem/ml-kem-768/clean/*.c)
PQCLEAN_SIG_SRC := $(wildcard $(ROOT)/lib/PQClean/crypto_sign/ml-dsa-65/clean/*.c)
PQCLEAN_COMMON_SRC := \
	$(ROOT)/lib/PQClean/common/fips202.c \
	$(ROOT)/lib/PQClean/common/sha2.c \
	$(ROOT)/lib/PQClean/common/sp800-185.c

SRC_ALL := $(SRC_COMMON) $(SRC_INITIATOR) $(SRC_RESPONDER) $(PQCLEAN_KEM_SRC) $(PQCLEAN_SIG_SRC) $(PQCLEAN_COMMON_SRC)
OBJ_ALL := $(patsubst %.c,$(OBJ_DIR)/%.o,$(SRC_ALL))

INITIATOR_OBJS := $(patsubst %.c,$(OBJ_DIR)/%.o,$(SRC_COMMON) $(SRC_INITIATOR) $(PQCLEAN_KEM_SRC) $(PQCLEAN_SIG_SRC) $(PQCLEAN_COMMON_SRC))
RESPONDER_OBJS := $(patsubst %.c,$(OBJ_DIR)/%.o,$(SRC_COMMON) $(SRC_RESPONDER) $(PQCLEAN_KEM_SRC) $(PQCLEAN_SIG_SRC) $(PQCLEAN_COMMON_SRC))

TARGET_INITIATOR := $(BUILD_DIR)/p2p_initiator
TARGET_RESPONDER := $(BUILD_DIR)/p2p_responder

all: $(TARGET_INITIATOR) $(TARGET_RESPONDER)

$(TARGET_INITIATOR): $(INITIATOR_OBJS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(INITIATOR_OBJS) -o $@ $(LDFLAGS_COMMON)

$(TARGET_RESPONDER): $(RESPONDER_OBJS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(RESPONDER_OBJS) -o $@ $(LDFLAGS_COMMON)

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
	rm -rf $(OBJ_DIR) $(TARGET_INITIATOR) $(TARGET_RESPONDER)

.PHONY: all clean
