CC = gcc

SRC = main.c

TARGET = monitor

CFLAGS = -Wall -g
LDFLAGS = -lcrypto -lssl

UNAME_S := $(shell uname -s)

#different path for OSX
ifeq ($(UNAME_S),Darwin)
    OPENSSL_DIR = /opt/homebrew/opt/openssl
    CFLAGS += -I$(OPENSSL_DIR)/include
    LDFLAGS += -L$(OPENSSL_DIR)/lib
else
    OPENSSL_DIR = /usr
    CFLAGS += -I$(OPENSSL_DIR)/include/openssl
    LDFLAGS += -L$(OPENSSL_DIR)/lib
endif

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) $(LDFLAGS) -o $(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all clean