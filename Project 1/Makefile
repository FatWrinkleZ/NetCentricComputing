CC = gcc

SRC = main.c

TARGET = monitor

CFLAGS = -Wall -g
LDFLAGS = -lcrypto -lssl

UNAME_S := $(shell uname -s)

OPENSSL_DIR = /usr
CFLAGS += -I$(OPENSSL_DIR)/include/openssl
LDFLAGS += -L$(OPENSSL_DIR)/lib

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) -std=gnu1x $(CFLAGS) $(SRC) $(LDFLAGS) -o $(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all clean