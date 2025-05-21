# SPDX-License-Identifier: Apache-2.0 OR MIT

BINARY = sandboxer
SOURCE = sandboxer.c
OBJECT = $(SOURCE:.c=.o)

OUT_DIR = out
LIB_DIR = $(OUT_DIR)/lib

PKG_NAME = landlockconfig
PKG_CONFIG_PATH := $(LIB_DIR)/pkgconfig

CC = gcc
CFLAGS = $(shell PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) pkg-config --cflags $(PKG_NAME)) \
	-Wall -Werror
LDFLAGS = $(shell PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) pkg-config --libs $(PKG_NAME)) \
	-L$(LIB_DIR) -Wl,--gc-sections

.PHONY: all clean mrproper run FORCE

all: $(BINARY)
	mkdir -p $(OUT_DIR)/bin
	cp $(BINARY) $(OUT_DIR)/bin/

clean:
	rm $(OBJECT) || :
	rm $(BINARY) || :

mrproper: clean
	rm -r $(OUT_DIR) || :

run: all
	LD_LIBRARY_PATH=$(LIB_DIR) $(OUT_DIR)/bin/$(BINARY) bash -i

test: all
	LD_LIBRARY_PATH=$(LIB_DIR) $(OUT_DIR)/bin/$(BINARY) true

$(OUT_DIR)/include/landlockconfig.h: FORCE
	cargo cinstall --package=landlockconfig_ffi --release --prefix=$(OUT_DIR)

%.o: %.c $(OUT_DIR)/include/landlockconfig.h
	$(CC) $(CFLAGS) -c $< -o $@

$(BINARY): $(OBJECT)
	$(CC) -o $@ $< $(LDFLAGS)
