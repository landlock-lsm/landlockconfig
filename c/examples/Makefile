# SPDX-License-Identifier: Apache-2.0 OR MIT

BINARY = sandboxer
SOURCE = sandboxer.c
OBJECT = $(SOURCE:.c=.o)

OUT_DIR = out

PKG_NAME = landlockconfig
# cargo cinstall may install into a multiarch libdir (e.g.
# lib/x86_64-linux-gnu), so locate the generated pkg-config file and let
# pkg-config provide the paths instead of assuming a fixed layout.
PKG_CONFIG = PKG_CONFIG_PATH="$(shell find $(OUT_DIR) -type d -name pkgconfig)" pkg-config

CC = gcc
CFLAGS = $(shell $(PKG_CONFIG) --cflags $(PKG_NAME)) -Wall -Werror
LDFLAGS = $(shell $(PKG_CONFIG) --libs $(PKG_NAME)) -Wl,--gc-sections
LIB_DIR = $(shell $(PKG_CONFIG) --variable=libdir $(PKG_NAME))

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
	LD_LIBRARY_PATH=$(LIB_DIR) $(OUT_DIR)/bin/$(BINARY) \
		../../tests/composition/source/ \
		bash -i

test: all
	LD_LIBRARY_PATH=$(LIB_DIR) $(OUT_DIR)/bin/$(BINARY) \
		../../examples/mini-write-tmp.toml \
		true
	LD_LIBRARY_PATH=$(LIB_DIR) $(OUT_DIR)/bin/$(BINARY) \
		../../tests/composition/source/ \
		true

$(OUT_DIR)/include/landlockconfig.h: FORCE
	cargo cinstall --package=landlockconfig_ffi --release --prefix=$(OUT_DIR)

%.o: %.c $(OUT_DIR)/include/landlockconfig.h
	$(CC) $(CFLAGS) -c $< -o $@

$(BINARY): $(OBJECT)
	$(CC) -o $@ $< $(LDFLAGS)
