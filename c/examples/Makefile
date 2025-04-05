BINARY = sandboxer
SOURCE = sandboxer.c
OBJECT = $(SOURCE:.c=.o)

LIB_DIR = ../../target/release
# Replace with landlockconfig.a for static linking.
LIB_FILE = $(LIB_DIR)/liblandlockconfig.so

CC = gcc
CFLAGS = -Wall -Werror
LDFLAGS = -L$(LIB_DIR) -llandlockconfig -Wl,--gc-sections

.PHONY: all clean mrproper run FFI FORCE

all: $(BINARY)

clean:
	rm $(OBJECT) || :

mrproper: clean
	rm $(BINARY) || :

run: $(BINARY)
	LD_LIBRARY_PATH=$(LIB_DIR) ./$(BINARY) bash -i

FFI: FORCE
	cargo build --package landlockconfig_ffi --release

${LIB_FILE}: FFI

../landlockconfig.h: FFI

%.o: %.c ../landlockconfig.h
	$(CC) $(CFLAGS) -c $< -o $@

$(BINARY): $(OBJECT) $(LIB_FILE)
	$(CC) -o $@ $< $(LDFLAGS)
