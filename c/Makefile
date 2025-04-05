CC = gcc
CFLAGS = -Wall -Werror
LDFLAGS = -Wl,--gc-sections

LIB_DIR = ../target/release
# Replace with landlockconfig.a for static linking.
LIB_FILE = $(LIB_DIR)/liblandlockconfig.so

TARGET = sandboxer
SRC = sandboxer.c
OBJ = $(SRC:.c=.o)

.PHONY: all clean run FORCE

all: $(TARGET)

clean:
	rm $(TARGET) $(OBJ) || :

run: $(TARGET)
	LD_LIBRARY_PATH=$(LIB_DIR) ./$(TARGET) bash -i

${LIB_FILE}: FORCE
	cargo build --package landlockconfig_ffi --release

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJ) ${LIB_FILE}
	$(CC) -o $@ $^ $(LDFLAGS)
