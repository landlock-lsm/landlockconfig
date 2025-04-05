CC = gcc
CFLAGS = -Wall -Werror -g
LIB_PATH=../target/debug
LDFLAGS = -L$(LIB_PATH) -llandlockconfig

TARGET = sandboxer
SRCS = sandboxer.c
OBJS = $(SRCS:.c=.o)

.PHONY: all clean run

all: $(TARGET)

clean:
	rm $(TARGET) $(OBJS)

run: $(TARGET)
	LD_LIBRARY_PATH=$(LIB_PATH) ./$(TARGET)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJS)
	cargo build
	$(CC) -o $@ $^ $(LDFLAGS)
