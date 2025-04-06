LIB_PATH=../target/debug
TARGET = sandboxer

all: $(TARGET)

run: $(TARGET)
	LD_LIBRARY_PATH=$(LIB_PATH) ./$(TARGET)

$(TARGET):
	cargo build
	go build ./cmd/...
