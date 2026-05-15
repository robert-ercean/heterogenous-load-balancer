CLANG ?= clang
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_CFLAGS := \
    -O2 -g -Wall \
    -target bpf \
    -D__TARGET_ARCH_$(ARCH) \
    -I./include \
    -I/usr/include/$(shell uname -m)-linux-gnu

OBJECTS := xdp_forward.o tc_return.o

.PHONY: all clean

all: $(OBJECTS)

%.o: %.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS)