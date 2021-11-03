CLANG ?= clang
BPF_SRCS := int.c
APP_SRCS := loader.c

APP := loader
BPF_OBJ := EXE

.PHONY: all
all: $(BPF_OBJ) $(APP)

.PHONY: check-env
check-env:
ifndef LIBBPF
	$(error LIBBPF is undefined)
endif

$(APP): $(APP_SRCS) common.h check-env
	$(CLANG) $(APP_SRCS) $(LIBBPF) -o $@ -lelf -lz


$(BPF_OBJ): $(BPF_SRCS) common.h
	$(CLANG) $(CFLAGS) -g -Wall -O2 -target bpf -c $(BPF_SRCS) -o $@

.PHONY: clean
clean:
	rm -rf $(BPF_OBJ)  $(APP)
