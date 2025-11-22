GO			:= go
GOFLAGS		:= -gcflags "all=-N -l"
BIN_NAME	:= redirect_test


BPF_DIR	:= bpf

.PHONY: all
all: build bpf

.PHONY: build
build:
	@echo "[Go] Building binary..."
	$(GO) build $(GOFLAGS) -o $(BIN_NAME) .

.PHONY: bpf
bpf:
	@echo "[BPF] Building eBPF Programs..."
	$(MAKE) -C $(BPF_DIR)

clean:
	@echo "[Clean] Removing build artifacts..."
	$(MAKE) -C $(BPF_DIR) clean
	rm -rf $(BIN_NAME)