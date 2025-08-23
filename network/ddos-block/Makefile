GO		:=	go
BINARY	:= app
OUTDIR	:= bin
OUT		:= $(OUTDIR)/$(BINARY)
SRCS	:= ./main.go

BPF_DIR	:= bpf

.PHONY: all build clean bpf go-build

all: build
	
build: bpf go-build

go-build:
	@echo "==> Building Go binary: $(OUT)"
	@mkdir -p $(OUTDIR)
	$(GO) build -o $(OUT) $(SRC)

bpf:
	@echo "==> Building BPF objects in $(BPF_DIR)"
	$(MAKE) -C $(BPF_DIR) bpf

clean:
	@echo "==> Cleaning"
	rm -rf $(OUTDIR)
	$(MAKE) -C $(BPF_DIR) clean
