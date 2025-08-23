# Makefile - build eBPF via split pileline: clang(IR) -> opt -> llc(ELF)

SRCS	:= $(wildcard *.c)
LLS		:= $(SRCS:.c=.ll)
OBJS	:= $(LLS:.ll=.o)
ASM		:= $(OBJS:.o=.S)
ELF		:= $(OBJS:.o=.elf)

# build command
CC		:= clang
LLC		:= llc
OBJDUMP	:= llvm-objdump
READELF	:= llvm-readelf

CFLAGS		:= -O2 -g -target bpf -I/usr/include -I/usr/include/bpf
LLCFLAGS	:= -march=bpf -filetype=obj
OBJDUMPARGS	:= -dr --no-show-raw-insn
READELFARGS	:= -S

all: bpf

bpf: $(LLS) $(OBJS) $(ASM) $(ELF)


# 1) .c -> .ll (LLVM IR 텍스트)
%.ll: %.c
	@echo " CLANG $< -> $@"
	$(CC) $(CFLAGS) -S -emit-llvm $< -o $@

# 2) .ll -> .o (eBPF ELF Object)
%.o: %.ll
	@echo "  LLC  $< -> $@"
	$(LLC) $(LLCFLAGS) $< -o $@

# 3) .o -> .S (eBPF ELF Object Disassembly)
%.S: %.o
	@echo " Disassembly $< -> $@"
	$(OBJDUMP) $(OBJDUMPARGS) $< > $@

%.elf: %.o
	@echo " Readelf $< -> $@"
	$(READELF) $(READELFARGS) $< > $@

clean:
	@echo "  CLEAN"
	rm -f $(LLS) $(OBJS) $(ASM) $(ELF)