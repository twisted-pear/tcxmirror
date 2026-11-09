LLC ?= llc
CLANG ?= clang
CC ?= gcc
BPFT ?= bpftool
PAHOLE ?= pahole

LIBBPF_PREFIX ?= /usr
VMLINUX_H_PREREQ = $(shell test -f /sys/kernel/btf/vmlinux && echo "/sys/kernel/btf/vmlinux" || echo "vmlinux.btf")

USER_TARGETS = tcxmirror
BPF_OBJ = tcxmirror_kern.o

ifdef NDEBUG
CFLAGS = -Wall -I $(LIBBPF_PREFIX)/include/ -O2 -DNDEBUG
else
CFLAGS = -Wall -I $(LIBBPF_PREFIX)/include/ -O2 -fsanitize=address -fsanitize=leak -g
endif
BPF_CFLAGS = -D __BPF_TRACING__ -I $(LIBBPF_PREFIX)/include/ -Wall -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Wno-address-of-packed-member -Wno-missing-declarations -Werror -O2
USER_LIBS = -lbpf

all: $(USER_TARGETS)

vmlinux.h: $(VMLINUX_H_PREREQ)
	$(BPFT) btf dump file $< format c > $@~
	mv --force $@~ $@

vmlinux.btf:
	$(PAHOLE) --btf_encode_detached=$@

%.skel.h: %.o vmlinux.h
	$(BPFT) gen skeleton $< > $@~
	mv --force $@~ $@

$(BPF_OBJ): %.o: %.c vmlinux.h
	$(CLANG) -S \
	    -target bpf \
	    $(BPF_CFLAGS) \
	    -emit-llvm -c -g -o ${@:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

$(USER_TARGETS): %: %.c tcxmirror_kern.skel.h
	$(CC) $(CFLAGS) -L $(LIBBPF_PREFIX)/lib64/ -o $@ $< $(USER_LIBS)

clean:
	rm -f *.o *.ll *.skel.h *.h~ $(USER_TARGETS) vmlinux.h vmlinux.btf

.PHONY: all clean
