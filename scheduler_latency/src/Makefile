TARGET = sched_latency
TEST_APP = userapp
ARCH = $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
BPF_OBJ = ${TARGET:=.bpf.o}
USER_C = ${TARGET:=.c}
USER_SKEL = ${TARGET:=.skel.h}
BPFTOOL = 
LIBBPF_SRC = 


all: check_env $(TARGET) $(BPF_OBJ) $(TEST_APP)
.PHONY: all

check_env:
	ifeq ($(BPFTOOL),)
		$(error Please update bpftool location, BPFTOOL, in Makefile)
	endif
	ifeq ($(LIBBPF_SRC),)
		$(error Please update libbpf source location, LIBBPF_SRC, in Makefile)
	endif

$(TARGET): $(USER_C) $(USER_SKEL)
	$(info [INFO]: Compiling usespace code)
	@gcc -o $(TARGET) $(USER_C) -L$(LIBBPF_SRC)/src -l:libbpf.a -lelf -lz -I $(LIBBPF_SRC)/src/

%.bpf.o: %.bpf.c vmlinux.h
	$(info [INFO]: Compiling to ebpf byte code)
	@clang \
	    -target bpf \
      -D __TARGET_ARCH_$(ARCH) \
			-I ~/my_world/kernel_study/ebpf/libbpf_src/libbpf/src/root/usr/include/ \
	    -Wall \
	    -O2 -g -o $@ -c $<
	llvm-strip -g $@

$(USER_SKEL): $(BPF_OBJ)
	$(info [INFO]: Generating skel file)
	@$(BPFTOOL) gen skeleton $< > $@

vmlinux.h:
	$(info [INFO]: Generating vmlinux.h)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

$(TEST_APP): $(TEST_APP).c
		$(info [INFO]: Compiling test application)
		@gcc -o $(TEST_APP) $(TEST_APP).c

clean:
	$(info [INFO]: Cleaning object files and executables)
	-rm -f $(BPF_OBJ)
	-rm -f $(USER_SKEL)
	-rm -f $(TARGET)
	-rm -f vmlinux.h
	-rm -f userapp

