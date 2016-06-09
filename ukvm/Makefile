all: ukvm gdb-chain

include Makefile.ukvm

gdb-chain: gdb-chain.c gdb-chain.h gdb-proxy.c
	gcc -o gdb-chain gdb-chain.c gdb-proxy.c

ukvm: ukvm.c ukvm.h misc.h gdb-chain.h $(UKVM_MODULE_FILES) Makefile.ukvm
	gcc -o ukvm $(UKVM_MODULE_FLAGS) -g ukvm.c $(UKVM_MODULE_FILES) -lpthread -lrt

clean:
	rm -f ukvm gdb-chain
