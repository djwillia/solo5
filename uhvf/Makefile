

all: uhvf

uhvf: uhvf.c uhvf-gdb.c Makefile
	clang -D__UKVM_HOST__ -DUKVM_MODULE_GDB -Wall -framework Hypervisor -o uhvf uhvf.c uhvf-gdb.c -g

clean:
	$(RM) uhvf
	$(RM) -r uhvf.dSYM
