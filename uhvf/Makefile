

all: uhvf

uhvf: uhvf.c uhvf-gdb.c uhvf-net.c uhvf-blk.c Makefile
	clang -D__UKVM_HOST__ -DUKVM_MODULE_BLK -DUKVM_MODULE_NET -Wall -framework Hypervisor -framework vmnet -o uhvf uhvf.c uhvf-gdb.c uhvf-net.c uhvf-blk.c -g

#clang -D__UKVM_HOST__ -DUKVM_MODULE_NET -DUKVM_MODULE_GDB -Wall -framework Hypervisor -o uhvf uhvf.c uhvf-gdb.c uhvf-net.c -g

clean:
	$(RM) uhvf
	$(RM) -r uhvf.dSYM
