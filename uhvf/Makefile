

all: uhvf

uhvf: uhvf.c Makefile
	clang -Wall -framework Hypervisor -o uhvf uhvf.c -g

clean:
	$(RM) uhvf
	$(RM) -r uhvf.dSYM
