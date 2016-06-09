#ifndef __UKVM_MODULES_H__
#define __UKVM_MODULES_H__

/* hypercall interfaces exported by modules are in ukvm.h */

struct ukvm_module {
    int (*handle_exit)(struct kvm_run *run, int vcpufd, uint8_t *mem);
    int (*handle_cmdarg)(char *cmdarg);
    int (*setup)(int vcpufd);
    char *(*usage)(void);
};

extern struct ukvm_module ukvm_disk;
extern struct ukvm_module ukvm_net;
extern struct ukvm_module ukvm_chain;
extern struct ukvm_module ukvm_gdb;

#endif
