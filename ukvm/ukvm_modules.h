#ifndef __UKVM_MODULES_H__
#define __UKVM_MODULES_H__

#include "unikernel-monitor.h"

/* hypercall interfaces exported by modules are in ukvm.h */

struct ukvm_module {
    int (*get_fd)(void);
    int (*handle_exit)(platform_vcpu_t vcpu, uint8_t *mem,
                       void *platform_data);
    int (*handle_cmdarg)(char *cmdarg);
    int (*setup)(platform_vcpu_t vcpu, uint8_t *mem);
    char *(*usage)(void);
};

extern struct ukvm_module ukvm_blk;
extern struct ukvm_module ukvm_net;
extern struct ukvm_module ukvm_gdb;

#endif
