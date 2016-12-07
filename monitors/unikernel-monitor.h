#ifndef __UNIKERNEL_MONITOR_H__
#define __UNIKERNEL_MONITOR_H__


enum {
    EXIT_HLT,
    EXIT_RDTSC,
    EXIT_IO,
    EXIT_DEBUG,
    EXIT_IGNORE,
    EXIT_FAIL,
};


#ifdef __APPLE__
#include <Hypervisor/hv.h>
typedef hv_vcpuid_t platform_vcpu_t;
#else
typedef uint64_t platform_vcpu_t;
#endif

struct platform {
    platform_vcpu_t vcpu;
    uint8_t *mem;
    void *priv;
};

int platform_init(struct platform **p);

void platform_setup_system_64bit(struct platform *p, uint64_t cr0,
                                 uint64_t cr4, uint64_t efer);
void platform_setup_system_page_tables(struct platform *p, uint64_t pml4);
void platform_setup_system_gdt(struct platform *p,
                               uint64_t cs_idx, uint64_t ds_idx,
                               uint64_t off, uint64_t limit);
void platform_setup_system(struct platform *p, uint64_t entry,
                           uint64_t boot_info);



int platform_run(struct platform *p);
int platform_get_exit_reason(struct platform *p);
int platform_get_io_port(struct platform *p);
uint64_t platform_get_io_data(struct platform *p);
void platform_advance_rip(struct platform *p);
void platform_cleanup(struct platform *p);


void platform_init_time(uint64_t *freq);
void platform_get_timestamp(uint64_t *s, uint64_t *ns);
uint64_t platform_get_exec_time(struct platform *p);
void platform_emul_rdtsc(struct platform *p, uint64_t new_tsc);

#endif
