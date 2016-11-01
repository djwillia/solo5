#ifndef __UNIKERNEL_MONITOR_H__
#define __UNIKERNEL_MONITOR_H__


enum {
    EXIT_HLT,
    EXIT_RDTSC,
    EXIT_IO,
    EXIT_IGNORE,
    EXIT_FAIL,
};


#ifdef __APPLE__
#include <Hypervisor/hv.h>
typedef hv_vcpuid_t platform_vcpu_t;
#else
typedef uint64_t platform_vcpu_t;
#endif

int platform_run(platform_vcpu_t vcpu, void *platform_data);
int platform_get_exit_reason(platform_vcpu_t vcpu, void *platform_data);
int platform_get_io_port(platform_vcpu_t vcpu, void *platform_data);
uint32_t platform_get_io_data(platform_vcpu_t vcpu, void *platform_data);
void platform_advance_rip(platform_vcpu_t vcpu, void *platform_data);

#endif
