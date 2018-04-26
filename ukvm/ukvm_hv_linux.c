/* 
 * Copyright (c) 2015-2017 Contributors as noted in the AUTHORS file
 *
 * This file is part of ukvm, a unikernel monitor.
 *
 * Permission to use, copy, modify, and/or distribute this software
 * for any purpose with or without fee is hereby granted, provided
 * that the above copyright notice and this permission notice appear
 * in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
 * OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * ukvm_hv_linux.c: Architecture-independent part of Linux backend
 * implementation.
 */

#define _GNU_SOURCE
#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include <linux/kvm.h>
#include <stdio.h>
#include <poll.h>

/* for seccomp */
#include <seccomp.h> /* from libseccomp-dev */
#include "seccomp-bpf.h"
#include "syscall-reporter.h"
#include "ukvm_cpu_x86_64.h"
/* #include <sys/prctl.h> */
/* #include <linux/seccomp.h> */

#include "ukvm.h"
#include "ukvm_hv_linux.h"

void ukvm_hv_mem_size(size_t *mem_size) {
    ukvm_x86_mem_size(mem_size);
}

void install_syscall_filter(void)
{
    //scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_TRAP);

    /* 
     * For core module.
     */
    extern struct pollfd pollfds[];
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1,
                     SCMP_A0(SCMP_CMP_EQ, 1));
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_gettime), 0);
#ifndef UKVM_MODULE_NET
    /* if there is a net module, it will define the poll below */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ppoll), 2,
                     SCMP_A0(SCMP_CMP_EQ, (scmp_datum_t)&pollfds),
                     SCMP_A1(SCMP_CMP_EQ, 0));
#endif

    /* 
     * For blk module.
     */
#ifdef UKVM_MODULE_BLK
    int blkfd = ukvm_module_blk.get_fd();
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pwrite64), 1,
                     SCMP_A0(SCMP_CMP_EQ, blkfd));
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pread64), 1,
                     SCMP_A0(SCMP_CMP_EQ, blkfd));
    /* seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1, */
    /*                  SCMP_A0(SCMP_CMP_EQ, 4)); */
    /* seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 1, */
    /*                  SCMP_A0(SCMP_CMP_EQ, 4)); */
    /* seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pwrite64), 1, */
    /*                  SCMP_A0(SCMP_CMP_EQ, 4)); */
    /* seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pread64), 1, */
    /*                  SCMP_A0(SCMP_CMP_EQ, 4)); */
#endif

    /* 
     * For net module. 
     */
#ifdef UKVM_MODULE_NET
    int netfd = ukvm_module_net.get_fd();
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 1,
                     SCMP_A0(SCMP_CMP_EQ, netfd));
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1,
                     SCMP_A0(SCMP_CMP_EQ, netfd));
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ppoll), 2,
                     SCMP_A0(SCMP_CMP_EQ, (scmp_datum_t)&pollfds),
                     SCMP_A1(SCMP_CMP_EQ, 1));
#endif

    seccomp_load(ctx);
}


struct ukvm_hv *ukvm_hv_init(size_t mem_size)
{
    struct ukvm_hv *hv = malloc(sizeof (struct ukvm_hv));
    if (hv == NULL)
        err(1, "malloc");
    memset(hv, 0, sizeof (struct ukvm_hv));
    struct ukvm_hvb *hvb = malloc(sizeof (struct ukvm_hvb));
    if (hvb == NULL)
        err(1, "malloc");
    memset(hvb, 0, sizeof (struct ukvm_hvb));

    // 0x100000 is the ELF minimal offset location
    hvb->realmem = mmap((void *)LINUX_MAP_ADDRESS, 0x100000 - LINUX_MAP_ADDRESS,
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (hvb->realmem == MAP_FAILED)
        err(1, "Error allocating guest memory");

    if (madvise((void *)LINUX_MAP_ADDRESS,
                0x100000 - LINUX_MAP_ADDRESS, MADV_MERGEABLE) != 0)
        err(1, "Error with madvise MADV_MERGEABLE");

    hvb->realmem = (void *)LINUX_MAP_ADDRESS;
    assert((uint64_t)hvb->realmem == LINUX_MAP_ADDRESS);

    /*
     * This is a bit of a nasty hack.
     *
     * hv->mem is at 0 so the unmodified unikernel ELF can be loaded
     * assuming its addressing starts at 0 (as it does when running as
     * a VM).  The unikernel doesn't use the really low memory (below
     * LINUX_MAP_ADDRESS), so it ends up being OK that we don't
     * actually allocate that.
     */
    hv->mem = 0; 
    hv->mem_size = mem_size;

    hv->b = hvb;
    return hv;
}


static void ukvm_hv_handle_exit(int nr, void *arg);

/* Yikes. Using rdtsc for timing is a bit suspect. */
uint64_t get_cpuinfo_freq(void)
{
    FILE *cpuinfo = fopen("/proc/cpuinfo", "rb");
    int ghz=0, mhz=0;
    char buf[256];
    
    do {
        char *ptr;
        ptr = fgets(buf, 256, cpuinfo);
        if (!ptr)
            continue;
                
        ptr = strstr(buf, "GHz");
        if (!ptr)
            continue;

        sscanf(ptr - 4, "%d.%d", &ghz, &mhz);
        break;
    } while(!feof(cpuinfo));

    fclose(cpuinfo);
    return ((uint64_t)ghz * 1000000000 + (uint64_t)mhz * 10000000);
}


void ukvm_hv_vcpu_init(struct ukvm_hv *hv, ukvm_gpa_t gpa_ep,
                       ukvm_gpa_t gpa_kend, char **cmdline)
{
    struct ukvm_boot_info *bi =
        (struct ukvm_boot_info *)(hv->mem + LINUX_BOOT_INFO_BASE);
    bi->mem_size = hv->mem_size;
    bi->kernel_end = gpa_kend;
    bi->cmdline = LINUX_CMDLINE_BASE;
    bi->cpu.tsc_freq =   get_cpuinfo_freq();
    
    uint64_t *hypercall_ptr = (uint64_t *)(hv->mem + LINUX_HYPERCALL_ADDRESS);
    *hypercall_ptr = (uint64_t)ukvm_hv_handle_exit;
    
    hv->b->entry = gpa_ep;
    hv->b->arg = bi;
        
    *cmdline = (char *)(hv->mem + LINUX_CMDLINE_BASE);
}

/* 
 * We could use pthreads for real "loop" behavior, but can avoid
 * pthreads because the ukvm "hypercalls" are synchronous.  We do need
 * to pass the hv structure to ukvm_hv_handle_exit though.
 */
static struct ukvm_hv *loop_hv;

int ukvm_hv_vcpu_loop(struct ukvm_hv *hv)
{
    void (*_start)(void *) = (void (*)(void *))hv->b->entry;
    loop_hv = hv;

    install_syscall_reporter();
    install_syscall_filter();
    /* prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT); */

#ifdef UKVM_MODULE_FTRACE    
    void ukvm_ftrace_ready(void);
    ukvm_ftrace_ready();
#endif

    /* 
     * First call into unikernel, call start.  Note we are sharing our
     * stack with the unikernel. 
     */
    _start(hv->b->arg);

#ifdef UKVM_MODULE_FTRACE    
    void ukvm_ftrace_finished(void);
    ukvm_ftrace_finished();
#endif

    return 0;
}

/* Called directly by the unikernel. */
static void ukvm_hv_handle_exit(int nr, void *arg)
{
    struct ukvm_hv *hv = loop_hv;

    /* Guest has halted the CPU. */
    if (nr == UKVM_HYPERCALL_HALT) {
        ukvm_gpa_t gpa = (ukvm_gpa_t)arg;
        struct ukvm_halt *p = 
            UKVM_CHECKED_GPA_P(hv, gpa, sizeof (struct ukvm_halt));
        exit(p->exit_status);
    }

    int handled = 0;
    for (ukvm_vmexit_fn_t *fn = ukvm_core_vmexits; *fn && !handled; fn++)
        handled = ((*fn)(hv) == 0);
    if (handled)
        return;

    if (nr <= 0 || nr >= (UKVM_HYPERCALL_MAX))
        errx(1, "Invalid guest port access: port=0x%x", nr);
    
    ukvm_hypercall_fn_t fn = ukvm_core_hypercalls[nr];
    if (fn == NULL)
        errx(1, "Invalid guest hypercall: num=%d", nr);
    
    ukvm_gpa_t gpa = (ukvm_gpa_t)arg;
    fn(hv, gpa);
}
