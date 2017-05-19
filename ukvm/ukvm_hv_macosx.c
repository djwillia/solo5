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
 * ukvm_hv_macosx.c: Architecture-independent part of Mac OSX
 *                   Hypervisor.framework backend implementation.
 */

#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>

#include <Hypervisor/hv.h>
#include <dispatch/dispatch.h>

#include "ukvm.h"
#include "ukvm_hv_macosx.h"

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

    /* create a VM instance for the current task */
    if (hv_vm_create(HV_VM_DEFAULT))
        err(1, "hv_vm_create");

    if (hv_vcpu_create(&hvb->vcpu, HV_VCPU_DEFAULT))
        err(1, "hv_vcpu_create");

    hvb->poll_sema = dispatch_semaphore_create(0);
    hvb->poll_net_mutex = dispatch_semaphore_create(1);

    hv->mem = mmap(NULL, mem_size, PROT_READ | PROT_WRITE,
               MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (hv->mem == MAP_FAILED)
        err(1, "Error allocating guest memory");
    hv->mem_size = mem_size;

    if (hv_vm_map(hv->mem, 0, mem_size,
                  HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC))
        err(1, "hv_vm_map");        

    hv->b = hvb;
    return hv;
}
