/* Copyright (c) 2015, IBM
 * Author(s): Dan Williams <djwillia@us.ibm.com>
 *            Ricardo Koller <kollerr@us.ibm.com>
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

/* We used several existing projects as guides
 *   kvmtest.c: http://lwn.net/Articles/658512/
 *   lkvm: http://github.com/clearlinux/kvmtool
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/kvm.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/const.h>
#include <asm/msr-index.h>
#include <elf.h>
#include <signal.h>
#include <pthread.h>
#include <poll.h>

#define KVM_32BIT_MAX_MEM_SIZE  (1ULL << 32)
#define KVM_32BIT_GAP_SIZE    (768 << 20)
#define KVM_32BIT_GAP_START    (KVM_32BIT_MAX_MEM_SIZE - KVM_32BIT_GAP_SIZE)

static struct platform platform;

static void setup_cpuid(int kvm, int vcpufd)
{
    struct kvm_cpuid2 *kvm_cpuid;
    int max_entries = 100;

    kvm_cpuid = calloc(1, sizeof(*kvm_cpuid) +
                          max_entries * sizeof(*kvm_cpuid->entries));
    kvm_cpuid->nent = max_entries;

    if (ioctl(kvm, KVM_GET_SUPPORTED_CPUID, kvm_cpuid) < 0)
        err(1, "KVM_GET_SUPPORTED_CPUID failed");

    printf("Setting the CPUID.\n");
    if (ioctl(vcpufd, KVM_SET_CPUID2, kvm_cpuid) < 0)
        err(1, "KVM_SET_CPUID2 failed");
}

void platform_setup_system_64bit(struct platform *p, uint64_t cr0,
                                 uint64_t cr4 ,uint64_t efer)
{
    struct kvm_sregs sregs;
    int ret;
    
    ret = ioctl(p->vcpu, KVM_GET_SREGS, &sregs);
    if (ret == -1)
        err(1, "KVM_GET_SREGS");

    sregs.cr0 = cr0;
    sregs.cr4 = cr4;
    sregs.efer = efer;

    ret = ioctl(p->vcpu, KVM_SET_SREGS, &sregs);
    if (ret == -1)
        err(1, "KVM_SET_SREGS");
}

void platform_setup_system_page_tables(struct platform *p,
                                       uint64_t pml4)
{
    struct kvm_sregs sregs;
    int ret;
    
    ret = ioctl(p->vcpu, KVM_GET_SREGS, &sregs);
    if (ret == -1)
        err(1, "KVM_GET_SREGS");
        
    sregs.cr3 = pml4;

    ret = ioctl(p->vcpu, KVM_SET_SREGS, &sregs);
    if (ret == -1)
        err(1, "KVM_SET_SREGS");
}

void platform_setup_system_gdt(struct platform *p,
                               uint64_t cs_idx,
                               uint64_t ds_idx,
                               uint64_t off,
                               uint64_t limit)
{
    struct kvm_sregs sregs;
    struct kvm_segment data_seg, code_seg;
    int ret;
    uint64_t *gdt = (uint64_t *) (p->mem + off);
    uint64_t cs_off = cs_idx * sizeof(uint64_t);
    uint64_t ds_off = ds_idx * sizeof(uint64_t);
    
    /* Set all cpu/mem system structures */
    ret = ioctl(p->vcpu, KVM_GET_SREGS, &sregs);
    if (ret == -1)
        err(1, "KVM_GET_SREGS");

    sregs.gdt.base = off;
    sregs.gdt.limit = limit;
    
    GDT_TO_KVM_SEGMENT(code_seg, gdt, cs_off);
    GDT_TO_KVM_SEGMENT(data_seg, gdt, ds_off);

    sregs.cs = code_seg;
    sregs.ds = data_seg;
    sregs.es = data_seg;
    sregs.fs = data_seg;
    sregs.gs = data_seg;
    sregs.ss = data_seg;

    ret = ioctl(p->vcpu, KVM_SET_SREGS, &sregs);
    if (ret == -1)
        err(1, "KVM_SET_SREGS");
}

void platform_setup_system(struct platform *p, uint64_t entry)
{
    int ret;
    /*
     * Initialize registers: instruction pointer for our code, addends,
     * and initial flags required by x86 architecture.
     * Arguments to the kernel main are passed using the x86_64 calling
     * convention: RDI, RSI, RDX, RCX, R8, and R9
     */
    struct kvm_regs regs = {
        .rip = entry,
        .rflags = 0x2,
        .rsp = GUEST_SIZE - 8,  /* x86_64 ABI requires ((rsp + 8) % 16) == 0 */
        .rdi = BOOT_INFO,       /* size arg in kernel main */
    };
    ret = ioctl(p->vcpu, KVM_SET_REGS, &regs);
    if (ret == -1)
        err(1, "KVM_SET_REGS");
}

int platform_init(struct platform **pdata_p)
{
    int kvm, ret, vmfd, vcpufd;
    uint8_t *mem;
    struct kvm_run *run;
    size_t mmap_size;

    kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (kvm == -1)
        err(1, "/dev/kvm");

    /* Make sure we have the stable version of the API */
    ret = ioctl(kvm, KVM_GET_API_VERSION, NULL);
    if (ret == -1)
        err(1, "KVM_GET_API_VERSION");
    if (ret != 12)
        errx(1, "KVM_GET_API_VERSION %d, expected 12", ret);

    vmfd = ioctl(kvm, KVM_CREATE_VM, 0);
    if (vmfd == -1)
        err(1, "KVM_CREATE_VM");

    /*
     * TODO If the guest size is larger than ~4GB, we need two region
     * slots: one before the pci gap, and one after it.
     * Reference: kvmtool x86/kvm.c:kvm__init_ram()
     */
    assert(GUEST_SIZE < KVM_32BIT_GAP_SIZE);

    /* Allocate GUEST_SIZE page-aligned guest memory. */
    mem = mmap(NULL, GUEST_SIZE, PROT_READ | PROT_WRITE,
               MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED)
        err(1, "allocating guest memory");

    struct kvm_userspace_memory_region region = {
        .slot = 0,
        .guest_phys_addr = 0,
        .memory_size = GUEST_SIZE,
        .userspace_addr = (uint64_t) mem,
    };

    ret = ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &region);
    if (ret == -1)
        err(1, "KVM_SET_USER_MEMORY_REGION");

    /* enabling this seems to mess up our receiving of hlt instructions */
    /* ret = ioctl(vmfd, KVM_CREATE_IRQCHIP); */
    /* if (ret == -1) */
    /*     err(1, "KVM_CREATE_IRQCHIP"); */

    vcpufd = ioctl(vmfd, KVM_CREATE_VCPU, 0);
    if (vcpufd == -1)
        err(1, "KVM_CREATE_VCPU");
    
    /* Map the shared kvm_run structure and following data. */
    ret = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, NULL);
    if (ret == -1)
        err(1, "KVM_GET_VCPU_MMAP_SIZE");
    mmap_size = ret;
    if (mmap_size < sizeof(*run))
        errx(1, "KVM_GET_VCPU_MMAP_SIZE unexpectedly small");
    run =
        mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, vcpufd,
             0);
    if (run == MAP_FAILED)
        err(1, "mmap vcpu");

    setup_cpuid(kvm, vcpufd);

    platform.mem = mem;
    platform.vcpu = vcpufd;
    platform.priv = run;

    *pdata_p = &platform;

    return 0;
}

void platform_cleanup(struct platform *p)
{
    /* XXX */
}

int platform_run(struct platform *p)
{
    int ret = ioctl(p->vcpu, KVM_RUN, NULL);

    if (ret && (errno != EINTR)) {
        assert(errno != EAGAIN);
        return 1;
    }

    return 0;
}

int platform_get_exit_reason(struct platform *p)
{
    struct kvm_run *run = (struct kvm_run *)p->priv;

    switch (run->exit_reason) {    
    case KVM_EXIT_HLT:
        return EXIT_HLT;
    case KVM_EXIT_IO:
        return EXIT_IO;
    case KVM_EXIT_INTR:
        return EXIT_IGNORE;
        
    case KVM_EXIT_FAIL_ENTRY:
        fprintf(stderr,
                "KVM_EXIT_FAIL_ENTRY: hw_entry_failure_reason = 0x%llx",
                run->fail_entry.hardware_entry_failure_reason);
        return EXIT_FAIL;
    case KVM_EXIT_INTERNAL_ERROR:
        fprintf(stderr,
                "KVM_EXIT_INTERNAL_ERROR: suberror = 0x%x",
                run->internal.suberror);
        return EXIT_FAIL;
    default:
        fprintf(stderr,
                "Unknown KVM_EXIT ERROR = 0x%x"
                , run->exit_reason);
        return EXIT_FAIL;
    }
}

int platform_get_io_port(struct platform *p)
{
    struct kvm_run *run = (struct kvm_run *)p->priv;
    assert(run->io.direction == KVM_EXIT_IO_OUT);
    
    return run->io.port;
}

uint64_t platform_get_io_data(struct platform *p)
{
    struct kvm_run *run = (struct kvm_run *)p->priv;
    assert(run->io.direction == KVM_EXIT_IO_OUT);
    assert(run->io.size == 4);
    
    return GUEST_PIO32_TO_PADDR((uint8_t *)run + run->io.data_offset);
}

void platform_advance_rip(struct platform *p)
{
    /* no-op: KVM automatically advances RIP after I/O */
}

void platform_init_time(uint64_t *freq)
{
    printf("unimplemented");
    assert(0);
}

uint64_t platform_get_exec_time(struct platform *p)
{
    printf("unimplemented");
    assert(0);
}

void platform_emul_rdtsc(struct platform *p, uint64_t new_tsc)
{
    printf("unimplemented");
    assert(0);
}

void platform_get_timestamp(uint64_t *s, uint64_t *ns)
{
    printf("unimplemented");
    assert(0);
}
