#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <err.h>

#include <zlib.h>
#include <linux/kvm.h>

#include "ukvm.h"
#include "ukvm_hv_kvm.h"
#include "ukvm_rr.h"
#include "rr_rdtsc_helper.h"

#define RR_DO_CHECKS
#ifdef RR_DO_CHECKS
#include "ukvm_module_rr_checks.h"
#else
#define HEAVY_CHECKS_IN(f) do{}while(0)
#define HEAVY_CHECKS_OUT(f) do{}while(0)
#define CHECK(a,b,c) do{}while(0)
#define CHECKS_INIT() do{}while(0)
#endif

int rr_mode = RR_MODE_NONE;
static int rr_fd;

void rr(uint8_t *x, size_t sz, int l, const char *func, int line)
{
    int ret;
    if ((l == RR_LOC_IN) && (rr_mode == RR_MODE_REPLAY)) {
        ret = read(rr_fd, x, sz);
        if (ret == 0)
            errx(0, "Reached end of replay\n");
        assert(ret == sz);
    }
    if ((l == RR_LOC_OUT) && (rr_mode == RR_MODE_RECORD)) {
        ret = write(rr_fd, x, sz);
        assert(ret == sz);
    }
}

#define RR(l, x, s) do {                                        \
        rr((uint8_t *)(x), s, l, __FUNCTION__, __LINE__);       \
    } while (0)

static int rdtsc_init_traps(struct ukvm_hv *hv)
{
    if (NUM_RDTSC_LOCS == 0)
        return 0;
    
    int i;
    struct kvm_guest_debug dbg = {0};
    
    for (i = 0; i < NUM_RDTSC_LOCS; i++) {
        uint8_t *addr = hv->mem + rdtsc_locs[i];
        /* rdtsc is 2 bytes; we replace it with a int3, which traps */
        addr[0] = 0xcc; /* int3 */
        addr[1] = 0x90; /* nop  */
    }

    dbg.control |= KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP;
    if (ioctl(hv->b->vcpufd, KVM_SET_GUEST_DEBUG, &dbg) == -1) {
        /* The KVM_CAP_SET_GUEST_DEBUG capbility is not available. */
        err(1, "KVM_SET_GUEST_DEBUG failed");
        return -1;
    }

    return 0;
}
static void rdtsc_emulate(struct ukvm_hv *hv)
{
    uint64_t tscval = 0;
    uint32_t eax, edx;
    struct kvm_regs regs;
    int ret;
    
    ret = ioctl(hv->b->vcpufd, KVM_GET_REGS, &regs);
    assert(ret == 0);

    RR_INPUT(hv, rdtsc, &tscval);
    
    __asm__("rdtsc" : "=a" (eax), "=d" (edx));
    tscval = ((uint64_t)edx << 32) | eax;

    RR_OUTPUT(hv, rdtsc, &tscval);
    
    regs.rax = tscval & 0xffffffff;
    regs.rdx = (tscval >> 32) & 0xffffffff;
    regs.rip += 2;
    
    ret = ioctl(hv->b->vcpufd, KVM_SET_REGS, &regs);
    assert(ret == 0);
}

static int rr_init(char *rr_file)
{
    CHECKS_INIT();
    
    switch (rr_mode) {
    case RR_MODE_RECORD: {
        rr_fd = open(rr_file, O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR | S_IWUSR);
        break;
    }
    case RR_MODE_REPLAY: {
        rr_fd = open(rr_file, O_RDONLY);
        break;
    }
    default:
        return -1;
    }
    if (rr_fd <= 0)
        errx(1, "couldn't open rr file %s\n", rr_file);
    return 0;
}
    
void rr_ukvm_walltime(struct ukvm_hv *hv, struct ukvm_walltime *o, int loc)
{
    HEAVY_CHECKS_IN();
    
	RR(loc, &o->nsecs, sizeof(o->nsecs));

    HEAVY_CHECKS_OUT();
}

void rr_ukvm_puts(struct ukvm_hv *hv, struct ukvm_puts *o, int loc)
{
    HEAVY_CHECKS_IN();
        
    CHECK(loc, &o->data, sizeof(o->data));
    CHECK(loc, UKVM_CHECKED_GPA_P(hv, o->data, o->len), o->len);
    CHECK(loc, &o->len, sizeof(o->len));

    HEAVY_CHECKS_OUT();
}
    
void rr_ukvm_poll(struct ukvm_hv *hv, struct ukvm_poll *o, int loc)
{
    HEAVY_CHECKS_IN();
    
    CHECK(loc, &o->timeout_nsecs, sizeof(o->timeout_nsecs));
    RR(loc, &o->ret, sizeof(o->ret));

    HEAVY_CHECKS_OUT();
}

void rr_ukvm_rdtsc(struct ukvm_hv *hv, uint64_t *new_tsc, int loc)
{
    HEAVY_CHECKS_IN();
    
    RR(loc, &*new_tsc, sizeof(*new_tsc));

    HEAVY_CHECKS_OUT();
}

void rr_ukvm_netinfo(struct ukvm_hv *hv, struct ukvm_netinfo *o, int loc)
{
    HEAVY_CHECKS_IN();
    
    RR(loc, &o->mac_str, sizeof(o->mac_str));

    HEAVY_CHECKS_OUT();
}
void rr_ukvm_netwrite(struct ukvm_hv *hv, struct ukvm_netwrite *o, int loc)
{
    HEAVY_CHECKS_IN();
    
    CHECK(loc, &o->data, sizeof(o->data));
    CHECK(loc, UKVM_CHECKED_GPA_P(hv, o->data, o->len), o->len);
    CHECK(loc, &o->len, sizeof(o->len));
	RR(loc, &o->ret, sizeof(o->ret));

    HEAVY_CHECKS_OUT();
}
void rr_ukvm_netread(struct ukvm_hv *hv, struct ukvm_netread *o, int loc)
{
    HEAVY_CHECKS_IN();

    CHECK(loc, &o->data, sizeof(o->data));
	RR(loc, &o->len, sizeof(o->len));
    RR(loc, UKVM_CHECKED_GPA_P(hv, o->data, o->len), o->len);
	RR(loc, &o->ret, sizeof(o->ret));

    HEAVY_CHECKS_OUT();
}
#if 0
void rr_ukvm_boot_info(struct ukvm_hv *hv, struct ukvm_boot_info *o, int loc)
{
    HEAVY_CHECKS_IN();
    
    RR(loc, &o->mem_size, sizeof(o->mem_size));
    RR(loc, &o->kernel_end, sizeof(o->kernel_end));
    RR(loc, &o->cmdline_len, sizeof(o->cmdline_len));
    RR(loc, UKVM_CHECKED_GPA_P(hv, o->cmdline, o->cmdline_len), o->cmdline_len);

    HEAVY_CHECKS_OUT();
}
#endif
void rr_ukvm_blkinfo(struct ukvm_hv *hv, struct ukvm_blkinfo *o, int loc)
{
    HEAVY_CHECKS_IN();
    
	RR(loc, &o->sector_size, sizeof(o->sector_size));
    RR(loc, &o->num_sectors, sizeof(o->num_sectors));
    RR(loc, &o->rw, sizeof(o->rw));

    HEAVY_CHECKS_OUT();
}
void rr_ukvm_blkwrite(struct ukvm_hv *hv, struct ukvm_blkwrite *o, int loc)
{
    HEAVY_CHECKS_IN();
    
    CHECK(loc, &o->sector, sizeof(o->sector));
    CHECK(loc, &o->data, sizeof(o->data));
    CHECK(loc, UKVM_CHECKED_GPA_P(hv, o->data, o->len), o->len);
    CHECK(loc, &o->len, sizeof(o->len));
    RR(loc, &o->ret, sizeof(o->ret));

    HEAVY_CHECKS_OUT();
}
void rr_ukvm_blkread(struct ukvm_hv *hv, struct ukvm_blkread *o, int loc)
{
    HEAVY_CHECKS_IN();
    
    CHECK(loc, &o->sector, sizeof(o->sector));
    CHECK(loc, &o->data, sizeof(o->data));
	RR(loc, &o->len, sizeof(o->len));
    RR(loc, UKVM_CHECKED_GPA_P(hv, o->data, o->len), o->len);
	RR(loc, &o->ret, sizeof(o->ret));

    HEAVY_CHECKS_OUT();
}
#if 0
void rr_ukvm_cpuid(struct ukvm_hv *hv, struct ukvm_cpuid *o, int loc)
{
    HEAVY_CHECKS_IN();
    
	CHECK(loc, &o->code, sizeof(o->code));
    RR(loc, &o->eax, sizeof(o->eax));
    RR(loc, &o->ebx, sizeof(o->ebx));
    RR(loc, &o->ecx, sizeof(o->ecx));
    RR(loc, &o->edx, sizeof(o->edx));

    HEAVY_CHECKS_OUT();
}
void rr_ukvm_rdrand(struct platform *p, uint64_t *r, int loc)
{
    HEAVY_CHECKS_IN();
    
    RR(loc, &*r, sizeof(*r));

    HEAVY_CHECKS_OUT();
}
#endif

static int handle_vmexits(struct ukvm_hv *hv)
{
    /* if it's not an int3 for a rdtsc, let the vcpu loop do it */
    if (hv->b->vcpurun->exit_reason != KVM_EXIT_DEBUG)
        return -1;

    struct kvm_regs regs;
    int ret, i;
    
    ret = ioctl(hv->b->vcpufd, KVM_GET_REGS, &regs);
    assert(ret == 0);
    
    for (i = 0; i < NUM_RDTSC_LOCS; i++) {
        if (rdtsc_locs[i] == regs.rip) {
            rdtsc_emulate(hv);
            return 0;
        }
    }

    /* it wasn't an rdtsc */
    return -1;
}

static int setup(struct ukvm_hv *hv)
{
    int ret;

    if (rr_mode == RR_MODE_NONE)
        return 0;
    
    rr_init("rr_out.dat");
    
    /* XXX should rdtsc trapping/emulation be its own module? */
    ret = rdtsc_init_traps(hv);
    assert(ret == 0);
    /* for rdtsc traps, we need to handle int3s */
    ret = ukvm_core_register_vmexit(handle_vmexits);
    assert(ret == 0);
    /* XXX we really want a entry exit hook for rr */
    return 0;
}

static int handle_cmdarg(char *cmdarg)
{
    if (!strncmp("--record", cmdarg, 8)) {
        rr_mode = RR_MODE_RECORD;
        return 0;
    } else if (!strncmp("--replay", cmdarg, 8)) {
        rr_mode = RR_MODE_REPLAY;
        return 0;
    } else {
        return -1;
    }
}

static char *usage(void)
{
    return "[--record][--replay]\n";
}

struct ukvm_module ukvm_module_rr = {
    .name = "rr",
    .setup = setup,
    .handle_cmdarg = handle_cmdarg,
    .usage = usage
};
