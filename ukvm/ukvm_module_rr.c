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

int rr_mode;

#define CHK_BUF_SZ 4096
static uint8_t check_buf[CHK_BUF_SZ];

static int rr_fd;
static int do_checks = 1;
FILE *cfile;
FILE *pfile;
FILE *heavy_in_file;
FILE *heavy_out_file;

#define REGISTER_CHECK_WRITE(r) do {                \
        fprintf(fp, #r" 0x%llx\n", r);              \
    } while (0)

#define SEGMENT_CHECK_WRITE(r) do {                                     \
        fprintf(fp, #r" 0x%llx 0x%x 0x%04x %02x %02x %02x %02x %02x"    \
                " %02x %02x %02x\n", r.base, r.limit, r.selector, r.type, \
                r.present, r.dpl, r.db, r.s, r.l, r.g, r.avl);          \
    } while (0)

#define DTABLE_CHECK_WRITE(r) do {                                     \
        fprintf(fp, #r" 0x%llx 0x%04x\n", r.base, r.limit);             \
    } while (0)

#define REGISTER_CHECK_CHECK(r) do {                                \
        uint64_t cval;                                              \
        int _ret = fscanf(fp, #r" 0x%lx\n", &cval);                 \
        assert(_ret == 1);                                          \
        fprintf(pfile, #r" 0x%llx\n", r);                           \
        if (r != cval) {                                            \
            printf("for %s ", func);                                \
            printf(#r" got 0x%llx expected 0x%lx\n", r, cval);      \
        }                                                           \
        assert(r == cval);                                          \
    } while (0)

#define DTABLE_CHECK_CHECK(r) do {                                \
        uint64_t _base;                                              \
        uint16_t _limit;                                             \
        uint32_t _tmp;                                                  \
        int _ret = fscanf(fp, #r" 0x%lx 0x%04x\n", &_base, &_tmp);      \
        assert(_ret == 2);                                              \
        _limit = (uint16_t)_tmp;                                        \
        fprintf(pfile, #r" 0x%llx 0x%04x\n", r.base, r.limit);          \
        if ((r.base != _base) || (r.limit != _limit)) {                    \
            printf("for %s ", func);                                \
        }                                                           \
        assert((r.base == _base) && (r.limit == _limit));           \
    } while (0)

#define SEGMENT_CHECK_CHECK(r) do {                                     \
        struct kvm_segment _s;                                          \
        uint32_t _tmp[9];                                               \
        int _ret = fscanf(fp, #r" 0x%llx 0x%x 0x%04x %02x %02x %02x %02x" \
                          " %02x %02x %02x %02x\n", &_s.base, &_s.limit, \
                          &_tmp[0], &_tmp[1], &_tmp[2], &_tmp[3],       \
                          &_tmp[4], &_tmp[5], &_tmp[6], &_tmp[7],       \
                          &_tmp[8]);                                    \
        assert(_ret == 11);                                             \
        _s.selector = (uint16_t)_tmp[0];                                \
        _s.type = (uint8_t)_tmp[1];                                     \
        _s.present = (uint8_t)_tmp[2];                                  \
        _s.dpl = (uint8_t)_tmp[3];                                      \
        _s.db = (uint8_t)_tmp[4];                                       \
        _s.s = (uint8_t)_tmp[5];                                        \
        _s.l = (uint8_t)_tmp[6];                                        \
        _s.g = (uint8_t)_tmp[7];                                        \
        _s.avl = (uint8_t)_tmp[8];                                      \
        fprintf(pfile, #r" 0x%llx 0x%x 0x%04x %02x %02x %02x %02x %02x"    \
                " %02x %02x %02x\n", r.base, r.limit, r.selector, r.type, \
                r.present, r.dpl, r.db, r.s, r.l, r.g, r.avl);          \
        if ((r.base != _s.base) || (r.limit != _s.limit) || (r.selector != _s.selector) || (r.type != _s.type) || (r.present != _s.present) || (r.dpl != _s.dpl) || (r.db != _s.db) || (r.s != _s.s) || (r.l != _s.l) || (r.g != _s.g) || (r.avl != _s.avl)) { \
            printf("for %s ", func);                                    \
        }                                                               \
        assert((r.base == _s.base) && (r.limit == _s.limit) && (r.selector == _s.selector) && (r.type == _s.type) && (r.present == _s.present) && (r.dpl == _s.dpl) && (r.db == _s.db) && (r.s == _s.s) && (r.l == _s.l) && (r.g == _s.g) && (r.avl == _s.avl)); \
    } while (0)

uint32_t do_crc32(uint8_t *mem, size_t sz) {
    uint32_t crc = crc32(0, Z_NULL, 0);
    int i;
    for (i = 0; i < sz; i++)
        crc = crc32(crc, mem + i, 1);
    return crc;
}

#define BUG_ADDR 0xfffffffff

void heavy_check_checks(FILE *fp, struct ukvm_hv *hv, const char *func)
{
    int i;
    int ret;

    struct kvm_regs regs;
    struct kvm_sregs sregs;
    ret = ioctl(hv->b->vcpufd, KVM_GET_REGS, &regs);
    assert(ret == 0);
    ret = ioctl(hv->b->vcpufd, KVM_GET_SREGS, &sregs);
    assert(ret == 0);
    
    memset(check_buf, 0, CHK_BUF_SZ);
    ret = fscanf(fp, "function: %s\n", check_buf);
    assert(ret == 1);
    if (memcmp(check_buf, func, strlen(func)))
        printf("out of order execution detected: got %s, expected %s\n",
               func, check_buf);
    assert(memcmp(check_buf, func, strlen(func)) == 0);
    
    if (regs.rip == BUG_ADDR) {
        ret = fscanf(fp, "memory: ");
        assert(ret == 0);
        for (i = 0; i < hv->mem_size; i++) {
            uint32_t val;
            ret = fscanf(fp, "%02x", &val);
            assert(ret == 1);
            if (hv->mem[i] != val)
                printf("%08x %02x -> %02x\n", i, val, hv->mem[i]);
        }
        ret = fscanf(fp, "\n");
        assert(ret == 0);
    }
    
    REGISTER_CHECK_CHECK(regs.rip);
	REGISTER_CHECK_CHECK(regs.rflags);
	REGISTER_CHECK_CHECK(regs.rax);
	REGISTER_CHECK_CHECK(regs.rbx);
	REGISTER_CHECK_CHECK(regs.rcx);
	REGISTER_CHECK_CHECK(regs.rdx);
	REGISTER_CHECK_CHECK(regs.rsi);
	REGISTER_CHECK_CHECK(regs.rdi);
	REGISTER_CHECK_CHECK(regs.rsp);
	REGISTER_CHECK_CHECK(regs.rbp);
	REGISTER_CHECK_CHECK(regs.r8);
	REGISTER_CHECK_CHECK(regs.r9);
	REGISTER_CHECK_CHECK(regs.r10);
	REGISTER_CHECK_CHECK(regs.r11);
	REGISTER_CHECK_CHECK(regs.r12);
	REGISTER_CHECK_CHECK(regs.r13);
	REGISTER_CHECK_CHECK(regs.r14);
	REGISTER_CHECK_CHECK(regs.r15);

	SEGMENT_CHECK_CHECK(sregs.cs);
	SEGMENT_CHECK_CHECK(sregs.ds);
	SEGMENT_CHECK_CHECK(sregs.es);
	SEGMENT_CHECK_CHECK(sregs.fs);
	SEGMENT_CHECK_CHECK(sregs.gs);
	SEGMENT_CHECK_CHECK(sregs.ss);

    DTABLE_CHECK_CHECK(sregs.gdt);
    DTABLE_CHECK_CHECK(sregs.idt);

#if 0
	REGISTER_CHECK_CHECK(HV_X86_IDT_BASE);
	REGISTER_CHECK_CHECK(HV_X86_IDT_LIMIT);
	REGISTER_CHECK_CHECK(HV_X86_GDT_BASE);
	REGISTER_CHECK_CHECK(HV_X86_GDT_LIMIT);
	REGISTER_CHECK_CHECK(HV_X86_LDTR);
	REGISTER_CHECK_CHECK(HV_X86_LDT_BASE);
	REGISTER_CHECK_CHECK(HV_X86_LDT_LIMIT);
	REGISTER_CHECK_CHECK(HV_X86_LDT_AR);
	REGISTER_CHECK_CHECK(HV_X86_TR);
	REGISTER_CHECK_CHECK(HV_X86_TSS_BASE);
	REGISTER_CHECK_CHECK(HV_X86_TSS_LIMIT);
	REGISTER_CHECK_CHECK(HV_X86_TSS_AR);
#endif
    
	REGISTER_CHECK_CHECK(sregs.cr0);
	REGISTER_CHECK_CHECK(sregs.cr2);
	REGISTER_CHECK_CHECK(sregs.cr3);
	REGISTER_CHECK_CHECK(sregs.cr4);
	REGISTER_CHECK_CHECK(sregs.cr8);
    REGISTER_CHECK_CHECK(sregs.efer);
    REGISTER_CHECK_CHECK(sregs.apic_base);

#if 0
	REGISTER_CHECK_CHECK(HV_X86_DR0);
	REGISTER_CHECK_CHECK(HV_X86_DR1);
	REGISTER_CHECK_CHECK(HV_X86_DR2);
	REGISTER_CHECK_CHECK(HV_X86_DR3);
	REGISTER_CHECK_CHECK(HV_X86_DR4);
	REGISTER_CHECK_CHECK(HV_X86_DR5);
	REGISTER_CHECK_CHECK(HV_X86_DR6);
	REGISTER_CHECK_CHECK(HV_X86_DR7);
	REGISTER_CHECK_CHECK(HV_X86_TPR);
	REGISTER_CHECK_CHECK(HV_X86_XCR0);
#endif
    
    uint32_t ccrc;
    ret = fscanf(fp, "crc: 0x%x\n", &ccrc);
    assert(ret == 1);
    uint32_t crc = do_crc32(hv->mem, hv->mem_size);
    fprintf(pfile, "crc: 0x%x\n", crc);
    if (crc != ccrc) {
        printf("crc diff for %s rip is 0x%llx\n", func, regs.rip);
        if (fp == heavy_in_file)
            printf("problem was on the way IN\n");
        if (fp == heavy_out_file)
            printf("problem was on the way OUT\n");
    }
    assert(crc == ccrc);
}

void heavy_write_checks(FILE *fp, struct ukvm_hv *hv, const char *func)
{
    int i;
    int ret;
    
    struct kvm_regs regs;
    struct kvm_sregs sregs;
    ret = ioctl(hv->b->vcpufd, KVM_GET_REGS, &regs);
    assert(ret == 0);
    ret = ioctl(hv->b->vcpufd, KVM_GET_SREGS, &sregs);
    assert(ret == 0);

    fprintf(fp, "function: %s\n", func);
    
    if (regs.rip == BUG_ADDR) {
        fprintf(fp, "memory: ");
        for (i = 0; i < hv->mem_size; i++)
            fprintf(fp, "%02x", hv->mem[i]);
        fprintf(fp, "\n");
    }

    REGISTER_CHECK_WRITE(regs.rip);
	REGISTER_CHECK_WRITE(regs.rflags);
	REGISTER_CHECK_WRITE(regs.rax);
	REGISTER_CHECK_WRITE(regs.rbx);
	REGISTER_CHECK_WRITE(regs.rcx);
	REGISTER_CHECK_WRITE(regs.rdx);
	REGISTER_CHECK_WRITE(regs.rsi);
	REGISTER_CHECK_WRITE(regs.rdi);
	REGISTER_CHECK_WRITE(regs.rsp);
	REGISTER_CHECK_WRITE(regs.rbp);
	REGISTER_CHECK_WRITE(regs.r8);
	REGISTER_CHECK_WRITE(regs.r9);
	REGISTER_CHECK_WRITE(regs.r10);
	REGISTER_CHECK_WRITE(regs.r11);
	REGISTER_CHECK_WRITE(regs.r12);
	REGISTER_CHECK_WRITE(regs.r13);
	REGISTER_CHECK_WRITE(regs.r14);
	REGISTER_CHECK_WRITE(regs.r15);

	SEGMENT_CHECK_WRITE(sregs.cs);
	SEGMENT_CHECK_WRITE(sregs.ds);
	SEGMENT_CHECK_WRITE(sregs.es);
	SEGMENT_CHECK_WRITE(sregs.fs);
	SEGMENT_CHECK_WRITE(sregs.gs);
	SEGMENT_CHECK_WRITE(sregs.ss);

    DTABLE_CHECK_WRITE(sregs.gdt);
    DTABLE_CHECK_WRITE(sregs.idt);

#if 0
	REGISTER_CHECK_WRITE(HV_X86_IDT_BASE);
	REGISTER_CHECK_WRITE(HV_X86_IDT_LIMIT);
	REGISTER_CHECK_WRITE(HV_X86_GDT_BASE);
	REGISTER_CHECK_WRITE(HV_X86_GDT_LIMIT);
	REGISTER_CHECK_WRITE(HV_X86_LDTR);
	REGISTER_CHECK_WRITE(HV_X86_LDT_BASE);
	REGISTER_CHECK_WRITE(HV_X86_LDT_LIMIT);
	REGISTER_CHECK_WRITE(HV_X86_LDT_AR);
	REGISTER_CHECK_WRITE(HV_X86_TR);
	REGISTER_CHECK_WRITE(HV_X86_TSS_BASE);
	REGISTER_CHECK_WRITE(HV_X86_TSS_LIMIT);
	REGISTER_CHECK_WRITE(HV_X86_TSS_AR);
#endif
    
	REGISTER_CHECK_WRITE(sregs.cr0);
	REGISTER_CHECK_WRITE(sregs.cr2);
	REGISTER_CHECK_WRITE(sregs.cr3);
	REGISTER_CHECK_WRITE(sregs.cr4);
	REGISTER_CHECK_WRITE(sregs.cr8);
    REGISTER_CHECK_WRITE(sregs.efer);
    REGISTER_CHECK_WRITE(sregs.apic_base);

#if 0
	REGISTER_CHECK_WRITE(HV_X86_DR0);
	REGISTER_CHECK_WRITE(HV_X86_DR1);
	REGISTER_CHECK_WRITE(HV_X86_DR2);
	REGISTER_CHECK_WRITE(HV_X86_DR3);
	REGISTER_CHECK_WRITE(HV_X86_DR4);
	REGISTER_CHECK_WRITE(HV_X86_DR5);
	REGISTER_CHECK_WRITE(HV_X86_DR6);
	REGISTER_CHECK_WRITE(HV_X86_DR7);
	REGISTER_CHECK_WRITE(HV_X86_TPR);
	REGISTER_CHECK_WRITE(HV_X86_XCR0);
#endif


    uint32_t crc = do_crc32(hv->mem, hv->mem_size);
    fprintf(fp, "crc: 0x%x\n", crc);
}

void check_checks(uint8_t *buf, size_t sz, const char *func, int line) {
    size_t c_sz;
    int c_line;
    int i;
    int ret;
    
    {
        fprintf(pfile, "%zu %s %d ", sz, func, line);
        for (i = 0; i < sz; i++)
            fprintf(pfile, "%02x", buf[i]);
        fprintf(pfile, "\n");
    }
    memset(check_buf, 0, CHK_BUF_SZ);
    ret = fscanf(cfile, "%zu %s %d ", &c_sz, check_buf, &c_line);
    assert(ret == 3);
    if ((c_line != line) || memcmp(check_buf, func, strlen(func))) {
        printf("out of order execution detected!!!!\n");
        printf("got %s:%d, expected %s:%d\n", func, line, check_buf, c_line);
    }
    assert(c_sz == sz);
    assert(c_line == line);
    assert(memcmp(check_buf, func, strlen(func)) == 0);
    for (i = 0; i < sz; i++) {
        uint32_t c;
        ret = fscanf(cfile, "%02x", &c);
        assert(ret == 1);
        assert(c == buf[i]);
    }
    ret = fscanf(cfile, "\n");
    assert(ret == 0);
}

void write_checks(uint8_t *buf, size_t sz, const char *func, int line) {
    int i;

    fprintf(cfile, "%zu %s %d ", sz, func, line);
    for (i = 0; i < sz; i++)
        fprintf(cfile, "%02x", buf[i]);
    fprintf(cfile, "\n");
}

void rr(uint8_t *x, size_t sz, int l, const char *func, int line)
{
    int ret;
    if (l == RR_LOC_IN) {
        if (rr_mode == RR_MODE_REPLAY) {
            if (0 && do_checks)
                check_checks(x, sz, func, line);
            ret = read(rr_fd, x, sz);
            if (ret == 0)
                errx(0, "Reached end of replay\n");
            if (ret != sz)
                printf("ret=%u, sz=%lu\n", ret, sz);
            assert(ret == sz);
        }
        if (rr_mode == RR_MODE_RECORD)
            if (0 && do_checks)
                write_checks(x, sz, func, line);
    }
    if (l == RR_LOC_OUT) {
        if (rr_mode == RR_MODE_RECORD) {
            ret = write(rr_fd, x, sz);
            assert(ret == sz);
        }
    }
}

#define RR(l, x, s) do {                                        \
        rr((uint8_t *)(x), s, l, __FUNCTION__, __LINE__);       \
    } while (0)

#define CHECK(l, x, s) do {                                            \
        if (l == RR_LOC_IN) {                                           \
            if (rr_mode == RR_MODE_REPLAY) {                            \
                if (do_checks)                                          \
                    check_checks((uint8_t *)(x), s, __FUNCTION__, __LINE__); \
            }                                                           \
            if (rr_mode == RR_MODE_RECORD)                              \
                if (do_checks)                                          \
                    write_checks((uint8_t *)(x), s, __FUNCTION__, __LINE__); \
        }                                                               \
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

static int rr_init(char *rr_file, char *check_file, char *progress_file)
{
    //printf("rdtsc_locs = %lu\n", NUM_RDTSC_LOCS);

    switch (rr_mode) {
    case RR_MODE_RECORD: {
        rr_fd = open(rr_file, O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR | S_IWUSR);
        if (check_file) {
            cfile = fopen(check_file, "w");
            heavy_in_file = fopen("rr_heavy_in.log", "w");
            heavy_out_file = fopen("rr_heavy_out.log", "w");
        }
        break;
    }
    case RR_MODE_REPLAY: {
        rr_fd = open(rr_file, O_RDONLY);
        if (check_file) {
            cfile = fopen(check_file, "r");
            pfile = fopen(progress_file, "w");
            heavy_in_file = fopen("rr_heavy_in.log", "r");
            heavy_out_file = fopen("rr_heavy_out.log", "r");
            if (!pfile)
                errx(1, "couldn't open progress file %s\n", progress_file);
        }
        break;
    }
    default:
        return -1;
    }
    if (rr_fd <= 0)
        errx(1, "couldn't open rr file %s\n", rr_file);
    if (check_file && !cfile)
        errx(1, "couldn't open check file %s\n", check_file);
    return 0;
}


#define HEAVY_CHECKS(f) do {                                    \
        if (rr_mode == RR_MODE_RECORD)                          \
            heavy_write_checks(f, hv, __FUNCTION__);             \
        if (rr_mode == RR_MODE_REPLAY)                          \
            heavy_check_checks(f, hv, __FUNCTION__);             \
    } while (0)    

#define HEAVY_CHECKS_IN() do {                  \
        if (loc == RR_LOC_IN)                   \
            HEAVY_CHECKS(heavy_in_file);        \
    } while (0)
#define HEAVY_CHECKS_OUT() do {                  \
        if (loc == RR_LOC_OUT)                   \
            HEAVY_CHECKS(heavy_out_file);        \
    } while (0)
    
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

    rr_init("rr_out.dat", "rr_check.log", "rr_prog.log");
    
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
