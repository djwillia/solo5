#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <err.h>
#include <zlib.h>

#include "ukvm.h"
#include "ukvm-private.h"
#include "unikernel-monitor.h"
#include "ukvm-rr.h"
int rr_mode;

#define CHK_BUF_SZ 4096
static uint8_t check_buf[CHK_BUF_SZ];

static int rr_fd;
static int do_checks = 1;
FILE *cfile;
FILE *pfile;
FILE *heavy_in_file;
FILE *heavy_out_file;

uint64_t rreg(hv_vcpuid_t vcpu, hv_x86_reg_t reg);
#include <Hypervisor/hv_arch_x86.h>

#define REGISTER_CHECK_WRITE(r) do {                     \
        fprintf(fp, #r" 0x%llx\n", rreg(p->vcpu, r));    \
    } while (0)

#define REGISTER_CHECK_CHECK(r) do {                                \
        uint64_t cval;                                              \
        uint64_t rval;                                              \
        fscanf(fp, #r" 0x%llx\n", &cval);                           \
        rval = rreg(p->vcpu, r);                                    \
        fprintf(pfile, #r" 0x%llx\n", rval);                        \
        if (rval != cval) {                                         \
            printf("for %s ", func);                                \
            printf(#r" got 0x%llx expected 0x%llx\n", rval, cval);  \
        }                                                           \
        assert(rval == cval);                                       \
    } while (0)

uint32_t do_crc32(uint8_t *mem, size_t sz) {
    uint32_t crc = crc32(0, Z_NULL, 0);
    int i;
    for (i = 0; i < sz; i++)
        crc = crc32(crc, mem + i, 1);
    return crc;
}

#define BUG_ADDR 0x100e14

void heavy_check_checks(FILE *fp, struct platform *p, const char *func)
{
    int i;

    if (rreg(p->vcpu, HV_X86_RIP) == BUG_ADDR) {
        fscanf(fp, "memory: ");
        for (i = 0; i < GUEST_SIZE; i++) {
            uint32_t val;
            fscanf(fp, "%02x", &val);
            if (p->mem[i] != val)
                printf("%08x %02x -> %02x\n", i, val, p->mem[i]);
        }
        fscanf(fp, "\n");
    }
    
    REGISTER_CHECK_CHECK(HV_X86_RIP);
	REGISTER_CHECK_CHECK(HV_X86_RFLAGS);
	REGISTER_CHECK_CHECK(HV_X86_RAX);
	REGISTER_CHECK_CHECK(HV_X86_RCX);
	REGISTER_CHECK_CHECK(HV_X86_RDX);
	REGISTER_CHECK_CHECK(HV_X86_RBX);
	REGISTER_CHECK_CHECK(HV_X86_RSI);
	REGISTER_CHECK_CHECK(HV_X86_RDI);
	REGISTER_CHECK_CHECK(HV_X86_RSP);
	REGISTER_CHECK_CHECK(HV_X86_RBP);
	REGISTER_CHECK_CHECK(HV_X86_R8);
	REGISTER_CHECK_CHECK(HV_X86_R9);
	REGISTER_CHECK_CHECK(HV_X86_R10);
	REGISTER_CHECK_CHECK(HV_X86_R11);
	REGISTER_CHECK_CHECK(HV_X86_R12);
	REGISTER_CHECK_CHECK(HV_X86_R13);
	REGISTER_CHECK_CHECK(HV_X86_R14);
	REGISTER_CHECK_CHECK(HV_X86_R15);
	REGISTER_CHECK_CHECK(HV_X86_CS);
	REGISTER_CHECK_CHECK(HV_X86_SS);
	REGISTER_CHECK_CHECK(HV_X86_DS);
	REGISTER_CHECK_CHECK(HV_X86_ES);
	REGISTER_CHECK_CHECK(HV_X86_FS);
	REGISTER_CHECK_CHECK(HV_X86_GS);
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
	REGISTER_CHECK_CHECK(HV_X86_CR0);
	REGISTER_CHECK_CHECK(HV_X86_CR1);
	REGISTER_CHECK_CHECK(HV_X86_CR2);
	REGISTER_CHECK_CHECK(HV_X86_CR3);
	REGISTER_CHECK_CHECK(HV_X86_CR4);
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

    uint32_t ccrc;
    fscanf(fp, "crc: 0x%x\n", &ccrc);
    uint32_t crc = do_crc32(p->mem, GUEST_SIZE);
    fprintf(pfile, "crc: 0x%x\n", crc);
    if (crc != ccrc) {
        printf("crc diff for %s rip is 0x%llx\n", func, rreg(p->vcpu, HV_X86_RIP));
        if (fp == heavy_in_file)
            printf("problem was on the way IN\n");
        if (fp == heavy_out_file)
            printf("problem was on the way OUT\n");
    }
    assert(crc == ccrc);
}

void heavy_write_checks(FILE *fp, struct platform *p, const char *func)
{
    int i;
    
    if (rreg(p->vcpu, HV_X86_RIP) == BUG_ADDR) {
        fprintf(fp, "memory: ");
        for (i = 0; i < GUEST_SIZE; i++)
            fprintf(fp, "%02x", p->mem[i]);
        fprintf(fp, "\n");
    }

    REGISTER_CHECK_WRITE(HV_X86_RIP);
	REGISTER_CHECK_WRITE(HV_X86_RFLAGS);
	REGISTER_CHECK_WRITE(HV_X86_RAX);
	REGISTER_CHECK_WRITE(HV_X86_RCX);
	REGISTER_CHECK_WRITE(HV_X86_RDX);
	REGISTER_CHECK_WRITE(HV_X86_RBX);
	REGISTER_CHECK_WRITE(HV_X86_RSI);
	REGISTER_CHECK_WRITE(HV_X86_RDI);
	REGISTER_CHECK_WRITE(HV_X86_RSP);
	REGISTER_CHECK_WRITE(HV_X86_RBP);
	REGISTER_CHECK_WRITE(HV_X86_R8);
	REGISTER_CHECK_WRITE(HV_X86_R9);
	REGISTER_CHECK_WRITE(HV_X86_R10);
	REGISTER_CHECK_WRITE(HV_X86_R11);
	REGISTER_CHECK_WRITE(HV_X86_R12);
	REGISTER_CHECK_WRITE(HV_X86_R13);
	REGISTER_CHECK_WRITE(HV_X86_R14);
	REGISTER_CHECK_WRITE(HV_X86_R15);
	REGISTER_CHECK_WRITE(HV_X86_CS);
	REGISTER_CHECK_WRITE(HV_X86_SS);
	REGISTER_CHECK_WRITE(HV_X86_DS);
	REGISTER_CHECK_WRITE(HV_X86_ES);
	REGISTER_CHECK_WRITE(HV_X86_FS);
	REGISTER_CHECK_WRITE(HV_X86_GS);
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
	REGISTER_CHECK_WRITE(HV_X86_CR0);
	REGISTER_CHECK_WRITE(HV_X86_CR1);
	REGISTER_CHECK_WRITE(HV_X86_CR2);
	REGISTER_CHECK_WRITE(HV_X86_CR3);
	REGISTER_CHECK_WRITE(HV_X86_CR4);
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

    uint32_t crc = do_crc32(p->mem, GUEST_SIZE);
    fprintf(fp, "crc: 0x%x\n", crc);
}

void check_checks(struct platform *p, uint8_t *buf, size_t sz, const char *func, int line) {
    size_t c_sz;
    int c_line;
    int i;

    {
        fprintf(pfile, "%zu %s %d ", sz, func, line);
        for (i = 0; i < sz; i++)
            fprintf(pfile, "%02x", buf[i]);
        fprintf(pfile, "\n");
    }
    memset(check_buf, 0, CHK_BUF_SZ);
    fscanf(cfile, "%zu %s %d ", &c_sz, check_buf, &c_line);
    if ((c_line != line) || memcmp(check_buf, func, strlen(func))) {
        printf("out of order execution detected!!!!\n");
        printf("got %s:%d, expected %s:%d\n", func, line, check_buf, c_line);
    }
    assert(c_sz == sz);
    assert(c_line == line);
    assert(memcmp(check_buf, func, strlen(func)) == 0);
    for (i = 0; i < sz; i++) {
        uint32_t c;
        fscanf(cfile, "%02x", &c);
        assert(c == buf[i]);
    }
    fscanf(cfile, "\n");
}

void write_checks(struct platform *p, uint8_t *buf, size_t sz, const char *func, int line) {
    int i;

    fprintf(cfile, "%zu %s %d ", sz, func, line);
    for (i = 0; i < sz; i++)
        fprintf(cfile, "%02x", buf[i]);
    fprintf(cfile, "\n");
}

#define RR_IN(x) do {                                                   \
        if (rr_mode == RR_MODE_REPLAY) {                                \
            if (do_checks)                                              \
                check_checks(p, (uint8_t *)(&(x)), sizeof(x), __FUNCTION__, __LINE__); \
            read(rr_fd, &(x), sizeof(x));                               \
        }                                                               \
        if (rr_mode == RR_MODE_RECORD)                                  \
            if (do_checks)                                               \
                write_checks(p, (uint8_t *)(&(x)), sizeof(x), __FUNCTION__, __LINE__); \
    } while (0)

#define RR_OUT(x) do {                                                 \
        if (rr_mode == RR_MODE_RECORD)                                 \
            write(rr_fd, &(x), sizeof(x));                             \
    } while (0)

#define RR(l,x) do {                                                \
        if (l == RR_LOC_IN)                                         \
            RR_IN(x);                                               \
        if (l == RR_LOC_OUT)                                        \
            RR_OUT(x);                                              \
    } while (0)

#define CHECK(l, x, s) do {                                            \
        if (l == RR_LOC_IN) {                                           \
            if (rr_mode == RR_MODE_REPLAY) {                            \
                if (do_checks)                                          \
                    check_checks(p, (uint8_t *)(x), s, __FUNCTION__, __LINE__); \
            }                                                           \
            if (rr_mode == RR_MODE_RECORD)                              \
                if (do_checks)                                          \
                    write_checks(p, (uint8_t *)(x), s, __FUNCTION__, __LINE__); \
        }                                                               \
    } while (0)
              
int rr_init(int m, char *rr_file, char *check_file, char *progress_file)
{
    rr_mode = m;
    switch (rr_mode) {
    case RR_MODE_RECORD:
        rr_fd = open(rr_file, O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR | S_IWUSR);
        if (check_file) {
            cfile = fopen(check_file, "w");
            heavy_in_file = fopen("rr_heavy_in.log", "w");
            heavy_out_file = fopen("rr_heavy_out.log", "w");
        }
        break;
    case RR_MODE_REPLAY:
        rr_fd = open(rr_file, O_RDONLY);
        if (check_file) {
            cfile = fopen(check_file, "r");
            pfile = fopen(progress_file, "w");
            heavy_in_file = fopen("rr_heavy_in.log", "r");
            heavy_out_file = fopen("rr_heavy_out.log", "r");
            if (!pfile)
                errx(1, "couldn't open progress file %s\n", progress_file);
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
            heavy_write_checks(f, p, __FUNCTION__);             \
        if (rr_mode == RR_MODE_REPLAY)                          \
            heavy_check_checks(f, p, __FUNCTION__);             \
    } while (0)    

#define HEAVY_CHECKS_IN() do {                  \
        if (loc == RR_LOC_IN)                   \
            HEAVY_CHECKS(heavy_in_file);        \
    } while (0)
#define HEAVY_CHECKS_OUT() do {                  \
        if (loc == RR_LOC_OUT)                   \
            HEAVY_CHECKS(heavy_out_file);        \
    } while (0)
    
void rr_ukvm_puts(struct platform *p, struct ukvm_puts *o, int loc)
{
    HEAVY_CHECKS_IN();
        
    CHECK(loc, &o->data, sizeof(o->data));
    CHECK(loc, p->mem + o->data, o->len);
    CHECK(loc, &o->len, sizeof(o->len));

    HEAVY_CHECKS_OUT();
}
    
void rr_ukvm_boot_info(struct platform *p, struct ukvm_boot_info *o, int loc)
{
    HEAVY_CHECKS_IN();
    
    RR(loc, o->mem_size);
    RR(loc, o->kernel_end);
    RR(loc, o->cmdline);

    HEAVY_CHECKS_OUT();
}
void rr_ukvm_blkinfo(struct platform *p, struct ukvm_blkinfo *o, int loc)
{
    HEAVY_CHECKS_IN();
    
	RR(loc, o->sector_size);
    RR(loc, o->num_sectors);
    RR(loc, o->rw);

    HEAVY_CHECKS_OUT();
}
void rr_ukvm_blkwrite(struct platform *p, struct ukvm_blkwrite *o, int loc)
{
    HEAVY_CHECKS_IN();
    
    CHECK(loc, &o->sector, sizeof(o->sector));
    CHECK(loc, &o->data, sizeof(o->data));
    CHECK(loc, p->mem + o->data, o->len);
    CHECK(loc, &o->len, sizeof(o->len));
    RR(loc, o->ret);

    HEAVY_CHECKS_OUT();
}
void rr_ukvm_blkread(struct platform *p, struct ukvm_blkread *o, int loc)
{
    HEAVY_CHECKS_IN();
    
    CHECK(loc, &o->sector, sizeof(o->sector));
    CHECK(loc, &o->data, sizeof(o->data));
    CHECK(loc, p->mem + o->data, o->len);
	RR(loc, o->len);
	RR(loc, o->ret);

    HEAVY_CHECKS_OUT();
}
void rr_ukvm_netinfo(struct platform *p, struct ukvm_netinfo *o, int loc)
{
    HEAVY_CHECKS_IN();
    
    RR(loc, o->mac_str);

    HEAVY_CHECKS_OUT();
}
void rr_ukvm_netwrite(struct platform *p, struct ukvm_netwrite *o, int loc)
{
    HEAVY_CHECKS_IN();
    
    CHECK(loc, &o->data, sizeof(o->data));
    CHECK(loc, p->mem + o->data, o->len);
    CHECK(loc, &o->len, sizeof(o->len));
	RR(loc, o->ret);

    HEAVY_CHECKS_OUT();
}
void rr_ukvm_netread(struct platform *p, struct ukvm_netread *o, int loc)
{
    HEAVY_CHECKS_IN();
    
    CHECK(loc, &o->data, sizeof(o->data));
    CHECK(loc, p->mem + o->data, o->len);
	RR(loc, o->len);
	RR(loc, o->ret);

    HEAVY_CHECKS_OUT();
}
void rr_ukvm_poll(struct platform *p, struct ukvm_poll *o, int loc)
{
    HEAVY_CHECKS_IN();
    
    CHECK(loc, &o->timeout_nsecs, sizeof(o->timeout_nsecs));
    RR(loc, o->ret);

    HEAVY_CHECKS_OUT();
}
void rr_ukvm_time_init(struct platform *p, struct ukvm_time_init *o, int loc)
{
    HEAVY_CHECKS_IN();
    
	RR(loc, o->freq);
    RR(loc, o->rtc_boot);

    HEAVY_CHECKS_OUT();
}
void rr_ukvm_cpuid(struct platform *p, struct ukvm_cpuid *o, int loc)
{
    HEAVY_CHECKS_IN();
    
	CHECK(loc, &o->code, sizeof(o->code));
    RR(loc, o->eax);
    RR(loc, o->ebx);
    RR(loc, o->ecx);
    RR(loc, o->edx);

    HEAVY_CHECKS_OUT();
}
void rr_ukvm_rdtsc(struct platform *p, uint64_t *new_tsc, int loc)
{
    HEAVY_CHECKS_IN();
    
    RR(loc, *new_tsc);

    HEAVY_CHECKS_OUT();
}
void rr_ukvm_rdrand(struct platform *p, uint64_t *r, int loc)
{
    HEAVY_CHECKS_IN();
    
    RR(loc, *r);

    HEAVY_CHECKS_OUT();
}
