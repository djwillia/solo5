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

#include "ukvm.h"
#include "unikernel-monitor.h"
#include "ukvm-rr.h"
int rr_mode;

#define CHK_BUF_SZ 256
static uint8_t check_buf[CHK_BUF_SZ];

static int rr_fd;
static int check_fd; /* set to 0 to disable checks */
#if 0
static void rr_64(int l, uint64_t *x) {
    if (l == RR_LOC_IN) {
        if (rr_mode == RR_MODE_REPLAY) {
            if (check_fd) {
                int ret;
                assert(sizeof(*x) < CHK_BUF_SZ);
                ret = read(check_fd, check_buf, sizeof(*x));
                assert(ret == sizeof(*x));
                printf("checking for 0x%p: 0x%llx == 0x%llx\n", x, *((uint64_t *)check_buf), *x);
                assert(memcmp(check_buf, x, sizeof(*x)) == 0);
            }
            read(rr_fd, x, sizeof(*x));
            printf("replaying for 0x%p: 0x%llx\n", x, *x);
        }
        if (rr_mode == RR_MODE_RECORD) {
            printf("should check for 0x%p: 0x%llx\n", x, *x);
            if (check_fd) write(check_fd, x, sizeof(*x));
        }
    }
    if (l == RR_LOC_OUT) {
        if (rr_mode == RR_MODE_RECORD) {
            write(rr_fd, x, sizeof(*x));
            printf("recording for 0x%p: 0x%llx\n", x, *x);
        }
    }
}
#endif
#define RR_IN(x) do {                                                  \
        if (rr_mode == RR_MODE_REPLAY) {                               \
            if (check_fd) {                                            \
                assert(sizeof(x) < CHK_BUF_SZ);                        \
                read(check_fd, check_buf, sizeof(x));                  \
                assert(memcmp(check_buf, &(x), sizeof(x)) == 0);       \
            }                                                          \
            read(rr_fd, &(x), sizeof(x));                              \
        }                                                              \
        if (rr_mode == RR_MODE_RECORD)                                 \
            if (check_fd) write(check_fd, &(x), sizeof(x));            \
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
        if (l == RR_LOC_IN) {                                          \
            if (rr_mode == RR_MODE_REPLAY) {                           \
                if (check_fd) {                                        \
                    assert(s < CHK_BUF_SZ);                            \
                    read(check_fd, check_buf, s);                      \
                    assert(memcmp(check_buf, x, s) == 0);              \
                }                                                      \
            }                                                          \
            if (rr_mode == RR_MODE_RECORD)                             \
                if (check_fd) write(check_fd, x, s);                   \
        }                                                              \
    } while (0)

int rr_init(int m, char *rr_file, char *check_file)
{
    rr_mode = m;
    switch (rr_mode) {
    case RR_MODE_RECORD:
        rr_fd = open(rr_file, O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR | S_IWUSR);
        if (check_file)
            check_fd = open(check_file,
                            O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR | S_IWUSR);
        break;
    case RR_MODE_REPLAY:
        rr_fd = open(rr_file, O_RDONLY);
        if (check_file)
            check_fd = open(check_file, O_RDONLY);
        break;
    default:
        return -1;
    }
    if (rr_fd <= 0)
        errx(1, "couldn't open rr file %s\n", rr_file);
    if (check_file && (check_fd <= 0))
        errx(1, "couldn't open check file %s\n", check_file);
    return 0;
}

void rr_ukvm_puts(struct platform *p, struct ukvm_puts *o, int loc)
{
    CHECK(loc, &o->data, sizeof(o->data));
    CHECK(loc, p->mem + o->data, o->len);
    CHECK(loc, &o->len, sizeof(o->len));
}
    
void rr_ukvm_boot_info(struct platform *p, struct ukvm_boot_info *o, int loc)
{
    RR(loc, o->mem_size);
    RR(loc, o->kernel_end);
    RR(loc, o->cmdline);
}
void rr_ukvm_blkinfo(struct platform *p, struct ukvm_blkinfo *o, int loc)
{
	RR(loc, o->sector_size);
    RR(loc, o->num_sectors);
    RR(loc, o->rw);
}
void rr_ukvm_blkwrite(struct platform *p, struct ukvm_blkwrite *o, int loc)
{
    CHECK(loc, &o->sector, sizeof(o->sector));
    CHECK(loc, &o->data, sizeof(o->data));
    CHECK(loc, p->mem + o->data, o->len);
    CHECK(loc, &o->len, sizeof(o->len));
    RR(loc, o->ret);
}
void rr_ukvm_blkread(struct platform *p, struct ukvm_blkread *o, int loc)
{
    CHECK(loc, &o->sector, sizeof(o->sector));
    CHECK(loc, &o->data, sizeof(o->data));
    CHECK(loc, p->mem + o->data, o->len);
	RR(loc, o->len);
	RR(loc, o->ret);
}
void rr_ukvm_netinfo(struct platform *p, struct ukvm_netinfo *o, int loc)
{
    RR(loc, o->mac_str);
}
void rr_ukvm_netwrite(struct platform *p, struct ukvm_netwrite *o, int loc)
{
    CHECK(loc, &o->data, sizeof(o->data));
    CHECK(loc, p->mem + o->data, o->len);
    CHECK(loc, &o->len, sizeof(o->len));
	RR(loc, o->ret);
}
void rr_ukvm_netread(struct platform *p, struct ukvm_netread *o, int loc)
{
    CHECK(loc, &o->data, sizeof(o->data));
    CHECK(loc, p->mem + o->data, o->len);
	RR(loc, o->len);
	RR(loc, o->ret);
}
void rr_ukvm_poll(struct platform *p, struct ukvm_poll *o, int loc)
{
    CHECK(loc, &o->timeout_nsecs, sizeof(o->timeout_nsecs));
    RR(loc, o->ret);
}
void rr_ukvm_time_init(struct platform *p, struct ukvm_time_init *o, int loc)
{
	RR(loc, o->freq);
    RR(loc, o->rtc_boot);
}

void rr_ukvm_rdtsc(struct platform *p, uint64_t *new_tsc, int loc)
{
    RR(loc, *new_tsc);
}
void rr_ukvm_rdrand(struct platform *p, uint64_t *r, int loc)
{
    RR(loc, *r);
}
