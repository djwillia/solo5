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

void rr_ukvm_puts(struct ukvm_puts *p, int loc)
{
    CHECK(loc, &p->data, sizeof(p->data));
    //CHECK(loc, p->data, p->len);
    CHECK(loc, &p->len, sizeof(p->len));
}
    
void rr_ukvm_boot_info(struct ukvm_boot_info *p, int loc)
{
    RR(loc, p->mem_size);
    RR(loc, p->kernel_end);
    RR(loc, p->cmdline);
}
void rr_ukvm_blkinfo(struct ukvm_blkinfo *p, int loc)
{
	RR(loc, p->sector_size);
    RR(loc, p->num_sectors);
    RR(loc, p->rw);
}
void rr_ukvm_blkwrite(struct ukvm_blkwrite *p, int loc)
{
    CHECK(loc, &p->sector, sizeof(p->sector));
    CHECK(loc, &p->data, sizeof(p->data));
    //CHECK(loc, p->data, p->len);
    CHECK(loc, &p->len, sizeof(p->len));
    RR(loc, p->ret);
}
void rr_ukvm_blkread(struct ukvm_blkread *p, int loc)
{
    CHECK(loc, &p->sector, sizeof(p->sector));
    CHECK(loc, &p->data, sizeof(p->data));
    //CHECK(loc, p->data, p->len);
	RR(loc, p->len);
	RR(loc, p->ret);
}
void rr_ukvm_netinfo(struct ukvm_netinfo *p, int loc)
{
    RR(loc, p->mac_str);
}
void rr_ukvm_netwrite(struct ukvm_netwrite *p, int loc)
{
    CHECK(loc, &p->data, sizeof(p->data));
    //CHECK(loc, p->data, p->len);
    CHECK(loc, &p->len, sizeof(p->len));
	RR(loc, p->ret);
}
void rr_ukvm_netread(struct ukvm_netread *p, int loc)
{
    CHECK(loc, &p->data, sizeof(p->data));
    //CHECK(loc, p->data, p->len);
	RR(loc, p->len);
	RR(loc, p->ret);
}
void rr_ukvm_poll(struct ukvm_poll *p, int loc)
{
    CHECK(loc, &p->timeout_nsecs, sizeof(p->timeout_nsecs));
    RR(loc, p->ret);
}
void rr_ukvm_time_init(struct ukvm_time_init *p, int loc)
{
	RR(loc, p->freq);
    RR(loc, p->rtc_boot);
}
