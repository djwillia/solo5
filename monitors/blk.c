#include <err.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include "ukvm-private.h"
#include "ukvm-modules.h"
#include "ukvm.h"

static struct ukvm_blkinfo blkinfo;
static char *diskfile;
static int diskfd;

static void ukvm_port_blkinfo(uint8_t *mem, uint64_t paddr)
{
    GUEST_CHECK_PADDR(paddr, GUEST_SIZE, sizeof (struct ukvm_blkinfo));
    struct ukvm_blkinfo *info = (struct ukvm_blkinfo *)(mem + paddr);

    info->sector_size = blkinfo.sector_size;
    info->num_sectors = blkinfo.num_sectors;
    info->rw = blkinfo.rw;
}

static void ukvm_port_blkwrite(uint8_t *mem, uint64_t paddr)
{
    GUEST_CHECK_PADDR(paddr, GUEST_SIZE, sizeof (struct ukvm_blkwrite));
    struct ukvm_blkwrite *wr = (struct ukvm_blkwrite *)(mem + paddr);
    int ret;

    if (wr->sector >= blkinfo.num_sectors) {
        wr->ret = -1;
        return;
    }
    
    ret = lseek(diskfd, blkinfo.sector_size * wr->sector, SEEK_SET);
    assert(ret != (off_t)-1);
    GUEST_CHECK_PADDR(wr->data, GUEST_SIZE, wr->len);
    ret = write(diskfd, mem + wr->data, wr->len);
    assert(ret == wr->len);
    wr->ret = 0;
}

static void ukvm_port_blkread(uint8_t *mem, uint64_t paddr)
{
    GUEST_CHECK_PADDR(paddr, GUEST_SIZE, sizeof (struct ukvm_blkread));
    struct ukvm_blkread *rd = (struct ukvm_blkread *)(mem + paddr);
    int ret;

    if (rd->sector >= blkinfo.num_sectors) {
        rd->ret = -1;
        return;
    }

    ret = lseek(diskfd, blkinfo.sector_size * rd->sector, SEEK_SET);
    assert(ret != (off_t)-1);
    GUEST_CHECK_PADDR(rd->data, GUEST_SIZE, rd->len);
    ret = read(diskfd, mem +  rd->data, rd->len);
    assert(ret == rd->len);
    rd->ret = 0;
}

static int handle_exit(struct platform *p)
{
    if (platform_get_exit_reason(p) != EXIT_IO)
        return -1;

    int port = platform_get_io_port(p);
    uint64_t data = platform_get_io_data(p);

    switch (port) {
    case UKVM_PORT_BLKINFO:
        ukvm_port_blkinfo(p->mem, data);
        break;
    case UKVM_PORT_BLKWRITE:
        ukvm_port_blkwrite(p->mem, data);
        break;
    case UKVM_PORT_BLKREAD:
        ukvm_port_blkread(p->mem, data);
        break;
    default:
        return -1;
    }

    platform_advance_rip(p);
    return 0;
}

static int handle_cmdarg(char *cmdarg)
{
    if (strncmp("--disk=", cmdarg, 7))
        return -1;
    diskfile = cmdarg + 7;

    return 0;
}

static int setup(struct platform *p)
{
    if (diskfile == NULL)
        return -1;

    /* set up virtual disk */
    diskfd = open(diskfile, O_RDWR);
    if (diskfd == -1)
        err(1, "couldn't open disk %s", diskfile);

    blkinfo.sector_size = 512;
    blkinfo.num_sectors = lseek(diskfd, 0, SEEK_END) / 512;
    blkinfo.rw = 1;

    printf("Providing disk: %zd sectors @ %zd = %zd bytes\n",
           blkinfo.num_sectors, blkinfo.sector_size,
           blkinfo.num_sectors * blkinfo.sector_size);

    return 0;
}

static int get_fd(void)
{
    return 0; /* no fd for poll to sleep on (synchronous) */
}

static char *usage(void)
{
    return "--disk=IMAGE (file exposed to the unikernel as a raw block device)";
}

struct ukvm_module ukvm_blk = {
    .get_fd = get_fd,
    .handle_exit = handle_exit,
    .handle_cmdarg = handle_cmdarg,
    .setup = setup,
    .usage = usage
};
