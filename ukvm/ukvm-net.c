#include <linux/kvm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
/* for net */
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <err.h>

#include "ukvm.h"
#include "ukvm_modules.h"

static char *netiface;
static int netfd;

/*
 * Create or reuse a TUN or TAP device named 'dev'.
 *
 * Copied from kernel docs: Documentation/networking/tuntap.txt
 */
static int tun_alloc(char *dev, int flags)
{
    struct ifreq ifr;
    int fd, err;
    char *clonedev = "/dev/net/tun";

    /* Arguments taken by the function:
     *
     * char *dev: the name of an interface (or '\0'). MUST have enough
     *   space to hold the interface name if '\0' is passed
     * int flags: interface flags (eg, IFF_TUN etc.)
     */

    /* open the clone device */
    if ((fd = open(clonedev, O_RDWR)) < 0) {
        return fd;
    }

    /* preparation of the struct ifr, of type "struct ifreq" */
    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = flags;	/* IFF_TUN or IFF_TAP, plus maybe IFF_NO_PI */

    if (*dev) {
        /* if a device name was specified, put it in the structure; otherwise,
         * the kernel will try to allocate the "next" device of the
         * specified type */
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }

    /* try to create the device */
    if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
        close(fd);
        return err;
    }

    /* if the operation was successful, write back the name of the
     * interface to the variable "dev", so the caller can know
     * it. Note that the caller MUST reserve space in *dev (see calling
     * code below) */
    strcpy(dev, ifr.ifr_name);

    /* this is the special file descriptor that the caller will use to talk
     * with the virtual interface */
    return fd;
}

static void ukvm_port_netinfo(uint8_t * mem, void *data)
{
    uint32_t mem_off = *(uint32_t *) data;
    struct ukvm_netinfo *info = (struct ukvm_netinfo *) (mem + mem_off);

    printf("%s: WARNING: returning hardcoded MAC\n", __FILE__);
    strcpy(info->mac_str, "52:54:00:12:34:56");
}

static void ukvm_port_netwrite(uint8_t * mem, void *data)
{
    uint32_t mem_off = *(uint32_t *) data;
    struct ukvm_netwrite *wr = (struct ukvm_netwrite *) (mem + mem_off);
    uint8_t *ptr = mem + (uint64_t) wr->data;
    int i;
    int ret;
    
    wr->ret = 0;
    ret = write(netfd, mem + (uint64_t) wr->data, wr->len);
    assert(wr->len == ret);
}

static void ukvm_port_netread(uint8_t * mem, void *data)
{
    uint32_t mem_off = *(uint32_t *) data;
    struct ukvm_netread *rd = (struct ukvm_netread *) (mem + mem_off);
    uint8_t *ptr = mem + (uint64_t) rd->data;
    struct timeval zero;
    fd_set netset;
    int ret;

    FD_ZERO(&netset);
    FD_SET(netfd, &netset);
    zero.tv_sec = 0;
    zero.tv_usec = 0;
    ret = select(netfd + 1, &netset, NULL, NULL, &zero);
    if (ret <= 0) {
        rd->ret = -1;
        return;
    }

    rd->len = read(netfd, mem + (uint64_t) rd->data, rd->len);
    rd->ret = 0;
}

static int handle_exit(struct kvm_run *run, int vcpufd, uint8_t *mem) {
    uint8_t *data;

    if ( run->exit_reason != KVM_EXIT_IO )
        return -1;

    if ( run->io.direction != KVM_EXIT_IO_OUT )
        return -1;

    data = (uint8_t *)run + run->io.data_offset;

    switch ( run->io.port ) {
    case UKVM_PORT_NETINFO:
        ukvm_port_netinfo(mem, data);
        break;
    case UKVM_PORT_NETWRITE:
        ukvm_port_netwrite(mem, data);
        break;
    case UKVM_PORT_NETREAD:
        ukvm_port_netread(mem, data);
        break;
    default:
        return -1;
    }
    
    return 0;
}

static int handle_cmdarg(char *cmdarg) {
    if ( strncmp("net=", cmdarg, 4) )
        return -1;
    netiface = cmdarg + 4;

    return 0;
}

static int setup(int vcpufd) {
    char tun_name[IFNAMSIZ];

    if ( netiface == NULL )
        return -1;
    
    /* set up virtual network */
    strcpy(tun_name, netiface);
    netfd = tun_alloc(tun_name, IFF_TAP | IFF_NO_PI);	/* TAP interface */
    if (netfd < 0)
        err(1, "Allocating interface");

    return 0;
}

static char *usage(void) {
    return "net=<tap100>";
}

struct ukvm_module ukvm_net = {
    .handle_exit = handle_exit,
    .handle_cmdarg = handle_cmdarg,
    .setup = setup,
    .usage = usage
};
