#include <linux/kvm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include "ukvm.h"
#include "gdb-chain.h"

static int chainfd;
static const char *chain;

static void ukvm_port_getval(uint8_t * mem, void *data)
{
    uint32_t mem_off = *(uint32_t *) data;
    struct ukvm_getval *p = (struct ukvm_getval *) (mem + mem_off);
    int ret;
    struct sockaddr_un addr;
    char buf[GDB_CHAIN_BUF_LEN];
        
    memset(buf, 0, GDB_CHAIN_BUF_LEN);
    
    chainfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if ( chainfd < 0 ) {
        perror("Socket fd");
        exit(1);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, chain, sizeof(addr.sun_path) - 1);

    if ( connect(chainfd, (struct sockaddr *)&addr, sizeof(addr)) ) {
        perror("connect");
        exit(1);
    }

    printf("Reading from %s\n", chain);
    ret = read(chainfd, buf, sizeof(buf) - 1);
    if ( ret <= 0 ) {
        perror("Read error");
        exit(1);
    }
    
    p->value = strtoull(buf, NULL, 10);
    printf("Got %ld\n", p->value);
}

static void ukvm_port_putval(uint8_t * mem, void *data) {
    uint32_t mem_off = *(uint32_t *) data;
    struct ukvm_putval *p = (struct ukvm_putval *) (mem + mem_off);
    char buf[GDB_CHAIN_BUF_LEN];
    int ret;
    int len;
    
    memset(buf, 0, GDB_CHAIN_BUF_LEN);
    len = snprintf(buf, GDB_CHAIN_BUF_LEN, "%ld", p->value);
    if ( len > GDB_CHAIN_BUF_LEN )
        len = GDB_CHAIN_BUF_LEN;
    
    ret = write(chainfd, buf, len);
    if ( ret != len ) {
        perror("Write error");
        exit(1);
    }
}

static int handle_exit(struct kvm_run *run, int vcpufd, uint8_t *mem) {
    uint8_t *data;
    
    if ( run->exit_reason != KVM_EXIT_IO )
        return -1;

    if ( run->io.direction != KVM_EXIT_IO_OUT )
        return -1;

    data = (uint8_t *)run + run->io.data_offset;

    switch ( run->io.port ) {
    case UKVM_PORT_GETVAL:
        ukvm_port_getval(mem, data);
        break;
    case UKVM_PORT_PUTVAL:
        ukvm_port_putval(mem, data);
        break;
    default:
        return -1;
    }

}

static int setup(int vcpufd) {
    if ( chain == NULL )
        return -1;

    return 0;
}

static int handle_cmdarg(char *cmdarg) {
    if ( strncmp("chain=", cmdarg, 6) )
        return -1;
    chain = cmdarg + 6;

    return 0;
}

static char *usage(void) {
    return "chain=<unix_socket>";
}

struct ukvm_module ukvm_chain = {
    .handle_exit = handle_exit,
    .handle_cmdarg = handle_cmdarg,
    .setup = setup,
    .usage = usage
};
