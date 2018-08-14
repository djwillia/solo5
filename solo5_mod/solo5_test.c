
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <string.h>

#include "../ukvm/ukvm_guest.h"


#define PUTS_BUF_LEN 256
#define PUTS_STR "Hello from userspace Solo5 test\n"

int main(int argc, char **argv)
{
    int fd = open("/dev/solo5", O_RDWR);
    int ret;
    struct ukvm_puts puts_arg;
    struct ukvm_halt halt_arg;
    struct ukvm_walltime walltime_arg;
    char puts_buf[PUTS_BUF_LEN];
    
    if (fd < 0) {
        perror("couldn't open solo5 device!\n");
        return errno;
    }

    memset(puts_buf, 0, PUTS_BUF_LEN);
    strcpy(puts_buf, PUTS_STR);
    puts_arg.data = puts_buf;
    puts_arg.len = strlen(PUTS_STR);
    ret = ioctl(fd, UKVM_IOCTL_PUTS, &puts_arg);
    printf("puts returned %d\n", ret);

    ret = ioctl(fd, UKVM_IOCTL_WALLTIME, &walltime_arg);
    printf("walltime returned %d, nsecs is 0x%ld\n", ret, walltime_arg.nsecs);
        
    halt_arg.exit_status = 0;
    ret = ioctl(fd, UKVM_IOCTL_HALT, &halt_arg);
    printf("halt returned %d\n", ret);

    return 0;
}
