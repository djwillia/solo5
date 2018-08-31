
#include <linux/module.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/kallsyms.h>

#include "../ukvm/ukvm_guest.h"

/* linux device stuff */
MODULE_LICENSE("GPL");
#define DEVICE_NAME "solo5"
#define CLASS_NAME "solo5"
static int solo5_devnum;
static struct class *solo5_devclass;
static struct device *solo5_dev;

#define COM1 0x3f8
#define COM1_DATA   (COM1 + 0)
#define COM1_INTR   (COM1 + 1)
#define COM1_CTRL   (COM1 + 3)
#define COM1_STATUS (COM1 + 5)
#define COM1_DIV_LO (COM1 + 0)
#define COM1_DIV_HI (COM1 + 1)
#define DLAB 0x80
#define PROT 0x03 /* 8N1 (8 bits, no parity, one stop bit) */

void serial_init(void)
{
	outb(0x00, COM1_INTR);      /* Disable all interrupts */
	outb(DLAB, COM1_CTRL);      /* Enable DLAB (set baud rate divisor) */
	outb(0x01, COM1_DIV_LO);    /* Set divisor to 1 (lo byte) 115200 baud */
	outb(0x00, COM1_DIV_HI);    /*                  (hi byte) */
	outb(PROT, COM1_CTRL);      /* Set 8N1, clear DLAB */
}


static int serial_tx_empty(void)
{
	return inb(COM1_STATUS) & 0x20;
}

static void serial_write(char a)
{
    while (!serial_tx_empty())
        ;

    outb(a, COM1_DATA);
}

static void serial_putc(char a)
{
    if (a == '\n')
        serial_write('\r');
    serial_write(a);
}



static int solo5_open(struct inode *inode, struct file *f)
{
    printk("%s\n", __FUNCTION__);
    return 0;
}
static int  solo5_release(struct inode *inode, struct file *f)
{
    printk("%s\n", __FUNCTION__);
    return 0;
}
static ssize_t solo5_read(struct file *f, char *buf, size_t len, loff_t *off)
{
    printk("%s\n", __FUNCTION__);
    return -EFAULT;
}
static ssize_t solo5_write(struct file *f, const char *buf, size_t len, loff_t *off)
{
    printk("%s\n", __FUNCTION__);
    return -EFAULT;
}

#if 0
static long hypercall_puts(unsigned long arg)
{
    typedef long (*sys_write_fn)(unsigned int, const char __user *, size_t);
    sys_write_fn sys_write_ptr;
    struct ukvm_puts p;
    const char __user *buf;
    size_t len;
    
    if (copy_from_user(&p, (struct ukvm_puts *)arg, sizeof(struct ukvm_puts)))
        return -EACCES;
    
    buf = p.data;
    len = p.len; /* XXX check this user input!!! */
    
    sys_write_ptr = (sys_write_fn)kallsyms_lookup_name("SyS_write");
    if (sys_write_ptr == 0) {
        pr_err("Unable to find write\n");
        return -EINVAL;
    }

    sys_write_ptr(1, buf, len);

    return 0;
}
#endif

#if 0
static long hypercall_puts_direct(unsigned long arg)
{
    typedef int (*log_store_fn)(int, int, int, u64, const char *, u16,
                                const char *, u16);
    log_store_fn log_store_ptr;
    struct ukvm_puts p;
    const char __user *buf;
#define MAX_PUTS_LEN 256
    char tmp[MAX_PUTS_LEN];
    size_t len, copylen;
    
    log_store_ptr = (log_store_fn)kallsyms_lookup_name("log_store");
    if (log_store_ptr == 0) {
        pr_err("Unable to find log_store\n");
        return -EINVAL;
    }

    if (copy_from_user(&p, (struct ukvm_puts *)arg, sizeof(struct ukvm_puts)))
        return -EACCES;
    
    buf = p.data;
    len = p.len; /* XXX check this user input!!! */
    copylen = min((size_t)MAX_PUTS_LEN, len);
    
    if (copy_from_user(tmp, buf, copylen))
        return -EACCES;

    /* static int log_store(int facility=0, int level=LOGLEVEL_DEFAULT,
       enum log_flags flags=0, u64 ts_nsec=0,
       const char *dict=NULL, u16 dict_len=0,
       const char *text, u16 text_len)
    */
    log_store_ptr(0, LOGLEVEL_DEFAULT, 0, 0, NULL, 0, tmp, copylen);

    return 0;
}
#endif
static long hypercall_puts_direct(unsigned long arg)
{
    struct ukvm_puts p;
    const char __user *buf;
#define MAX_PUTS_LEN 256
    char tmp[MAX_PUTS_LEN];
    size_t len, copylen;
    int i;
    
    if (copy_from_user(&p, (struct ukvm_puts *)arg, sizeof(struct ukvm_puts)))
        return -EACCES;
    
    buf = p.data;
    len = p.len; /* XXX check this user input!!! */
    copylen = min((size_t)MAX_PUTS_LEN, len);
    
    if (copy_from_user(tmp, buf, copylen))
        return -EACCES;

    for (i = 0; i < copylen; i++)
        serial_putc(tmp[i]);
    
    return 0;
}

#if 0
static long hypercall_walltime(unsigned long arg)
{
    typedef long (*sys_clock_gettime_fn)(const clockid_t, struct timespec __user *);
    sys_clock_gettime_fn sys_clock_gettime_ptr;
    struct ukvm_walltime wt;
    struct timespec64 ts;
    int rc;
    
    sys_clock_gettime_ptr = (sys_clock_gettime_fn)kallsyms_lookup_name("do_clock_gettime");
    if (sys_clock_gettime_ptr == 0) {
        pr_err("Unable to find kernel function\n");
        return -EINVAL;
    }

    rc = sys_clock_gettime_ptr(CLOCK_REALTIME, &ts);
    if (rc != 0)
        return -EINVAL;

    wt.nsecs = (ts.tv_sec * 1000000000ULL) + ts.tv_nsec;
    
    if (copy_to_user((struct ukvm_walltime *)arg, &wt, sizeof(struct ukvm_walltime)))
        return -EACCES;
                 
    return 0;
}
#endif

static long hypercall_halt(unsigned long arg)
{
    typedef long (*sys_exit_fn)(int);
    sys_exit_fn sys_exit_ptr;
    struct ukvm_halt h;
    
    if (copy_from_user(&h, (struct ukvm_halt *)arg, sizeof(struct ukvm_halt)))
        return -EACCES;

    sys_exit_ptr = (sys_exit_fn)kallsyms_lookup_name("SyS_exit");
    if (sys_exit_ptr == 0) {
        pr_err("Unable to find write\n");
        return -EINVAL;
    }

    sys_exit_ptr(h.exit_status);
                 
    return 0;
}

static long solo5_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    switch (cmd) {
#if 0
    case UKVM_IOCTL_WALLTIME:
        return hypercall_walltime(arg);
        break;
#endif        
    case UKVM_IOCTL_PUTS:
        return hypercall_puts_direct(arg);
        break;
    case UKVM_IOCTL_HALT:
        return hypercall_halt(arg);
        break;
    default:
        return -EFAULT;
    }
    printk("a=0x%x b=0x%lx\n", cmd, arg);
    return 0;
}


static struct file_operations solo5_fops =
{
   .open = solo5_open,
   .read = solo5_read,
   .write = solo5_write,
   .unlocked_ioctl = solo5_ioctl,
   .release = solo5_release,
};

#define OUT(l,r)                                \
    do {                                        \
        ret = r;                                \
        goto l;                                 \
    } while(0)

static int __init solo5_mod_init(void)
{
    int ret = 0;

    {
        int i;
        for (i = 0; i < 10000; i++)
            serial_putc('D');
    }

    printk(KERN_INFO "Solo5: module initializing.\n");

    solo5_devnum = register_chrdev(0, DEVICE_NAME, &solo5_fops);
    if (solo5_devnum < 0)
        OUT(out1, solo5_devnum);

    solo5_devclass = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(solo5_devclass))
        OUT(out2, PTR_ERR(solo5_devclass));
    
    solo5_dev = device_create(solo5_devclass, NULL,
                              MKDEV(solo5_devnum, 0), NULL, DEVICE_NAME);
    if (IS_ERR(solo5_dev))
        OUT(out3, PTR_ERR(solo5_dev));

    return 0;

 out3:
    class_unregister(solo5_devclass);
    class_destroy(solo5_devclass);
 out2:
    unregister_chrdev(solo5_devnum, DEVICE_NAME);
 out1:
    return ret;
}

static void __exit solo5_mod_exit(void)
{
    printk(KERN_INFO "Solo5: module exiting.\n");

    device_destroy(solo5_devclass, MKDEV(solo5_devnum, 0));
    class_unregister(solo5_devclass);
    class_destroy(solo5_devclass);
    unregister_chrdev(solo5_devnum, DEVICE_NAME);
}

module_init(solo5_mod_init);
module_exit(solo5_mod_exit);
