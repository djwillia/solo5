
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
        return hypercall_puts(arg);
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
