/* Copyright (c) 2016, IBM
 * Author(s): Dan Williams <djwillia@us.ibm.com>
 *
 * Permission to use, copy, modify, and/or distribute this software
 * for any purpose with or without fee is hereby granted, provided
 * that the above copyright notice and this permission notice appear
 * in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
 * OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* We used several existing projects as guides
 *   hvdos: https://github.com/mist64/hvdos
 *   xhyve: https://github.com/mist64/xhyve
 *   ukvm: https://github.com/solo5/solo5
 */

#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <assert.h>
#include <libgen.h> /* for `basename` */
#include "elf.h"
#include "specialreg.h"

#include <sys/sysctl.h>
#include <sys/select.h>
#include <Hypervisor/hv.h>
#include <Hypervisor/hv_vmx.h>


#ifdef __MACH__
#include <mach/clock.h>
#include <mach/mach.h>
#endif

/* from ukvm */
#include "ukvm-private.h"
#include "ukvm-modules.h"
#include "ukvm-cpu.h"
#include "ukvm.h"
#include "unikernel-monitor.h"

struct ukvm_module *modules[] = {
#ifdef UKVM_MODULE_BLK
    &ukvm_blk,
#endif
#ifdef UKVM_MODULE_NET
    &ukvm_net,
#endif
#ifdef UKVM_MODULE_GDB
    &ukvm_gdb,
#endif
    NULL,
};
#define NUM_MODULES ((sizeof(modules) / sizeof(struct ukvm_module *)) - 1)

    
/*
 * Memory map:
 *
 * 0x100000    loaded elf file (linker script dictates location)
 * ########    unused
 * 0x013000
 * 0x012000    bootstrap pde
 * 0x011000    bootstrap pdpte
 * 0x010000    bootstrap pml4
 * ########    command line arguments
 * 0x002000    ukvm_boot_info
 * 0x001000    bootstrap gdt (contains correct code/data/ but tss points to 0)
 */

#define GUEST_PAGE_SIZE 0x200000   /* 2 MB pages in guest */

#define BOOT_GDT     0x1000
#define BOOT_INFO    0x2000
#define BOOT_PML4    0x10000
#define BOOT_PDPTE   0x11000
#define BOOT_PDE     0x12000

static uint64_t sleep_time_s;  /* track unikernel sleeping time */
static uint64_t sleep_time_ns; 

//#define DEBUG 1

/* read GPR */
uint64_t
rreg(hv_vcpuid_t vcpu, hv_x86_reg_t reg)
{
    uint64_t v;

    if (hv_vcpu_read_register(vcpu, reg, &v)) {
        abort();
    }

    return v;
}

/* write GPR */
void
wreg(hv_vcpuid_t vcpu, hv_x86_reg_t reg, uint64_t v)
{
    if (hv_vcpu_write_register(vcpu, reg, v)) {
        abort();
    }
}

/* read VMCS field */
static uint64_t
rvmcs(hv_vcpuid_t vcpu, uint32_t field)
{
    uint64_t v;

    if (hv_vmx_vcpu_read_vmcs(vcpu, field, &v)) {
        abort();
    }

    return v;
}

/* write VMCS field */
static void
wvmcs(hv_vcpuid_t vcpu, uint32_t field, uint64_t v)
{
    if (hv_vmx_vcpu_write_vmcs(vcpu, field, v)) {
        abort();
    }
}

/* desired control word constrained by hardware/hypervisor capabilities */
static uint64_t
cap2ctrl(uint64_t cap, uint64_t ctrl)
{
    return (ctrl | (cap & 0xffffffff)) & (cap >> 32);
}

static void setup_boot_info(uint8_t *mem,
                            uint64_t size,
                            uint64_t kernel_end,
                            int argc, char **argv)
{
    struct ukvm_boot_info *bi = (struct ukvm_boot_info *)(mem + BOOT_INFO);
    uint64_t cmdline = BOOT_INFO + sizeof(struct ukvm_boot_info);
    size_t cmdline_free = BOOT_PML4 - cmdline - 1;
    char *cmdline_p = (char *)(mem + cmdline);

    bi->mem_size = size;
    bi->kernel_end = kernel_end;
    bi->cmdline = cmdline;
    cmdline_p[0] = 0;

    for (; *argv; argc--, argv++) {
        size_t alen = snprintf(cmdline_p, cmdline_free, "%s%s", *argv,
                (argc > 1) ? " " : "");
        if (alen >= cmdline_free) {
            warnx("command line too long, truncated");
            break;
        }
        cmdline_free -= alen;
        cmdline_p += alen;
    }

}

static ssize_t pread_in_full(int fd, void *buf, size_t count, off_t offset)
{
    ssize_t total = 0;
    char *p = (char *)buf;

    lseek(fd, 0, SEEK_SET);
    while (count > 0) {
        ssize_t nr;

        lseek(fd, offset, SEEK_SET);
        nr = read(fd, p, count);
        if (nr <= 0) {
            if (total > 0)
                return total;

            return -1;
        }

        count -= nr;
        total += nr;
        p += nr;
        offset += nr;
    }

    return total;
}

/*
 * Load code from elf file into *mem and return the elf entry point
 * and the last byte of the program when loaded into memory. This
 * accounts not only for the last loaded piece of code from the elf,
 * but also for the zeroed out pieces that are not loaded and sould be
 * reserved.
 *
 * Memory will look like this after the elf is loaded:
 *
 * *mem                    *p_entry                                 *p_end
 *   |             |                    |                |            |
 *   |    ...      | .text .rodata      |   .data .bss   |            |
 *   |             |        code        |   00000000000  | empty page |
 *   |             |  [PROT_EXEC|READ]  |                | PROT_NONE  |
 *
 */
static void load_code(const char *file, uint8_t *mem,     /* IN */
                      uint64_t *p_entry, uint64_t *p_end) /* OUT */
{
    int fd_kernel;
    ssize_t numb;
    size_t buflen;
    Elf64_Off ph_off;
    Elf64_Half ph_entsz;
    Elf64_Half ph_cnt;
    Elf64_Half ph_i;
    Elf64_Phdr *phdr = NULL;
    Elf64_Ehdr hdr;

    /* elf entry point (on physical memory) */
    *p_entry = 0;
    /* highest byte of the program (on physical memory) */
    *p_end = 0;

    fd_kernel = open(file, O_RDONLY);
    if (fd_kernel == -1)
        err(1, "couldn't open elf");

    numb = pread_in_full(fd_kernel, &hdr, sizeof(Elf64_Ehdr), 0);
    if (numb < 0 || (size_t) numb != sizeof(Elf64_Ehdr))
        err(1, "unable to read ELF64 hdr");

    /*
     * Validate program is in ELF64 format:
     * 1. EI_MAG fields 0, 1, 2, 3 spell ELFMAG('0x7f', 'E', 'L', 'F'),
     * 2. File contains 64-bit objects,
     * 3. Objects are Executable,
     * 4. Target instruction set architecture is set to x86_64.
     */
    if (hdr.e_ident[EI_MAG0] != ELFMAG0 || hdr.e_ident[EI_MAG1] != ELFMAG1 || \
        hdr.e_ident[EI_MAG2] != ELFMAG2 || hdr.e_ident[EI_MAG3] != ELFMAG3 || \
        hdr.e_ident[EI_CLASS] != ELFCLASS64 || hdr.e_type != ET_EXEC || \
        hdr.e_machine != EM_X86_64)
        errx(1, "%s is in invalid ELF64 format.", file);

    ph_off = hdr.e_phoff;
    ph_entsz = hdr.e_phentsize;
    ph_cnt = hdr.e_phnum;
    buflen = ph_entsz * ph_cnt;

    phdr = (Elf64_Phdr *)malloc(buflen);
    if (!phdr)
        err(1, "unable to allocate program header buffer\n");

    numb = pread_in_full(fd_kernel, phdr, buflen, ph_off);
    if (numb < 0 || (size_t) numb != buflen)
        err(1, "unable to read program header");

    /*
     * Load all segments with the LOAD directive from the elf file at offset
     * p_offset, and copy that into p_addr in memory. The amount of bytes
     * copied is p_filesz.  However, each segment should be given
     * ALIGN_UP(p_memsz, p_align) bytes on memory.
     */
    for (ph_i = 0; ph_i < ph_cnt; ph_i++) {
        uint8_t *dst;
        size_t _end;
        size_t offset = phdr[ph_i].p_offset;
        size_t filesz = phdr[ph_i].p_filesz;
        size_t memsz = phdr[ph_i].p_memsz;
        uint64_t paddr = phdr[ph_i].p_paddr;
        uint64_t align = phdr[ph_i].p_align;

        if ((phdr[ph_i].p_type & PT_LOAD) == 0)
            continue;

        dst = mem + paddr;

        numb = pread_in_full(fd_kernel, dst, filesz, offset);
        if (numb < 0 || (size_t) numb != filesz)
            err(1, "unable to load segment");

        memset(mem + paddr + filesz, 0, memsz - filesz);

        /* Protect the executable code */
        if (phdr[ph_i].p_flags & PF_X)
            mprotect((void *) dst, memsz, PROT_EXEC | PROT_READ);

        _end = ALIGN_UP(paddr + memsz, align);
        if (_end > *p_end)
            *p_end = _end;
    }

    /*
     * Not needed, but let's give it an empty page at the end for "safety".
     * And, even protect it against any type of access.
     */
    mprotect((void *) ((uint64_t) mem + p_end), 0x1000, PROT_NONE);
    *p_end += 0x1000;

    *p_entry = hdr.e_entry;
}


static void setup_system_64bit(hv_vcpuid_t vcpu)
{
    uint64_t cr0 = (CR0_NE | CR0_PE | CR0_PG) & ~(CR0_NW | CR0_CD);
    uint64_t cr4 = CR4_PAE | CR4_VMXE;
    uint64_t efer = EFER_LME | EFER_LMA;
    
    wvmcs(vcpu, VMCS_GUEST_CR0, cr0);
    wvmcs(vcpu, VMCS_GUEST_CR4, cr4);
    wvmcs(vcpu, VMCS_GUEST_IA32_EFER, efer);

    if (1){
        /* enable sse */
        uint64_t cr0, cr4;
        cr0 = rvmcs(vcpu, VMCS_GUEST_CR0);
        cr4 = rvmcs(vcpu, VMCS_GUEST_CR4);
        wvmcs(vcpu, VMCS_GUEST_CR0, (cr0 | CR0_MP) & ~(CR0_EM));
        wvmcs(vcpu, VMCS_GUEST_CR4, cr4 | CR4_FXSR | CR4_XMM); /* OSFXSR and OSXMMEXCPT */
    }
}


static void setup_system_page_tables(hv_vcpuid_t vcpu, uint8_t *mem)
{
    uint64_t *pml4 = (uint64_t *) (mem + BOOT_PML4);
    uint64_t *pdpte = (uint64_t *) (mem + BOOT_PDPTE);
    uint64_t *pde = (uint64_t *) (mem + BOOT_PDE);
    uint64_t paddr;
        
    /*
     * For simplicity we currently use 2MB pages and only a single
     * PML4/PDPTE/PDE.  Sanity check that the guest size is a multiple of the
     * page size and will fit in a single PDE (512 entries).
     */
    assert((GUEST_SIZE & (GUEST_PAGE_SIZE - 1)) == 0);
    assert(GUEST_SIZE <= (GUEST_PAGE_SIZE * 512));

    memset(pml4, 0, 4096);
    memset(pdpte, 0, 4096);
    memset(pde, 0, 4096);

    *pml4 = BOOT_PDPTE | (X86_PDPT_P | X86_PDPT_RW);
    *pdpte = BOOT_PDE | (X86_PDPT_P | X86_PDPT_RW);
    for (paddr = 0; paddr < GUEST_SIZE; paddr += GUEST_PAGE_SIZE, pde++)
        *pde = paddr | (X86_PDPT_P | X86_PDPT_RW | X86_PDPT_PS);

	wvmcs(vcpu, VMCS_GUEST_CR3, BOOT_PML4);
}

static void setup_system_gdt(hv_vcpuid_t vcpu,
                             uint8_t *mem,
                             uint64_t off)
{
	uint64_t *gdt_entry;

    gdt_entry = ((uint64_t *) (mem + off));
	gdt_entry[0] = 0x0000000000000000;
    gdt_entry[1] = 0x00af9b000000ffff;	/* 64bit CS		*/
    gdt_entry[2] = 0x00cf9b000000ffff;	/* 32bit CS		*/
    gdt_entry[3] = 0x00cf93000000ffff;	/* DS			*/
	gdt_entry[4] = 0x0000000000000000;	/* TSS part 1 (via C)	*/
	gdt_entry[5] = 0x0000000000000000;	/* TSS part 2 (via C)	*/

    wvmcs(vcpu, VMCS_GUEST_CS_BASE, 0);
    wvmcs(vcpu, VMCS_GUEST_CS_LIMIT, 0xffffffff);
    wvmcs(vcpu, VMCS_GUEST_CS_AR, 0xa09b);
    wvmcs(vcpu, VMCS_GUEST_SS_BASE, 0);
    wvmcs(vcpu, VMCS_GUEST_SS_LIMIT, 0xffffffff);
    wvmcs(vcpu, VMCS_GUEST_SS_AR, 0xc093);
    wvmcs(vcpu, VMCS_GUEST_DS_BASE, 0);
    wvmcs(vcpu, VMCS_GUEST_DS_LIMIT, 0xffffffff);
    wvmcs(vcpu, VMCS_GUEST_DS_AR, 0xc093);
    wvmcs(vcpu, VMCS_GUEST_ES_BASE, 0);
    wvmcs(vcpu, VMCS_GUEST_ES_LIMIT, 0xffffffff);
    wvmcs(vcpu, VMCS_GUEST_ES_AR, 0xc093);
    wvmcs(vcpu, VMCS_GUEST_FS_BASE, 0);
    wvmcs(vcpu, VMCS_GUEST_FS_LIMIT, 0xffffffff);
    wvmcs(vcpu, VMCS_GUEST_FS_AR, 0xc093);
    wvmcs(vcpu, VMCS_GUEST_GS_BASE, 0);
    wvmcs(vcpu, VMCS_GUEST_GS_LIMIT, 0xffffffff);
    wvmcs(vcpu, VMCS_GUEST_GS_AR, 0xc093);

    wvmcs(vcpu, VMCS_GUEST_CS, 0x08);
	wvmcs(vcpu, VMCS_GUEST_DS, 0x18);
	wvmcs(vcpu, VMCS_GUEST_SS, 0x18);
	wvmcs(vcpu, VMCS_GUEST_ES, 0x18);
	wvmcs(vcpu, VMCS_GUEST_FS, 0x18);
	wvmcs(vcpu, VMCS_GUEST_GS, 0x18);

    wvmcs(vcpu, VMCS_GUEST_GDTR_BASE, off);
    wvmcs(vcpu, VMCS_GUEST_GDTR_LIMIT, 0x2f);

    /* no IDT: all interrupts/exceptions exit */
    wvmcs(vcpu, VMCS_GUEST_IDTR_BASE, 0);
    wvmcs(vcpu, VMCS_GUEST_IDTR_LIMIT, 0);

    wvmcs(vcpu, VMCS_GUEST_TR_BASE, 0);
    wvmcs(vcpu, VMCS_GUEST_TR_LIMIT, 0);
    wvmcs(vcpu, VMCS_GUEST_TR_AR, 0x0000008b);
    wvmcs(vcpu, VMCS_GUEST_LDTR_BASE, 0);
    wvmcs(vcpu, VMCS_GUEST_LDTR_LIMIT, 0xffff);
    wvmcs(vcpu, VMCS_GUEST_LDTR_AR, 0x00000082);
}

static void platform_setup_system(hv_vcpuid_t vcpu, uint8_t *mem,
                                  uint64_t entry)
{
    setup_system_gdt(vcpu, mem, BOOT_GDT);
    setup_system_page_tables(vcpu, mem);
    setup_system_64bit(vcpu);
    
	wvmcs(vcpu, VMCS_GUEST_RFLAGS, 0x2);
	wvmcs(vcpu, VMCS_GUEST_RIP, entry);
    wvmcs(vcpu, VMCS_GUEST_RSP, GUEST_SIZE - 8);
    wreg(vcpu, HV_X86_RDI, BOOT_INFO);

    /* trap everything for cr0 and cr4 */
	wvmcs(vcpu, VMCS_CTRL_CR0_MASK, 0xffffffff);
	wvmcs(vcpu, VMCS_CTRL_CR4_MASK, 0xffffffff);
	wvmcs(vcpu, VMCS_CTRL_CR0_SHADOW, rvmcs(vcpu, VMCS_GUEST_CR0));
	wvmcs(vcpu, VMCS_CTRL_CR4_SHADOW, rvmcs(vcpu, VMCS_GUEST_CR4));
}

void ukvm_port_puts(uint8_t *mem, uint64_t paddr)
{
    GUEST_CHECK_PADDR(paddr, GUEST_SIZE, sizeof (struct ukvm_puts));
    struct ukvm_puts *p = (struct ukvm_puts *)(mem + paddr);

    GUEST_CHECK_PADDR(p->data, GUEST_SIZE, p->len);
    assert(write(1, mem + p->data, p->len) != -1);
}

static void ukvm_port_time_init(uint8_t *mem, uint32_t mem_off)
{
    struct ukvm_time_init *p = (struct ukvm_time_init *) (mem + mem_off);
    size_t len = sizeof(p->freq);

    sysctlbyname("machdep.tsc.frequency", &p->freq, &len, NULL, 0);
}

#define START_TIME                                                      \
    clock_serv_t cclock;                                                \
    mach_timespec_t mts;                                                \
    host_get_clock_service(mach_host_self(), CALENDAR_CLOCK, &cclock);  \
    clock_get_time(cclock, &mts);                                       \
    uint64_t _time_s = mts.tv_sec;                                      \
    uint64_t _time_ns = mts.tv_nsec;                                    

#define END_TIME                                    \
    clock_get_time(cclock, &mts);                   \
    mach_port_deallocate(mach_task_self(), cclock); \
    sleep_time_s += mts.tv_sec - _time_s;        \
    sleep_time_ns += mts.tv_nsec - _time_ns;     

static void ukvm_port_poll(uint8_t *mem, uint32_t mem_off)
{
    struct ukvm_poll *t = (struct ukvm_poll *) (mem + mem_off);

    struct timespec ts;
    int rc, i, max_fd = 0;
    fd_set readfds;
    START_TIME;

    FD_ZERO(&readfds);
    for (i = 0; i < NUM_MODULES; i++) {
        int fd = modules[i]->get_fd();

        if (fd) {
            FD_SET(fd, &readfds);
            if (fd > max_fd) max_fd = fd;
        }
    }
    ts.tv_sec = t->timeout_nsecs / 1000000000ULL;
    ts.tv_nsec = t->timeout_nsecs % 1000000000ULL;

    /*
     * Guest execution is blocked during the poll() call, note that
     * interrupts will not be injected.
     */
    rc = pselect(max_fd + 1, &readfds, NULL, NULL, &ts, NULL);
    assert(rc >= 0);

    END_TIME;
    t->ret = rc;
}

#define VMX_CTRLS(v,c,t,f) do {                 \
    uint64_t cap;                               \
    if (hv_vmx_read_capability((c), &cap)) {    \
        abort();                                \
	}                                           \
                                                \
    uint64_t zeros = cap & 0xffffffff;              \
    uint64_t ones = (cap >> 32) & 0xffffffff;       \
    uint64_t setting = cap2ctrl(cap, (f));          \
    if (0) {                                        \
        printf("%s %s\n", #c, #t);                  \
        printf("   0s:      0x%08llx\n", zeros);    \
        printf("   1s:      0x%08llx\n", ones);     \
        printf("   setting: 0x%08llx\n", setting);  \
    }                                               \
    wvmcs((v), (t), setting);                       \
    } while(0)                                      \

int platform_init(platform_vcpu_t *vcpu_p, uint8_t **mem_p)
{
	hv_vcpuid_t vcpu;
    uint8_t *mem;

    /* create a VM instance for the current task */
	if (hv_vm_create(HV_VM_DEFAULT)) {
		abort();
	}

	/* allocate some guest physical memory */
	if (!(mem = (uint8_t *)valloc(GUEST_SIZE))) {
		abort();
	}
    memset(mem, 0, GUEST_SIZE);

    /* map a segment of guest physical memory into the guest physical
	 * address space of the vm (at address 0) */
	if (hv_vm_map(mem, 0, GUEST_SIZE,
                  HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC)) {
        abort();
    }

	/* create a vCPU instance for this thread */
	if (hv_vcpu_create(&vcpu, HV_VCPU_DEFAULT)) {
		abort();
	}

	/* 
     * From FreeBSD:
     *
	 * It is safe to allow direct access to MSR_GSBASE and MSR_FSBASE.
	 * The guest FSBASE and GSBASE are saved and restored during
	 * vm-exit and vm-entry respectively. The host FSBASE and GSBASE are
	 * always restored from the vmcs host state area on vm-exit.
	 *
	 * The SYSENTER_CS/ESP/EIP MSRs are identical to FS/GSBASE in
	 * how they are saved/restored so can be directly accessed by the
	 * guest.
	 *
	 * MSR_EFER is saved and restored in the guest VMCS area on a
	 * VM exit and entry respectively. It is also restored from the
	 * host VMCS area on a VM exit.
     */
	if (hv_vcpu_enable_native_msr(vcpu, MSR_GSBASE, 1) ||
		hv_vcpu_enable_native_msr(vcpu, MSR_FSBASE, 1) ||
		hv_vcpu_enable_native_msr(vcpu, MSR_SYSENTER_CS_MSR, 1) ||
		hv_vcpu_enable_native_msr(vcpu, MSR_SYSENTER_ESP_MSR, 1) ||
		hv_vcpu_enable_native_msr(vcpu, MSR_SYSENTER_EIP_MSR, 1) ||
        hv_vcpu_enable_native_msr(vcpu, MSR_LSTAR, 1) ||
        hv_vcpu_enable_native_msr(vcpu, MSR_CSTAR, 1) ||
        hv_vcpu_enable_native_msr(vcpu, MSR_STAR, 1) ||
        hv_vcpu_enable_native_msr(vcpu, MSR_SF_MASK, 1) ||
        hv_vcpu_enable_native_msr(vcpu, MSR_KGSBASE, 1))
	{
		abort();
	}
    
    VMX_CTRLS(vcpu, HV_VMX_CAP_PINBASED, VMCS_CTRL_PIN_BASED, 0);

    /* It appears that bit 19 and 20 (CR8 load/store exiting) are
     * necessary for a bunch of things to work, including
     * CPU_BASED_HLT (bit 7) and MONITOR_TRAP_FLAG (bit 27) */
    VMX_CTRLS(vcpu, HV_VMX_CAP_PROCBASED, VMCS_CTRL_CPU_BASED, 0
              | CPU_BASED_HLT | CPU_BASED_INVLPG
              | CPU_BASED_MWAIT | CPU_BASED_RDPMC
              | CPU_BASED_RDTSC | CPU_BASED_UNCOND_IO
              | CPU_BASED_CR8_LOAD | CPU_BASED_CR8_STORE
              | CPU_BASED_CR3_LOAD | CPU_BASED_CR3_STORE);
    VMX_CTRLS(vcpu, HV_VMX_CAP_PROCBASED2, VMCS_CTRL_CPU_BASED2, 0
              | CPU_BASED2_DESC_TABLE | CPU_BASED2_RDRAND);
    VMX_CTRLS(vcpu, HV_VMX_CAP_ENTRY, VMCS_CTRL_VMENTRY_CONTROLS, 0
              | VMENTRY_GUEST_IA32E | VMENTRY_LOAD_EFER);
    VMX_CTRLS(vcpu, HV_VMX_CAP_EXIT, VMCS_CTRL_VMEXIT_CONTROLS, 0);
              
    wvmcs(vcpu, VMCS_CTRL_EXC_BITMAP, 0xffffffff);

    *mem_p = mem;
    *vcpu_p = vcpu;
    
    return 0;
}

void platform_cleanup(platform_vcpu_t vcpu, uint8_t *mem)
{
	/* destroy vCPU */
	if (hv_vcpu_destroy(vcpu)) {
		abort();
	}

	/* unmap memory segment at address 0 */
	if (hv_vm_unmap(0, GUEST_SIZE)) {
		abort();
	}
	/* destroy VM instance of this task */
	if (hv_vm_destroy()) {
		abort();
	}

	free(mem);
}


int platform_run(platform_vcpu_t vcpu,
                 void *platform_data __attribute__((unused)))
{
    return !!hv_vcpu_run(vcpu);
}
int platform_get_exit_reason(platform_vcpu_t vcpu,
                             void *platform_data __attribute__((unused)))
{
    uint64_t exit_reason = rvmcs(vcpu, VMCS_RO_EXIT_REASON);

    switch ((int)exit_reason) {    
    case VMX_REASON_HLT:
        return EXIT_HLT;
    case VMX_REASON_RDTSC:
        return EXIT_RDTSC;
    case VMX_REASON_IO:
        return EXIT_IO;

    case VMX_REASON_IRQ:           /* host interrupt */
    case VMX_REASON_EPT_VIOLATION: /* cold misses */
        return EXIT_IGNORE;

    case VMX_REASON_EXC_NMI: {
        uint32_t idt_vector_info = rvmcs(vcpu, VMCS_RO_IDT_VECTOR_INFO);
        uint32_t idt_vector_error = rvmcs(vcpu, VMCS_RO_IDT_VECTOR_ERROR);
        uint32_t irq_info = rvmcs(vcpu, VMCS_RO_VMEXIT_IRQ_INFO);
        uint32_t irq_error = rvmcs(vcpu, VMCS_RO_VMEXIT_IRQ_ERROR);

        printf("EXIT_REASON_EXCEPTION\n");
        if (idt_vector_info) {
            printf("idt_vector_info = 0x%x\n", idt_vector_info);
            printf("idt_vector_error = 0x%x\n", idt_vector_error);
        }
        if (irq_info) {
            printf("irq_info = 0x%x\n", irq_info);
            printf("  vector = %d (0x%x)\n",
                   irq_info & 0xff,
                   irq_info & 0xff);
            switch((irq_info >> 8) & 0x3) {
            case 0:
                printf("  type = external\n");
                break;
            case 2:
                printf("  type = NMI\n");
                break;
            case 3:
                printf("  type = HW exception\n");
                break;
            case 6:
                printf("  type = SW exception\n");
                break;
            default:
                printf("  type = BOGUS!!!\n");
            }
            if ((irq_info >> 11) & 0x1) {
                printf("irq_error = 0x%x\n", irq_error);
            }
        }

        printf("RIP was 0x%llx\n", rreg(vcpu, HV_X86_RIP));
        printf("RSP was 0x%llx\n", rreg(vcpu, HV_X86_RSP));
        return EXIT_FAIL;
    }
    case VMX_REASON_VMENTRY_GUEST:
        fprintf(stderr, "Invalid VMCS!");
        return EXIT_FAIL;
    default:
        fprintf(stderr, "unhandled VMEXIT %lld (0x%llx)\n",
                exit_reason, exit_reason);
        fprintf(stderr, "RIP was 0x%llx\n", rreg(vcpu, HV_X86_RIP));
        return EXIT_FAIL;
    }
}
int platform_get_io_port(platform_vcpu_t vcpu, void *platform_data)
{
    uint64_t exit_qualification = rvmcs(vcpu, VMCS_RO_EXIT_QUALIFIC);
    uint16_t port = (uint16_t)(exit_qualification >> 16);

    return port;
}
uint64_t platform_get_io_data(platform_vcpu_t vcpu, void *platform_data)
{
    uint64_t rax = rreg(vcpu, HV_X86_RAX);
    return rax;
}
void platform_advance_rip(platform_vcpu_t vcpu, void *platform_data)
{
    uint64_t len = rvmcs(vcpu, VMCS_RO_VMEXIT_INSTR_LEN);
    wvmcs(vcpu, VMCS_GUEST_RIP, rreg(vcpu, HV_X86_RIP) + len);
}

static uint64_t tsc_freq;
static void tsc_init(void) {
    size_t len = sizeof(tsc_freq);

    sysctlbyname("machdep.tsc.frequency", &tsc_freq, &len, NULL, 0);
    printf("tsc_freq=0x%llx(%lld)\n", tsc_freq, tsc_freq);
}


//static int vcpu_loop(hv_vcpuid_t vcpu, uint8_t *mem)
static int vcpu_loop(platform_vcpu_t vcpu, void *platform_data, uint8_t *mem)
{
    tsc_init();
    /* Repeatedly run code and handle VM exits. */
    while (1) {
        int i;
        int handled = 0;

        if (platform_run(vcpu, platform_data))
            err(1, "Couldn't run vcpu");

        for (i = 0; i < NUM_MODULES; i++) {
            if (!modules[i]->handle_exit(vcpu, mem, platform_data)) {
                handled = 1;
                break;
            }
        }

        if (handled)
            continue;
        
        switch (platform_get_exit_reason(vcpu, platform_data)) {
        case EXIT_HLT: {
            puts("Exiting due to HLT\n");
            /* get_and_dump_sregs(vcpufd); */
            return 0;
        }
        case EXIT_RDTSC: {
            uint64_t exec_time;
            uint64_t sleep_time;
            uint64_t new_tsc;
            double tsc_f;
            int dbg_sanity_check_rdtsc = 0;
                
            if (hv_vcpu_get_exec_time(vcpu, &exec_time)) 
                errx(1, "couldn't get exec time");

            if (dbg_sanity_check_rdtsc) {
                static uint64_t last_exec_time;
                assert(exec_time > last_exec_time);
                last_exec_time = exec_time;
            }
            
            sleep_time = ((sleep_time_s * 1000000000ULL) + sleep_time_ns);

            if (dbg_sanity_check_rdtsc) {
                static uint64_t last_sleep_time;
                assert(sleep_time >= last_sleep_time);
                last_sleep_time = sleep_time;
            }


            tsc_f = (((double)exec_time + (double)sleep_time)
                     * (double)tsc_freq) / 1000000000ULL;
            
            new_tsc = (uint64_t)tsc_f;
            
            {
                static uint64_t last_tsc;
                assert(new_tsc > last_tsc);
                last_tsc = new_tsc;
            }
            
            wreg(vcpu, HV_X86_RAX, new_tsc & 0xffffffff);
            wreg(vcpu, HV_X86_RDX, (new_tsc >> 32) & 0xffffffff);
            
            platform_advance_rip(vcpu, platform_data);
            break;
        }
        case EXIT_IO: {
            int port = platform_get_io_port(vcpu, platform_data);
            uint64_t data = platform_get_io_data(vcpu, platform_data);

            switch (port) {
            case UKVM_PORT_PUTS:
                ukvm_port_puts(mem, data);
                break;
            case UKVM_PORT_TIME_INIT:
                ukvm_port_time_init(mem, data);
                break;
            case UKVM_PORT_POLL:
                ukvm_port_poll(mem, data);
                break;
#if 0
            case UKVM_PORT_NANOSLEEP:
                ukvm_port_nanosleep(mem, data, (struct kvm_run *)platform_data);
                break;
            case UKVM_PORT_DBG_STACK:
                ukvm_port_dbg_stack(mem, (int)vcpu);
                break;
#endif                
            default:
                errx(1, "unhandled IO_PORT EXIT (0x%x)", port);
                return -1;
            };

            platform_advance_rip(vcpu, platform_data);

            break;
        }
        case EXIT_IGNORE: {
            break;
        }
        case EXIT_FAIL:
            return -1;
        }
    }
    
    return -1; /* never reached */
}

int setup_modules(int vcpufd, uint8_t *mem)
{
    int i;

    for (i = 0; i < NUM_MODULES; i++) {
        if (modules[i]->setup(vcpufd, mem)) {
            printf("Please check you have correctly specified:\n %s\n",
                   modules[i]->usage());
            return -1;
        }
    }
    return 0;
}

void sig_handler(int signo)
{
    printf("Received SIGINT. Exiting\n");
    exit(0);
}

static void usage(const char *prog)
{
    int m;

    printf("usage: %s [ CORE OPTIONS ] [ MODULE OPTIONS ] KERNEL", prog);
    printf(" [ -- ] [ ARGS ]\n");
    printf("Core options:\n");
    printf("    --help (display this help)\n");
    printf("Compiled-in module options:\n");
    for (m = 0; m < NUM_MODULES; m++)
        printf("    %s\n", modules[m]->usage());
    exit(1);
}

int main(int argc, char **argv)
{
    uint64_t elf_entry;
    uint64_t kernel_end;

    platform_vcpu_t vcpu;
	uint8_t *mem;

    const char *prog;
    const char *elffile;
    int matched;
    
    prog = basename(*argv);
    argc--;
    argv++;
    
    if (argc < 1)
        usage(prog);

    do {
        int j;

        if (!strcmp("--help", *argv))
            usage(prog);

        matched = 0;
        for (j = 0; j < NUM_MODULES; j++) {
            if (!modules[j]->handle_cmdarg(*argv)) {
                matched = 1;
                argc--;
                argv++;
                break;
            }
        }
    } while (matched && *argv);

    if (!*argv)
        usage(prog);

    if (*argv[0] == '-') {
        printf("Invalid option: %s\n", *argv);
        return 1;
    }

    elffile = *argv;
    argc--;
    argv++;

    if (argc) {
        if (strcmp("--", *argv))
            usage(prog);
        argc--;
        argv++;
    }

    if (signal(SIGINT, sig_handler) == SIG_ERR)
        err(1, "Can not catch SIGINT");

    if (platform_init(&vcpu, &mem))
        err(1, "platform init");
    
    load_code(elffile, mem, &elf_entry, &kernel_end);

    platform_setup_system(vcpu, mem, elf_entry);
    
    /* Setup ukvm_boot_info and command line */
    setup_boot_info(mem, GUEST_SIZE, kernel_end, argc, argv);

    if (setup_modules(vcpu, mem))
        errx(1, "couldn't setup modules");

    printf("going to vcpu loop\n");
    /* vCPU run loop */
    vcpu_loop(vcpu, NULL, mem);

    platform_cleanup(vcpu, mem);
	return 0;
}

