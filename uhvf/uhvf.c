// Copyright (c) 2009-present, the hvdos developers. All Rights Reserved.
// Read LICENSE.txt for licensing information.
//
// hvdos - a simple DOS emulator based on the OS X 10.10 Hypervisor.framework

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <err.h>
#include <assert.h>
#include <errno.h>
#include <sys/mman.h>

#include "elf.h"
#include "specialreg.h"

#include <Hypervisor/hv.h>
#include <Hypervisor/hv_vmx.h>

/* from ukvm */
#include "ukvm.h"
#include "misc.h"
#include "processor-flags.h"

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
        if (phdr[ph_i].p_flags & ELF_SEGMENT_X)
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

    if (0){
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

static void setup_system(hv_vcpuid_t vcpu, uint8_t *mem)
{
        setup_system_gdt(vcpu, mem, BOOT_GDT);
        setup_system_page_tables(vcpu, mem);
        setup_system_64bit(vcpu);
}

static void ukvm_port_puts(uint8_t *mem, uint32_t mem_off)
{
    struct ukvm_puts *p = (struct ukvm_puts *) (mem + mem_off);
    printf("%.*s", p->len, (char *) (mem + (uint64_t) p->data));
}

int main(int argc, char **argv)
{
    const char *elffile;
    uint64_t elf_entry;
    uint64_t kernel_end;
	uint8_t *mem;

    if (argc < 2) {
        fprintf(stderr, "Usage: hvdos [unikernel.ukvm]\n");
        exit(1);
    }

    elffile = argv[1];
    
	/* create a VM instance for the current task */
	if (hv_vm_create(HV_VM_DEFAULT)) {
		abort();
	}

	/* get hypervisor enforced capabilities of the machine, (see Intel docs) */
	uint64_t vmx_cap_pinbased, vmx_cap_procbased, vmx_cap_procbased2, vmx_cap_entry;
	if (hv_vmx_read_capability(HV_VMX_CAP_PINBASED, &vmx_cap_pinbased)) {
		abort();
	}
	if (hv_vmx_read_capability(HV_VMX_CAP_PROCBASED, &vmx_cap_procbased)) {
		abort();
	}
	if (hv_vmx_read_capability(HV_VMX_CAP_PROCBASED2, &vmx_cap_procbased2)) {
		abort();
	}
	if (hv_vmx_read_capability(HV_VMX_CAP_ENTRY, &vmx_cap_entry)) {
		abort();
	}

    printf("pin-based:   0x%016llx\n", vmx_cap_pinbased);
    printf("proc-based:  0x%016llx\n", vmx_cap_procbased);
    printf("proc-based2: 0x%016llx\n", vmx_cap_procbased2);
    printf("cap-entry:   0x%016llx\n", vmx_cap_entry);

    
	/* allocate some guest physical memory */
	if (!(mem = (uint8_t *)valloc(GUEST_SIZE))) {
		abort();
	}
    memset(mem, 0, GUEST_SIZE);

    /* map a segment of guest physical memory into the guest physical address
	 * space of the vm (at address 0) */
	if (hv_vm_map(mem, 0, GUEST_SIZE, HV_MEMORY_READ | HV_MEMORY_WRITE
                  | HV_MEMORY_EXEC))
        {
            abort();
        }

	/* create a vCPU instance for this thread */
	hv_vcpuid_t vcpu;
	if (hv_vcpu_create(&vcpu, HV_VCPU_DEFAULT)) {
		abort();
	}

#if 0
	if (hv_vcpu_enable_native_msr(vcpu, MSR_GSBASE, 1) ||
		hv_vcpu_enable_native_msr(vcpu, MSR_FSBASE, 1) ||
		hv_vcpu_enable_native_msr(vcpu, MSR_SYSENTER_CS_MSR, 1) ||
		hv_vcpu_enable_native_msr(vcpu, MSR_SYSENTER_ESP_MSR, 1) ||
		hv_vcpu_enable_native_msr(vcpu, MSR_SYSENTER_EIP_MSR, 1) ||
		hv_vcpu_enable_native_msr(vcpu, MSR_TSC, 1) ||
		hv_vcpu_enable_native_msr(vcpu, MSR_IA32_TSC_AUX, 1))
	{
		abort();
	}
    hv_vcpu_enable_native_msr(((hv_vcpuid_t) vcpu), MSR_LSTAR, 1);
    hv_vcpu_enable_native_msr(((hv_vcpuid_t) vcpu), MSR_CSTAR, 1);
	hv_vcpu_enable_native_msr(((hv_vcpuid_t) vcpu), MSR_STAR, 1);
	hv_vcpu_enable_native_msr(((hv_vcpuid_t) vcpu), MSR_SF_MASK, 1);
#endif
	hv_vcpu_enable_native_msr(((hv_vcpuid_t) vcpu), MSR_KGSBASE, 1);

	/* vCPU setup */
#define VMCS_PRI_PROC_BASED_CTLS_HLT           (1 << 7)
#define VMCS_PRI_PROC_BASED_CTLS_CR8_LOAD      (1 << 19)
#define VMCS_PRI_PROC_BASED_CTLS_CR8_STORE     (1 << 20)
#define VMCS_PRI_PROC_BASED_CTLS_UNCOND_IO     (1 << 24)

    wvmcs(vcpu, VMCS_CTRL_PIN_BASED, cap2ctrl(vmx_cap_pinbased, 0));
    wvmcs(vcpu, VMCS_CTRL_CPU_BASED,
          cap2ctrl(vmx_cap_procbased,
                   VMCS_PRI_PROC_BASED_CTLS_HLT |
                   VMCS_PRI_PROC_BASED_CTLS_CR8_LOAD |
                   VMCS_PRI_PROC_BASED_CTLS_CR8_STORE));

    
	wvmcs(vcpu, VMCS_CTRL_CPU_BASED2, cap2ctrl(vmx_cap_procbased2, 0));
    wvmcs(vcpu, VMCS_CTRL_VMENTRY_CONTROLS,
          cap2ctrl(vmx_cap_entry, VMENTRY_GUEST_IA32E | VMENTRY_LOAD_EFER));
	wvmcs(vcpu, VMCS_CTRL_EXC_BITMAP, 0xffffffff);
	wvmcs(vcpu, VMCS_CTRL_CR0_MASK, 0);
	wvmcs(vcpu, VMCS_CTRL_CR0_SHADOW, 0);
	wvmcs(vcpu, VMCS_CTRL_CR4_MASK, 0);
	wvmcs(vcpu, VMCS_CTRL_CR4_SHADOW, 0);

    load_code(elffile, mem, &elf_entry, &kernel_end);

    setup_system(vcpu, mem);
    
    /* Setup ukvm_boot_info and command line */
    setup_boot_info(mem, GUEST_SIZE, kernel_end, argc, argv);

	wvmcs(vcpu, VMCS_GUEST_RFLAGS, 0x2);
	wvmcs(vcpu, VMCS_GUEST_RIP, elf_entry);
    wvmcs(vcpu, VMCS_GUEST_RSP, GUEST_SIZE - 8);
    wreg(vcpu, HV_X86_RDI, BOOT_INFO);

    /* vCPU run loop */
	int stop = 0;
	do {
        int err;
        err = hv_vcpu_run(vcpu);
		if (err) {
            printf("run failed with err 0x%x\n", err);
			abort();
		}

		/* handle VMEXIT */
		uint64_t exit_reason = rvmcs(vcpu, VMCS_RO_EXIT_REASON);
		uint64_t exit_qualification = rvmcs(vcpu, VMCS_RO_EXIT_QUALIFIC);
        
		switch (exit_reason) {
        case VMX_REASON_HLT:
            puts("EXIT_HLT\n");
            stop = 1;
            break;
        case VMX_REASON_IO: {
            uint16_t port = (uint16_t)(exit_qualification >> 16);
            uint64_t rax = rreg(vcpu, HV_X86_RAX);
            assert(rax == (rax & 0xffffffff));

            switch(port) {
            case UKVM_PORT_CHAR: {
                printf("[%llx]", rax);
                break;
            }
            case UKVM_PORT_PUTS: {
                ukvm_port_puts(mem, rax);
                break;
            }
            default:
                printf("unknown port I/O 0x%x\n", port);
                stop = 1;
            }

            if (!stop) {
                /* advance RIP past I/O instruction */
                uint64_t len = rvmcs(vcpu, VMCS_RO_VMEXIT_INSTR_LEN);
                wvmcs(vcpu, VMCS_GUEST_RIP, rreg(vcpu, HV_X86_RIP) + len);
            }

            break;
        }
        case VMX_REASON_EXC_NMI: {
            uint8_t interrupt_number = rvmcs(vcpu, VMCS_RO_IDT_VECTOR_INFO) & 0xFF;
            printf("EXIT_REASON_EXCEPTION %d\n", interrupt_number);
            printf("RIP was 0x%llx\n", rreg(vcpu, HV_X86_RIP));
            printf("RSP was 0x%llx\n", rreg(vcpu, HV_X86_RSP));
            stop = 1;
            break;
        }
        case VMX_REASON_IRQ:
            /* VMEXIT due to host interrupt, nothing to do */
            printf("IRQ\n");
            break;
        case VMX_REASON_EPT_VIOLATION:
            /* disambiguate between EPT cold misses and MMIO */
            /* ... handle MMIO ... */
            break;
	 		/* ... many more exit reasons go here ... */
        case VMX_REASON_VMENTRY_GUEST:
            printf("Invalid VMCS!");
            break;
        default:
            printf("unhandled VMEXIT (0x%llx)\n", exit_reason);
            printf("RIP was 0x%llx\n", rreg(vcpu, HV_X86_RIP));
            stop = 1;
		}
	} while (!stop);

	/*
	 * optional clean-up
	 */

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

	return 0;
}

