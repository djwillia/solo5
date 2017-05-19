/* 
 * Copyright (c) 2015-2017 Contributors as noted in the AUTHORS file
 *
 * This file is part of ukvm, a unikernel monitor.
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

/*
 * ukvm_hv_macosx_x86_64.c: x86_64 architecture-dependent part of Mac
 * OSX Hypervisor.framework backend implementation.
 */

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <string.h>
#include <stdio.h>

#include <sys/sysctl.h>
#include <Hypervisor/hv.h>
#include <Hypervisor/hv_vmx.h>
#include <dispatch/dispatch.h>

#include "ukvm.h"
#include "ukvm_hv_macosx.h"
#include "ukvm_cpu_x86_64.h"


static uint64_t x86_sreg_to_ar(const struct x86_sreg *s) {
    return (s->g << 15 | s->db << 14 | s->l << 13 | s->avl << 12
            | s->p << 7 | s->dpl << 5 | s->s << 4 | s->type);
}

/* read GPR */
uint64_t rreg(hv_vcpuid_t vcpu, hv_x86_reg_t reg)
{
    uint64_t v;

    if (hv_vcpu_read_register(vcpu, reg, &v))
        err(1, "vcpu_read_register");

    return v;
}

/* write GPR */
void wreg(hv_vcpuid_t vcpu, hv_x86_reg_t reg, uint64_t v)
{
    if (hv_vcpu_write_register(vcpu, reg, v))
        err(1, "vcpu_write_register");
}

/* read VMCS field */
static uint64_t rvmcs(hv_vcpuid_t vcpu, uint32_t field)
{
    uint64_t v;

    if (hv_vmx_vcpu_read_vmcs(vcpu, field, &v))
        err(1, "vcpu_read_vmcs");

    return v;
}

/* write VMCS field */
static void wvmcs(hv_vcpuid_t vcpu, uint32_t field, uint64_t v)
{
    if (hv_vmx_vcpu_write_vmcs(vcpu, field, v))
        err(1, "vcpu_write_vmcs");
}

/* desired control word constrained by hardware/hypervisor capabilities */
static uint64_t cap2ctrl(uint64_t cap, uint64_t ctrl)
{
    return (ctrl | (cap & 0xffffffff)) & (cap >> 32);
}

#define VMX_CTRLS(v,c,t,f) do {                 \
    uint64_t cap;                               \
    if (hv_vmx_read_capability((c), &cap)) {    \
        err(1, "hv_vmx_read_capability");       \
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
    } while (0)                                     \


static int init_vcpu_state(struct ukvm_hv *hv, ukvm_gpa_t gpa_ep)
{
    hv_vcpuid_t vcpu = hv->b->vcpu;
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
        hv_vcpu_enable_native_msr(vcpu, MSR_KGSBASE, 1)) {
        return -1;
    }

    VMX_CTRLS(vcpu, HV_VMX_CAP_PINBASED, VMCS_CTRL_PIN_BASED, 0);

    /* It appears that bit 19 and 20 (CR8 load/store exiting) are
     * necessary for a bunch of things to work, including
     * CPU_BASED_HLT (bit 7) and MONITOR_TRAP_FLAG (bit 27)
     */
    VMX_CTRLS(vcpu, HV_VMX_CAP_PROCBASED, VMCS_CTRL_CPU_BASED, 0
              | CPU_BASED_HLT | CPU_BASED_INVLPG
              | CPU_BASED_MWAIT | CPU_BASED_RDPMC
              | CPU_BASED_UNCOND_IO
              | CPU_BASED_CR8_LOAD | CPU_BASED_CR8_STORE
              | CPU_BASED_CR3_LOAD | CPU_BASED_CR3_STORE);
    /* ^^^ note: to trap RDTSC, add CPU_BASED_RDTSC */

    VMX_CTRLS(vcpu, HV_VMX_CAP_PROCBASED2, VMCS_CTRL_CPU_BASED2, 0
              | CPU_BASED2_DESC_TABLE | CPU_BASED2_RDRAND);
    VMX_CTRLS(vcpu, HV_VMX_CAP_ENTRY, VMCS_CTRL_VMENTRY_CONTROLS, 0
              | VMENTRY_GUEST_IA32E | VMENTRY_LOAD_EFER);
    VMX_CTRLS(vcpu, HV_VMX_CAP_EXIT, VMCS_CTRL_VMEXIT_CONTROLS, 0);

    wvmcs(vcpu, VMCS_CTRL_EXC_BITMAP, 0xffffffff);


    wvmcs(vcpu, VMCS_GUEST_CS_BASE, ukvm_x86_sreg_code.base);
    wvmcs(vcpu, VMCS_GUEST_CS_LIMIT, ukvm_x86_sreg_code.limit);
    wvmcs(vcpu, VMCS_GUEST_CS_AR, x86_sreg_to_ar(&ukvm_x86_sreg_code));
    wvmcs(vcpu, VMCS_GUEST_SS_BASE, ukvm_x86_sreg_data.base);
    wvmcs(vcpu, VMCS_GUEST_SS_LIMIT, ukvm_x86_sreg_data.limit);
    wvmcs(vcpu, VMCS_GUEST_SS_AR, x86_sreg_to_ar(&ukvm_x86_sreg_data));
    wvmcs(vcpu, VMCS_GUEST_DS_BASE, ukvm_x86_sreg_data.base);
    wvmcs(vcpu, VMCS_GUEST_DS_LIMIT, ukvm_x86_sreg_data.limit);
    wvmcs(vcpu, VMCS_GUEST_DS_AR, x86_sreg_to_ar(&ukvm_x86_sreg_data));
    wvmcs(vcpu, VMCS_GUEST_ES_BASE, ukvm_x86_sreg_data.base);
    wvmcs(vcpu, VMCS_GUEST_ES_LIMIT, ukvm_x86_sreg_data.limit);
    wvmcs(vcpu, VMCS_GUEST_ES_AR, x86_sreg_to_ar(&ukvm_x86_sreg_data));
    wvmcs(vcpu, VMCS_GUEST_FS_BASE, ukvm_x86_sreg_data.base);
    wvmcs(vcpu, VMCS_GUEST_FS_LIMIT, ukvm_x86_sreg_data.limit);
    wvmcs(vcpu, VMCS_GUEST_FS_AR, x86_sreg_to_ar(&ukvm_x86_sreg_data));
    wvmcs(vcpu, VMCS_GUEST_GS_BASE, ukvm_x86_sreg_data.base);
    wvmcs(vcpu, VMCS_GUEST_GS_LIMIT, ukvm_x86_sreg_data.limit);
    wvmcs(vcpu, VMCS_GUEST_GS_AR, x86_sreg_to_ar(&ukvm_x86_sreg_data));

    wvmcs(vcpu, VMCS_GUEST_CS, X86_GDT_CODE * sizeof(uint64_t));
    wvmcs(vcpu, VMCS_GUEST_DS, X86_GDT_DATA * sizeof(uint64_t));
    wvmcs(vcpu, VMCS_GUEST_SS, X86_GDT_DATA * sizeof(uint64_t));
    wvmcs(vcpu, VMCS_GUEST_ES, X86_GDT_DATA * sizeof(uint64_t));
    wvmcs(vcpu, VMCS_GUEST_FS, X86_GDT_DATA * sizeof(uint64_t));
    wvmcs(vcpu, VMCS_GUEST_GS, X86_GDT_DATA * sizeof(uint64_t));

    wvmcs(vcpu, VMCS_GUEST_GDTR_BASE, X86_GDT_BASE);
    wvmcs(vcpu, VMCS_GUEST_GDTR_LIMIT, X86_GDTR_LIMIT);

    /* no IDT: all interrupts/exceptions exit */
    wvmcs(vcpu, VMCS_GUEST_IDTR_BASE, 0);
    wvmcs(vcpu, VMCS_GUEST_IDTR_LIMIT, 0);

    wvmcs(vcpu, VMCS_GUEST_TR_BASE, ukvm_x86_sreg_tr.base);
    wvmcs(vcpu, VMCS_GUEST_TR_LIMIT, ukvm_x86_sreg_tr.limit);
    wvmcs(vcpu, VMCS_GUEST_TR_AR, x86_sreg_to_ar(&ukvm_x86_sreg_tr));
    //wvmcs(vcpu, VMCS_GUEST_TR_AR, 0x0000008b);

    /* XXX KVM uses ukvm_x86_sreg_unusable, which doesn't seem to fit
     * our needs... */
    wvmcs(vcpu, VMCS_GUEST_LDTR_BASE, 0);
    wvmcs(vcpu, VMCS_GUEST_LDTR_LIMIT, 0xffff);
    wvmcs(vcpu, VMCS_GUEST_LDTR_AR, 0x00000082);
    
    wvmcs(vcpu, VMCS_GUEST_CR0, X86_CR0_INIT);
    wvmcs(vcpu, VMCS_GUEST_CR3, X86_CR3_INIT);
    wvmcs(vcpu, VMCS_GUEST_CR4, X86_CR4_INIT);
    wvmcs(vcpu, VMCS_GUEST_IA32_EFER, X86_EFER_INIT);

    /*
     * Initialize user registers using (Linux) x86_64 ABI convention.
     */
    wvmcs(vcpu, VMCS_GUEST_RIP, gpa_ep);
    wvmcs(vcpu, VMCS_GUEST_RFLAGS, X86_RFLAGS_INIT);
    /* x86_64 ABI requires ((rsp + 8) % 16) == 0 */
    wvmcs(vcpu, VMCS_GUEST_RSP, hv->mem_size - 8);
    wreg(vcpu, HV_X86_RDI, X86_BOOT_INFO_BASE);
    
    wreg(vcpu, HV_X86_DR0, 0x0);
    wreg(vcpu, HV_X86_DR1, 0x0);
    wreg(vcpu, HV_X86_DR2, 0x0);
    wreg(vcpu, HV_X86_DR3, 0x0);
    wreg(vcpu, HV_X86_DR6, 0xffff0ff0);
    
    /* trap everything for cr0 and cr4 */
    wvmcs(vcpu, VMCS_CTRL_CR0_MASK, 0xffffffff);
    wvmcs(vcpu, VMCS_CTRL_CR4_MASK, 0xffffffff);
    wvmcs(vcpu, VMCS_CTRL_CR0_SHADOW, rvmcs(vcpu, VMCS_GUEST_CR0));
    wvmcs(vcpu, VMCS_CTRL_CR4_SHADOW, rvmcs(vcpu, VMCS_GUEST_CR4));

    return 0;
}

void ukvm_hv_vcpu_init(struct ukvm_hv *hv, ukvm_gpa_t gpa_ep,
        ukvm_gpa_t gpa_kend, char **cmdline)
{
    ukvm_x86_setup_gdt(hv->mem);
    ukvm_x86_setup_pagetables(hv->mem, hv->mem_size);

    struct ukvm_boot_info *bi =
        (struct ukvm_boot_info *)(hv->mem + X86_BOOT_INFO_BASE);
    bi->mem_size = hv->mem_size;
    bi->kernel_end = gpa_kend;
    bi->cmdline = X86_CMDLINE_BASE;

    size_t len = sizeof(&bi->cpu.tsc_freq);
    sysctlbyname("machdep.tsc.frequency", &bi->cpu.tsc_freq, &len, NULL, 0);

    if (init_vcpu_state(hv, gpa_ep))
        err(1, "init_vcpu_state");
    
    *cmdline = (char *)(hv->mem + X86_CMDLINE_BASE);
}

static void advance_rip(hv_vcpuid_t vcpu) {
    uint64_t len = rvmcs(vcpu, VMCS_RO_VMEXIT_INSTR_LEN);

    wvmcs(vcpu, VMCS_GUEST_RIP, rreg(vcpu, HV_X86_RIP) + len);
}

void ukvm_hv_vcpu_loop(struct ukvm_hv *hv)
{
    struct ukvm_hvb *hvb = hv->b;
    hv_vcpuid_t vcpu = hvb->vcpu;

    while (1) {
        if(!!hv_vcpu_run(vcpu))
            err(1, "Couldn't run vcpu");

        int handled = 0;
        for (ukvm_vmexit_fn_t *fn = ukvm_core_vmexits; *fn && !handled; fn++)
            handled = ((*fn)(hv) == 0);
        if (handled)
            continue;

        uint64_t exit_reason = rvmcs(vcpu, VMCS_RO_EXIT_REASON);

        switch (exit_reason) {
        case VMX_REASON_HLT:
            /* Guest has halted the CPU, this is considered a normal exit. */
            return;

        case VMX_REASON_IO: {
            uint64_t exit_qual = rvmcs(vcpu, VMCS_RO_EXIT_QUALIFIC);
            uint16_t port = (uint16_t)(exit_qual >> 16);
            
            if (port < UKVM_HYPERCALL_PIO_BASE ||
                port >= (UKVM_HYPERCALL_PIO_BASE + UKVM_HYPERCALL_MAX))
                errx(1, "Invalid guest port access: port=0x%x", port);

            int nr = port - UKVM_HYPERCALL_PIO_BASE;
            ukvm_hypercall_fn_t fn = ukvm_core_hypercalls[nr];
            if (fn == NULL)
                errx(1, "Invalid guest hypercall: num=%d", nr);

            uint64_t rax = rreg(vcpu, HV_X86_RAX);
            ukvm_gpa_t gpa = rax;
            fn(hv, gpa);

            advance_rip(vcpu);
            break;
        }

        case VMX_REASON_CPUID: {
            errx(1, "cpuid");
        }
#if 0
        case VMX_REASON_CPUID: {
            struct ukvm_cpuid cpuid;
            cpuid.code = rreg(vcpu, HV_X86_RAX);
            cpuid.eax = cpuid.ebx = cpuid.ecx = cpuid.edx = 0;

            switch (cpuid.code) {
            case 0: /* genuine intel */
            case 1: /* family/model, etc. */
                break;
            default:
                // XXX make sure all of these are OK
                //printf("unsupported cpuid %llx\n", code);
                //return -1;
                break;
            }
    
            __asm__ volatile("cpuid"
                             :"=a"(cpuid.eax),"=b"(cpuid.ebx),
                              "=c"(cpuid.ecx),"=d"(cpuid.edx)
                             :"a"((uint32_t)cpuid.code));

            wreg(vcpu, HV_X86_RAX, (uint64_t)cpuid.eax & 0xffffffff);
            wreg(vcpu, HV_X86_RBX, (uint64_t)cpuid.ebx & 0xffffffff);
            wreg(vcpu, HV_X86_RCX, (uint64_t)cpuid.ecx & 0xffffffff);
            wreg(vcpu, HV_X86_RDX, (uint64_t)cpuid.edx & 0xffffffff);
            
            advance_rip(vcpu);
            break;
        }
#endif            
        case VMX_REASON_VMENTRY_GUEST:
            errx(1, "entry failure");

            /* exits to ignore */
        case VMX_REASON_IRQ:           /* host interrupt */
        case VMX_REASON_EPT_VIOLATION: /* cold misses */
            break;

        case VMX_REASON_EXC_NMI: {
            uint32_t idt_vector_info = rvmcs(vcpu, VMCS_RO_IDT_VECTOR_INFO);
            uint32_t idt_vector_error = rvmcs(vcpu, VMCS_RO_IDT_VECTOR_ERROR);
            uint32_t irq_info = rvmcs(vcpu, VMCS_RO_VMEXIT_IRQ_INFO);
            uint32_t irq_error = rvmcs(vcpu, VMCS_RO_VMEXIT_IRQ_ERROR);

            #if 0
            /* irq && HW exception && #DB */
            if (irq_info
                && (((irq_info >> 8) & 0x3) == 3)
                && ((irq_info & 0xff) == 1))
                return EXIT_DEBUG;
            #endif
            
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
                switch ((irq_info >> 8) & 0x3) {
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
                if ((irq_info >> 11) & 0x1)
                    printf("irq_error = 0x%x\n", irq_error);
            }
            
            printf("RIP was 0x%llx\n", rreg(vcpu, HV_X86_RIP));
            printf("RSP was 0x%llx\n", rreg(vcpu, HV_X86_RSP));
            err(1, "exit fail");
        }

        default:
            errx(1, "KVM: unhandled exit: exit_reason=0x%llx, rip=0x%llx", 
                 exit_reason, rreg(vcpu, HV_X86_RIP));
        } /* switch(exit_reason) */
    }
}

