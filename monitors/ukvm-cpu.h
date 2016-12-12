#ifndef __UKVM_CPU_H__
#define __UKVM_CPU_H__

#ifndef _BITUL

#ifdef __ASSEMBLY__
#define _AC(X,Y)	X
#define _AT(T,X)	X
#else
#define __AC(X,Y)	(X##Y)
#define _AC(X,Y)	__AC(X,Y)
#define _AT(T,X)	((T)(X))
#endif

#define _BITUL(x)	(_AC(1,UL) << (x))
#define _BITULL(x)	(_AC(1,ULL) << (x))

#endif

/*
 * EFLAGS bits
 */
#define X86_EFLAGS_CF	0x00000001 /* Carry Flag */
#define X86_EFLAGS_TF_BIT   8 /* Trap flag (single step) */
#define X86_EFLAGS_TF   _BITUL(X86_EFLAGS_TF_BIT)

/*
 * Basic CPU control in CR0
 */
//#define X86_CR0_PE_BIT		0 /* Protection Enable */
//#define X86_CR0_PE		_BITUL(X86_CR0_PE_BIT)
//#define X86_CR0_PG_BIT		31 /* Paging */
//#define X86_CR0_PG		_BITUL(X86_CR0_PG_BIT)
#define	X86_CR0_PE	0x00000001	/* Protected mode Enable */
#define	X86_CR0_NE	0x00000020	/* Numeric Error enable (EX16 vs IRQ13) */
#define	X86_CR0_PG	0x80000000	/* PaGing enable */
#define	X86_CR0_NW  0x20000000	/* Not Write-through */
#define	X86_CR0_CD  0x40000000	/* Cache Disable */
#define	X86_CR0_MP	0x00000002	/* "Math" (fpu) Present */
#define	X86_CR0_EM	0x00000004	/* EMulate FPU instructions. (trap ESC only) */
    
/*
 * Intel CPU features in CR4
 */
//#define X86_CR4_PAE_BIT		5 /* enable physical address extensions */
//#define X86_CR4_PAE		_BITUL(X86_CR4_PAE_BIT)
#define	X86_CR4_PAE	 0x00000020	/* Physical address extension */
#define	X86_CR4_VMXE 0x00002000	/* enable VMX operation (Intel-specific) */
#define	X86_CR4_FXSR 0x00000200	/* Fast FPU save/restore used by OS */
#define	X86_CR4_XMM	 0x00000400	/* enable SIMD/MMX2 to use except 16 */


#define	X86_EFER_LME 0x000000100	/* Long mode enable (R/W) */
#define	X86_EFER_LMA 0x000000400	/* Long mode active (R) */


/*
 * Model-specific registers for the i386 family
 */
#define	MSR_P5_MC_ADDR		0x000
#define	MSR_P5_MC_TYPE		0x001
#define	MSR_TSC			0x010
#define	MSR_P5_CESR		0x011
#define	MSR_P5_CTR0		0x012
#define	MSR_P5_CTR1		0x013
#define	MSR_IA32_PLATFORM_ID	0x017
#define	MSR_APICBASE		0x01b
#define	MSR_EBL_CR_POWERON	0x02a
#define	MSR_TEST_CTL		0x033
#define	MSR_IA32_FEATURE_CONTROL 0x03a
#define	MSR_BIOS_UPDT_TRIG	0x079
#define	MSR_BBL_CR_D0		0x088
#define	MSR_BBL_CR_D1		0x089
#define	MSR_BBL_CR_D2		0x08a
#define	MSR_BIOS_SIGN		0x08b
#define	MSR_PERFCTR0		0x0c1
#define	MSR_PERFCTR1		0x0c2
#define	MSR_PLATFORM_INFO	0x0ce
#define	MSR_MPERF		0x0e7
#define	MSR_APERF		0x0e8
#define	MSR_IA32_EXT_CONFIG	0x0ee	/* Undocumented. Core Solo/Duo only */
#define	MSR_MTRRcap		0x0fe
#define	MSR_BBL_CR_ADDR		0x116
#define	MSR_BBL_CR_DECC		0x118
#define	MSR_BBL_CR_CTL		0x119
#define	MSR_BBL_CR_TRIG		0x11a
#define	MSR_BBL_CR_BUSY		0x11b
#define	MSR_BBL_CR_CTL3		0x11e
#define	MSR_SYSENTER_CS_MSR	0x174
#define	MSR_SYSENTER_ESP_MSR	0x175
#define	MSR_SYSENTER_EIP_MSR	0x176
#define	MSR_MCG_CAP		0x179
#define	MSR_MCG_STATUS		0x17a
#define	MSR_MCG_CTL		0x17b
#define	MSR_EVNTSEL0		0x186
#define	MSR_EVNTSEL1		0x187
#define	MSR_THERM_CONTROL	0x19a
#define	MSR_THERM_INTERRUPT	0x19b
#define	MSR_THERM_STATUS	0x19c
#define	MSR_IA32_MISC_ENABLE	0x1a0
#define	MSR_IA32_TEMPERATURE_TARGET	0x1a2
#define	MSR_TURBO_RATIO_LIMIT	0x1ad
#define	MSR_TURBO_RATIO_LIMIT1	0x1ae
#define	MSR_DEBUGCTLMSR		0x1d9
#define	MSR_LASTBRANCHFROMIP	0x1db
#define	MSR_LASTBRANCHTOIP	0x1dc
#define	MSR_LASTINTFROMIP	0x1dd
#define	MSR_LASTINTTOIP		0x1de
#define	MSR_ROB_CR_BKUPTMPDR6	0x1e0
#define	MSR_MTRRVarBase		0x200
#define	MSR_MTRR64kBase		0x250
#define	MSR_MTRR16kBase		0x258
#define	MSR_MTRR4kBase		0x268
#define	MSR_PAT			0x277
#define	MSR_MC0_CTL2		0x280
#define	MSR_MTRRdefType		0x2ff
#define	MSR_MC0_CTL		0x400
#define	MSR_MC0_STATUS		0x401
#define	MSR_MC0_ADDR		0x402
#define	MSR_MC0_MISC		0x403
#define	MSR_MC1_CTL		0x404
#define	MSR_MC1_STATUS		0x405
#define	MSR_MC1_ADDR		0x406
#define	MSR_MC1_MISC		0x407
#define	MSR_MC2_CTL		0x408
#define	MSR_MC2_STATUS		0x409
#define	MSR_MC2_ADDR		0x40a
#define	MSR_MC2_MISC		0x40b
#define	MSR_MC3_CTL		0x40c
#define	MSR_MC3_STATUS		0x40d
#define	MSR_MC3_ADDR		0x40e
#define	MSR_MC3_MISC		0x40f
#define	MSR_MC4_CTL		0x410
#define	MSR_MC4_STATUS		0x411
#define	MSR_MC4_ADDR		0x412
#define	MSR_MC4_MISC		0x413
#define	MSR_RAPL_POWER_UNIT	0x606
#define	MSR_PKG_ENERGY_STATUS	0x611
#define	MSR_DRAM_ENERGY_STATUS	0x619
#define	MSR_PP0_ENERGY_STATUS	0x639
#define	MSR_PP1_ENERGY_STATUS	0x641

/*
 * VMX MSRs
 */
#define	MSR_VMX_BASIC		0x480
#define	MSR_VMX_PINBASED_CTLS	0x481
#define	MSR_VMX_PROCBASED_CTLS	0x482
#define	MSR_VMX_EXIT_CTLS	0x483
#define	MSR_VMX_ENTRY_CTLS	0x484
#define	MSR_VMX_CR0_FIXED0	0x486
#define	MSR_VMX_CR0_FIXED1	0x487
#define	MSR_VMX_CR4_FIXED0	0x488
#define	MSR_VMX_CR4_FIXED1	0x489
#define	MSR_VMX_PROCBASED_CTLS2	0x48b
#define	MSR_VMX_EPT_VPID_CAP	0x48c
#define	MSR_VMX_TRUE_PINBASED_CTLS	0x48d
#define	MSR_VMX_TRUE_PROCBASED_CTLS	0x48e
#define	MSR_VMX_TRUE_EXIT_CTLS	0x48f
#define	MSR_VMX_TRUE_ENTRY_CTLS	0x490

/* AMD64 MSR's */
#define	MSR_EFER	0xc0000080	/* extended features */
#define	MSR_STAR	0xc0000081	/* legacy mode SYSCALL target/cs/ss */
#define	MSR_LSTAR	0xc0000082	/* long mode SYSCALL target rip */
#define	MSR_CSTAR	0xc0000083	/* compat mode SYSCALL target rip */
#define	MSR_SF_MASK	0xc0000084	/* syscall flags mask */
#define	MSR_FSBASE	0xc0000100	/* base address of the %fs "segment" */
#define	MSR_GSBASE	0xc0000101	/* base address of the %gs "segment" */
#define	MSR_KGSBASE	0xc0000102	/* base address of the kernel %gs */
#define	MSR_PERFEVSEL0	0xc0010000
#define	MSR_PERFEVSEL1	0xc0010001
#define	MSR_PERFEVSEL2	0xc0010002
#define	MSR_PERFEVSEL3	0xc0010003
#define	MSR_K7_PERFCTR0	0xc0010004
#define	MSR_K7_PERFCTR1	0xc0010005
#define	MSR_K7_PERFCTR2	0xc0010006
#define	MSR_K7_PERFCTR3	0xc0010007
#define	MSR_SYSCFG	0xc0010010
#define	MSR_HWCR	0xc0010015
#define	MSR_IORRBASE0	0xc0010016
#define	MSR_IORRMASK0	0xc0010017
#define	MSR_IORRBASE1	0xc0010018
#define	MSR_IORRMASK1	0xc0010019
#define	MSR_TOP_MEM	0xc001001a	/* boundary for ram below 4G */
#define	MSR_TOP_MEM2	0xc001001d	/* boundary for ram above 4G */
#define	MSR_NB_CFG1	0xc001001f	/* NB configuration 1 */
#define	MSR_P_STATE_LIMIT 0xc0010061	/* P-state Current Limit Register */
#define	MSR_P_STATE_CONTROL 0xc0010062	/* P-state Control Register */
#define	MSR_P_STATE_STATUS 0xc0010063	/* P-state Status Register */
#define	MSR_P_STATE_CONFIG(n) (0xc0010064 + (n)) /* P-state Config */
#define	MSR_SMM_ADDR	0xc0010112	/* SMM TSEG base address */
#define	MSR_SMM_MASK	0xc0010113	/* SMM TSEG address mask */
#define	MSR_IC_CFG	0xc0011021	/* Instruction Cache Configuration */
#define	MSR_K8_UCODE_UPDATE	0xc0010020	/* update microcode */
#define	MSR_MC0_CTL_MASK	0xc0010044
#define	MSR_VM_CR		0xc0010114 /* SVM: feature control */
#define	MSR_VM_HSAVE_PA		0xc0010117 /* SVM: host save area address */

/*
 * Intel long mode page directory/table entries
 */
#define X86_PDPT_P_BIT          0 /* Present */
#define X86_PDPT_P              _BITUL(X86_PDPT_P_BIT)
#define X86_PDPT_RW_BIT         1 /* Writable */
#define X86_PDPT_RW             _BITUL(X86_PDPT_RW_BIT)
#define X86_PDPT_PS_BIT         7 /* Page size */
#define X86_PDPT_PS             _BITUL(X86_PDPT_PS_BIT)

/*
 * GDT and KVM segment manipulation
 */

#define GDT_DESC_OFFSET(n) ((n) * 0x8)

#define GDT_GET_BASE(x) (                      \
    (((x) & 0xFF00000000000000) >> 32) |       \
    (((x) & 0x000000FF00000000) >> 16) |       \
    (((x) & 0x00000000FFFF0000) >> 16))

#define GDT_GET_LIMIT(x) (__u32)(                                      \
                                 (((x) & 0x000F000000000000) >> 32) |  \
                                 (((x) & 0x000000000000FFFF)))

/* Constructor for a conventional segment GDT (or LDT) entry */
/* This is a macro so it can be used in initializers */
#define GDT_ENTRY(flags, base, limit)               \
    ((((base)  & _AC(0xff000000, ULL)) << (56-24)) | \
     (((flags) & _AC(0x0000f0ff, ULL)) << 40) |      \
     (((limit) & _AC(0x000f0000, ULL)) << (48-16)) | \
     (((base)  & _AC(0x00ffffff, ULL)) << 16) |      \
     (((limit) & _AC(0x0000ffff, ULL))))

struct _kvm_segment {
    uint64_t base;
    uint32_t limit;
    uint16_t selector;
    uint8_t type;
    uint8_t present, dpl, db, s, l, g, avl;
    uint8_t unusable;
    uint8_t padding;
};

#define GDT_GET_G(x)   (uint8_t)(((x) & 0x0080000000000000) >> 55)
#define GDT_GET_DB(x)  (uint8_t)(((x) & 0x0040000000000000) >> 54)
#define GDT_GET_L(x)   (uint8_t)(((x) & 0x0020000000000000) >> 53)
#define GDT_GET_AVL(x) (uint8_t)(((x) & 0x0010000000000000) >> 52)
#define GDT_GET_P(x)   (uint8_t)(((x) & 0x0000800000000000) >> 47)
#define GDT_GET_DPL(x) (uint8_t)(((x) & 0x0000600000000000) >> 45)
#define GDT_GET_S(x)   (uint8_t)(((x) & 0x0000100000000000) >> 44)
#define GDT_GET_TYPE(x)(uint8_t)(((x) & 0x00000F0000000000) >> 40)

#define GDT_TO_KVM_SEGMENT(seg, gdt_table, sel) \
    do {                                        \
        uint64_t gdt_ent = gdt_table[sel];         \
        seg.base = GDT_GET_BASE(gdt_ent);       \
        seg.limit = GDT_GET_LIMIT(gdt_ent);     \
        seg.selector = sel * 8;                 \
        seg.type = GDT_GET_TYPE(gdt_ent);       \
        seg.present = GDT_GET_P(gdt_ent);       \
        seg.dpl = GDT_GET_DPL(gdt_ent);         \
        seg.db = GDT_GET_DB(gdt_ent);           \
        seg.s = GDT_GET_S(gdt_ent);             \
        seg.l = GDT_GET_L(gdt_ent);             \
        seg.g = GDT_GET_G(gdt_ent);             \
        seg.avl = GDT_GET_AVL(gdt_ent);         \
    } while (0)

#endif
