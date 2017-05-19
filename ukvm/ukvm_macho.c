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
 * ukvm_macho.c: Mach-O loader.
 *
 * This module should be kept backend-independent and architectural
 * dependencies should be self-contained.
 */

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>
#include <mach-o/loader.h>

void ukvm_elf_load(const char *file, uint8_t *mem, size_t mem_size, /* IN */
                   uint64_t *p_entry, uint64_t *p_end)   /* OUT */
{
    int fd_kernel;
    uint32_t off;
    int i;
    uint8_t *macho;
    struct stat fd_stat;
    struct mach_header_64 *hdr;
    int dbg = 0;
    
    /* elf entry point (on physical memory) */
    *p_entry = 0;
    /* highest byte of the program (on physical memory) */
    *p_end = 0;

    fd_kernel = open(file, O_RDONLY);
    if (fd_kernel == -1)
        goto out_error;
    fstat(fd_kernel, &fd_stat);
    
    macho = mmap(NULL, fd_stat.st_size, PROT_READ, MAP_SHARED, fd_kernel, 0);
    if (macho == MAP_FAILED)
        goto out_error;

    hdr = (struct mach_header_64 *)macho;

    if (hdr->magic != MH_MAGIC_64
        || hdr->cputype != CPU_TYPE_X86_64)
        goto out_invalid;

    off = sizeof(struct mach_header_64);
    if (dbg) printf("%d load commands\n", hdr->ncmds);
    
    for (i = 0; i < hdr->ncmds; i++) {
        struct load_command *lc = (struct load_command *)(macho + off);
        
        if (dbg) printf("0x%08x ", off);
        switch (lc->cmd) {
        case LC_UNIXTHREAD: {
            struct x86_thread_state *ts;
            ts = (struct x86_thread_state *)(macho + off
                                             + sizeof(struct load_command));

            if (dbg) printf("LC_UNIXTHREAD [%d]\n", lc->cmdsize);
            assert(ts->tsh.flavor == x86_THREAD_STATE64);

            *p_entry = ts->uts.ts64.__rip;

            if (dbg) printf("    entry point is 0x%llx\n", *p_entry);
            break;
        }
        case LC_UUID:
            if (dbg) printf("LC_UUID\n");
            break;
        case LC_SOURCE_VERSION:
            if (dbg) printf("LC_SOURCE_VERSION\n");
            break;
        case LC_SYMTAB:
            if (dbg) printf("LC_SYMTAB\n");
            break;
        case LC_SEGMENT_64: {
            struct segment_command_64 *sc;
            int sects;

            sc = (struct segment_command_64 *)(macho + off);
            if (dbg)
                printf("LC_SEGMENT_64 [%08llx - %08llx] %s (%d sections)\n",
                       sc->vmaddr, sc->vmaddr + sc->vmsize,
                       sc->segname, sc->nsects);

            for (sects = 0; sects < sc->nsects; sects++) {
                struct section_64 *s = (struct section_64 *)(macho + off
                                        + sizeof(struct segment_command_64)
                                        + sects * sizeof(struct section_64));

                if (dbg) printf("    [%08llx - %08llx] (0x%x) %s:%s\n",
                                s->addr, s->addr + s->size, s->flags,
                                s->segname, s->sectname);

                if ((s->flags & 0x7) == S_ZEROFILL) {
                    if (dbg) printf("zeroing %lld bytes at 0x%llx\n",
                                    s->size, s->addr);
                    memset(mem + s->addr, 0, s->size);
                } else {
                    if (dbg) printf("copying %lld bytes from 0x%x to 0x%llx\n",
                                    s->size, s->offset, s->addr);
                    memcpy(mem + s->addr, macho + s->offset, s->size);
                }
            }

            *p_end = sc->vmaddr + sc->vmsize;
            break;
        }
        default:
            printf("unknown %x (%d)\n", lc->cmd, lc->cmd);
        }
            
        off += lc->cmdsize;
    }
    
    return;

 out_error:
    err(1, "%s", file);
out_invalid:
    errx(1, "%s: Exec format error", file);
}
