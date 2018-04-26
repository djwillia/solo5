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
 * ukvm_elf.c: ELF loader.
 *
 * This module should be kept backend-independent and architectural
 * dependencies should be self-contained.
 */

#define _GNU_SOURCE
#include <assert.h>
#include <err.h>
#include <elf.h>
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

#include "ukvm.h"

#define ALIGN_PAGE_UP(x) (4096 * ((x + 4095) / 4096))
#define DOMMAP

static ssize_t pread_in_full(int fd, void *buf, size_t count, off_t offset, int mmapable)
{
    ssize_t total = 0;
    char *p = buf;

    if (count > SSIZE_MAX) {
        errno = E2BIG;
        return -1;
    }

    if (mmapable) {
        off_t minimal_offset = 0x100000 - (uint64_t)buf;

        p += minimal_offset;
        offset += minimal_offset;
        count -= minimal_offset;
    }

    while (count > 0) {
        ssize_t nr;
        char *addr;

        if (mmapable) {
#ifdef DOMMAP
            /* XXX: at the moment we have to mark this as writable because the
             * last portion of the last page has to be zeroed out. */
            addr = mmap(p, count,
                        PROT_READ|PROT_EXEC|PROT_WRITE,
                        MAP_PRIVATE|MAP_FIXED,
                        fd, offset);
            assert((off_t)addr == (off_t)p);
#else
            addr = mmap(p, count,
                        PROT_READ|PROT_WRITE|PROT_EXEC,
                        MAP_SHARED|MAP_ANONYMOUS,
                        -1, 0);
            assert((off_t)addr == (off_t)p);
            nr = pread(fd, p, count, offset);
#endif
            nr = count;
        } else
            nr = pread(fd, p, count, offset);

        if (nr == 0)
            return total;
        else if (nr == -1 && errno == EINTR)
            continue;
        else if (nr == -1)
            return -1;

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
 * *mem                    *p_entry                   *p_end
 *   |             |                    |                |
 *   |    ...      | .text .rodata      |   .data .bss   |
 *   |             |        code        |   00000000000  |
 *   |             |  [PROT_EXEC|READ]  |                |
 *
 */
void ukvm_elf_load(const char *file, uint8_t *mem, size_t mem_size,
       ukvm_gpa_t *p_entry, ukvm_gpa_t *p_end)
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
        err(1, "%s can't open kernel", file);

    numb = pread_in_full(fd_kernel, &hdr, sizeof(Elf64_Ehdr), 0, 0);
    if (numb < 0)
        err(1, "%s failed pread", file);
    if (numb != sizeof(Elf64_Ehdr))
            errx(1, "%s: failed pread", file);

    /*
     * Validate program is in ELF64 format:
     * 1. EI_MAG fields 0, 1, 2, 3 spell ELFMAG('0x7f', 'E', 'L', 'F'),
     * 2. File contains 64-bit objects,
     * 3. Objects are Executable,
     * 4. Target instruction must be set to the correct architecture.
     */
    if (hdr.e_ident[EI_MAG0] != ELFMAG0
            || hdr.e_ident[EI_MAG1] != ELFMAG1
            || hdr.e_ident[EI_MAG2] != ELFMAG2
            || hdr.e_ident[EI_MAG3] != ELFMAG3
            || hdr.e_ident[EI_CLASS] != ELFCLASS64
            || hdr.e_type != ET_EXEC
#if defined(__x86_64__)
            || hdr.e_machine != EM_X86_64
#elif defined(__aarch64__)
            || hdr.e_machine != EM_AARCH64
#else
#error Unsupported target
#endif
        )
           errx(1, "%s: bad header entry", file);

    ph_off = hdr.e_phoff;
    ph_entsz = hdr.e_phentsize;
    ph_cnt = hdr.e_phnum;
    buflen = ph_entsz * ph_cnt;

    phdr = malloc(buflen);
    if (!phdr)
        err(1, "%s failed malloc", file);
    numb = pread_in_full(fd_kernel, phdr, buflen, ph_off, 0);
    if (numb < 0)
        err(1, "%s failed pread", file);
    if (numb != buflen)
            errx(1, "%s: incomplete pread 1", file);

    /*
     * Load all segments with the LOAD directive from the elf file at offset
     * p_offset, and copy that into p_addr in memory. The amount of bytes
     * copied is p_filesz.  However, each segment should be given
     * p_memsz aligned up to p_align bytes on memory.
     */
    uint64_t _end = 0;
    for (ph_i = 0; ph_i < ph_cnt; ph_i++) {
        uint8_t *daddr;
        size_t offset = phdr[ph_i].p_offset;
        size_t filesz = phdr[ph_i].p_filesz;
        size_t memsz = phdr[ph_i].p_memsz;
        uint64_t paddr = phdr[ph_i].p_paddr;
        uint64_t align = phdr[ph_i].p_align;
        uint64_t result;

        if (phdr[ph_i].p_type != PT_LOAD)
            continue;

        if ((paddr >= mem_size) || add_overflow(paddr, filesz, result)
                || (result >= mem_size))
                errx(1, "%s: paddr >= mem_size", file);
        if (add_overflow(paddr, memsz, result) || (result >= mem_size))
                errx(1, "%s: paddr >= mem_size", file);
        /*
         * Verify that align is a non-zero power of 2 and safely compute
         * ((_end + (align - 1)) & -align).
         */
        if (align > 0 && (align & (align - 1)) == 0) {
            if (add_overflow(result, (align - 1), _end))
                    errx(1, "%s: not aligned", file);
            _end = _end & -align;
        }
        else {
            _end = result;
        }
        if (_end > *p_end)
            *p_end = _end;

        daddr = mem + paddr;
        numb = pread_in_full(fd_kernel, daddr, ALIGN_PAGE_UP(filesz), offset, 1);
        assert(numb = ALIGN_PAGE_UP(filesz));

        /* XXX: daddr + filesz can overflow */
        uint64_t aligned_filesz_end = ALIGN_PAGE_UP((uint64_t)daddr + filesz);
        if (_end > aligned_filesz_end) {
            /* XXX: remove the PROT_EXEC */
            void *addr = mmap((void *)aligned_filesz_end, _end - aligned_filesz_end,
                            PROT_READ|PROT_WRITE|PROT_EXEC,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            assert((off_t)addr == aligned_filesz_end);
            if (madvise((void *)aligned_filesz_end,  _end - aligned_filesz_end,
                        MADV_MERGEABLE) != 0)
                err(1, "Error with madvise MADV_MERGEABLE");
        }
        memset(daddr + filesz, 0, memsz - filesz);
    }

    /* Allocate the rest of the memory */
    /* XXX: remove the PROT_EXEC */
    void *addr = mmap((void *)_end, mem_size - _end,
                      PROT_READ|PROT_WRITE|PROT_EXEC,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert((off_t)addr == _end);
    if (madvise((void *)_end, mem_size - _end,
                MADV_MERGEABLE) != 0)
        err(1, "Error with madvise MADV_MERGEABLE");

    free (phdr);
    close (fd_kernel);
    *p_entry = hdr.e_entry;
    return;
}
