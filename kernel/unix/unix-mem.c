/* 
 * Copyright (c) 2015-2017 Contributors as noted in the AUTHORS file
 *
 * This file is part of Solo5, a unikernel base layer.
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

#include "kernel.h"

static uint64_t heap_start;
static uint64_t heap_top;
static uint64_t stack_guard_size;

void mem_init(void)
{
    uint64_t mem_size;

    mem_size = platform_mem_size();
    heap_start = (platform_kernel_end() + PAGE_SIZE - 1) & PAGE_MASK;
    heap_top = heap_start;

    /*
     * Cowardly refuse to run with less than 512KB of free memory.
     */
    if (heap_start + 0x80000 > mem_size)
	PANIC("Not enough memory");

    /*
     * If we have <1MB of free memory then don't let the heap grow to more than
     * roughly half of free memory, otherwise don't let it grow to within 1MB
     * of the stack.
     * TODO: Use guard pages here instead?
     */
    stack_guard_size = (mem_size - heap_start >= 0x100000) ?
	0x100000 : ((mem_size - heap_start) / 2);
}

/*
 * Called by dlmalloc to allocate or free memory.
 */
void *sbrk(intptr_t increment)
{
    uint64_t prev, brk;
    /*
     * Heap is limited by the stack (currently at &prev).
     */
    uint64_t heap_max = (uint64_t)&prev - stack_guard_size;
    prev = brk = heap_top;

    /*
     * dlmalloc guarantees increment values less than half of size_t, so this
     * is safe from overflow.
     */
    brk += increment;
    if (brk >= heap_max || brk < heap_start)
        return (void *)-1;

    heap_top = brk;
    return (void *)prev;
}
