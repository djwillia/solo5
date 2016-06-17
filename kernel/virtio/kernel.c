/* Copyright (c) 2015, IBM 
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

#include "kernel.h"

extern int start_kernel(int argc, char **argv);
static char *str = "solo5";

extern void bounce_stack(uint64_t stack_start, void (*tramp)(void));
static void kernel_main2(void) __attribute__((noreturn));

void kernel_main(uint32_t arg)
{
    volatile int gdb = 1;
    serial_init();

    printf("            |      ___|  \n");
    printf("  __|  _ \\  |  _ \\ __ \\  \n");
    printf("\\__ \\ (   | | (   |  ) | \n");
    printf("____/\\___/ _|\\___/____/  \n");

    if (!gdb) printf("looping for gdb\n");
    while ( gdb == 0 ); 

    /*
     * Initialise memory map, then immediately switch stack to top of RAM.
     * Indirectly calls kernel_main2().
     */
    mem_init((struct multiboot_info *)((uint64_t)arg));
    bounce_stack(mem_max_addr(), kernel_main2);
}

static void kernel_main2(void)
{
    interrupts_init();
    /* ocaml needs floating point */
    sse_enable();
    time_init();

    pci_enumerate();

    interrupts_enable();

    {
        int argc = 1;
        char **argv = &str;
        start_kernel(argc, argv);
    }

    printf("Kernel done. \nGoodbye!\n");
    kernel_hang();
}
