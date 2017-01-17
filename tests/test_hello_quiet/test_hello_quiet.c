#include "solo5.h"

static size_t strlen(const char *s)
{
    size_t len = 0;

    while (*s++)
        len += 1;
    return len;
}

static void puts(const char *s)
{
    solo5_console_write(s, strlen(s));
}

int solo5_app_main(__attribute__((unused)) char *cmdline)
{
    puts("Hello\n");
    return 0;
}
