/* 
 * Copyright (c) 2015-2018 Contributors as noted in the AUTHORS file
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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>
#include <assert.h>
#include <pthread.h>

#include "ukvm.h"

#ifndef __linux__
#error Unsupported target
#endif

#define OUT(l, x...)                            \
    do {                                        \
        printf(x);                              \
        ret = -1;                               \
        goto l;                                 \
    } while(0)

struct ukvm_ftrace_ctxt {
    int uni_ready;
    int trace_ready;
    int uni_exiting;
    int trace_exiting;
};

struct ftrace {
    int trace;
    int tracing_on;
    int current_tracer;
    int set_ftrace_pid;
    int trace_options;
};

static struct ftrace ftrace;
static struct ukvm_ftrace_ctxt *shared;
static bool use_ftrace = false;
static char *outfile;

#define FTRACE_OPEN_FN(f)                                       \
    int ftrace_open_##f(struct ftrace *t) {                     \
        t->f = open("/sys/kernel/debug/tracing/" #f,            \
                    O_WRONLY | O_CREAT | O_TRUNC, S_IWUSR);     \
        if (t->f <= 0) {                                        \
            printf("couldn't open %s\n", #f);                   \
            return -1;                                          \
        }                                                       \
        return 0;                                               \
    }

#define FTRACE_WRITE_FN(f)                                              \
    int ftrace_write_##f(struct ftrace *t, char *s) {                   \
        int len = strlen(s);                                            \
        int ret;                                                        \
        ret = write(t->f, s, len);                                      \
        if (ret <= 0) {                                                 \
            printf("couldn't write %s ret=%d len=%d\n", #f, ret, len);  \
            perror("error");                                            \
            return -1;                                                  \
        }                                                               \
        return 0;                                                       \
    }

#define FTRACE_DECLARE(f)                       \
    FTRACE_OPEN_FN(f)                           \
    FTRACE_WRITE_FN(f)

FTRACE_DECLARE(trace);
FTRACE_DECLARE(tracing_on);
FTRACE_DECLARE(current_tracer);
FTRACE_DECLARE(set_ftrace_pid);
FTRACE_DECLARE(trace_options);

#define FTRACE_OPEN(f) ftrace_open_##f(&ftrace)
#define FTRACE_WRITE(f,s) ftrace_write_##f(&ftrace, s)
#define FTRACE_CLOSE(f) close(ftrace.f);        

#define BUF_SIZE 1024
static void *extract(void *arg) {
    int fdin = open ("/sys/kernel/debug/tracing/trace_pipe",
                     O_RDONLY, S_IWUSR);
    int fdout = open (outfile,
                      O_WRONLY | O_CREAT | O_TRUNC, S_IWUSR);
    while(1){
        char buf[BUF_SIZE];
        int len, wlen;
        len = read(fdin, buf, BUF_SIZE);
        if (len == 0)
            continue;
        if (len < 0) {
            printf("couldn't read trace %d\n", len);
            perror("error");
        }
        wlen = write(fdout, buf, len);
        if (wlen < len) {
            printf("couldn't write trace %d\n", wlen);
            perror("error");
        }
    }
    return NULL;
}

#if 0
static int extract_trace(char *pidbuf) {
    char *extractcmd;
    FILE *f;
    int ret;

    ret = asprintf(&extractcmd,
                   "cat /sys/kernel/debug/tracing/trace "           \
                   "| grep \"\\-%s \" "                             \
                   "| grep -v \"=>\" "                              \
                   "| tee %s.raw "                                  \
                   "| grep -v \"^#\" "                              \
                   "| cut -f 3 -d '|' "                             \
                   "| grep -o \"[a-z_0-9A-Z\\.]*\" "                \
                   "| sort "                                        \
                   "| uniq -c "                                     \
                   "> %s.summary",
                   pidbuf, outfile, outfile);
    printf("extracting trace with:\n\t%s\n", extractcmd);
    
    if (ret < 0)
        return -1;
        
    f = popen(extractcmd, "r");
    free(extractcmd);

    if (f)
        fclose(f);
    else
        return -1;

    return 0;
}
#endif

void ukvm_ftrace_ready(void)
{
    if (!use_ftrace)
        return;
    /*
     * Note: To ensure a clean trace, there should be no more syscalls
     * after setting uni_ready! 
     */
    shared->uni_ready = 1;  
    while (!shared->trace_ready)
        __asm__ __volatile__("" ::: "memory");
}

void ukvm_ftrace_finished(void)
{
    if (!use_ftrace)
        return;

    shared->uni_exiting = 1;
    while(!shared->trace_exiting)
        __asm__ __volatile__("" ::: "memory");
    
    /* I am the unikernel and I am now exiting. */
}

static void sig_handler(int signo)
{
    printf(" Exiting on signal %d\n", signo);
}

static int setup(struct ukvm_hv *hv)
{
    pid_t pid_trace, pid_uni;
    int ret = -1;
    char *pidbuf;

    if (!use_ftrace)
        return 0;

    shared = (struct ukvm_ftrace_ctxt *)mmap(NULL,
                                             sizeof(struct ukvm_ftrace_ctxt),
                                             PROT_READ | PROT_WRITE,
                                             MAP_ANONYMOUS | MAP_SHARED,
                                             0, 0);
    if (shared == MAP_FAILED)
        OUT(o0, "bad mmap result\n");
    shared->uni_ready = 0;
    shared->trace_ready = 0;
    shared->uni_exiting = 0;
    shared->trace_exiting = 0;

    pid_uni = getpid();
    pid_trace = fork();
    /* The parent (not the child) must be the one to continue
     * unikernel setup and execution because KVM ioctls do not work in
     * the child */
    if (pid_trace > 0) 
        return 0;

    if (pid_trace < 0)
        OUT(o1, "bad fork result %d", pid_trace);
    if (asprintf(&pidbuf, "%d", pid_uni) < 0)
        OUT(o2, "couldn't asprintf");

    /* The child will do the tracing */
    assert(pid_trace == 0);

    struct sigaction sa;
    memset (&sa, 0, sizeof (struct sigaction));
    sa.sa_handler = sig_handler;
    sigfillset(&sa.sa_mask);
    if (sigaction(SIGINT, &sa, NULL) == -1)
        err(1, "Could not install signal handler");
    if (sigaction(SIGTERM, &sa, NULL) == -1)
        err(1, "Could not install signal handler");
    
    /* wait for unikernel to get ready */
    while(!shared->uni_ready)
        usleep(10);
    
    if (FTRACE_OPEN(trace))
        OUT(o3, "couldn't open trace\n");
    if (FTRACE_OPEN(current_tracer))
        OUT(o4, "couldn't open current_tracer\n");
    if (FTRACE_OPEN(tracing_on))
        OUT(o5, "couldn't open tracing_on\n");
    if (FTRACE_OPEN(set_ftrace_pid))
        OUT(o6, "couldn't open set_ftrace_pid\n");
    if (FTRACE_OPEN(trace_options))
        OUT(o7, "couldn't open trace_options\n");

    if (FTRACE_WRITE(tracing_on, "0")) 
        OUT(o8, "couldn't disable tracing\n");
    if (FTRACE_WRITE(trace, " "))
        OUT(o8, "couldn't clear trace\n");
    if (FTRACE_WRITE(current_tracer, "function_graph"))
        OUT(o8, "couldn't set function_graph tracer\n");
    if (FTRACE_WRITE(set_ftrace_pid, " "))
        OUT(o8, "couldn't set pid\n");
    if (FTRACE_WRITE(set_ftrace_pid, pidbuf))
        OUT(o8, "couldn't set pid\n");
    if (FTRACE_WRITE(trace_options, "nofuncgraph-irqs"))
        OUT(o8, "couldn't set trace_options\n");
    if (FTRACE_WRITE(trace_options, "nofuncgraph-overhead"))
        OUT(o8, "couldn't set trace_options\n");
    if (FTRACE_WRITE(trace_options, "nofuncgraph-duration"))
        OUT(o8, "couldn't set trace_options\n");
    if (FTRACE_WRITE(trace_options, "funcgraph-abstime"))
        OUT(o8, "couldn't set trace_options\n");
    if (FTRACE_WRITE(trace_options, "nofuncgraph-tail"))
        OUT(o8, "couldn't set trace_options\n");
    if (FTRACE_WRITE(trace_options, "funcgraph-proc"))
        OUT(o8, "couldn't set trace_options\n");

    pthread_t extractor;
    pthread_create(&extractor, NULL, extract, NULL);

    if (FTRACE_WRITE(tracing_on, "1"))
        OUT(o8, "couldn't enable tracing\n");
    
    shared->trace_ready = 1;
    
    /* wait for unikernel to be exiting */
    while(!shared->uni_exiting)
        usleep(10);

    if (FTRACE_WRITE(tracing_on, "0"))
        OUT(o8, "couldn't disable tracing\n");

#if 0
    if (extract_trace(pidbuf))
        OUT(o8, "couldn't extract trace\n");
#endif

    printf("Waiting for extractor to finish (extracting to %s)\n", outfile);
    sleep(5); /* XXX allow extractor to finish */
    
    ret = 0;
    shared->trace_exiting = 1;
    
 o8:
    FTRACE_CLOSE(trace_options);
 o7:
    FTRACE_CLOSE(set_ftrace_pid);
 o6:
    FTRACE_CLOSE(tracing_on);
 o5:
    FTRACE_CLOSE(current_tracer);
 o4:
    FTRACE_CLOSE(trace);
 o3:
    free(pidbuf);
 o2:
    kill(pid_uni, SIGKILL);
 o1:
    munmap(shared, sizeof(struct ukvm_ftrace_ctxt));
 o0:
    if (ret == 0) {
        /* I am the tracer and I am now exiting. */
        exit(0);
    }
    return ret;
}

static int handle_cmdarg(char *cmdarg)
{
    if (!strncmp("--ftrace=", cmdarg, 9)) {
        use_ftrace = true;
        outfile = cmdarg + 9;
        return 0;
    }
    return -1;
}

static char *usage(void)
{
    return "--ftrace=OUTFILE (enable ftrace and output in OUTFILE)\n";
}

struct ukvm_module ukvm_module_ftrace = {
    .name = "ftrace",
    .setup = setup,
    .handle_cmdarg = handle_cmdarg,
    .usage = usage
};
